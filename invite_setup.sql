-- 莓桃工作台：一次性邀请码
-- 作用：
-- 1) 只有携带有效邀请码的新账号才能注册
-- 2) 每个邀请码默认只能使用一次
-- 3) 登录不需要邀请码
-- 4) 校验在数据库触发器中执行，不把邀请码列表写进公开网页源码

create table if not exists public.invite_codes (
  code text primary key,
  is_active boolean not null default true,
  max_uses integer not null default 1 check (max_uses > 0),
  used_count integer not null default 0 check (used_count >= 0),
  expires_at timestamptz,
  used_by uuid references auth.users(id) on delete set null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

alter table public.invite_codes enable row level security;

-- 前端用户不需要直接读取邀请码表。
revoke all on table public.invite_codes from anon, authenticated;

create or replace function public.consume_invite_on_signup()
returns trigger
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  supplied_code text;
  matched_code text;
begin
  supplied_code := upper(trim(coalesce(new.raw_user_meta_data ->> 'invite_code', '')));

  if supplied_code = '' then
    raise exception '邀请码必填';
  end if;

  select code
    into matched_code
  from public.invite_codes
  where code = supplied_code
    and is_active = true
    and used_count < max_uses
    and (expires_at is null or expires_at > now())
  for update;

  if matched_code is null then
    raise exception '邀请码无效、已使用或已过期';
  end if;

  update public.invite_codes
  set used_count = used_count + 1,
      is_active = case when used_count + 1 >= max_uses then false else is_active end,
      used_by = new.id,
      used_at = now()
  where code = matched_code;

  return new;
end;
$$;

drop trigger if exists trg_require_invite_on_signup on auth.users;

create trigger trg_require_invite_on_signup
after insert on auth.users
for each row
execute function public.consume_invite_on_signup();

-- 示例：新增一个一次性邀请码
-- 把 BERRY-2026-01 换成你自己想要的码，然后运行这一行。
-- insert into public.invite_codes(code) values ('BERRY-2026-01');

-- 查看邀请码状态（仅后台 SQL Editor 使用）
-- select code, is_active, max_uses, used_count, expires_at, used_at from public.invite_codes order by created_at desc;
