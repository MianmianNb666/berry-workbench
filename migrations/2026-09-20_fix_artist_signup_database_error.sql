-- 莓桃工作台：修复美工注册 “Database error saving new user”
-- 适用现象：
-- 1) 美工点击第一次注册
-- 2) 前端提示 Database error saving new user
-- 3) Authentication -> Users 里没有留下该用户
-- 4) 使用 BERRY-7D-GENERAL
--
-- 这份修复不会删除现有用户。
-- 会：
-- - 修复 pgcrypto/digest 在注册 trigger 中的调用
-- - 再确认通用 7 天邀请码为 multi，最多 100 个不同账号
-- - 清掉旧的“一个邀请码只能有一条兑换记录”约束
-- - 保留 used_count，不把已经使用次数清零

begin;

create extension if not exists pgcrypto with schema extensions;

-- =========================================================
-- A. 确保通用邀请码所需字段存在
-- =========================================================

alter table public.invite_codes
  add column if not exists use_mode text not null default 'single';

alter table public.invite_codes
  add column if not exists max_uses integer;

alter table public.invite_codes
  add column if not exists used_count integer not null default 0;

update public.invite_codes
set used_count = greatest(
  coalesce(used_count, 0),
  case when used_at is not null then 1 else 0 end
);

-- =========================================================
-- B. 修复多用户共用邀请码时可能残留的旧唯一约束
-- =========================================================

alter table public.invite_redemptions
  drop constraint if exists invite_redemptions_invite_id_key;

alter table public.invite_redemptions
  drop constraint if exists one_redemption_per_invite;

create unique index if not exists invite_redemptions_invite_user_unique
  on public.invite_redemptions(invite_id, user_id);

-- =========================================================
-- C. 确保 BERRY-7D-GENERAL 存在，并保持为 100 人通用 7 天码
-- 不会把 used_count 重置为 0
-- =========================================================

insert into public.invite_codes as ic(
  code_hash,
  label,
  purpose,
  grant_type,
  duration_days,
  use_mode,
  max_uses,
  used_count,
  is_active
)
values (
  encode(extensions.digest(upper(trim('BERRY-7D-GENERAL')), 'sha256'), 'hex'),
  '通用7天注册试用码',
  'signup',
  'days',
  7,
  'multi',
  100,
  0,
  true
)
on conflict (code_hash) do update
set
  label = excluded.label,
  purpose = 'signup',
  grant_type = 'days',
  duration_days = 7,
  use_mode = 'multi',
  max_uses = greatest(coalesce(ic.max_uses, 100), 100),
  is_active = case
    when coalesce(ic.used_count, 0) < greatest(coalesce(ic.max_uses, 100), 100)
      and (ic.expires_at is null or ic.expires_at > now())
    then true
    else ic.is_active
  end;

-- =========================================================
-- D. 修复美工 / 顾客注册 trigger 函数
-- 关键修复：
--   search_path 加 extensions
--   digest 显式写成 extensions.digest
-- =========================================================

create or replace function public.handle_new_user_access()
returns trigger
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_role text;
  v_code text;
  v_hash text;
  v_invite public.invite_codes%rowtype;
  v_new_until timestamptz;
begin
  v_role := lower(trim(coalesce(new.raw_user_meta_data ->> 'account_role', 'artist')));

  -- 顾客端不走美工注册邀请码。
  if v_role = 'customer' then
    insert into public.user_roles(user_id, role)
    values (new.id, 'customer')
    on conflict do nothing;

    return new;
  end if;

  -- 美工账号。
  insert into public.user_roles(user_id, role)
  values (new.id, 'artist')
  on conflict do nothing;

  v_code := upper(trim(coalesce(new.raw_user_meta_data ->> 'invite_code', '')));

  if v_code = '' then
    raise exception '注册需要有效邀请码';
  end if;

  v_hash := encode(extensions.digest(v_code, 'sha256'), 'hex');

  update public.invite_codes ic
  set
    used_count = coalesce(ic.used_count, 0) + 1,
    used_at = case
      when ic.use_mode = 'single' then now()
      else ic.used_at
    end,
    used_by = case
      when ic.use_mode = 'single' then new.id
      else ic.used_by
    end,
    is_active = case
      when ic.use_mode = 'single' then false
      when ic.max_uses is not null
           and coalesce(ic.used_count, 0) + 1 >= ic.max_uses then false
      else true
    end
  where ic.code_hash = v_hash
    and ic.purpose = 'signup'
    and ic.grant_type = 'days'
    and ic.duration_days = 7
    and ic.is_active = true
    and (ic.expires_at is null or ic.expires_at > now())
    and (
      (ic.use_mode = 'single' and ic.used_at is null)
      or
      (
        ic.use_mode = 'multi'
        and (ic.max_uses is null or coalesce(ic.used_count, 0) < ic.max_uses)
      )
    )
  returning *
    into v_invite;

  if v_invite.id is null then
    raise exception '邀请码无效、已使用、已达使用上限或已过期';
  end if;

  v_new_until := now() + make_interval(days => v_invite.duration_days);

  insert into public.user_access(
    user_id,
    access_type,
    valid_from,
    valid_until,
    updated_at
  )
  values (
    new.id,
    'temporary',
    now(),
    v_new_until,
    now()
  )
  on conflict (user_id) do update
  set
    access_type = excluded.access_type,
    valid_from = excluded.valid_from,
    valid_until = excluded.valid_until,
    updated_at = excluded.updated_at;

  insert into public.invite_redemptions(
    invite_id,
    user_id,
    purpose,
    grant_type,
    duration_days,
    old_valid_until,
    new_valid_until
  )
  values (
    v_invite.id,
    new.id,
    'signup',
    'days',
    v_invite.duration_days,
    null,
    v_new_until
  )
  on conflict (invite_id, user_id) do nothing;

  insert into public.artist_profiles(
    artist_user_id,
    public_name
  )
  values (
    new.id,
    '莓桃美工'
  )
  on conflict (artist_user_id) do nothing;

  return new;
end;
$$;

commit;

-- =========================================================
-- E. 跑完以后会显示当前通用邀请码状态
-- 正常应为：
-- purpose=signup
-- grant_type=days
-- duration_days=7
-- use_mode=multi
-- max_uses >= 100
-- is_active=true（如果还没满 100 人）
-- =========================================================

select
  label,
  purpose,
  grant_type,
  duration_days,
  use_mode,
  max_uses,
  used_count,
  is_active,
  expires_at
from public.invite_codes
where code_hash =
  encode(extensions.digest(upper(trim('BERRY-7D-GENERAL')), 'sha256'), 'hex');
