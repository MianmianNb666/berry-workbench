-- 莓桃工作台：核心数据库结构备份
-- 文件用途：仅用于基础结构参考 / 灾备，不代表 9 月 20 日以后全部功能迁移。
-- 新建完整环境时，还需要按日期运行 migrations/，最后运行：
-- migrations/2026-09-20_final_permission_lockdown.sql
-- 重要：不要在正在使用的生产库里整份盲目重复执行。
-- 若只是日常修改数据库，请使用单独的增量 SQL。
-- 本文件不包含任何真实邀请码、密码、邮箱密钥或 service_role key。
-- 最后整理：2026-09-19
-- 已支持：一次性邀请码 + 多账号通用邀请码（每账号仅可使用一次）

create extension if not exists pgcrypto with schema extensions;

-- =========================================================
-- 1. 工作台数据
-- =========================================================

create table if not exists public.workspaces (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null default '{"orders":[],"times":[],"title":"莓桃工作台"}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.workspaces enable row level security;

revoke all on table public.workspaces from anon, authenticated;
grant select, insert, update, delete on table public.workspaces to authenticated;


-- =========================================================
-- 2. 用户使用期限
-- =========================================================

create table if not exists public.user_access (
  user_id uuid primary key references auth.users(id) on delete cascade,
  access_type text not null default 'temporary'
    check (access_type in ('temporary','permanent')),
  valid_from timestamptz not null default now(),
  valid_until timestamptz,
  updated_at timestamptz not null default now()
);

alter table public.user_access enable row level security;
revoke all on table public.user_access from anon, authenticated;


-- =========================================================
-- 3. 邀请码
-- 不保存明文邀请码，只保存 SHA-256 hash
-- =========================================================

create table if not exists public.invite_codes (
  id uuid primary key default gen_random_uuid(),
  code_hash text not null unique,
  label text,
  purpose text not null
    check (purpose in ('signup','renewal')),
  grant_type text not null
    check (grant_type in ('days','permanent')),
  duration_days integer,
  is_active boolean not null default true,
  expires_at timestamptz,
  used_at timestamptz,
  used_by uuid references auth.users(id) on delete set null,
  use_mode text not null default 'single'
    check (use_mode in ('single','multi')),
  max_uses integer check (max_uses is null or max_uses > 0),
  used_count integer not null default 0,
  created_at timestamptz not null default now(),

  constraint invite_duration_check check (
    (grant_type = 'days' and duration_days in (7,30,90,365))
    or
    (grant_type = 'permanent' and duration_days is null)
  ),

  constraint signup_invite_check check (
    purpose <> 'signup'
    or (grant_type = 'days' and duration_days = 7)
  )
);

alter table public.invite_codes enable row level security;
revoke all on table public.invite_codes from anon, authenticated;


-- =========================================================
-- 4. 邀请码兑换记录
-- =========================================================

create table if not exists public.invite_redemptions (
  id uuid primary key default gen_random_uuid(),
  invite_id uuid not null references public.invite_codes(id) on delete restrict,
  user_id uuid not null references auth.users(id) on delete cascade,
  purpose text not null
    check (purpose in ('signup','renewal')),
  grant_type text not null
    check (grant_type in ('days','permanent')),
  duration_days integer,
  old_valid_until timestamptz,
  new_valid_until timestamptz,
  redeemed_at timestamptz not null default now()
);

create unique index if not exists invite_redemptions_invite_user_unique
  on public.invite_redemptions(invite_id, user_id);

alter table public.invite_redemptions enable row level security;
revoke all on table public.invite_redemptions from anon, authenticated;

create index if not exists invite_redemptions_user_id_idx
  on public.invite_redemptions(user_id);


-- =========================================================
-- 5. 判断当前用户是否还有权限
-- =========================================================

create or replace function public.has_active_access()
returns boolean
language sql
stable
security definer
set search_path = public, auth
as $$
  select exists (
    select 1
    from public.user_access ua
    where ua.user_id = auth.uid()
      and (
        ua.access_type = 'permanent'
        or (ua.valid_until is not null and ua.valid_until > now())
      )
  );
$$;

revoke all on function public.has_active_access() from public;
grant execute on function public.has_active_access() to authenticated;


-- =========================================================
-- 6. 前端读取当前账号权限状态
-- =========================================================

create or replace function public.get_access_status()
returns jsonb
language plpgsql
stable
security definer
set search_path = public, auth
as $$
declare
  v_uid uuid := auth.uid();
  v_access public.user_access%rowtype;
begin
  if v_uid is null then
    return jsonb_build_object(
      'has_access', false,
      'access_type', null,
      'valid_from', null,
      'valid_until', null
    );
  end if;

  select *
    into v_access
  from public.user_access
  where user_id = v_uid;

  if not found then
    return jsonb_build_object(
      'has_access', false,
      'access_type', null,
      'valid_from', null,
      'valid_until', null
    );
  end if;

  return jsonb_build_object(
    'has_access',
      (
        v_access.access_type = 'permanent'
        or (v_access.valid_until is not null and v_access.valid_until > now())
      ),
    'access_type', v_access.access_type,
    'valid_from', v_access.valid_from,
    'valid_until', v_access.valid_until
  );
end;
$$;

revoke all on function public.get_access_status() from public;
grant execute on function public.get_access_status() to authenticated;


-- =========================================================
-- 7. 新用户注册时自动消费 7 天注册邀请码
-- =========================================================

create or replace function public.handle_new_user_access()
returns trigger
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_code text;
  v_hash text;
  v_invite public.invite_codes%rowtype;
  v_new_until timestamptz;
begin
  v_code := upper(trim(coalesce(new.raw_user_meta_data ->> 'invite_code', '')));

  if v_code = '' then
    raise exception '注册需要有效邀请码';
  end if;

  v_hash := encode(extensions.digest(v_code, 'sha256'), 'hex');

  update public.invite_codes
  set used_at = now(),
      used_by = new.id,
      is_active = false
  where code_hash = v_hash
    and purpose = 'signup'
    and grant_type = 'days'
    and duration_days = 7
    and is_active = true
    and used_at is null
    and (expires_at is null or expires_at > now())
  returning *
    into v_invite;

  if v_invite.id is null then
    raise exception '邀请码无效、已使用或已过期';
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
  set access_type = excluded.access_type,
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
  );

  return new;
end;
$$;

drop trigger if exists trg_handle_new_user_access on auth.users;

create trigger trg_handle_new_user_access
after insert on auth.users
for each row
execute function public.handle_new_user_access();


-- =========================================================
-- 8. 兑换续期码
-- 支持 7 / 30 / 90 / 365 天或永久
-- 未到期：从原到期时间继续往后加
-- 已到期：从当前时间重新开始计算
-- =========================================================

create or replace function public.redeem_renewal_code(p_code text)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_uid uuid := auth.uid();
  v_hash text;
  v_invite public.invite_codes%rowtype;
  v_access public.user_access%rowtype;
  v_old_until timestamptz;
  v_base timestamptz;
  v_new_until timestamptz;
begin
  if v_uid is null then
    raise exception '请先登录';
  end if;

  select *
    into v_access
  from public.user_access
  where user_id = v_uid
  for update;

  if not found then
    insert into public.user_access(
      user_id,
      access_type,
      valid_from,
      valid_until,
      updated_at
    )
    values (
      v_uid,
      'temporary',
      now(),
      now(),
      now()
    )
    returning *
      into v_access;
  end if;

  if v_access.access_type = 'permanent' then
    return jsonb_build_object(
      'success', false,
      'reason', 'ALREADY_PERMANENT',
      'access_type', 'permanent'
    );
  end if;

  v_hash := encode(digest(upper(trim(coalesce(p_code, ''))), 'sha256'), 'hex');

  update public.invite_codes
  set used_at = now(),
      used_by = v_uid,
      is_active = false
  where code_hash = v_hash
    and purpose = 'renewal'
    and is_active = true
    and used_at is null
    and (expires_at is null or expires_at > now())
  returning *
    into v_invite;

  if v_invite.id is null then
    return jsonb_build_object(
      'success', false,
      'reason', 'INVALID_OR_USED'
    );
  end if;

  v_old_until := v_access.valid_until;

  if v_invite.grant_type = 'permanent' then
    update public.user_access
    set access_type = 'permanent',
        valid_until = null,
        updated_at = now()
    where user_id = v_uid;

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
      v_uid,
      'renewal',
      'permanent',
      null,
      v_old_until,
      null
    );

    return jsonb_build_object(
      'success', true,
      'access_type', 'permanent',
      'added_days', null,
      'valid_until', null
    );
  end if;

  v_base :=
    case
      when v_access.valid_until is not null and v_access.valid_until > now()
        then v_access.valid_until
      else now()
    end;

  v_new_until := v_base + make_interval(days => v_invite.duration_days);

  update public.user_access
  set access_type = 'temporary',
      valid_until = v_new_until,
      updated_at = now()
  where user_id = v_uid;

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
    v_uid,
    'renewal',
    'days',
    v_invite.duration_days,
    v_old_until,
    v_new_until
  );

  return jsonb_build_object(
    'success', true,
    'access_type', 'temporary',
    'added_days', v_invite.duration_days,
    'valid_until', v_new_until
  );
end;
$$;

revoke all on function public.redeem_renewal_code(text) from public;
grant execute on function public.redeem_renewal_code(text) to authenticated;


-- =========================================================
-- 9. workspaces RLS
-- 登录账号只能操作自己的数据，并且必须处于有效使用期
-- =========================================================

drop policy if exists "users_select_own_workspace" on public.workspaces;
create policy "users_select_own_workspace"
on public.workspaces
for select
to authenticated
using (
  auth.uid() is not null
  and auth.uid() = user_id
  and public.has_active_access()
);

drop policy if exists "users_insert_own_workspace" on public.workspaces;
create policy "users_insert_own_workspace"
on public.workspaces
for insert
to authenticated
with check (
  auth.uid() is not null
  and auth.uid() = user_id
  and public.has_active_access()
);

drop policy if exists "users_update_own_workspace" on public.workspaces;
create policy "users_update_own_workspace"
on public.workspaces
for update
to authenticated
using (
  auth.uid() is not null
  and auth.uid() = user_id
  and public.has_active_access()
)
with check (
  auth.uid() is not null
  and auth.uid() = user_id
  and public.has_active_access()
);

drop policy if exists "users_delete_own_workspace" on public.workspaces;
create policy "users_delete_own_workspace"
on public.workspaces
for delete
to authenticated
using (
  auth.uid() is not null
  and auth.uid() = user_id
  and public.has_active_access()
);


-- =========================================================
-- 10. Realtime
-- =========================================================

do $$
begin
  if not exists (
    select 1
    from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'workspaces'
  ) then
    alter publication supabase_realtime add table public.workspaces;
  end if;
end
$$;


-- =========================================================
-- 11. 后台管理示例
-- 注意：下面全部是注释示例，不包含真实邀请码
-- =========================================================

-- 生成 7 天注册邀请码：
-- 把 YOUR-SIGNUP-CODE 改成你自己生成的一次性邀请码。
--
-- insert into public.invite_codes(
--   code_hash, label, purpose, grant_type, duration_days
-- )
-- values (
--   encode(digest(upper(trim('YOUR-SIGNUP-CODE')), 'sha256'), 'hex'),
--   '7天注册邀请码',
--   'signup',
--   'days',
--   7
-- );


-- 生成续期邀请码：
-- duration_days 可用 7 / 30 / 90 / 365
--
-- insert into public.invite_codes(
--   code_hash, label, purpose, grant_type, duration_days
-- )
-- values (
--   encode(digest(upper(trim('YOUR-RENEWAL-CODE')), 'sha256'), 'hex'),
--   '30天续期码',
--   'renewal',
--   'days',
--   30
-- );


-- 生成永久邀请码：
--
-- insert into public.invite_codes(
--   code_hash, label, purpose, grant_type, duration_days
-- )
-- values (
--   encode(digest(upper(trim('YOUR-PERMANENT-CODE')), 'sha256'), 'hex'),
--   '永久续期码',
--   'renewal',
--   'permanent',
--   null
-- );


-- 给某个已经存在的账号设置永久权限：
-- 不要把真实邮箱提交到公开 GitHub。
--
-- insert into public.user_access(
--   user_id, access_type, valid_from, valid_until, updated_at
-- )
-- select
--   id, 'permanent', now(), null, now()
-- from auth.users
-- where email = 'YOUR_EMAIL@example.com'
-- on conflict (user_id) do update
-- set access_type = 'permanent',
--     valid_until = null,
--     updated_at = now();


-- 后台查看权限：
-- select * from public.user_access order by updated_at desc;

-- 后台查看邀请码：
-- select id, label, purpose, grant_type, duration_days,
--        is_active, expires_at, used_at, used_by, created_at
-- from public.invite_codes
-- order by created_at desc;

-- 后台查看兑换记录：
-- select * from public.invite_redemptions order by redeemed_at desc;


-- =========================================================
-- 12. 通用邀请码示例
-- =========================================================

-- 通用 7 天注册试用码
-- 同一个码可供多个不同账号注册使用，每个账号只能用一次。
-- max_uses 可自行调整，例如 100。
--
-- insert into public.invite_codes(
--   code_hash, label, purpose, grant_type, duration_days,
--   use_mode, max_uses, used_count, is_active
-- )
-- values (
--   encode(digest(upper(trim('YOUR-GENERAL-SIGNUP-CODE')), 'sha256'), 'hex'),
--   '通用7天注册试用码',
--   'signup',
--   'days',
--   7,
--   'multi',
--   100,
--   0,
--   true
-- );

-- 通用 7 天续期码
-- 已注册用户可兑换，每个账号只能兑换一次。
--
-- insert into public.invite_codes(
--   code_hash, label, purpose, grant_type, duration_days,
--   use_mode, max_uses, used_count, is_active
-- )
-- values (
--   encode(digest(upper(trim('YOUR-GENERAL-RENEW-CODE')), 'sha256'), 'hex'),
--   '通用7天续期码',
--   'renewal',
--   'days',
--   7,
--   'multi',
--   100,
--   0,
--   true
-- );
