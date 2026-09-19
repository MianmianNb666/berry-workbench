-- 莓桃工作台：顾客端基础架构
-- 作用：
-- 1) 登录入口区分“美工端 / 顾客端”
-- 2) 顾客注册不需要美工邀请码
-- 3) 每个美工拥有唯一公开编号，可生成个人链接
-- 4) 顾客账号可以绑定多个美工
-- 5) 暂不改动现有订单结构；顾客排单读取将在下一阶段接入
--
-- 运行位置：Supabase -> SQL Editor
-- 运行一次即可。

begin;

create extension if not exists pgcrypto;

-- =========================================================
-- A. 一个账号可以拥有一个或多个角色
-- =========================================================
create table if not exists public.user_roles (
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('artist','customer')),
  created_at timestamptz not null default now(),
  primary key (user_id, role)
);

alter table public.user_roles enable row level security;

revoke all on table public.user_roles from anon, authenticated;
grant select, insert, delete on table public.user_roles to authenticated;

drop policy if exists "users_read_own_roles" on public.user_roles;
create policy "users_read_own_roles"
on public.user_roles
for select
to authenticated
using (auth.uid() = user_id);

drop policy if exists "users_add_own_customer_role" on public.user_roles;
create policy "users_add_own_customer_role"
on public.user_roles
for insert
to authenticated
with check (auth.uid() = user_id and role = 'customer');

drop policy if exists "users_delete_own_customer_role" on public.user_roles;
create policy "users_delete_own_customer_role"
on public.user_roles
for delete
to authenticated
using (auth.uid() = user_id and role = 'customer');

-- 已有工作台用户全部视为美工账号。
insert into public.user_roles(user_id, role)
select user_id, 'artist'
from public.user_access
on conflict do nothing;


-- =========================================================
-- B. 美工公开资料 + 唯一美工编号
-- =========================================================
create table if not exists public.artist_profiles (
  artist_user_id uuid primary key references auth.users(id) on delete cascade,
  artist_code text not null unique
    default ('MT-' || upper(substr(encode(gen_random_bytes(5), 'hex'), 1, 10))),
  public_name text not null default '莓桃美工',
  privacy_mode text not null default 'private'
    check (privacy_mode in ('public','private')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.artist_profiles enable row level security;

revoke all on table public.artist_profiles from anon, authenticated;
grant select on table public.artist_profiles to anon, authenticated;
grant insert, update on table public.artist_profiles to authenticated;

drop policy if exists "artist_profiles_public_read" on public.artist_profiles;
create policy "artist_profiles_public_read"
on public.artist_profiles
for select
to anon, authenticated
using (true);

drop policy if exists "artists_insert_own_profile" on public.artist_profiles;
create policy "artists_insert_own_profile"
on public.artist_profiles
for insert
to authenticated
with check (
  auth.uid() = artist_user_id
  and exists (
    select 1 from public.user_roles r
    where r.user_id = auth.uid() and r.role = 'artist'
  )
);

drop policy if exists "artists_update_own_profile" on public.artist_profiles;
create policy "artists_update_own_profile"
on public.artist_profiles
for update
to authenticated
using (auth.uid() = artist_user_id)
with check (auth.uid() = artist_user_id);

-- 给已有美工补资料；名称优先沿用工作台名称。
insert into public.artist_profiles(artist_user_id, public_name)
select
  ua.user_id,
  coalesce(nullif(w.data ->> 'title',''), '莓桃美工')
from public.user_access ua
left join public.workspaces w on w.user_id = ua.user_id
on conflict (artist_user_id) do nothing;


-- =========================================================
-- C. 顾客绑定美工
-- =========================================================
create table if not exists public.customer_artist_bindings (
  customer_user_id uuid not null references auth.users(id) on delete cascade,
  artist_user_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (customer_user_id, artist_user_id),
  check (customer_user_id <> artist_user_id)
);

create index if not exists customer_artist_bindings_artist_idx
  on public.customer_artist_bindings(artist_user_id);

alter table public.customer_artist_bindings enable row level security;

revoke all on table public.customer_artist_bindings from anon, authenticated;
grant select, insert, delete on table public.customer_artist_bindings to authenticated;

drop policy if exists "binding_participants_read" on public.customer_artist_bindings;
create policy "binding_participants_read"
on public.customer_artist_bindings
for select
to authenticated
using (
  auth.uid() = customer_user_id
  or auth.uid() = artist_user_id
);

drop policy if exists "customers_bind_artist" on public.customer_artist_bindings;
create policy "customers_bind_artist"
on public.customer_artist_bindings
for insert
to authenticated
with check (
  auth.uid() = customer_user_id
  and exists (
    select 1 from public.user_roles r
    where r.user_id = auth.uid() and r.role = 'customer'
  )
  and exists (
    select 1 from public.artist_profiles a
    where a.artist_user_id = artist_user_id
  )
);

drop policy if exists "customers_unbind_artist" on public.customer_artist_bindings;
create policy "customers_unbind_artist"
on public.customer_artist_bindings
for delete
to authenticated
using (auth.uid() = customer_user_id);


-- =========================================================
-- D. 注册触发器：顾客免费注册；美工仍按原邀请码规则
-- =========================================================
create or replace function public.handle_new_user_access()
returns trigger
language plpgsql
security definer
set search_path = public, auth, extensions
as $
declare
  v_role text;
  v_code text;
  v_hash text;
  v_invite public.invite_codes%rowtype;
  v_new_until timestamptz;
begin
  v_role := lower(trim(coalesce(new.raw_user_meta_data ->> 'account_role', 'artist')));

  -- 顾客端账号不需要邀请码，也不创建工作台使用期限。
  if v_role = 'customer' then
    insert into public.user_roles(user_id, role)
    values (new.id, 'customer')
    on conflict do nothing;

    return new;
  end if;

  -- 其他情况统一按美工账号处理，保留原来的邀请码校验。
  insert into public.user_roles(user_id, role)
  values (new.id, 'artist')
  on conflict do nothing;

  v_code := upper(trim(coalesce(new.raw_user_meta_data ->> 'invite_code', '')));

  if v_code = '' then
    raise exception '注册需要有效邀请码';
  end if;

  v_hash := encode(extensions.digest(v_code, 'sha256'), 'hex');

  update public.invite_codes ic
  set used_count = ic.used_count + 1,
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
             and ic.used_count + 1 >= ic.max_uses then false
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
        and (ic.max_uses is null or ic.used_count < ic.max_uses)
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

  insert into public.artist_profiles(artist_user_id, public_name)
  values (new.id, '莓桃美工')
  on conflict (artist_user_id) do nothing;

  return new;
end;
$$;

commit;
