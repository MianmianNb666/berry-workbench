-- =========================================================
-- 莓桃工作台：顾客端 + 顾客码 + 多美工 + 余额 + 到期只读 FINAL
-- 运行位置：Supabase -> SQL Editor
--
-- 前提：已经运行过顾客端基础表 / workspaces / invite / push reminders 的既有迁移。
--
-- 最终规则：
-- 1) 一个美工一个专属顾客码。
-- 2) 一个顾客账号可绑定多个美工，但每位美工必须用各自顾客码单独解锁。
-- 3) 顾客只能看已解锁美工对应的顾客档案 / 余额 / 排单数据。
-- 4) 主账号保留自测兼容。
-- 5) 美工使用期到期后，不删除、不解绑，顾客端继续可看。
-- 6) 到期美工端进入只读：可看，不可新增 / 修改 / 删除。
-- 7) 续期后自动恢复写入。
-- =========================================================

-- 莓桃工作台：美工顾客档案 + 预算账本
-- 运行位置：Supabase -> SQL Editor
-- 运行一次即可。
--
-- 设计：
-- 1) 美工可以先手动建立顾客档案，不要求顾客已经注册。
-- 2) 每个美工有自己的专属顾客码；顾客必须持有该码才能解锁该美工。
-- 3) 一个顾客账号可以凭不同顾客码解锁多个美工，各美工数据彼此隔离。
-- 4) 余额采用“流水账”方式增加 / 减少，不直接覆盖历史。
-- 5) 顾客端只读取已通过顾客码授权的美工档案与流水。

begin;

create extension if not exists pgcrypto;


-- =========================================================
-- A0. 顾客码：一个美工一个码；顾客账号可凭不同美工码解锁多个美工
-- =========================================================
create table if not exists public.artist_customer_access_codes (
  artist_user_id uuid primary key references auth.users(id) on delete cascade,
  access_code text not null unique
    default ('GC-' || upper(substr(encode(extensions.gen_random_bytes(6), 'hex'), 1, 12))),
  is_active boolean not null default true,
  updated_at timestamptz not null default now()
);

alter table public.artist_customer_access_codes enable row level security;

revoke all on table public.artist_customer_access_codes from anon, authenticated;
grant select on table public.artist_customer_access_codes to authenticated;

drop policy if exists "owner_artist_reads_customer_code"
on public.artist_customer_access_codes;

create policy "owner_artist_reads_customer_code"
on public.artist_customer_access_codes
for select
to authenticated
using (
  auth.uid() = artist_user_id
  and encode(extensions.digest(auth.uid()::text, 'sha256'), 'hex') = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
);

insert into public.artist_customer_access_codes(artist_user_id)
select artist_user_id
from public.artist_profiles
on conflict (artist_user_id) do nothing;


create table if not exists public.customer_portal_access (
  customer_user_id uuid not null references auth.users(id) on delete cascade,
  artist_user_id uuid not null references auth.users(id) on delete cascade,
  granted_at timestamptz not null default now()
);

-- 兼容之前的一对一测试结构，升级成“一个顾客可解锁多个美工”。
alter table public.customer_portal_access
  drop constraint if exists customer_portal_access_pkey;

alter table public.customer_portal_access
  add constraint customer_portal_access_pkey
  primary key (customer_user_id, artist_user_id);


-- 把旧测试阶段已经存在的顾客-美工绑定同步成顾客端访问权限，
-- 这样主账号之前的自绑测试不会被新顾客码机制挡在门外。
insert into public.customer_portal_access(customer_user_id, artist_user_id, granted_at)
select b.customer_user_id, b.artist_user_id, coalesce(b.created_at, now())
from public.customer_artist_bindings b
on conflict (customer_user_id, artist_user_id) do nothing;


create index if not exists customer_portal_access_artist_idx
  on public.customer_portal_access(artist_user_id);

alter table public.customer_portal_access enable row level security;

revoke all on table public.customer_portal_access from anon, authenticated;
grant select on table public.customer_portal_access to authenticated;

drop policy if exists "customer_reads_own_portal_access"
on public.customer_portal_access;

create policy "customer_reads_own_portal_access"
on public.customer_portal_access
for select
to authenticated
using (
  auth.uid() = customer_user_id
  or (
    auth.uid() = artist_user_id
    and encode(extensions.digest(auth.uid()::text, 'sha256'), 'hex') = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
  )
);


create or replace function public.rotate_customer_access_code()
returns text
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_code text;
begin
  if auth.uid() is null
     or encode(extensions.digest(auth.uid()::text, 'sha256'), 'hex') <> 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8' then
    raise exception 'not allowed';
  end if;

  loop
    v_code := 'GC-' || upper(substr(encode(extensions.gen_random_bytes(6), 'hex'), 1, 12));
    begin
      insert into public.artist_customer_access_codes(
        artist_user_id, access_code, is_active, updated_at
      )
      values (auth.uid(), v_code, true, now())
      on conflict (artist_user_id) do update
      set access_code = excluded.access_code,
          is_active = true,
          updated_at = now();
      exit;
    exception when unique_violation then
      null;
    end;
  end loop;

  return v_code;
end;
$$;

revoke all on function public.rotate_customer_access_code() from public, anon;
grant execute on function public.rotate_customer_access_code() to authenticated;


create or replace function public.claim_customer_access_code(p_code text)
returns jsonb
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_artist uuid;
begin
  if auth.uid() is null then
    return jsonb_build_object('success', false, 'reason', 'NOT_SIGNED_IN');
  end if;

  select artist_user_id
    into v_artist
  from public.artist_customer_access_codes
  where access_code = upper(trim(coalesce(p_code,'')))
    and is_active = true
  limit 1;

  if v_artist is null then
    return jsonb_build_object('success', false, 'reason', 'INVALID_CODE');
  end if;

  insert into public.user_roles(user_id, role)
  values (auth.uid(), 'customer')
  on conflict do nothing;

  insert into public.customer_portal_access(customer_user_id, artist_user_id)
  values (auth.uid(), v_artist)
  on conflict (customer_user_id, artist_user_id) do nothing;

  -- 保留兼容绑定表，同一个顾客可以绑定多个美工。
  insert into public.customer_artist_bindings(customer_user_id, artist_user_id)
  values (auth.uid(), v_artist)
  on conflict do nothing;

  return jsonb_build_object(
    'success', true,
    'artist_user_id', v_artist
  );
end;
$$;

revoke all on function public.claim_customer_access_code(text) from public, anon;
grant execute on function public.claim_customer_access_code(text) to authenticated;


-- 新顾客注册必须先携带至少一个有效顾客码；后续可继续添加其他美工码。
create or replace function public.attach_customer_portal_access_on_signup()
returns trigger
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_role text;
  v_code text;
  v_artist uuid;
begin
  v_role := lower(trim(coalesce(new.raw_user_meta_data ->> 'account_role', '')));
  if v_role <> 'customer' then
    return new;
  end if;

  v_code := upper(trim(coalesce(new.raw_user_meta_data ->> 'customer_access_code', '')));
  if v_code = '' then
    raise exception '注册顾客端需要美工提供的顾客码';
  end if;

  select artist_user_id
    into v_artist
  from public.artist_customer_access_codes
  where access_code = v_code
    and is_active = true
  limit 1;

  if v_artist is null then
    raise exception '顾客码无效';
  end if;

  insert into public.customer_portal_access(customer_user_id, artist_user_id)
  values (new.id, v_artist)
  on conflict (customer_user_id, artist_user_id) do nothing;

  insert into public.customer_artist_bindings(customer_user_id, artist_user_id)
  values (new.id, v_artist)
  on conflict do nothing;

  return new;
end;
$$;

drop trigger if exists trg_attach_customer_portal_access_on_signup
on auth.users;

create trigger trg_attach_customer_portal_access_on_signup
after insert on auth.users
for each row
execute function public.attach_customer_portal_access_on_signup();


create table if not exists public.artist_customers (
  id uuid primary key default gen_random_uuid(),
  artist_user_id uuid not null references auth.users(id) on delete cascade,
  display_name text not null default '新顾客',
  note text not null default '',
  linked_customer_user_id uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists artist_customers_artist_idx
  on public.artist_customers(artist_user_id, created_at desc);

create unique index if not exists artist_customers_unique_linked_account
  on public.artist_customers(artist_user_id, linked_customer_user_id)
  where linked_customer_user_id is not null;

alter table public.artist_customers enable row level security;

revoke all on table public.artist_customers from anon, authenticated;
grant select, insert, update, delete on table public.artist_customers to authenticated;

drop policy if exists "artist_customer_participants_read"
on public.artist_customers;
create policy "artist_customer_participants_read"
on public.artist_customers
for select
to authenticated
using (
  (
    auth.uid() = artist_user_id
    and encode(extensions.digest(auth.uid()::text, 'sha256'), 'hex') = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
  )
  or (
    auth.uid() = linked_customer_user_id
    and exists (
      select 1
      from public.customer_portal_access pa
      where pa.customer_user_id = auth.uid()
        and pa.artist_user_id = artist_customers.artist_user_id
    )
  )
);

drop policy if exists "artists_insert_customers"
on public.artist_customers;
create policy "artists_insert_customers"
on public.artist_customers
for insert
to authenticated
with check (
  auth.uid() = artist_user_id
  and encode(extensions.digest(auth.uid()::text, 'sha256'), 'hex') = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
);

drop policy if exists "artists_update_customers"
on public.artist_customers;
create policy "artists_update_customers"
on public.artist_customers
for update
to authenticated
using (
  auth.uid() = artist_user_id
  and encode(extensions.digest(auth.uid()::text, 'sha256'), 'hex') = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
)
with check (
  auth.uid() = artist_user_id
  and encode(extensions.digest(auth.uid()::text, 'sha256'), 'hex') = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
);

drop policy if exists "artists_delete_customers"
on public.artist_customers;
create policy "artists_delete_customers"
on public.artist_customers
for delete
to authenticated
using (
  auth.uid() = artist_user_id
  and encode(extensions.digest(auth.uid()::text, 'sha256'), 'hex') = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
);


create table if not exists public.artist_customer_ledger (
  id uuid primary key default gen_random_uuid(),
  artist_customer_id uuid not null references public.artist_customers(id) on delete cascade,
  artist_user_id uuid not null references auth.users(id) on delete cascade,
  amount numeric(12,2) not null check (amount <> 0),
  note text not null default '',
  created_at timestamptz not null default now()
);

create index if not exists artist_customer_ledger_customer_idx
  on public.artist_customer_ledger(artist_customer_id, created_at desc);

alter table public.artist_customer_ledger enable row level security;

revoke all on table public.artist_customer_ledger from anon, authenticated;
grant select, insert on table public.artist_customer_ledger to authenticated;

drop policy if exists "artist_customer_ledger_participants_read"
on public.artist_customer_ledger;
create policy "artist_customer_ledger_participants_read"
on public.artist_customer_ledger
for select
to authenticated
using (
  (
    auth.uid() = artist_user_id
    and encode(extensions.digest(auth.uid()::text, 'sha256'), 'hex') = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
  )
  or exists (
    select 1
    from public.artist_customers c
    where c.id = artist_customer_id
      and c.linked_customer_user_id = auth.uid()
      and exists (
        select 1
        from public.customer_portal_access pa
        where pa.customer_user_id = auth.uid()
          and pa.artist_user_id = c.artist_user_id
      )
  )
);

drop policy if exists "artists_add_customer_ledger"
on public.artist_customer_ledger;
create policy "artists_add_customer_ledger"
on public.artist_customer_ledger
for insert
to authenticated
with check (
  auth.uid() = artist_user_id
  and encode(extensions.digest(auth.uid()::text, 'sha256'), 'hex') = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
  and exists (
    select 1
    from public.artist_customers c
    where c.id = artist_customer_id
      and c.artist_user_id = auth.uid()
  )
);


-- 返回当前美工已经绑定到顾客端的账号，用于“关联顾客端账号”选择。
create or replace function public.get_artist_bound_customer_accounts()
returns table (
  customer_user_id uuid,
  customer_label text
)
language sql
security definer
set search_path = public, auth
as $$
  select
    b.customer_user_id,
    '顾客 · ' || right(b.customer_user_id::text, 4) as customer_label
  from public.customer_portal_access b
  where b.artist_user_id = auth.uid()
    and encode(extensions.digest(auth.uid()::text, 'sha256'), 'hex') = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
  order by b.granted_at;
$$;

revoke all on function public.get_artist_bound_customer_accounts() from public, anon;
grant execute on function public.get_artist_bound_customer_accounts() to authenticated;


-- 顾客绑定美工后，如果还没有关联档案，先自动建一个占位档案。
create or replace function public.create_artist_customer_after_binding()
returns trigger
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if encode(extensions.digest(new.artist_user_id::text, 'sha256'), 'hex') <> 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8' then
    return new;
  end if;

  insert into public.artist_customers(
    artist_user_id,
    display_name,
    linked_customer_user_id
  )
  values (
    new.artist_user_id,
    '顾客 · ' || right(new.customer_user_id::text, 4),
    new.customer_user_id
  )
  on conflict do nothing;

  return new;
end;
$$;

drop trigger if exists trg_create_artist_customer_after_binding
on public.customer_artist_bindings;

create trigger trg_create_artist_customer_after_binding
after insert on public.customer_artist_bindings
for each row
execute function public.create_artist_customer_after_binding();


-- 给已经存在的绑定补顾客档案。
insert into public.artist_customers(
  artist_user_id,
  display_name,
  linked_customer_user_id
)
select
  b.artist_user_id,
  '顾客 · ' || right(b.customer_user_id::text, 4),
  b.customer_user_id
from public.customer_artist_bindings b
where encode(extensions.digest(b.artist_user_id::text, 'sha256'), 'hex') = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
on conflict do nothing;

commit;


-- 莓桃工作台：美工使用期到期后进入只读模式
-- 规则：
-- 1) 到期后保留全部数据，仍可读取。
-- 2) 顾客端绑定关系、顾客码、余额历史不会删除，顾客仍可查看。
-- 3) 到期美工不能新增 / 修改 / 删除工作台、顾客档案、余额流水、公开资料或提醒。
-- 4) 续期成功后自动恢复写入权限。
--
-- 运行位置：Supabase -> SQL Editor
-- 运行一次即可。

begin;

create extension if not exists pgcrypto;

-- 统一判断某个美工当前是否仍有“写入权限”。
create or replace function public.artist_write_access_active(p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public, auth
as $$
  select exists (
    select 1
    from public.user_access ua
    where ua.user_id = p_user_id
      and (
        ua.access_type = 'permanent'
        or (ua.valid_until is not null and ua.valid_until > now())
      )
  );
$$;

revoke all on function public.artist_write_access_active(uuid) from public, anon;
grant execute on function public.artist_write_access_active(uuid) to authenticated;


-- =========================================================
-- A. 工作台：到期后只读
-- =========================================================

drop policy if exists "users_insert_own_workspace" on public.workspaces;
create policy "users_insert_own_workspace"
on public.workspaces
for insert
to authenticated
with check (
  auth.uid() is not null
  and auth.uid() = user_id
  and public.artist_write_access_active(auth.uid())
);

drop policy if exists "users_update_own_workspace" on public.workspaces;
create policy "users_update_own_workspace"
on public.workspaces
for update
to authenticated
using (
  auth.uid() is not null
  and auth.uid() = user_id
  and public.artist_write_access_active(auth.uid())
)
with check (
  auth.uid() is not null
  and auth.uid() = user_id
  and public.artist_write_access_active(auth.uid())
);

drop policy if exists "users_delete_own_workspace" on public.workspaces;
create policy "users_delete_own_workspace"
on public.workspaces
for delete
to authenticated
using (
  auth.uid() is not null
  and auth.uid() = user_id
  and public.artist_write_access_active(auth.uid())
);

-- select policy 不改，因此到期后仍可正常查看全部工作台数据。


-- =========================================================
-- B. 美工公开资料：到期后仍公开可读，但本人不能修改
-- =========================================================

drop policy if exists "artists_insert_own_profile" on public.artist_profiles;
create policy "artists_insert_own_profile"
on public.artist_profiles
for insert
to authenticated
with check (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
  and exists (
    select 1
    from public.user_roles r
    where r.user_id = auth.uid()
      and r.role = 'artist'
  )
);

drop policy if exists "artists_update_own_profile" on public.artist_profiles;
create policy "artists_update_own_profile"
on public.artist_profiles
for update
to authenticated
using (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
)
with check (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
);

-- artist_profiles_public_read 保持不变，因此顾客端仍可读取美工资料。


-- =========================================================
-- C. 顾客档案与余额：到期后保留并可看，但不能再改
-- =========================================================

drop policy if exists "artists_insert_customers"
on public.artist_customers;
create policy "artists_insert_customers"
on public.artist_customers
for insert
to authenticated
with check (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
  and encode(
    extensions.digest(auth.uid()::text, 'sha256'),
    'hex'
  ) = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
);

drop policy if exists "artists_update_customers"
on public.artist_customers;
create policy "artists_update_customers"
on public.artist_customers
for update
to authenticated
using (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
  and encode(
    extensions.digest(auth.uid()::text, 'sha256'),
    'hex'
  ) = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
)
with check (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
  and encode(
    extensions.digest(auth.uid()::text, 'sha256'),
    'hex'
  ) = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
);

drop policy if exists "artists_delete_customers"
on public.artist_customers;
create policy "artists_delete_customers"
on public.artist_customers
for delete
to authenticated
using (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
  and encode(
    extensions.digest(auth.uid()::text, 'sha256'),
    'hex'
  ) = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
);

drop policy if exists "artists_add_customer_ledger"
on public.artist_customer_ledger;
create policy "artists_add_customer_ledger"
on public.artist_customer_ledger
for insert
to authenticated
with check (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
  and encode(
    extensions.digest(auth.uid()::text, 'sha256'),
    'hex'
  ) = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
  and exists (
    select 1
    from public.artist_customers c
    where c.id = artist_customer_id
      and c.artist_user_id = auth.uid()
  )
);

-- 顾客端读取 artist_customers / artist_customer_ledger 的 policy 不改，
-- 所以美工到期后顾客仍然可以查看原来的余额和明细。


-- =========================================================
-- D. DDL 提醒：到期后不能再新增 / 修改 / 删除
-- =========================================================

drop policy if exists "users_insert_own_order_reminders" on public.order_reminders;
create policy "users_insert_own_order_reminders"
on public.order_reminders
for insert
to authenticated
with check (
  auth.uid() = user_id
  and public.artist_write_access_active(auth.uid())
);

drop policy if exists "users_update_own_order_reminders" on public.order_reminders;
create policy "users_update_own_order_reminders"
on public.order_reminders
for update
to authenticated
using (
  auth.uid() = user_id
  and public.artist_write_access_active(auth.uid())
)
with check (
  auth.uid() = user_id
  and public.artist_write_access_active(auth.uid())
);

drop policy if exists "users_delete_own_order_reminders" on public.order_reminders;
create policy "users_delete_own_order_reminders"
on public.order_reminders
for delete
to authenticated
using (
  auth.uid() = user_id
  and public.artist_write_access_active(auth.uid())
);


-- =========================================================
-- E. 顾客码：到期后旧码继续有效，但美工不能重新生成
-- =========================================================

create or replace function public.rotate_customer_access_code()
returns text
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_code text;
begin
  if auth.uid() is null
     or not public.artist_write_access_active(auth.uid())
     or encode(
       extensions.digest(auth.uid()::text, 'sha256'),
       'hex'
     ) <> 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
  then
    raise exception '当前美工账号已进入只读模式';
  end if;

  loop
    v_code := 'GC-' || upper(
      substr(
        encode(extensions.gen_random_bytes(6), 'hex'),
        1,
        12
      )
    );

    begin
      insert into public.artist_customer_access_codes(
        artist_user_id,
        access_code,
        is_active,
        updated_at
      )
      values (
        auth.uid(),
        v_code,
        true,
        now()
      )
      on conflict (artist_user_id) do update
      set access_code = excluded.access_code,
          is_active = true,
          updated_at = now();

      exit;
    exception when unique_violation then
      null;
    end;
  end loop;

  return v_code;
end;
$$;

revoke all on function public.rotate_customer_access_code() from public, anon;
grant execute on function public.rotate_customer_access_code() to authenticated;

commit;



-- =========================================================
-- PART 3 · 顾客免登录分享入口
-- =========================================================

-- 莓桃工作台：顾客免登录分享入口
-- 功能：
-- 1) 美工可针对“某个顾客的全部关联订单”生成免登录链接。
-- 2) 美工也可针对“某一笔订单”单独生成免登录链接。
-- 3) 链接使用随机 token，不暴露用户 UUID。
-- 4) 匿名访问只返回经过清洗的排单 / 订单信息，不返回金额、内部备注、联系方式或工作台原始 JSON。
-- 5) 美工到期后，已生成链接仍可查看；到期美工不能再生成新链接。

begin;

create extension if not exists pgcrypto;

create table if not exists public.customer_public_share_links (
  token text primary key
    default ('SH-' || upper(encode(extensions.gen_random_bytes(18), 'hex'))),
  artist_user_id uuid not null references auth.users(id) on delete cascade,
  artist_customer_id uuid references public.artist_customers(id) on delete cascade,
  order_id text,
  created_at timestamptz not null default now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  constraint customer_public_share_target_check
    check (artist_customer_id is not null or nullif(trim(order_id), '') is not null)
);

create index if not exists customer_public_share_artist_idx
  on public.customer_public_share_links(artist_user_id, created_at desc);

alter table public.customer_public_share_links enable row level security;

revoke all on table public.customer_public_share_links from anon, authenticated;
grant select, insert, update, delete on table public.customer_public_share_links to authenticated;

drop policy if exists "artists_read_own_public_share_links"
on public.customer_public_share_links;

create policy "artists_read_own_public_share_links"
on public.customer_public_share_links
for select
to authenticated
using (auth.uid() = artist_user_id);

drop policy if exists "artists_create_own_public_share_links"
on public.customer_public_share_links;

create policy "artists_create_own_public_share_links"
on public.customer_public_share_links
for insert
to authenticated
with check (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
);

drop policy if exists "artists_update_own_public_share_links"
on public.customer_public_share_links;

create policy "artists_update_own_public_share_links"
on public.customer_public_share_links
for update
to authenticated
using (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
)
with check (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
);

drop policy if exists "artists_delete_own_public_share_links"
on public.customer_public_share_links;

create policy "artists_delete_own_public_share_links"
on public.customer_public_share_links
for delete
to authenticated
using (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
);


create or replace function public.create_customer_public_share(
  p_artist_customer_id uuid default null,
  p_order_id text default null
)
returns text
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_uid uuid := auth.uid();
  v_token text;
  v_orders jsonb;
begin
  if v_uid is null then
    raise exception '请先登录';
  end if;

  if not public.artist_write_access_active(v_uid) then
    raise exception '当前美工账号已进入只读模式';
  end if;

  if p_artist_customer_id is null
     and nullif(trim(coalesce(p_order_id,'')), '') is null then
    raise exception '请选择顾客或订单';
  end if;

  if p_artist_customer_id is not null
     and not exists (
       select 1
       from public.artist_customers c
       where c.id = p_artist_customer_id
         and c.artist_user_id = v_uid
     ) then
    raise exception '顾客档案不存在';
  end if;

  if nullif(trim(coalesce(p_order_id,'')), '') is not null then
    select coalesce(w.data -> 'orders', '[]'::jsonb)
      into v_orders
    from public.workspaces w
    where w.user_id = v_uid;

    if not exists (
      select 1
      from jsonb_array_elements(coalesce(v_orders, '[]'::jsonb)) o
      where o ->> 'id' = p_order_id
    ) then
      raise exception '订单不存在';
    end if;
  end if;

  loop
    v_token := 'SH-' || upper(encode(extensions.gen_random_bytes(18), 'hex'));
    begin
      insert into public.customer_public_share_links(
        token,
        artist_user_id,
        artist_customer_id,
        order_id
      )
      values (
        v_token,
        v_uid,
        p_artist_customer_id,
        nullif(trim(coalesce(p_order_id,'')), '')
      );
      exit;
    exception when unique_violation then
      null;
    end;
  end loop;

  return v_token;
end;
$$;

revoke all on function public.create_customer_public_share(uuid,text) from public, anon;
grant execute on function public.create_customer_public_share(uuid,text) to authenticated;


create or replace function public.get_customer_public_share(
  p_token text
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_share public.customer_public_share_links%rowtype;
  v_artist_name text;
  v_customer_name text;
  v_workspace jsonb;
  v_orders jsonb := '[]'::jsonb;
  v_updated_at timestamptz;
begin
  select *
    into v_share
  from public.customer_public_share_links s
  where s.token = upper(trim(coalesce(p_token,'')))
    and s.revoked_at is null
    and (s.expires_at is null or s.expires_at > now())
  limit 1;

  if v_share.token is null then
    return jsonb_build_object(
      'success', false,
      'reason', 'NOT_FOUND'
    );
  end if;

  select coalesce(a.public_name, '莓桃美工')
    into v_artist_name
  from public.artist_profiles a
  where a.artist_user_id = v_share.artist_user_id;

  if v_share.artist_customer_id is not null then
    select c.display_name
      into v_customer_name
    from public.artist_customers c
    where c.id = v_share.artist_customer_id
      and c.artist_user_id = v_share.artist_user_id;
  end if;

  select w.data, w.updated_at
    into v_workspace, v_updated_at
  from public.workspaces w
  where w.user_id = v_share.artist_user_id;

  select coalesce(
    jsonb_agg(
      jsonb_build_object(
        'id', o.item ->> 'id',
        'name', o.item ->> 'name',
        'status', o.item ->> 'status',
        'start', o.item ->> 'start',
        'due', o.item ->> 'due',
        'dueTime', o.item ->> 'dueTime',
        'cat', o.item ->> 'cat',
        'progress', coalesce(nullif(o.item ->> 'progress','')::numeric, 0)
      )
      order by o.ord
    ),
    '[]'::jsonb
  )
  into v_orders
  from jsonb_array_elements(
    coalesce(v_workspace -> 'orders', '[]'::jsonb)
  ) with ordinality as o(item, ord)
  where
    (
      v_share.order_id is not null
      and o.item ->> 'id' = v_share.order_id
    )
    or
    (
      v_share.order_id is null
      and v_share.artist_customer_id is not null
      and o.item ->> 'artistCustomerId' = v_share.artist_customer_id::text
    );

  -- 单订单链接如果没有绑定顾客档案，用订单里的客户昵称作为展示名。
  if coalesce(v_customer_name,'') = ''
     and v_share.order_id is not null then
    select o.item ->> 'client'
      into v_customer_name
    from jsonb_array_elements(
      coalesce(v_workspace -> 'orders', '[]'::jsonb)
    ) o(item)
    where o.item ->> 'id' = v_share.order_id
    limit 1;
  end if;

  return jsonb_build_object(
    'success', true,
    'mode', case when v_share.order_id is null then 'customer' else 'order' end,
    'artist_name', coalesce(v_artist_name, '莓桃美工'),
    'customer_name', coalesce(nullif(v_customer_name,''), '顾客'),
    'orders', v_orders,
    'updated_at', v_updated_at
  );
end;
$$;

revoke all on function public.get_customer_public_share(text) from public;
grant execute on function public.get_customer_public_share(text) to anon, authenticated;

commit;

