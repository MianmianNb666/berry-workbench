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
