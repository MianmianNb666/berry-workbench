-- 莓桃工作台：修复普通美工无法保存顾客端配置 / 顾客资料
-- 作用：
-- 1) 顾客中心正式开放给所有有效美工账号，不再只允许 Owner。
-- 2) 保留到期只读规则：有效期内可写，到期后只能查看。
-- 3) 补齐历史美工角色、公开资料和顾客码。
-- 4) 修复普通美工读取顾客码、顾客绑定、顾客档案和余额权限。
-- 运行位置：Supabase -> SQL Editor

begin;

create extension if not exists pgcrypto;

-- =========================================================
-- A. 补齐美工身份 / 美工资料 / 顾客码
-- =========================================================

insert into public.user_roles(user_id, role)
select ua.user_id, 'artist'
from public.user_access ua
on conflict do nothing;

insert into public.artist_profiles(artist_user_id, public_name)
select
  r.user_id,
  coalesce(nullif(w.data ->> 'title',''), '莓桃美工')
from public.user_roles r
left join public.workspaces w on w.user_id = r.user_id
where r.role = 'artist'
on conflict (artist_user_id) do nothing;

insert into public.artist_customer_access_codes(artist_user_id)
select ap.artist_user_id
from public.artist_profiles ap
on conflict (artist_user_id) do nothing;


-- =========================================================
-- B. 美工公开资料
-- 有效美工可修改；到期后只读
-- =========================================================

drop policy if exists "artists_insert_own_profile"
on public.artist_profiles;

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

drop policy if exists "artists_update_own_profile"
on public.artist_profiles;

create policy "artists_update_own_profile"
on public.artist_profiles
for update
to authenticated
using (
  auth.uid() = artist_user_id
)
with check (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
);


-- =========================================================
-- C. 每位美工都可以读取自己的顾客码
-- 到期后仍可查看旧码，但不能重新生成
-- =========================================================

drop policy if exists "owner_artist_reads_customer_code"
on public.artist_customer_access_codes;

drop policy if exists "artist_reads_own_customer_code"
on public.artist_customer_access_codes;

create policy "artist_reads_own_customer_code"
on public.artist_customer_access_codes
for select
to authenticated
using (
  auth.uid() = artist_user_id
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
  if auth.uid() is null then
    raise exception '请先登录';
  end if;

  if not public.artist_write_access_active(auth.uid()) then
    raise exception '当前美工账号已进入只读模式';
  end if;

  if not exists (
    select 1
    from public.user_roles r
    where r.user_id = auth.uid()
      and r.role = 'artist'
  ) then
    raise exception '当前账号不是美工账号';
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

revoke all on function public.rotate_customer_access_code()
from public, anon;

grant execute
on function public.rotate_customer_access_code()
to authenticated;


-- =========================================================
-- D. 美工 / 顾客都可以读取自己参与的绑定关系
-- =========================================================

drop policy if exists "customer_reads_own_portal_access"
on public.customer_portal_access;

create policy "customer_reads_own_portal_access"
on public.customer_portal_access
for select
to authenticated
using (
  auth.uid() = customer_user_id
  or auth.uid() = artist_user_id
);


-- =========================================================
-- E. 顾客档案
-- 美工可看自己的全部顾客；
-- 有效期内可新增 / 修改 / 删除；
-- 顾客仅可看自己被关联到的档案
-- =========================================================

drop policy if exists "artist_customer_participants_read"
on public.artist_customers;

create policy "artist_customer_participants_read"
on public.artist_customers
for select
to authenticated
using (
  auth.uid() = artist_user_id
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
  and public.artist_write_access_active(auth.uid())
);

drop policy if exists "artists_update_customers"
on public.artist_customers;

create policy "artists_update_customers"
on public.artist_customers
for update
to authenticated
using (
  auth.uid() = artist_user_id
)
with check (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
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
);


-- =========================================================
-- F. 顾客余额流水
-- =========================================================

drop policy if exists "artist_customer_ledger_participants_read"
on public.artist_customer_ledger;

create policy "artist_customer_ledger_participants_read"
on public.artist_customer_ledger
for select
to authenticated
using (
  auth.uid() = artist_user_id
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
  and public.artist_write_access_active(auth.uid())
  and exists (
    select 1
    from public.artist_customers c
    where c.id = artist_customer_id
      and c.artist_user_id = auth.uid()
  )
);


-- =========================================================
-- G. 美工读取已绑定顾客账号
-- =========================================================

create or replace function public.get_artist_bound_customer_accounts()
returns table (
  customer_user_id uuid,
  customer_label text
)
language sql
stable
security definer
set search_path = public, auth
as $$
  select
    pa.customer_user_id,
    coalesce(
      nullif(cp.display_name,''),
      '顾客 · ' || right(pa.customer_user_id::text, 4)
    ) as customer_label
  from public.customer_portal_access pa
  left join public.chat_profiles cp
    on cp.user_id = pa.customer_user_id
  where pa.artist_user_id = auth.uid()
  order by pa.granted_at;
$$;

revoke all on function public.get_artist_bound_customer_accounts()
from public, anon;

grant execute
on function public.get_artist_bound_customer_accounts()
to authenticated;


-- =========================================================
-- H. 顾客绑定美工后，为所有美工自动建立顾客档案
-- 不再只对 Owner 生效
-- =========================================================

create or replace function public.create_artist_customer_after_binding()
returns trigger
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_name text;
begin
  select nullif(cp.display_name,'')
    into v_name
  from public.chat_profiles cp
  where cp.user_id = new.customer_user_id;

  insert into public.artist_customers(
    artist_user_id,
    display_name,
    linked_customer_user_id
  )
  values (
    new.artist_user_id,
    coalesce(v_name, '顾客 · ' || right(new.customer_user_id::text, 4)),
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


-- 已经存在的绑定关系也补齐顾客档案
insert into public.artist_customers(
  artist_user_id,
  display_name,
  linked_customer_user_id
)
select
  pa.artist_user_id,
  coalesce(
    nullif(cp.display_name,''),
    '顾客 · ' || right(pa.customer_user_id::text, 4)
  ),
  pa.customer_user_id
from public.customer_portal_access pa
left join public.chat_profiles cp
  on cp.user_id = pa.customer_user_id
where not exists (
  select 1
  from public.artist_customers ac
  where ac.artist_user_id = pa.artist_user_id
    and ac.linked_customer_user_id = pa.customer_user_id
)
on conflict do nothing;

commit;
