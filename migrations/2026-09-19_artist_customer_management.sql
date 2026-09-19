-- 莓桃工作台：美工顾客档案 + 预算账本
-- 运行位置：Supabase -> SQL Editor
-- 运行一次即可。
--
-- 设计：
-- 1) 美工可以先手动建立顾客档案，不要求顾客已经注册。
-- 2) 顾客注册并绑定美工后，可把顾客档案关联到她的顾客端账号。
-- 3) 余额采用“流水账”方式增加 / 减少，不直接覆盖历史。
-- 4) 顾客端只读取与自己账号关联的档案与流水。

begin;

create extension if not exists pgcrypto;

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
  or auth.uid() = linked_customer_user_id
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
  from public.customer_artist_bindings b
  where b.artist_user_id = auth.uid()
    and encode(extensions.digest(auth.uid()::text, 'sha256'), 'hex') = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
  order by b.created_at;
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
