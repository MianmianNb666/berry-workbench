-- 莓桃工作台：Web Push + DDL 定时提醒
-- 运行位置：Supabase -> SQL Editor
-- 运行一次即可，不会删除现有订单或用户数据。

begin;

-- =========================================================
-- 1. 设备 Push 订阅
-- =========================================================

create table if not exists public.push_subscriptions (
  endpoint text primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  p256dh text not null,
  auth text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists push_subscriptions_user_id_idx
  on public.push_subscriptions(user_id);

alter table public.push_subscriptions enable row level security;

revoke all on table public.push_subscriptions from anon, authenticated;
grant select, delete on table public.push_subscriptions to authenticated;

drop policy if exists "users_select_own_push_subscriptions" on public.push_subscriptions;
create policy "users_select_own_push_subscriptions"
on public.push_subscriptions
for select
to authenticated
using (auth.uid() = user_id);

drop policy if exists "users_delete_own_push_subscriptions" on public.push_subscriptions;
create policy "users_delete_own_push_subscriptions"
on public.push_subscriptions
for delete
to authenticated
using (auth.uid() = user_id);


-- 安全注册 / 更新当前设备订阅。
-- endpoint 若曾经属于另一个登录账号，会自动转到当前账号。
create or replace function public.register_push_subscription(
  p_endpoint text,
  p_p256dh text,
  p_auth text
)
returns boolean
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null then
    raise exception '请先登录';
  end if;

  if coalesce(trim(p_endpoint), '') = ''
     or coalesce(trim(p_p256dh), '') = ''
     or coalesce(trim(p_auth), '') = '' then
    raise exception 'Push subscription 不完整';
  end if;

  insert into public.push_subscriptions(
    endpoint, user_id, p256dh, auth, created_at, updated_at
  )
  values (
    p_endpoint, v_uid, p_p256dh, p_auth, now(), now()
  )
  on conflict (endpoint) do update
  set user_id = excluded.user_id,
      p256dh = excluded.p256dh,
      auth = excluded.auth,
      updated_at = now();

  return true;
end;
$$;

revoke all on function public.register_push_subscription(text,text,text) from public;
grant execute on function public.register_push_subscription(text,text,text) to authenticated;


-- =========================================================
-- 2. 订单提醒
-- =========================================================

create table if not exists public.order_reminders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  order_id text not null,
  order_name text not null,
  reminder_type text not null
    check (reminder_type in ('1d','3h','custom')),
  due_at timestamptz not null,
  remind_at timestamptz not null,
  message text not null,
  sent_at timestamptz,
  created_at timestamptz not null default now(),

  constraint order_reminders_unique
    unique (user_id, order_id, remind_at)
);

create index if not exists order_reminders_due_idx
  on public.order_reminders(remind_at)
  where sent_at is null;

create index if not exists order_reminders_user_order_idx
  on public.order_reminders(user_id, order_id);

alter table public.order_reminders enable row level security;

revoke all on table public.order_reminders from anon, authenticated;
grant select, insert, update, delete on table public.order_reminders to authenticated;

drop policy if exists "users_select_own_order_reminders" on public.order_reminders;
create policy "users_select_own_order_reminders"
on public.order_reminders
for select
to authenticated
using (auth.uid() = user_id);

drop policy if exists "users_insert_own_order_reminders" on public.order_reminders;
create policy "users_insert_own_order_reminders"
on public.order_reminders
for insert
to authenticated
with check (auth.uid() = user_id);

drop policy if exists "users_update_own_order_reminders" on public.order_reminders;
create policy "users_update_own_order_reminders"
on public.order_reminders
for update
to authenticated
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

drop policy if exists "users_delete_own_order_reminders" on public.order_reminders;
create policy "users_delete_own_order_reminders"
on public.order_reminders
for delete
to authenticated
using (auth.uid() = user_id);

commit;

-- 检查：
-- select * from public.push_subscriptions;
-- select * from public.order_reminders order by remind_at desc;
