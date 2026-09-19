-- 莓桃工作台：顾客端“我的 / 设置”与美工自动解绑开关
-- 运行位置：Supabase -> SQL Editor
-- 运行一次即可。

begin;

-- =========================================================
-- A. 美工端：排单结束后自动解绑顾客开关
-- =========================================================
alter table public.artist_profiles
  add column if not exists auto_unbind_on_finish boolean not null default false;

-- =========================================================
-- B. 顾客端：个人主题设置
-- =========================================================
create table if not exists public.customer_preferences (
  user_id uuid primary key references auth.users(id) on delete cascade,
  accent text not null default '#e9789d',
  bg text not null default '#fff8fb',
  panel text not null default '#ffffff',
  text_color text not null default '#45383d',
  updated_at timestamptz not null default now()
);

alter table public.customer_preferences enable row level security;

revoke all on table public.customer_preferences from anon, authenticated;
grant select, insert, update on table public.customer_preferences to authenticated;

drop policy if exists "customers_read_own_preferences"
on public.customer_preferences;
create policy "customers_read_own_preferences"
on public.customer_preferences
for select
to authenticated
using (auth.uid() = user_id);

drop policy if exists "customers_insert_own_preferences"
on public.customer_preferences;
create policy "customers_insert_own_preferences"
on public.customer_preferences
for insert
to authenticated
with check (auth.uid() = user_id);

drop policy if exists "customers_update_own_preferences"
on public.customer_preferences;
create policy "customers_update_own_preferences"
on public.customer_preferences
for update
to authenticated
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

commit;
