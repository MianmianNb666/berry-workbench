-- 莓桃工作台：Supabase 多端同步数据表
-- 只需要在 Supabase SQL Editor 中运行一次。

create table if not exists public.workspaces (
  user_id uuid primary key references auth.users(id) on delete cascade,
  data jsonb not null default '{"orders":[],"times":[],"title":"莓桃工作台"}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.workspaces enable row level security;

revoke all on table public.workspaces from anon, authenticated;
grant select, insert, update, delete on table public.workspaces to authenticated;

drop policy if exists "users_select_own_workspace" on public.workspaces;
create policy "users_select_own_workspace"
on public.workspaces
for select
to authenticated
using (auth.uid() is not null and auth.uid() = user_id);

drop policy if exists "users_insert_own_workspace" on public.workspaces;
create policy "users_insert_own_workspace"
on public.workspaces
for insert
to authenticated
with check (auth.uid() is not null and auth.uid() = user_id);

drop policy if exists "users_update_own_workspace" on public.workspaces;
create policy "users_update_own_workspace"
on public.workspaces
for update
to authenticated
using (auth.uid() is not null and auth.uid() = user_id)
with check (auth.uid() is not null and auth.uid() = user_id);

drop policy if exists "users_delete_own_workspace" on public.workspaces;
create policy "users_delete_own_workspace"
on public.workspaces
for delete
to authenticated
using (auth.uid() is not null and auth.uid() = user_id);

-- 让同一个账号在不同设备上的修改可以实时推送。
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
