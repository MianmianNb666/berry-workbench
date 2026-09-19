-- 莓桃工作台：聊天昵称 + 双向联系人备注
-- 运行位置：Supabase -> SQL Editor
-- 作用：
-- 1) 顾客可设置自己的显示名字，绑定美工后美工端/聊天显示该名字。
-- 2) 美工聊天资料同步自己的工作台名称和头像。
-- 3) 顾客可以给每位美工写仅自己可见的备注。
-- 美工给顾客的备注继续使用 artist_customers.note，仅美工自己使用。

begin;

alter table public.chat_profiles
  add column if not exists display_name text not null default '';

create table if not exists public.contact_notes (
  owner_user_id uuid not null references auth.users(id) on delete cascade,
  counterpart_user_id uuid not null references auth.users(id) on delete cascade,
  note text not null default '',
  updated_at timestamptz not null default now(),
  primary key (owner_user_id, counterpart_user_id),
  constraint contact_notes_not_self check (owner_user_id <> counterpart_user_id),
  constraint contact_notes_length check (char_length(note) <= 120)
);

alter table public.contact_notes enable row level security;

revoke all on table public.contact_notes from anon, authenticated;
grant select, insert, update, delete on table public.contact_notes to authenticated;

drop policy if exists "contact_notes_owner_read" on public.contact_notes;
create policy "contact_notes_owner_read"
on public.contact_notes
for select
to authenticated
using (auth.uid() = owner_user_id);

drop policy if exists "contact_notes_owner_insert" on public.contact_notes;
create policy "contact_notes_owner_insert"
on public.contact_notes
for insert
to authenticated
with check (auth.uid() = owner_user_id);

drop policy if exists "contact_notes_owner_update" on public.contact_notes;
create policy "contact_notes_owner_update"
on public.contact_notes
for update
to authenticated
using (auth.uid() = owner_user_id)
with check (auth.uid() = owner_user_id);

drop policy if exists "contact_notes_owner_delete" on public.contact_notes;
create policy "contact_notes_owner_delete"
on public.contact_notes
for delete
to authenticated
using (auth.uid() = owner_user_id);

commit;
