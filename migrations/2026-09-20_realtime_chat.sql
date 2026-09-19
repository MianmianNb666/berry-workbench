-- 莓桃工作台：顾客 ↔ 美工实时文字聊天
-- 功能：文字消息、未读数量、已读状态、Supabase Realtime 实时同步
-- 运行位置：Supabase -> SQL Editor

begin;

create table if not exists public.chat_messages (
  id uuid primary key default extensions.gen_random_uuid(),
  artist_user_id uuid not null references auth.users(id) on delete cascade,
  customer_user_id uuid not null references auth.users(id) on delete cascade,
  sender_user_id uuid not null references auth.users(id) on delete cascade,
  body text not null,
  created_at timestamptz not null default now(),
  read_at timestamptz,
  constraint chat_messages_participants_different check (artist_user_id <> customer_user_id),
  constraint chat_messages_sender_participant check (sender_user_id in (artist_user_id, customer_user_id)),
  constraint chat_messages_body_length check (char_length(trim(body)) between 1 and 1000)
);

create index if not exists chat_messages_pair_created_idx
  on public.chat_messages(artist_user_id, customer_user_id, created_at);

create index if not exists chat_messages_unread_idx
  on public.chat_messages(artist_user_id, customer_user_id, read_at, created_at);

alter table public.chat_messages enable row level security;

revoke all on table public.chat_messages from anon, authenticated;
grant select, insert on table public.chat_messages to authenticated;
grant update (read_at) on table public.chat_messages to authenticated;

drop policy if exists "chat_participants_read" on public.chat_messages;
create policy "chat_participants_read"
on public.chat_messages
for select
to authenticated
using (
  auth.uid() in (artist_user_id, customer_user_id)
  and exists (
    select 1
    from public.customer_artist_bindings b
    where b.artist_user_id = chat_messages.artist_user_id
      and b.customer_user_id = chat_messages.customer_user_id
  )
);

drop policy if exists "chat_participants_send" on public.chat_messages;
create policy "chat_participants_send"
on public.chat_messages
for insert
to authenticated
with check (
  sender_user_id = auth.uid()
  and auth.uid() in (artist_user_id, customer_user_id)
  and exists (
    select 1
    from public.customer_artist_bindings b
    where b.artist_user_id = chat_messages.artist_user_id
      and b.customer_user_id = chat_messages.customer_user_id
  )
);

drop policy if exists "chat_recipient_mark_read" on public.chat_messages;
create policy "chat_recipient_mark_read"
on public.chat_messages
for update
to authenticated
using (
  auth.uid() in (artist_user_id, customer_user_id)
  and sender_user_id <> auth.uid()
  and exists (
    select 1
    from public.customer_artist_bindings b
    where b.artist_user_id = chat_messages.artist_user_id
      and b.customer_user_id = chat_messages.customer_user_id
  )
)
with check (
  auth.uid() in (artist_user_id, customer_user_id)
  and sender_user_id <> auth.uid()
  and exists (
    select 1
    from public.customer_artist_bindings b
    where b.artist_user_id = chat_messages.artist_user_id
      and b.customer_user_id = chat_messages.customer_user_id
  )
);

create or replace function public.chat_list_my_conversations()
returns table (
  artist_user_id uuid,
  customer_user_id uuid,
  counterpart_label text,
  last_body text,
  last_at timestamptz,
  unread_count bigint
)
language sql
stable
security definer
set search_path = public, auth
as $$
  select
    b.artist_user_id,
    b.customer_user_id,
    case
      when auth.uid() = b.artist_user_id
        then coalesce(nullif(ac.display_name,''), '顾客')
      else coalesce(nullif(ap.public_name,''), '莓桃美工')
    end as counterpart_label,
    lm.body as last_body,
    lm.created_at as last_at,
    coalesce(uc.unread_count,0)::bigint as unread_count
  from public.customer_artist_bindings b
  left join public.artist_customers ac
    on ac.artist_user_id = b.artist_user_id
   and ac.linked_customer_user_id = b.customer_user_id
  left join public.artist_profiles ap
    on ap.artist_user_id = b.artist_user_id
  left join lateral (
    select m.body, m.created_at
    from public.chat_messages m
    where m.artist_user_id = b.artist_user_id
      and m.customer_user_id = b.customer_user_id
    order by m.created_at desc
    limit 1
  ) lm on true
  left join lateral (
    select count(*)::bigint as unread_count
    from public.chat_messages m
    where m.artist_user_id = b.artist_user_id
      and m.customer_user_id = b.customer_user_id
      and m.sender_user_id <> auth.uid()
      and m.read_at is null
  ) uc on true
  where auth.uid() in (b.artist_user_id, b.customer_user_id)
  order by lm.created_at desc nulls last, b.created_at desc;
$$;

revoke all on function public.chat_list_my_conversations() from public, anon;
grant execute on function public.chat_list_my_conversations() to authenticated;

create or replace function public.chat_mark_read(
  p_artist_user_id uuid,
  p_customer_user_id uuid
)
returns integer
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_count integer;
begin
  if auth.uid() is null then
    raise exception '请先登录';
  end if;

  if not exists (
    select 1
    from public.customer_artist_bindings b
    where b.artist_user_id = p_artist_user_id
      and b.customer_user_id = p_customer_user_id
      and auth.uid() in (b.artist_user_id, b.customer_user_id)
  ) then
    raise exception '没有聊天权限';
  end if;

  update public.chat_messages
  set read_at = now()
  where artist_user_id = p_artist_user_id
    and customer_user_id = p_customer_user_id
    and sender_user_id <> auth.uid()
    and read_at is null;

  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

revoke all on function public.chat_mark_read(uuid,uuid) from public, anon;
grant execute on function public.chat_mark_read(uuid,uuid) to authenticated;

do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (
       select 1
       from pg_publication_tables
       where pubname = 'supabase_realtime'
         and schemaname = 'public'
         and tablename = 'chat_messages'
     ) then
    execute 'alter publication supabase_realtime add table public.chat_messages';
  end if;
end;
$$;

commit;
