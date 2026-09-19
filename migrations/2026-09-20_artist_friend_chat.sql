-- 莓桃工作台：美工好友实时聊天
-- 功能：好友之间文字聊天、未读/已读、Realtime
-- 依赖：artist_friendships
-- 运行位置：Supabase -> SQL Editor

begin;

create table if not exists public.artist_friend_messages (
  id uuid primary key default extensions.gen_random_uuid(),
  sender_user_id uuid not null references auth.users(id) on delete cascade,
  recipient_user_id uuid not null references auth.users(id) on delete cascade,
  body text not null,
  created_at timestamptz not null default now(),
  read_at timestamptz,
  constraint artist_friend_messages_not_self check (sender_user_id <> recipient_user_id),
  constraint artist_friend_messages_body_length check (char_length(trim(body)) between 1 and 1000)
);

create index if not exists artist_friend_messages_pair_created_idx
  on public.artist_friend_messages(sender_user_id, recipient_user_id, created_at);

create index if not exists artist_friend_messages_unread_idx
  on public.artist_friend_messages(recipient_user_id, read_at, created_at);

alter table public.artist_friend_messages enable row level security;

revoke all on table public.artist_friend_messages from anon, authenticated;
grant select, insert on table public.artist_friend_messages to authenticated;
grant update (read_at) on table public.artist_friend_messages to authenticated;

drop policy if exists "artist_friend_messages_read" on public.artist_friend_messages;
create policy "artist_friend_messages_read"
on public.artist_friend_messages
for select
to authenticated
using (
  auth.uid() in (sender_user_id, recipient_user_id)
  and exists (
    select 1
    from public.artist_friendships f
    where f.status='accepted'
      and (
        (f.requester_user_id=artist_friend_messages.sender_user_id and f.addressee_user_id=artist_friend_messages.recipient_user_id)
        or
        (f.requester_user_id=artist_friend_messages.recipient_user_id and f.addressee_user_id=artist_friend_messages.sender_user_id)
      )
  )
);

drop policy if exists "artist_friend_messages_send" on public.artist_friend_messages;
create policy "artist_friend_messages_send"
on public.artist_friend_messages
for insert
to authenticated
with check (
  sender_user_id=auth.uid()
  and exists (
    select 1
    from public.artist_friendships f
    where f.status='accepted'
      and (
        (f.requester_user_id=artist_friend_messages.sender_user_id and f.addressee_user_id=artist_friend_messages.recipient_user_id)
        or
        (f.requester_user_id=artist_friend_messages.recipient_user_id and f.addressee_user_id=artist_friend_messages.sender_user_id)
      )
  )
);

drop policy if exists "artist_friend_messages_mark_read" on public.artist_friend_messages;
create policy "artist_friend_messages_mark_read"
on public.artist_friend_messages
for update
to authenticated
using (
  recipient_user_id=auth.uid()
)
with check (
  recipient_user_id=auth.uid()
);

drop function if exists public.artist_list_friend_conversations();

create function public.artist_list_friend_conversations()
returns table (
  friend_user_id uuid,
  artist_code text,
  artist_name text,
  avatar_data text,
  last_body text,
  last_at timestamptz,
  unread_count bigint
)
language sql
stable
security definer
set search_path = public, auth
as $$
  with friends as (
    select
      case when f.requester_user_id=auth.uid() then f.addressee_user_id else f.requester_user_id end as friend_user_id
    from public.artist_friendships f
    where f.status='accepted'
      and auth.uid() in (f.requester_user_id,f.addressee_user_id)
  )
  select
    fr.friend_user_id,
    ap.artist_code,
    coalesce(nullif(cp.display_name,''),nullif(ap.public_name,''),'莓桃美工') as artist_name,
    coalesce(cp.avatar_data,'') as avatar_data,
    lm.body as last_body,
    lm.created_at as last_at,
    coalesce(uc.unread_count,0)::bigint as unread_count
  from friends fr
  join public.artist_profiles ap on ap.artist_user_id=fr.friend_user_id
  left join public.chat_profiles cp on cp.user_id=fr.friend_user_id
  left join lateral (
    select m.body,m.created_at
    from public.artist_friend_messages m
    where
      (m.sender_user_id=auth.uid() and m.recipient_user_id=fr.friend_user_id)
      or
      (m.sender_user_id=fr.friend_user_id and m.recipient_user_id=auth.uid())
    order by m.created_at desc
    limit 1
  ) lm on true
  left join lateral (
    select count(*)::bigint as unread_count
    from public.artist_friend_messages m
    where m.sender_user_id=fr.friend_user_id
      and m.recipient_user_id=auth.uid()
      and m.read_at is null
  ) uc on true
  order by lm.created_at desc nulls last, artist_name;
$$;

revoke all on function public.artist_list_friend_conversations() from public, anon;
grant execute on function public.artist_list_friend_conversations() to authenticated;

create or replace function public.artist_mark_friend_messages_read(p_friend_user_id uuid)
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
    from public.artist_friendships f
    where f.status='accepted'
      and (
        (f.requester_user_id=auth.uid() and f.addressee_user_id=p_friend_user_id)
        or
        (f.requester_user_id=p_friend_user_id and f.addressee_user_id=auth.uid())
      )
  ) then
    raise exception '不是好友，不能聊天';
  end if;

  update public.artist_friend_messages
  set read_at=now()
  where sender_user_id=p_friend_user_id
    and recipient_user_id=auth.uid()
    and read_at is null;

  get diagnostics v_count=row_count;
  return v_count;
end;
$$;

revoke all on function public.artist_mark_friend_messages_read(uuid) from public, anon;
grant execute on function public.artist_mark_friend_messages_read(uuid) to authenticated;

do $$
begin
  if exists (select 1 from pg_publication where pubname='supabase_realtime')
     and not exists (
       select 1 from pg_publication_tables
       where pubname='supabase_realtime'
         and schemaname='public'
         and tablename='artist_friend_messages'
     ) then
    execute 'alter publication supabase_realtime add table public.artist_friend_messages';
  end if;
end;
$$;

commit;
