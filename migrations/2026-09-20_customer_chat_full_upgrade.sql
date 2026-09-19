-- 莓桃工作台：顾客系统 + 实时聊天 + 顾客专属码 + 名字头像 + 双向备注
-- 直接整段复制到 Supabase -> SQL Editor -> Run
-- 已经跑过其中一部分也没关系，大多数操作使用 if not exists / create or replace，可重复执行。

-- ============================================================
-- SOURCE: migrations/2026-09-20_realtime_chat.sql
-- ============================================================

-- 莓桃工作台：顾客 ↔ 美工实时文字聊天
-- 功能：文字消息、未读数量、已读状态、Supabase Realtime 实时同步
-- 运行位置：Supabase -> SQL Editor

begin;

-- 顾客档案头像字段也一起补齐，避免聊天头像依赖旧迁移。
alter table public.artist_customers
  add column if not exists avatar_data text not null default '';

create table if not exists public.chat_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  avatar_data text not null default '',
  updated_at timestamptz not null default now()
);

alter table public.chat_profiles enable row level security;

revoke all on table public.chat_profiles from anon, authenticated;
grant select, insert, update on table public.chat_profiles to authenticated;

drop policy if exists "chat_profiles_participant_read" on public.chat_profiles;
create policy "chat_profiles_participant_read"
on public.chat_profiles
for select
to authenticated
using (
  auth.uid() = user_id
  or exists (
    select 1
    from public.customer_artist_bindings b
    where
      (b.artist_user_id = auth.uid() and b.customer_user_id = chat_profiles.user_id)
      or
      (b.customer_user_id = auth.uid() and b.artist_user_id = chat_profiles.user_id)
  )
);

drop policy if exists "chat_profiles_insert_own" on public.chat_profiles;
create policy "chat_profiles_insert_own"
on public.chat_profiles
for insert
to authenticated
with check (auth.uid() = user_id);

drop policy if exists "chat_profiles_update_own" on public.chat_profiles;
create policy "chat_profiles_update_own"
on public.chat_profiles
for update
to authenticated
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

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

drop function if exists public.chat_list_my_conversations();

create function public.chat_list_my_conversations()
returns table (
  artist_user_id uuid,
  customer_user_id uuid,
  counterpart_label text,
  counterpart_avatar text,
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
    case
      when auth.uid() = b.artist_user_id
        then coalesce(nullif(cp_customer.avatar_data,''), nullif(ac.avatar_data,''), '')
      else coalesce(nullif(cp_artist.avatar_data,''), '')
    end as counterpart_avatar,
    lm.body as last_body,
    lm.created_at as last_at,
    coalesce(uc.unread_count,0)::bigint as unread_count
  from public.customer_artist_bindings b
  left join public.artist_customers ac
    on ac.artist_user_id = b.artist_user_id
   and ac.linked_customer_user_id = b.customer_user_id
  left join public.artist_profiles ap
    on ap.artist_user_id = b.artist_user_id
  left join public.chat_profiles cp_customer
    on cp_customer.user_id = b.customer_user_id
  left join public.chat_profiles cp_artist
    on cp_artist.user_id = b.artist_user_id
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
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    if not exists (
      select 1
      from pg_publication_tables
      where pubname = 'supabase_realtime'
        and schemaname = 'public'
        and tablename = 'chat_messages'
    ) then
      execute 'alter publication supabase_realtime add table public.chat_messages';
    end if;

    if not exists (
      select 1
      from pg_publication_tables
      where pubname = 'supabase_realtime'
        and schemaname = 'public'
        and tablename = 'chat_profiles'
    ) then
      execute 'alter publication supabase_realtime add table public.chat_profiles';
    end if;
  end if;
end;
$$;

commit;


-- ============================================================
-- SOURCE: migrations/2026-09-20_customer_profile_codes.sql
-- ============================================================

-- 莓桃工作台：顾客专属码
-- 两种绑定方式：
-- 1) 先建顾客档案 -> 自动生成该顾客专属码，顾客用码后直接绑定到这位美工 + 这份档案。
-- 2) 顾客先来 -> 继续使用美工通用顾客码，系统先绑定美工并建立占位档案，之后美工再完善档案。

begin;

create extension if not exists pgcrypto;

create table if not exists public.artist_customer_profile_codes (
  artist_customer_id uuid primary key references public.artist_customers(id) on delete cascade,
  artist_user_id uuid not null references auth.users(id) on delete cascade,
  access_code text not null unique,
  claimed_by uuid references auth.users(id) on delete set null,
  claimed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists artist_customer_profile_codes_artist_idx
  on public.artist_customer_profile_codes(artist_user_id, created_at desc);

alter table public.artist_customer_profile_codes enable row level security;

revoke all on table public.artist_customer_profile_codes from anon, authenticated;
grant select on table public.artist_customer_profile_codes to authenticated;

drop policy if exists "artist_reads_own_customer_profile_codes"
on public.artist_customer_profile_codes;

create policy "artist_reads_own_customer_profile_codes"
on public.artist_customer_profile_codes
for select
to authenticated
using (auth.uid() = artist_user_id);


create or replace function public.ensure_artist_customer_profile_code(
  p_artist_customer_id uuid
)
returns text
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_artist uuid;
  v_existing text;
  v_code text;
begin
  if auth.uid() is null then
    raise exception '请先登录';
  end if;

  select c.artist_user_id
    into v_artist
  from public.artist_customers c
  where c.id = p_artist_customer_id
    and c.artist_user_id = auth.uid();

  if v_artist is null then
    raise exception '没有权限读取这个顾客档案';
  end if;

  select pc.access_code
    into v_existing
  from public.artist_customer_profile_codes pc
  where pc.artist_customer_id = p_artist_customer_id;

  if v_existing is not null then
    return v_existing;
  end if;

  loop
    v_code := 'CC-' || upper(substr(encode(extensions.gen_random_bytes(6), 'hex'), 1, 12));
    begin
      insert into public.artist_customer_profile_codes(
        artist_customer_id,
        artist_user_id,
        access_code
      )
      values (
        p_artist_customer_id,
        v_artist,
        v_code
      );
      exit;
    exception when unique_violation then
      -- 如果只是同一档案被并发创建，直接读取已有值。
      select pc.access_code
        into v_existing
      from public.artist_customer_profile_codes pc
      where pc.artist_customer_id = p_artist_customer_id;

      if v_existing is not null then
        return v_existing;
      end if;
    end;
  end loop;

  return v_code;
end;
$$;

revoke all on function public.ensure_artist_customer_profile_code(uuid) from public, anon;
grant execute on function public.ensure_artist_customer_profile_code(uuid) to authenticated;


-- 同一个入口同时支持：
-- GC-... 美工通用顾客码
-- CC-... 某一份顾客档案的专属码
create or replace function public.claim_customer_access_code(p_code text)
returns jsonb
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_code text;
  v_artist uuid;
  v_customer_record uuid;
  v_linked_customer uuid;
  v_claimed_by uuid;
begin
  if auth.uid() is null then
    return jsonb_build_object('success', false, 'reason', 'NOT_SIGNED_IN');
  end if;

  v_code := upper(trim(coalesce(p_code,'')));

  -- A. 先尝试美工通用顾客码。
  select ac.artist_user_id
    into v_artist
  from public.artist_customer_access_codes ac
  where ac.access_code = v_code
    and ac.is_active = true
  limit 1;

  -- B. 如果不是通用码，再尝试顾客专属码。
  if v_artist is null then
    select
      pc.artist_user_id,
      pc.artist_customer_id,
      c.linked_customer_user_id,
      pc.claimed_by
    into
      v_artist,
      v_customer_record,
      v_linked_customer,
      v_claimed_by
    from public.artist_customer_profile_codes pc
    join public.artist_customers c
      on c.id = pc.artist_customer_id
     and c.artist_user_id = pc.artist_user_id
    where pc.access_code = v_code
    limit 1;

    if v_artist is null then
      return jsonb_build_object('success', false, 'reason', 'INVALID_CODE');
    end if;

    if (v_claimed_by is not null and v_claimed_by <> auth.uid())
       or (v_linked_customer is not null and v_linked_customer <> auth.uid()) then
      return jsonb_build_object('success', false, 'reason', 'CODE_ALREADY_CLAIMED');
    end if;

    -- 先把这份档案绑定到当前顾客。
    -- 这样后面插入 customer_artist_bindings 时，不会再产生重复占位档案。
    update public.artist_customers
    set linked_customer_user_id = auth.uid(),
        updated_at = now()
    where id = v_customer_record
      and artist_user_id = v_artist
      and (linked_customer_user_id is null or linked_customer_user_id = auth.uid());

    update public.artist_customer_profile_codes
    set claimed_by = auth.uid(),
        claimed_at = coalesce(claimed_at, now()),
        updated_at = now()
    where artist_customer_id = v_customer_record
      and (claimed_by is null or claimed_by = auth.uid());
  end if;

  insert into public.user_roles(user_id, role)
  values (auth.uid(), 'customer')
  on conflict do nothing;

  insert into public.customer_portal_access(customer_user_id, artist_user_id)
  values (auth.uid(), v_artist)
  on conflict (customer_user_id, artist_user_id) do nothing;

  insert into public.customer_artist_bindings(customer_user_id, artist_user_id)
  values (auth.uid(), v_artist)
  on conflict do nothing;

  return jsonb_build_object(
    'success', true,
    'artist_user_id', v_artist,
    'artist_customer_id', v_customer_record,
    'code_type', case when v_customer_record is null then 'artist' else 'customer' end
  );
end;
$$;

revoke all on function public.claim_customer_access_code(text) from public, anon;
grant execute on function public.claim_customer_access_code(text) to authenticated;


-- 注册时同样兼容两种码。
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
  v_customer_record uuid;
  v_linked_customer uuid;
  v_claimed_by uuid;
begin
  v_role := lower(trim(coalesce(new.raw_user_meta_data ->> 'account_role', '')));
  if v_role <> 'customer' then
    return new;
  end if;

  v_code := upper(trim(coalesce(new.raw_user_meta_data ->> 'customer_access_code', '')));
  if v_code = '' then
    raise exception '注册顾客端需要美工提供的顾客码或顾客专属码';
  end if;

  -- A. 美工通用顾客码
  select ac.artist_user_id
    into v_artist
  from public.artist_customer_access_codes ac
  where ac.access_code = v_code
    and ac.is_active = true
  limit 1;

  -- B. 顾客专属码
  if v_artist is null then
    select
      pc.artist_user_id,
      pc.artist_customer_id,
      c.linked_customer_user_id,
      pc.claimed_by
    into
      v_artist,
      v_customer_record,
      v_linked_customer,
      v_claimed_by
    from public.artist_customer_profile_codes pc
    join public.artist_customers c
      on c.id = pc.artist_customer_id
     and c.artist_user_id = pc.artist_user_id
    where pc.access_code = v_code
    limit 1;

    if v_artist is null then
      raise exception '顾客码无效';
    end if;

    if (v_claimed_by is not null and v_claimed_by <> new.id)
       or (v_linked_customer is not null and v_linked_customer <> new.id) then
      raise exception '这个顾客专属码已经绑定其他账号';
    end if;

    update public.artist_customers
    set linked_customer_user_id = new.id,
        updated_at = now()
    where id = v_customer_record
      and artist_user_id = v_artist
      and (linked_customer_user_id is null or linked_customer_user_id = new.id);

    update public.artist_customer_profile_codes
    set claimed_by = new.id,
        claimed_at = coalesce(claimed_at, now()),
        updated_at = now()
    where artist_customer_id = v_customer_record
      and (claimed_by is null or claimed_by = new.id);
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

commit;


-- ============================================================
-- SOURCE: migrations/2026-09-20_chat_names_contact_notes.sql
-- ============================================================

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


-- ============================================================
-- SOURCE: migrations/2026-09-20_artist_friends.sql
-- ============================================================

-- 莓桃工作台：美工好友
-- 功能：通过美工编号发送好友申请、接受/拒绝、好友列表、删除好友
-- 依赖：artist_profiles / chat_profiles
-- 运行位置：Supabase -> SQL Editor

begin;

create table if not exists public.artist_friendships (
  id uuid primary key default extensions.gen_random_uuid(),
  requester_user_id uuid not null references auth.users(id) on delete cascade,
  addressee_user_id uuid not null references auth.users(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending','accepted')),
  created_at timestamptz not null default now(),
  responded_at timestamptz,
  updated_at timestamptz not null default now(),
  constraint artist_friendships_not_self check (requester_user_id <> addressee_user_id)
);

create index if not exists artist_friendships_requester_idx
  on public.artist_friendships(requester_user_id, status, created_at desc);

create index if not exists artist_friendships_addressee_idx
  on public.artist_friendships(addressee_user_id, status, created_at desc);

alter table public.artist_friendships enable row level security;

revoke all on table public.artist_friendships from anon, authenticated;

drop policy if exists "artist_friendships_read_own" on public.artist_friendships;
create policy "artist_friendships_read_own"
on public.artist_friendships
for select
to authenticated
using (auth.uid() in (requester_user_id, addressee_user_id));

grant select on table public.artist_friendships to authenticated;


create or replace function public.artist_send_friend_request(p_artist_code text)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_me uuid := auth.uid();
  v_target uuid;
  v_target_code text;
  v_target_name text;
  v_existing public.artist_friendships%rowtype;
begin
  if v_me is null then
    return jsonb_build_object('success',false,'reason','NOT_SIGNED_IN');
  end if;

  select ap.artist_user_id, ap.artist_code, coalesce(nullif(cp.display_name,''), nullif(ap.public_name,''), '莓桃美工')
    into v_target, v_target_code, v_target_name
  from public.artist_profiles ap
  left join public.chat_profiles cp on cp.user_id = ap.artist_user_id
  where upper(ap.artist_code) = upper(trim(coalesce(p_artist_code,'')))
  limit 1;

  if v_target is null then
    return jsonb_build_object('success',false,'reason','NOT_FOUND');
  end if;

  if v_target = v_me then
    return jsonb_build_object('success',false,'reason','SELF');
  end if;

  select *
    into v_existing
  from public.artist_friendships f
  where
    (f.requester_user_id = v_me and f.addressee_user_id = v_target)
    or
    (f.requester_user_id = v_target and f.addressee_user_id = v_me)
  order by f.created_at desc
  limit 1;

  if v_existing.id is not null then
    if v_existing.status = 'accepted' then
      return jsonb_build_object('success',false,'reason','ALREADY_FRIENDS');
    end if;

    if v_existing.requester_user_id = v_target
       and v_existing.addressee_user_id = v_me
       and v_existing.status = 'pending' then
      update public.artist_friendships
      set status='accepted', responded_at=now(), updated_at=now()
      where id=v_existing.id;

      return jsonb_build_object(
        'success',true,
        'auto_accepted',true,
        'relation_id',v_existing.id,
        'artist_code',v_target_code,
        'artist_name',v_target_name
      );
    end if;

    return jsonb_build_object('success',false,'reason','ALREADY_PENDING');
  end if;

  insert into public.artist_friendships(requester_user_id, addressee_user_id)
  values (v_me, v_target)
  returning id into v_existing.id;

  return jsonb_build_object(
    'success',true,
    'auto_accepted',false,
    'relation_id',v_existing.id,
    'artist_code',v_target_code,
    'artist_name',v_target_name
  );
end;
$$;

revoke all on function public.artist_send_friend_request(text) from public, anon;
grant execute on function public.artist_send_friend_request(text) to authenticated;


drop function if exists public.artist_list_friendships();

create function public.artist_list_friendships()
returns table (
  relation_id uuid,
  other_user_id uuid,
  artist_code text,
  artist_name text,
  avatar_data text,
  status text,
  direction text,
  created_at timestamptz
)
language sql
stable
security definer
set search_path = public, auth
as $$
  select
    f.id as relation_id,
    case when f.requester_user_id = auth.uid() then f.addressee_user_id else f.requester_user_id end as other_user_id,
    ap.artist_code,
    coalesce(nullif(cp.display_name,''), nullif(ap.public_name,''), '莓桃美工') as artist_name,
    coalesce(cp.avatar_data,'') as avatar_data,
    f.status,
    case
      when f.status='pending' and f.addressee_user_id=auth.uid() then 'incoming'
      when f.status='pending' and f.requester_user_id=auth.uid() then 'outgoing'
      else 'friend'
    end as direction,
    f.created_at
  from public.artist_friendships f
  join public.artist_profiles ap
    on ap.artist_user_id =
      case when f.requester_user_id = auth.uid() then f.addressee_user_id else f.requester_user_id end
  left join public.chat_profiles cp
    on cp.user_id = ap.artist_user_id
  where auth.uid() in (f.requester_user_id, f.addressee_user_id)
  order by
    case
      when f.status='pending' and f.addressee_user_id=auth.uid() then 0
      when f.status='pending' then 1
      else 2
    end,
    f.created_at desc;
$$;

revoke all on function public.artist_list_friendships() from public, anon;
grant execute on function public.artist_list_friendships() to authenticated;


create or replace function public.artist_respond_friend_request(
  p_relation_id uuid,
  p_accept boolean
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_me uuid := auth.uid();
  v_row public.artist_friendships%rowtype;
begin
  if v_me is null then
    return jsonb_build_object('success',false,'reason','NOT_SIGNED_IN');
  end if;

  select * into v_row
  from public.artist_friendships
  where id=p_relation_id
    and addressee_user_id=v_me
    and status='pending';

  if v_row.id is null then
    return jsonb_build_object('success',false,'reason','NOT_FOUND');
  end if;

  if p_accept then
    update public.artist_friendships
    set status='accepted', responded_at=now(), updated_at=now()
    where id=p_relation_id;
    return jsonb_build_object('success',true,'accepted',true);
  end if;

  delete from public.artist_friendships where id=p_relation_id;
  return jsonb_build_object('success',true,'accepted',false);
end;
$$;

revoke all on function public.artist_respond_friend_request(uuid,boolean) from public, anon;
grant execute on function public.artist_respond_friend_request(uuid,boolean) to authenticated;


create or replace function public.artist_remove_friend(p_relation_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_me uuid := auth.uid();
  v_deleted integer;
begin
  if v_me is null then
    return jsonb_build_object('success',false,'reason','NOT_SIGNED_IN');
  end if;

  delete from public.artist_friendships
  where id=p_relation_id
    and v_me in (requester_user_id, addressee_user_id);

  get diagnostics v_deleted = row_count;

  return jsonb_build_object('success',v_deleted>0);
end;
$$;

revoke all on function public.artist_remove_friend(uuid) from public, anon;
grant execute on function public.artist_remove_friend(uuid) to authenticated;


do $$
begin
  if exists (select 1 from pg_publication where pubname='supabase_realtime')
     and not exists (
       select 1 from pg_publication_tables
       where pubname='supabase_realtime'
         and schemaname='public'
         and tablename='artist_friendships'
     ) then
    execute 'alter publication supabase_realtime add table public.artist_friendships';
  end if;
end;
$$;

commit;


-- ============================================================
-- SOURCE: migrations/2026-09-20_artist_friend_chat.sql
-- ============================================================

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
