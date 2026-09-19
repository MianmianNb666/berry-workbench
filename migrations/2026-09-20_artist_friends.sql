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
