-- 莓桃管理端：系统容量监控
-- 功能：
-- 1) 注册账号总数
-- 2) 当前数据库占用
-- 3) Realtime 当前连接估算（由美工端 / 顾客端心跳统计）
-- 4) 今日聊天消息量
-- 5) 仅 Owner 可以读取容量汇总

begin;

create table if not exists public.client_presence (
  session_id text primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  client_type text not null check (client_type in ('artist','customer')),
  realtime_channels integer not null default 0 check (realtime_channels between 0 and 20),
  last_seen timestamptz not null default now()
);

create index if not exists client_presence_last_seen_idx
  on public.client_presence(last_seen desc);

alter table public.client_presence enable row level security;
revoke all on table public.client_presence from public, anon, authenticated;

create or replace function public.report_client_presence(
  p_session_id text,
  p_client_type text,
  p_realtime_channels integer default 1
)
returns void
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if auth.uid() is null then
    raise exception 'not authenticated';
  end if;

  if length(trim(coalesce(p_session_id,''))) < 8
     or length(trim(coalesce(p_session_id,''))) > 120 then
    raise exception 'invalid session id';
  end if;

  if p_client_type not in ('artist','customer') then
    raise exception 'invalid client type';
  end if;

  insert into public.client_presence(
    session_id,
    user_id,
    client_type,
    realtime_channels,
    last_seen
  )
  values (
    trim(p_session_id),
    auth.uid(),
    p_client_type,
    greatest(0, least(coalesce(p_realtime_channels,0),20)),
    now()
  )
  on conflict (session_id) do update
  set user_id = auth.uid(),
      client_type = excluded.client_type,
      realtime_channels = excluded.realtime_channels,
      last_seen = now();
end;
$$;

revoke all on function public.report_client_presence(text,text,integer) from public, anon;
grant execute on function public.report_client_presence(text,text,integer) to authenticated;

create or replace function public.admin_system_capacity()
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_registered bigint := 0;
  v_database_bytes bigint := 0;
  v_active_sessions bigint := 0;
  v_realtime_connections bigint := 0;
  v_today_messages bigint := 0;
  v_month_messages bigint := 0;
  v_day_start timestamptz;
  v_month_start timestamptz;
begin
  if not public.admin_owner_allowed() then
    raise exception 'not allowed';
  end if;

  -- 清理一天前的陈旧心跳，避免表无限增长。
  delete from public.client_presence
   where last_seen < now() - interval '1 day';

  select count(*)
    into v_registered
  from auth.users;

  select pg_database_size(current_database())
    into v_database_bytes;

  select
    count(*),
    coalesce(sum(realtime_channels),0)
  into
    v_active_sessions,
    v_realtime_connections
  from public.client_presence
  where last_seen >= now() - interval '90 seconds';

  v_day_start :=
    date_trunc('day', now() at time zone 'Australia/Melbourne')
    at time zone 'Australia/Melbourne';

  v_month_start :=
    date_trunc('month', now() at time zone 'Australia/Melbourne')
    at time zone 'Australia/Melbourne';

  if to_regclass('public.chat_messages') is not null then
    execute
      'select count(*) from public.chat_messages where created_at >= $1'
      into v_today_messages
      using v_day_start;

    execute
      'select count(*) from public.chat_messages where created_at >= $1'
      into v_month_messages
      using v_month_start;
  end if;

  return jsonb_build_object(
    'registered_users', v_registered,
    'database_bytes', v_database_bytes,
    'active_sessions', v_active_sessions,
    'realtime_connections_estimate', v_realtime_connections,
    'today_chat_messages', v_today_messages,
    'month_chat_messages', v_month_messages,
    'measured_at', now()
  );
end;
$$;

revoke all on function public.admin_system_capacity() from public, anon;
grant execute on function public.admin_system_capacity() to authenticated;

commit;
