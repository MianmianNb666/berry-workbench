-- 莓桃工作台：管理端“全面开放 / 全面暂停”总开关
-- 运行位置：Supabase -> SQL Editor
-- 默认状态：暂停（保持当前所有普通美工端被锁定）
-- Owner 自己始终可以进入，不受总开关影响。

begin;

create table if not exists public.system_controls (
  control_key text primary key,
  enabled boolean not null default false,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id) on delete set null
);

alter table public.system_controls enable row level security;
revoke all on table public.system_controls from public, anon, authenticated;

insert into public.system_controls(control_key, enabled)
values ('artist_frontend_open', false)
on conflict (control_key) do nothing;

create or replace function public.client_frontend_open()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(
    (select sc.enabled
       from public.system_controls sc
      where sc.control_key = 'artist_frontend_open'),
    false
  );
$$;

revoke all on function public.client_frontend_open() from public;
grant execute on function public.client_frontend_open() to anon, authenticated;

create or replace function public.admin_set_client_frontend_open(
  p_open boolean
)
returns boolean
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if not public.admin_owner_allowed() then
    raise exception 'not allowed';
  end if;

  insert into public.system_controls(
    control_key,
    enabled,
    updated_at,
    updated_by
  )
  values (
    'artist_frontend_open',
    coalesce(p_open, false),
    now(),
    auth.uid()
  )
  on conflict (control_key) do update
    set enabled = excluded.enabled,
        updated_at = now(),
        updated_by = auth.uid();

  return coalesce(p_open, false);
end;
$$;

revoke all on function public.admin_set_client_frontend_open(boolean) from public, anon;
grant execute on function public.admin_set_client_frontend_open(boolean) to authenticated;

commit;
