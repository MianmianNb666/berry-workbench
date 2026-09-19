-- 莓桃管理端补丁：管理员备注 + 工作台名称同步
-- 运行位置：Supabase -> SQL Editor
-- 功能：
-- 1) 管理员可以给每个账号写仅自己可见的备注
-- 2) 管理端自动显示对方自己设置的工作台名称（workspaces.data.title）
-- 3) 搜索支持邮箱 / UID / 管理员备注 / 工作台名称

begin;

-- =========================================================
-- A. 管理员账号备注
-- =========================================================

create table if not exists public.admin_account_notes (
  target_user_id uuid primary key references auth.users(id) on delete cascade,
  admin_user_id uuid not null references auth.users(id) on delete cascade,
  note text not null default '',
  updated_at timestamptz not null default now()
);

alter table public.admin_account_notes enable row level security;
revoke all on table public.admin_account_notes from anon, authenticated;


create or replace function public.admin_save_account_note(
  p_target_user_id uuid,
  p_note text
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

  if p_target_user_id is null
     or not exists (
       select 1
       from auth.users u
       where u.id = p_target_user_id
     ) then
    raise exception '账号不存在';
  end if;

  insert into public.admin_account_notes(
    target_user_id,
    admin_user_id,
    note,
    updated_at
  )
  values (
    p_target_user_id,
    auth.uid(),
    left(trim(coalesce(p_note,'')), 200),
    now()
  )
  on conflict (target_user_id) do update
  set admin_user_id = excluded.admin_user_id,
      note = excluded.note,
      updated_at = now();

  return true;
end;
$$;

revoke all on function public.admin_save_account_note(uuid,text) from public, anon;
grant execute on function public.admin_save_account_note(uuid,text) to authenticated;


-- =========================================================
-- B. 管理端账号列表：加入工作台名称 + 管理员备注
-- =========================================================

drop function if exists public.admin_list_accounts(text);

create function public.admin_list_accounts(
  p_search text default ''
)
returns table (
  user_id uuid,
  email text,
  created_at timestamptz,
  last_sign_in_at timestamptz,
  access_type text,
  valid_from timestamptz,
  valid_until timestamptz,
  has_access boolean,
  roles text[],
  workspace_title text,
  admin_note text
)
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if not public.admin_owner_allowed() then
    raise exception 'not allowed';
  end if;

  return query
  select
    u.id,
    u.email::text,
    u.created_at,
    u.last_sign_in_at,
    ua.access_type,
    ua.valid_from,
    ua.valid_until,
    coalesce(
      ua.access_type = 'permanent'
      or (ua.valid_until is not null and ua.valid_until > now()),
      false
    ) as has_access,
    coalesce(
      (
        select array_agg(r.role order by r.role)
        from public.user_roles r
        where r.user_id = u.id
      ),
      array[]::text[]
    ) as roles,
    nullif(trim(coalesce(w.data ->> 'title','')), '') as workspace_title,
    coalesce(n.note,'') as admin_note
  from auth.users u
  left join public.user_access ua
    on ua.user_id = u.id
  left join public.workspaces w
    on w.user_id = u.id
  left join public.admin_account_notes n
    on n.target_user_id = u.id
  where
    trim(coalesce(p_search,'')) = ''
    or coalesce(u.email,'') ilike '%' || trim(p_search) || '%'
    or u.id::text ilike '%' || trim(p_search) || '%'
    or coalesce(n.note,'') ilike '%' || trim(p_search) || '%'
    or coalesce(w.data ->> 'title','') ilike '%' || trim(p_search) || '%'
  order by u.created_at desc
  limit 300;
end;
$$;

revoke all on function public.admin_list_accounts(text) from public, anon;
grant execute on function public.admin_list_accounts(text) to authenticated;

commit;
