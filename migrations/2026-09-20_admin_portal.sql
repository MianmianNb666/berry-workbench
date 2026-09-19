-- 莓桃管理端
-- 运行位置：Supabase -> SQL Editor
-- 功能：
-- 1) 仅 Owner 账号可读取账号列表与使用期限
-- 2) Owner 可直接给美工账号增加使用天数 / 设为永久
-- 3) Owner 可生成注册邀请码、续期码，并管理启用状态
-- 4) 所有直接充值操作写入后台审计记录

begin;

create extension if not exists pgcrypto;

-- =========================================================
-- A. Owner 校验
-- =========================================================

create or replace function public.admin_owner_allowed()
returns boolean
language sql
stable
security definer
set search_path = public, auth, extensions
as $$
  select
    auth.uid() is not null
    and encode(
      extensions.digest(auth.uid()::text, 'sha256'),
      'hex'
    ) = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8';
$$;

revoke all on function public.admin_owner_allowed() from public, anon;
grant execute on function public.admin_owner_allowed() to authenticated;


-- =========================================================
-- B. 管理端充值审计
-- =========================================================

create table if not exists public.admin_access_adjustments (
  id uuid primary key default extensions.gen_random_uuid(),
  admin_user_id uuid not null references auth.users(id) on delete restrict,
  target_user_id uuid not null references auth.users(id) on delete cascade,
  action_type text not null check (action_type in ('add_days','permanent')),
  added_days integer,
  old_access_type text,
  old_valid_until timestamptz,
  new_access_type text not null,
  new_valid_until timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists admin_access_adjustments_target_idx
  on public.admin_access_adjustments(target_user_id, created_at desc);

alter table public.admin_access_adjustments enable row level security;
revoke all on table public.admin_access_adjustments from anon, authenticated;


-- =========================================================
-- C. 管理端读取账号
-- =========================================================

create or replace function public.admin_list_accounts(
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
  roles text[]
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
    ) as roles
  from auth.users u
  left join public.user_access ua
    on ua.user_id = u.id
  where
    trim(coalesce(p_search,'')) = ''
    or coalesce(u.email,'') ilike '%' || trim(p_search) || '%'
    or u.id::text ilike '%' || trim(p_search) || '%'
  order by u.created_at desc
  limit 300;
end;
$$;

revoke all on function public.admin_list_accounts(text) from public, anon;
grant execute on function public.admin_list_accounts(text) to authenticated;


-- =========================================================
-- D. 直接给美工增加使用时间 / 永久
-- =========================================================

create or replace function public.admin_grant_access(
  p_target_user_id uuid,
  p_days integer default null,
  p_permanent boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_access public.user_access%rowtype;
  v_old_type text;
  v_old_until timestamptz;
  v_base timestamptz;
  v_new_until timestamptz;
begin
  if not public.admin_owner_allowed() then
    raise exception 'not allowed';
  end if;

  if p_target_user_id is null then
    raise exception '请选择账号';
  end if;

  if not exists (
    select 1
    from auth.users u
    where u.id = p_target_user_id
  ) then
    raise exception '账号不存在';
  end if;

  -- 防止误给纯顾客账号充值。
  if not exists (
    select 1 from public.user_access ua where ua.user_id = p_target_user_id
  )
  and not exists (
    select 1
    from public.user_roles r
    where r.user_id = p_target_user_id
      and r.role = 'artist'
  ) then
    raise exception '该账号不是美工账号';
  end if;

  select *
    into v_access
  from public.user_access
  where user_id = p_target_user_id
  for update;

  if found then
    v_old_type := v_access.access_type;
    v_old_until := v_access.valid_until;
  else
    v_old_type := null;
    v_old_until := null;
  end if;

  if p_permanent then
    insert into public.user_access(
      user_id,
      access_type,
      valid_from,
      valid_until,
      updated_at
    )
    values (
      p_target_user_id,
      'permanent',
      now(),
      null,
      now()
    )
    on conflict (user_id) do update
    set access_type = 'permanent',
        valid_until = null,
        updated_at = now();

    insert into public.admin_access_adjustments(
      admin_user_id,
      target_user_id,
      action_type,
      added_days,
      old_access_type,
      old_valid_until,
      new_access_type,
      new_valid_until
    )
    values (
      auth.uid(),
      p_target_user_id,
      'permanent',
      null,
      v_old_type,
      v_old_until,
      'permanent',
      null
    );

    return jsonb_build_object(
      'success', true,
      'access_type', 'permanent',
      'valid_until', null
    );
  end if;

  if p_days is null or p_days < 1 or p_days > 3650 then
    raise exception '增加天数必须在 1 到 3650 天之间';
  end if;

  if v_old_type = 'permanent' then
    return jsonb_build_object(
      'success', false,
      'reason', 'ALREADY_PERMANENT',
      'access_type', 'permanent',
      'valid_until', null
    );
  end if;

  v_base :=
    case
      when v_old_until is not null and v_old_until > now()
        then v_old_until
      else now()
    end;

  v_new_until := v_base + make_interval(days => p_days);

  insert into public.user_access(
    user_id,
    access_type,
    valid_from,
    valid_until,
    updated_at
  )
  values (
    p_target_user_id,
    'temporary',
    now(),
    v_new_until,
    now()
  )
  on conflict (user_id) do update
  set access_type = 'temporary',
      valid_until = excluded.valid_until,
      updated_at = now();

  insert into public.admin_access_adjustments(
    admin_user_id,
    target_user_id,
    action_type,
    added_days,
    old_access_type,
    old_valid_until,
    new_access_type,
    new_valid_until
  )
  values (
    auth.uid(),
    p_target_user_id,
    'add_days',
    p_days,
    v_old_type,
    v_old_until,
    'temporary',
    v_new_until
  );

  return jsonb_build_object(
    'success', true,
    'access_type', 'temporary',
    'added_days', p_days,
    'valid_until', v_new_until
  );
end;
$$;

revoke all on function public.admin_grant_access(uuid,integer,boolean) from public, anon;
grant execute on function public.admin_grant_access(uuid,integer,boolean) to authenticated;


-- =========================================================
-- E. 生成邀请码
-- =========================================================

create or replace function public.admin_create_invite(
  p_purpose text,
  p_grant_type text,
  p_duration_days integer default null,
  p_use_mode text default 'single',
  p_max_uses integer default 1,
  p_label text default null,
  p_expires_at timestamptz default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_code text;
  v_hash text;
  v_id uuid;
  v_max_uses integer;
begin
  if not public.admin_owner_allowed() then
    raise exception 'not allowed';
  end if;

  p_purpose := lower(trim(coalesce(p_purpose,'')));
  p_grant_type := lower(trim(coalesce(p_grant_type,'')));
  p_use_mode := lower(trim(coalesce(p_use_mode,'single')));

  if p_purpose not in ('signup','renewal') then
    raise exception '邀请码用途无效';
  end if;

  if p_grant_type not in ('days','permanent') then
    raise exception '授权类型无效';
  end if;

  if p_use_mode not in ('single','multi') then
    raise exception '使用模式无效';
  end if;

  if p_purpose = 'signup' then
    p_grant_type := 'days';
    p_duration_days := 7;
  elsif p_grant_type = 'days'
    and p_duration_days not in (7,30,90,365) then
    raise exception '续期天数仅支持 7 / 30 / 90 / 365 天';
  elsif p_grant_type = 'permanent' then
    p_duration_days := null;
  end if;

  if p_use_mode = 'single' then
    v_max_uses := 1;
  else
    if p_max_uses is not null and p_max_uses < 1 then
      raise exception '使用次数必须大于 0';
    end if;
    v_max_uses := p_max_uses;
  end if;

  loop
    v_code :=
      case when p_purpose = 'signup' then 'BERRY-S-' else 'BERRY-R-' end
      || upper(substr(encode(extensions.gen_random_bytes(8),'hex'),1,16));

    v_hash := encode(
      extensions.digest(v_code,'sha256'),
      'hex'
    );

    begin
      insert into public.invite_codes(
        code_hash,
        label,
        purpose,
        grant_type,
        duration_days,
        is_active,
        expires_at,
        use_mode,
        max_uses,
        used_count
      )
      values (
        v_hash,
        nullif(trim(coalesce(p_label,'')),''),
        p_purpose,
        p_grant_type,
        p_duration_days,
        true,
        p_expires_at,
        p_use_mode,
        v_max_uses,
        0
      )
      returning id into v_id;

      exit;
    exception when unique_violation then
      null;
    end;
  end loop;

  return jsonb_build_object(
    'success', true,
    'id', v_id,
    'code', v_code,
    'purpose', p_purpose,
    'grant_type', p_grant_type,
    'duration_days', p_duration_days,
    'use_mode', p_use_mode,
    'max_uses', v_max_uses,
    'expires_at', p_expires_at
  );
end;
$$;

revoke all on function public.admin_create_invite(text,text,integer,text,integer,text,timestamptz) from public, anon;
grant execute on function public.admin_create_invite(text,text,integer,text,integer,text,timestamptz) to authenticated;


-- =========================================================
-- F. 查看 / 启停邀请码
-- 注意：数据库只保存 hash，所以历史邀请码不会再次显示明文。
-- 新生成时请立即复制保存。
-- =========================================================

create or replace function public.admin_list_invites()
returns table (
  id uuid,
  label text,
  purpose text,
  grant_type text,
  duration_days integer,
  is_active boolean,
  expires_at timestamptz,
  use_mode text,
  max_uses integer,
  used_count integer,
  created_at timestamptz
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
    i.id,
    i.label,
    i.purpose,
    i.grant_type,
    i.duration_days,
    i.is_active,
    i.expires_at,
    i.use_mode,
    i.max_uses,
    i.used_count,
    i.created_at
  from public.invite_codes i
  order by i.created_at desc
  limit 300;
end;
$$;

revoke all on function public.admin_list_invites() from public, anon;
grant execute on function public.admin_list_invites() to authenticated;


create or replace function public.admin_set_invite_active(
  p_invite_id uuid,
  p_active boolean
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

  update public.invite_codes
  set is_active = coalesce(p_active,false)
  where id = p_invite_id;

  return found;
end;
$$;

revoke all on function public.admin_set_invite_active(uuid,boolean) from public, anon;
grant execute on function public.admin_set_invite_active(uuid,boolean) to authenticated;


-- =========================================================
-- G. 最近充值记录
-- =========================================================

create or replace function public.admin_list_access_adjustments()
returns table (
  id uuid,
  target_user_id uuid,
  target_email text,
  action_type text,
  added_days integer,
  old_access_type text,
  old_valid_until timestamptz,
  new_access_type text,
  new_valid_until timestamptz,
  created_at timestamptz
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
    a.id,
    a.target_user_id,
    u.email::text,
    a.action_type,
    a.added_days,
    a.old_access_type,
    a.old_valid_until,
    a.new_access_type,
    a.new_valid_until,
    a.created_at
  from public.admin_access_adjustments a
  left join auth.users u on u.id = a.target_user_id
  order by a.created_at desc
  limit 100;
end;
$$;

revoke all on function public.admin_list_access_adjustments() from public, anon;
grant execute on function public.admin_list_access_adjustments() to authenticated;

commit;


-- =========================================================
-- H. 管理员备注 + 工作台名称同步
-- =========================================================

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

