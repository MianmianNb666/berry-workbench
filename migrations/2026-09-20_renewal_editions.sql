-- 莓桃工作台：续费邀请码版本 + 版本升级规则
-- 规则：
-- 1) 注册邀请码完全不改。
-- 2) 新续费码必须标记为 artist（美工版）或 full（完整版）。
-- 3) 美工版续费码只续时长，绝不降级完整版账号。
-- 4) 完整版续费码续时长；若当前是美工版，同时升级为完整版。
-- 5) 历史续费码 renewal_edition = null，只续时长，不改变版本。
-- 6) 升级只改权限版本字段，原订单 / 财务 / 好友 / 聊天等数据完全不迁移、不重建。
-- 7) 为保持现有账号 / 注册逻辑兼容，现有与新建 user_access 默认 edition='full'；
--    后续需要美工版账号时，只需把对应 user_access.edition 设为 'artist'。
--
-- 可重复执行。

begin;

create extension if not exists pgcrypto with schema extensions;

-- =========================================================
-- A. 账号版本
-- =========================================================

alter table public.user_access
  add column if not exists edition text not null default 'full';

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'user_access_edition_check'
      and conrelid = 'public.user_access'::regclass
  ) then
    alter table public.user_access
      add constraint user_access_edition_check
      check (edition in ('artist','full'));
  end if;
end
$$;

-- 老账号保持现有完整功能，不因为加字段发生降级。
update public.user_access
set edition = 'full'
where edition is null
   or edition not in ('artist','full');


-- =========================================================
-- B. 续费码版本
-- signup 永远为 null；历史 renewal 也保持 null，代表 legacy/time-only。
-- =========================================================

alter table public.invite_codes
  add column if not exists renewal_edition text;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'invite_codes_renewal_edition_check'
      and conrelid = 'public.invite_codes'::regclass
  ) then
    alter table public.invite_codes
      add constraint invite_codes_renewal_edition_check
      check (
        renewal_edition is null
        or (
          purpose = 'renewal'
          and renewal_edition in ('artist','full')
        )
      );
  end if;
end
$$;

update public.invite_codes
set renewal_edition = null
where purpose = 'signup';


-- =========================================================
-- C. 兑换记录也保存续费版本，方便以后查历史。
-- 旧记录保持 null。
-- =========================================================

alter table public.invite_redemptions
  add column if not exists renewal_edition text;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'invite_redemptions_renewal_edition_check'
      and conrelid = 'public.invite_redemptions'::regclass
  ) then
    alter table public.invite_redemptions
      add constraint invite_redemptions_renewal_edition_check
      check (
        renewal_edition is null
        or renewal_edition in ('artist','full')
      );
  end if;
end
$$;


-- =========================================================
-- D. 当前账号权限状态增加 edition
-- =========================================================

create or replace function public.get_access_status()
returns jsonb
language plpgsql
stable
security definer
set search_path = public, auth
as $$
declare
  v_uid uuid := auth.uid();
  v_access public.user_access%rowtype;
begin
  if v_uid is null then
    return jsonb_build_object(
      'has_access', false,
      'access_type', null,
      'valid_from', null,
      'valid_until', null,
      'edition', null
    );
  end if;

  select *
    into v_access
  from public.user_access
  where user_id = v_uid;

  if not found then
    return jsonb_build_object(
      'has_access', false,
      'access_type', null,
      'valid_from', null,
      'valid_until', null,
      'edition', null
    );
  end if;

  return jsonb_build_object(
    'has_access',
      (
        v_access.access_type = 'permanent'
        or (v_access.valid_until is not null and v_access.valid_until > now())
      ),
    'access_type', v_access.access_type,
    'valid_from', v_access.valid_from,
    'valid_until', v_access.valid_until,
    'edition', v_access.edition
  );
end;
$$;

revoke all on function public.get_access_status() from public, anon;
grant execute on function public.get_access_status() to authenticated;


-- =========================================================
-- E. 续费兑换
-- 保留 multi / single 逻辑。
-- =========================================================

create or replace function public.redeem_renewal_code(p_code text)
returns jsonb
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_uid uuid := auth.uid();
  v_hash text;
  v_invite public.invite_codes%rowtype;
  v_access public.user_access%rowtype;
  v_old_until timestamptz;
  v_base timestamptz;
  v_new_until timestamptz;
  v_already_used boolean := false;
  v_old_edition text;
  v_new_edition text;
  v_upgraded boolean := false;
begin
  if v_uid is null then
    raise exception '请先登录';
  end if;

  -- 续费码只给美工账号使用。
  if not exists (
    select 1
    from public.user_roles r
    where r.user_id = v_uid
      and r.role = 'artist'
  ) then
    return jsonb_build_object(
      'success', false,
      'reason', 'NOT_ARTIST'
    );
  end if;

  select *
    into v_access
  from public.user_access
  where user_id = v_uid
  for update;

  if not found then
    insert into public.user_access(
      user_id,
      access_type,
      valid_from,
      valid_until,
      edition,
      updated_at
    )
    values (
      v_uid,
      'temporary',
      now(),
      now(),
      'full',
      now()
    )
    returning *
      into v_access;
  end if;

  v_old_edition := coalesce(v_access.edition, 'full');
  v_new_edition := v_old_edition;

  v_hash := encode(
    extensions.digest(
      upper(trim(coalesce(p_code, ''))),
      'sha256'
    ),
    'hex'
  );

  -- 先读取码，避免永久账号在不需要续期时误消耗邀请码。
  select *
    into v_invite
  from public.invite_codes ic
  where ic.code_hash = v_hash
    and ic.purpose = 'renewal'
    and ic.is_active = true
    and (ic.expires_at is null or ic.expires_at > now())
    and (
      (ic.use_mode = 'single' and ic.used_at is null)
      or
      (
        ic.use_mode = 'multi'
        and (
          ic.max_uses is null
          or coalesce(ic.used_count, 0) < ic.max_uses
        )
      )
    )
  limit 1;

  if v_invite.id is null then
    return jsonb_build_object(
      'success', false,
      'reason', 'INVALID_OR_USED'
    );
  end if;

  select exists (
    select 1
    from public.invite_redemptions ir
    where ir.invite_id = v_invite.id
      and ir.user_id = v_uid
  )
  into v_already_used;

  if v_already_used then
    return jsonb_build_object(
      'success', false,
      'reason', 'ALREADY_USED_BY_USER'
    );
  end if;

  -- 只有完整版码可以升级；artist / legacy 都不改变当前版本。
  if v_invite.renewal_edition = 'full'
     and v_old_edition = 'artist' then
    v_new_edition := 'full';
    v_upgraded := true;
  end if;

  -- 永久账号没有时长可续。
  -- 唯一例外：永久美工版可使用“完整版续费码”完成版本升级。
  if v_access.access_type = 'permanent'
     and not v_upgraded then
    return jsonb_build_object(
      'success', false,
      'reason', 'ALREADY_PERMANENT',
      'access_type', 'permanent',
      'edition', v_old_edition
    );
  end if;

  -- 到这里才真正消耗邀请码。
  update public.invite_codes ic
  set
    used_count = coalesce(ic.used_count, 0) + 1,
    used_at = case
      when ic.use_mode = 'single' then now()
      else ic.used_at
    end,
    used_by = case
      when ic.use_mode = 'single' then v_uid
      else ic.used_by
    end,
    is_active = case
      when ic.use_mode = 'single' then false
      when ic.max_uses is not null
           and coalesce(ic.used_count, 0) + 1 >= ic.max_uses then false
      else true
    end
  where ic.id = v_invite.id
    and ic.is_active = true
    and (ic.expires_at is null or ic.expires_at > now())
    and (
      (ic.use_mode = 'single' and ic.used_at is null)
      or
      (
        ic.use_mode = 'multi'
        and (
          ic.max_uses is null
          or coalesce(ic.used_count, 0) < ic.max_uses
        )
      )
    )
  returning *
    into v_invite;

  if v_invite.id is null then
    return jsonb_build_object(
      'success', false,
      'reason', 'INVALID_OR_USED'
    );
  end if;

  v_old_until := v_access.valid_until;

  -- 永久美工版 -> 完整版：只改版本，不改数据、不改永久状态。
  if v_access.access_type = 'permanent' then
    update public.user_access
    set
      edition = v_new_edition,
      updated_at = now()
    where user_id = v_uid;

    insert into public.invite_redemptions(
      invite_id,
      user_id,
      purpose,
      grant_type,
      duration_days,
      renewal_edition,
      old_valid_until,
      new_valid_until
    )
    values (
      v_invite.id,
      v_uid,
      'renewal',
      v_invite.grant_type,
      v_invite.duration_days,
      v_invite.renewal_edition,
      null,
      null
    );

    return jsonb_build_object(
      'success', true,
      'access_type', 'permanent',
      'added_days', null,
      'valid_until', null,
      'edition', v_new_edition,
      'renewal_edition', v_invite.renewal_edition,
      'upgraded', v_upgraded
    );
  end if;

  if v_invite.grant_type = 'permanent' then
    update public.user_access
    set
      access_type = 'permanent',
      valid_until = null,
      edition = v_new_edition,
      updated_at = now()
    where user_id = v_uid;

    insert into public.invite_redemptions(
      invite_id,
      user_id,
      purpose,
      grant_type,
      duration_days,
      renewal_edition,
      old_valid_until,
      new_valid_until
    )
    values (
      v_invite.id,
      v_uid,
      'renewal',
      'permanent',
      null,
      v_invite.renewal_edition,
      v_old_until,
      null
    );

    return jsonb_build_object(
      'success', true,
      'access_type', 'permanent',
      'added_days', null,
      'valid_until', null,
      'edition', v_new_edition,
      'renewal_edition', v_invite.renewal_edition,
      'upgraded', v_upgraded
    );
  end if;

  v_base :=
    case
      when v_access.valid_until is not null
       and v_access.valid_until > now()
        then v_access.valid_until
      else now()
    end;

  v_new_until :=
    v_base + make_interval(days => v_invite.duration_days);

  update public.user_access
  set
    access_type = 'temporary',
    valid_until = v_new_until,
    edition = v_new_edition,
    updated_at = now()
  where user_id = v_uid;

  insert into public.invite_redemptions(
    invite_id,
    user_id,
    purpose,
    grant_type,
    duration_days,
    renewal_edition,
    old_valid_until,
    new_valid_until
  )
  values (
    v_invite.id,
    v_uid,
    'renewal',
    'days',
    v_invite.duration_days,
    v_invite.renewal_edition,
    v_old_until,
    v_new_until
  );

  return jsonb_build_object(
    'success', true,
    'access_type', 'temporary',
    'added_days', v_invite.duration_days,
    'valid_until', v_new_until,
    'edition', v_new_edition,
    'renewal_edition', v_invite.renewal_edition,
    'upgraded', v_upgraded
  );
end;
$$;

revoke all on function public.redeem_renewal_code(text) from public, anon;
grant execute on function public.redeem_renewal_code(text) to authenticated;


-- =========================================================
-- F. 管理端生成邀请码
-- 注册码 p_renewal_edition 会被强制置 null。
-- 新续费码必须选择 artist / full。
-- =========================================================

drop function if exists public.admin_create_invite(
  text,text,integer,text,integer,text,timestamptz
);

drop function if exists public.admin_create_invite(
  text,text,integer,text,integer,text,timestamptz,text
);

create function public.admin_create_invite(
  p_purpose text,
  p_grant_type text,
  p_duration_days integer default null,
  p_use_mode text default 'single',
  p_max_uses integer default 1,
  p_label text default null,
  p_expires_at timestamptz default null,
  p_renewal_edition text default null
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

  p_purpose := lower(trim(coalesce(p_purpose, '')));
  p_grant_type := lower(trim(coalesce(p_grant_type, '')));
  p_use_mode := lower(trim(coalesce(p_use_mode, 'single')));
  p_renewal_edition :=
    nullif(lower(trim(coalesce(p_renewal_edition, ''))), '');

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
    -- 注册逻辑保持原样。
    p_grant_type := 'days';
    p_duration_days := 7;
    p_renewal_edition := null;
  else
    if p_renewal_edition not in ('artist','full') then
      raise exception '续费版本必须选择美工版或完整版';
    end if;

    if p_grant_type = 'days'
       and p_duration_days not in (7,30,90,365) then
      raise exception '续期天数仅支持 7 / 30 / 90 / 365 天';
    elsif p_grant_type = 'permanent' then
      p_duration_days := null;
    end if;
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
      case
        when p_purpose = 'signup' then 'BERRY-S-'
        else 'BERRY-R-'
      end
      || upper(
        substr(
          encode(extensions.gen_random_bytes(8), 'hex'),
          1,
          16
        )
      );

    v_hash :=
      encode(
        extensions.digest(v_code, 'sha256'),
        'hex'
      );

    begin
      insert into public.invite_codes(
        code_hash,
        label,
        purpose,
        grant_type,
        duration_days,
        renewal_edition,
        is_active,
        expires_at,
        use_mode,
        max_uses,
        used_count
      )
      values (
        v_hash,
        nullif(trim(coalesce(p_label, '')), ''),
        p_purpose,
        p_grant_type,
        p_duration_days,
        p_renewal_edition,
        true,
        p_expires_at,
        p_use_mode,
        v_max_uses,
        0
      )
      returning id
        into v_id;

      insert into public.admin_invite_plain_codes(
        invite_id,
        code
      )
      values (
        v_id,
        v_code
      )
      on conflict (invite_id) do update
      set code = excluded.code;

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
    'renewal_edition', p_renewal_edition,
    'use_mode', p_use_mode,
    'max_uses', v_max_uses,
    'expires_at', p_expires_at
  );
end;
$$;

revoke all
on function public.admin_create_invite(
  text,text,integer,text,integer,text,timestamptz,text
)
from public, anon;

grant execute
on function public.admin_create_invite(
  text,text,integer,text,integer,text,timestamptz,text
)
to authenticated;


-- =========================================================
-- G. 管理端邀请码列表增加 renewal_edition
-- =========================================================

drop function if exists public.admin_list_invites();

create function public.admin_list_invites()
returns table (
  id uuid,
  label text,
  purpose text,
  grant_type text,
  duration_days integer,
  renewal_edition text,
  is_active boolean,
  expires_at timestamptz,
  use_mode text,
  max_uses integer,
  used_count integer,
  created_at timestamptz,
  invite_code text
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
    i.renewal_edition,
    i.is_active,
    i.expires_at,
    i.use_mode,
    i.max_uses,
    i.used_count,
    i.created_at,
    p.code
  from public.invite_codes i
  left join public.admin_invite_plain_codes p
    on p.invite_id = i.id
  order by i.created_at desc
  limit 300;
end;
$$;

revoke all on function public.admin_list_invites() from public, anon;
grant execute on function public.admin_list_invites() to authenticated;


-- =========================================================
-- H. 续期历史增加版本
-- =========================================================

drop function if exists public.get_my_renewal_history();

create function public.get_my_renewal_history()
returns table (
  redeemed_at timestamptz,
  grant_type text,
  duration_days integer,
  renewal_edition text,
  old_valid_until timestamptz,
  new_valid_until timestamptz
)
language sql
stable
security definer
set search_path = public, auth
as $$
  select
    ir.redeemed_at,
    ir.grant_type,
    ir.duration_days,
    ir.renewal_edition,
    ir.old_valid_until,
    ir.new_valid_until
  from public.invite_redemptions ir
  where ir.user_id = auth.uid()
    and ir.purpose = 'renewal'
  order by ir.redeemed_at desc;
$$;

revoke all on function public.get_my_renewal_history() from public, anon;
grant execute on function public.get_my_renewal_history() to authenticated;

commit;


-- =========================================================
-- I. 快速检查
-- =========================================================

select
  'user_access.edition' as item,
  count(*) filter (where edition not in ('artist','full'))::bigint as bad_rows
from public.user_access

union all

select
  'signup renewal_edition must be null',
  count(*) filter (
    where purpose = 'signup'
      and renewal_edition is not null
  )::bigint
from public.invite_codes;
