-- 2026-09-21: renewal edition switching
-- New rule:
--   renewal_edition='artist' => account becomes artist edition
--   renewal_edition='full'   => account becomes full edition
--   renewal_edition=null     => legacy code, time-only, edition unchanged
-- Existing data/orders/chat/friends/customers are preserved; only user_access.edition changes.

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
  v_downgraded boolean := false;
  v_edition_changed boolean := false;
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

  -- 新规则：续费码的版本就是续费后的账号版本。
  -- full 可把 artist 升级；artist 也可把 full 降级。
  -- 旧续费码 renewal_edition = null，仍然只续时长、不改版本。
  if v_invite.renewal_edition in ('artist','full') then
    v_new_edition := v_invite.renewal_edition;
  end if;

  v_upgraded := v_old_edition = 'artist' and v_new_edition = 'full';
  v_downgraded := v_old_edition = 'full' and v_new_edition = 'artist';
  v_edition_changed := v_new_edition is distinct from v_old_edition;

  -- 永久账号没有时长可续。
  -- 但如果续费码会切换版本，允许消耗该码并完成版本切换。
  if v_access.access_type = 'permanent'
     and not v_edition_changed then
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

  -- 永久账号切换版本：只改版本，不改数据、不改永久状态。
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
      'upgraded', v_upgraded,
      'downgraded', v_downgraded
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
      'upgraded', v_upgraded,
      'downgraded', v_downgraded
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
    'upgraded', v_upgraded,
    'downgraded', v_downgraded
  );
end;
$$;

revoke all on function public.redeem_renewal_code(text) from public, anon;
grant execute on function public.redeem_renewal_code(text) to authenticated;

select
  'renewal_edition_switching' as check_name,
  case
    when to_regprocedure('public.redeem_renewal_code(text)') is not null
    then 'OK'
    else 'MISSING'
  end as result;
