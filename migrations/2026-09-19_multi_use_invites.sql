-- 莓桃工作台：支持“通用邀请码”的增量迁移
-- 目标：
-- 1) 保留现有一次性邀请码
-- 2) 新增 multi 通用邀请码，可被多个不同账号使用
-- 3) 同一个账号对同一个通用码只能兑换一次
-- 4) 可设置最大使用次数，例如 100 次
-- 5) 不删除现有用户、订单、邀请码或兑换记录
--
-- 运行位置：Supabase -> SQL Editor
-- 运行一次即可。

begin;

-- =========================================================
-- A. 扩展 invite_codes
-- =========================================================

alter table public.invite_codes
  add column if not exists use_mode text not null default 'single';

alter table public.invite_codes
  add column if not exists max_uses integer;

alter table public.invite_codes
  add column if not exists used_count integer not null default 0;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'invite_codes_use_mode_check'
      and conrelid = 'public.invite_codes'::regclass
  ) then
    alter table public.invite_codes
      add constraint invite_codes_use_mode_check
      check (use_mode in ('single','multi'));
  end if;

  if not exists (
    select 1
    from pg_constraint
    where conname = 'invite_codes_max_uses_check'
      and conrelid = 'public.invite_codes'::regclass
  ) then
    alter table public.invite_codes
      add constraint invite_codes_max_uses_check
      check (max_uses is null or max_uses > 0);
  end if;
end
$$;

-- 给旧的一次性邀请码补齐计数。
update public.invite_codes
set used_count = greatest(
  coalesce(used_count, 0),
  case when used_at is not null then 1 else 0 end
);

update public.invite_codes
set max_uses = 1
where use_mode = 'single'
  and max_uses is null;


-- =========================================================
-- B. 兑换记录：允许同一个邀请码被不同用户使用
-- 但同一个用户 + 同一个邀请码只能有一条记录
-- =========================================================

alter table public.invite_redemptions
  drop constraint if exists invite_redemptions_invite_id_key;

alter table public.invite_redemptions
  drop constraint if exists one_redemption_per_invite;

create unique index if not exists invite_redemptions_invite_user_unique
  on public.invite_redemptions(invite_id, user_id);


-- =========================================================
-- C. 注册邀请码逻辑
-- single = 仍然只可使用一次
-- multi  = 可供多人注册，直到达到 max_uses
-- =========================================================

create or replace function public.handle_new_user_access()
returns trigger
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_code text;
  v_hash text;
  v_invite public.invite_codes%rowtype;
  v_new_until timestamptz;
begin
  v_code := upper(trim(coalesce(new.raw_user_meta_data ->> 'invite_code', '')));

  if v_code = '' then
    raise exception '注册需要有效邀请码';
  end if;

  v_hash := encode(digest(v_code, 'sha256'), 'hex');

  update public.invite_codes ic
  set used_count = ic.used_count + 1,
      used_at = case
        when ic.use_mode = 'single' then now()
        else ic.used_at
      end,
      used_by = case
        when ic.use_mode = 'single' then new.id
        else ic.used_by
      end,
      is_active = case
        when ic.use_mode = 'single' then false
        when ic.max_uses is not null
             and ic.used_count + 1 >= ic.max_uses then false
        else true
      end
  where ic.code_hash = v_hash
    and ic.purpose = 'signup'
    and ic.grant_type = 'days'
    and ic.duration_days = 7
    and ic.is_active = true
    and (ic.expires_at is null or ic.expires_at > now())
    and (
      (ic.use_mode = 'single' and ic.used_at is null)
      or
      (
        ic.use_mode = 'multi'
        and (ic.max_uses is null or ic.used_count < ic.max_uses)
      )
    )
  returning *
    into v_invite;

  if v_invite.id is null then
    raise exception '邀请码无效、已使用、已达使用上限或已过期';
  end if;

  v_new_until := now() + make_interval(days => v_invite.duration_days);

  insert into public.user_access(
    user_id,
    access_type,
    valid_from,
    valid_until,
    updated_at
  )
  values (
    new.id,
    'temporary',
    now(),
    v_new_until,
    now()
  )
  on conflict (user_id) do update
  set access_type = excluded.access_type,
      valid_from = excluded.valid_from,
      valid_until = excluded.valid_until,
      updated_at = excluded.updated_at;

  insert into public.invite_redemptions(
    invite_id,
    user_id,
    purpose,
    grant_type,
    duration_days,
    old_valid_until,
    new_valid_until
  )
  values (
    v_invite.id,
    new.id,
    'signup',
    'days',
    v_invite.duration_days,
    null,
    v_new_until
  );

  return new;
end;
$$;


-- =========================================================
-- D. 续期邀请码逻辑
-- multi 通用续期码：不同账号可以使用
-- 同一个账号不能重复兑换同一通用码
-- =========================================================

create or replace function public.redeem_renewal_code(p_code text)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
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
begin
  if v_uid is null then
    raise exception '请先登录';
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
      updated_at
    )
    values (
      v_uid,
      'temporary',
      now(),
      now(),
      now()
    )
    returning *
      into v_access;
  end if;

  if v_access.access_type = 'permanent' then
    return jsonb_build_object(
      'success', false,
      'reason', 'ALREADY_PERMANENT',
      'access_type', 'permanent'
    );
  end if;

  v_hash := encode(digest(upper(trim(coalesce(p_code, ''))), 'sha256'), 'hex');

  select exists (
    select 1
    from public.invite_codes ic
    join public.invite_redemptions ir
      on ir.invite_id = ic.id
    where ic.code_hash = v_hash
      and ir.user_id = v_uid
  )
  into v_already_used;

  if v_already_used then
    return jsonb_build_object(
      'success', false,
      'reason', 'ALREADY_USED_BY_USER'
    );
  end if;

  update public.invite_codes ic
  set used_count = ic.used_count + 1,
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
             and ic.used_count + 1 >= ic.max_uses then false
        else true
      end
  where ic.code_hash = v_hash
    and ic.purpose = 'renewal'
    and ic.is_active = true
    and (ic.expires_at is null or ic.expires_at > now())
    and (
      (ic.use_mode = 'single' and ic.used_at is null)
      or
      (
        ic.use_mode = 'multi'
        and (ic.max_uses is null or ic.used_count < ic.max_uses)
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

  if v_invite.grant_type = 'permanent' then
    update public.user_access
    set access_type = 'permanent',
        valid_until = null,
        updated_at = now()
    where user_id = v_uid;

    insert into public.invite_redemptions(
      invite_id,
      user_id,
      purpose,
      grant_type,
      duration_days,
      old_valid_until,
      new_valid_until
    )
    values (
      v_invite.id,
      v_uid,
      'renewal',
      'permanent',
      null,
      v_old_until,
      null
    );

    return jsonb_build_object(
      'success', true,
      'access_type', 'permanent',
      'added_days', null,
      'valid_until', null
    );
  end if;

  v_base :=
    case
      when v_access.valid_until is not null and v_access.valid_until > now()
        then v_access.valid_until
      else now()
    end;

  v_new_until := v_base + make_interval(days => v_invite.duration_days);

  update public.user_access
  set access_type = 'temporary',
      valid_until = v_new_until,
      updated_at = now()
  where user_id = v_uid;

  insert into public.invite_redemptions(
    invite_id,
    user_id,
    purpose,
    grant_type,
    duration_days,
    old_valid_until,
    new_valid_until
  )
  values (
    v_invite.id,
    v_uid,
    'renewal',
    v_invite.grant_type,
    v_invite.duration_days,
    v_old_until,
    v_new_until
  );

  return jsonb_build_object(
    'success', true,
    'access_type', 'temporary',
    'added_days', v_invite.duration_days,
    'valid_until', v_new_until
  );
end;
$$;

commit;


-- =========================================================
-- E. 创建“通用 7 天注册试用码”
-- 下面这段请在上面的迁移成功后单独运行。
--
-- 现在示例设置为：
--   通用码：BERRY-7D-GENERAL
--   最多：100 个账号
--   每个新账号：获得 7 天
--
-- 想换名字，只改 BERRY-7D-GENERAL 即可。
-- 想改人数，只改 100 即可。
-- =========================================================

-- insert into public.invite_codes(
--   code_hash,
--   label,
--   purpose,
--   grant_type,
--   duration_days,
--   use_mode,
--   max_uses,
--   used_count,
--   is_active
-- )
-- values (
--   encode(digest(upper(trim('BERRY-7D-GENERAL')), 'sha256'), 'hex'),
--   '通用7天注册试用码',
--   'signup',
--   'days',
--   7,
--   'multi',
--   100,
--   0,
--   true
-- );


-- =========================================================
-- F. 可选：创建“通用 7 天续期码”
-- 给已经注册的用户使用，每个账号只能兑一次。
-- =========================================================

-- insert into public.invite_codes(
--   code_hash,
--   label,
--   purpose,
--   grant_type,
--   duration_days,
--   use_mode,
--   max_uses,
--   used_count,
--   is_active
-- )
-- values (
--   encode(digest(upper(trim('BERRY-7D-RENEW-ALL')), 'sha256'), 'hex'),
--   '通用7天续期码',
--   'renewal',
--   'days',
--   7,
--   'multi',
--   100,
--   0,
--   true
-- );
