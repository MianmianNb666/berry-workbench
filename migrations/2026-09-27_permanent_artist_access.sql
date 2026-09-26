-- 2026-09-27: signup invite only, permanent artist access
-- Run once in Supabase SQL Editor after deploying the frontend change.
-- Rules:
--   * Artist registration still requires a valid signup invite.
--   * Successful signup grants permanent access.
--   * Existing artist accounts become permanent.
--   * Renewal codes are disabled and renewal RPC access is revoked.

begin;

create extension if not exists pgcrypto with schema extensions;

-- 1) Existing artist accounts: permanent access.
insert into public.user_access(
  user_id,
  access_type,
  valid_from,
  valid_until,
  updated_at
)
select
  r.user_id,
  'permanent',
  now(),
  null,
  now()
from public.user_roles r
where r.role = 'artist'
on conflict (user_id) do update
set
  access_type = 'permanent',
  valid_until = null,
  updated_at = now();

-- 2) Retire all existing renewal codes.
update public.invite_codes
set is_active = false
where purpose = 'renewal'
  and is_active = true;

-- 3) New artist signup: invite is only an admission gate, access is permanent.
create or replace function public.handle_new_user_access()
returns trigger
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_role text;
  v_code text;
  v_hash text;
  v_invite public.invite_codes%rowtype;
begin
  v_role := lower(trim(coalesce(new.raw_user_meta_data ->> 'account_role', 'artist')));

  -- Customer accounts do not consume artist signup invites.
  if v_role = 'customer' then
    insert into public.user_roles(user_id, role)
    values (new.id, 'customer')
    on conflict do nothing;

    return new;
  end if;

  insert into public.user_roles(user_id, role)
  values (new.id, 'artist')
  on conflict do nothing;

  v_code := upper(trim(coalesce(new.raw_user_meta_data ->> 'invite_code', '')));

  if v_code = '' then
    raise exception '注册需要有效邀请码';
  end if;

  v_hash := encode(extensions.digest(v_code, 'sha256'), 'hex');

  update public.invite_codes ic
  set
    used_count = coalesce(ic.used_count, 0) + 1,
    used_at = case
      when coalesce(ic.use_mode, 'single') = 'single' then now()
      else ic.used_at
    end,
    used_by = case
      when coalesce(ic.use_mode, 'single') = 'single' then new.id
      else ic.used_by
    end,
    is_active = case
      when coalesce(ic.use_mode, 'single') = 'single' then false
      when ic.max_uses is not null
           and coalesce(ic.used_count, 0) + 1 >= ic.max_uses then false
      else true
    end
  where ic.code_hash = v_hash
    and ic.purpose = 'signup'
    and ic.is_active = true
    and (ic.expires_at is null or ic.expires_at > now())
    and (
      (
        coalesce(ic.use_mode, 'single') = 'single'
        and ic.used_at is null
      )
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
    raise exception '邀请码无效、已使用、已达使用上限或已过期';
  end if;

  insert into public.user_access(
    user_id,
    access_type,
    valid_from,
    valid_until,
    updated_at
  )
  values (
    new.id,
    'permanent',
    now(),
    null,
    now()
  )
  on conflict (user_id) do update
  set
    access_type = 'permanent',
    valid_from = excluded.valid_from,
    valid_until = null,
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
    'permanent',
    null,
    null,
    null
  )
  on conflict (invite_id, user_id) do nothing;

  insert into public.artist_profiles(
    artist_user_id,
    public_name
  )
  values (
    new.id,
    '莓桃美工'
  )
  on conflict (artist_user_id) do nothing;

  insert into public.artist_customer_access_codes(artist_user_id)
  values (new.id)
  on conflict (artist_user_id) do nothing;

  return new;
end;
$$;

drop trigger if exists trg_handle_new_user_access on auth.users;

create trigger trg_handle_new_user_access
after insert on auth.users
for each row
execute function public.handle_new_user_access();

-- 4) Old clients must not be able to redeem renewal codes anymore.
do $$
begin
  if to_regprocedure('public.redeem_renewal_code(text)') is not null then
    revoke execute on function public.redeem_renewal_code(text) from authenticated;
  end if;
end
$$;

commit;

select
  count(*) filter (where r.role = 'artist') as artist_accounts,
  count(*) filter (
    where r.role = 'artist'
      and ua.access_type = 'permanent'
      and ua.valid_until is null
  ) as permanent_artist_accounts
from public.user_roles r
left join public.user_access ua on ua.user_id = r.user_id;
