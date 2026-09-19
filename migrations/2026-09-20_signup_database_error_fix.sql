-- 莓桃工作台：修复注册时报 "Database error saving new user"
-- 作用：
-- 1) 修复 handle_new_user_access 的 pgcrypto/digest 搜索路径问题
-- 2) 顾客账号不会误走美工邀请码逻辑
-- 3) 清理旧版重复邀请码触发器（如果以前跑过 invite_setup.sql）
-- 4) 保留美工邀请码、多次使用邀请码、7 天试用逻辑
-- 运行位置：Supabase -> SQL Editor

begin;

create extension if not exists pgcrypto;

-- 旧版 invite_setup.sql 如果曾经运行过，会留下这个旧触发器。
-- 当前系统只保留 trg_handle_new_user_access，避免同一次注册被两个触发器重复处理。
drop trigger if exists trg_require_invite_on_signup on auth.users;

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
  v_new_until timestamptz;
begin
  v_role := lower(trim(coalesce(new.raw_user_meta_data ->> 'account_role', 'artist')));

  -- 顾客端注册不走美工邀请码。
  -- 顾客码绑定由 trg_attach_customer_portal_access_on_signup 单独处理。
  if v_role = 'customer' then
    insert into public.user_roles(user_id, role)
    values (new.id, 'customer')
    on conflict do nothing;

    return new;
  end if;

  -- 其他账号按美工处理。
  insert into public.user_roles(user_id, role)
  values (new.id, 'artist')
  on conflict do nothing;

  v_code := upper(trim(coalesce(new.raw_user_meta_data ->> 'invite_code', '')));

  if v_code = '' then
    raise exception '注册需要有效邀请码';
  end if;

  -- 明确使用 extensions.digest，避免 Auth trigger 中找不到 digest()。
  v_hash := encode(extensions.digest(v_code, 'sha256'), 'hex');

  update public.invite_codes ic
  set used_count = coalesce(ic.used_count, 0) + 1,
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
             and coalesce(ic.used_count,0) + 1 >= ic.max_uses then false
        else true
      end
  where ic.code_hash = v_hash
    and ic.purpose = 'signup'
    and ic.grant_type = 'days'
    and ic.duration_days = 7
    and ic.is_active = true
    and (ic.expires_at is null or ic.expires_at > now())
    and (
      (
        coalesce(ic.use_mode,'single') = 'single'
        and ic.used_at is null
      )
      or
      (
        ic.use_mode = 'multi'
        and (ic.max_uses is null or coalesce(ic.used_count,0) < ic.max_uses)
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
  )
  on conflict (invite_id, user_id) do nothing;

  insert into public.artist_profiles(artist_user_id, public_name)
  values (new.id, '莓桃美工')
  on conflict (artist_user_id) do nothing;

  return new;
end;
$$;

drop trigger if exists trg_handle_new_user_access on auth.users;

create trigger trg_handle_new_user_access
after insert on auth.users
for each row
execute function public.handle_new_user_access();

commit;


-- =========================================================
-- 跑完上面的修复后，用下面这段检查你截图里的通用注册码
-- 只查询，不会修改数据。
-- =========================================================

select
  id,
  label,
  purpose,
  grant_type,
  duration_days,
  use_mode,
  max_uses,
  used_count,
  is_active,
  expires_at,
  used_at
from public.invite_codes
where code_hash = encode(
  extensions.digest(upper(trim('BERRY-7D-GENERAL')), 'sha256'),
  'hex'
);
