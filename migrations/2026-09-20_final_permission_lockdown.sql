-- 莓桃工作台：最终权限收口
-- 目的：
-- 1) 清理注册旧 trigger / 邀请码旧唯一约束，避免再次出现 Database error saving new user
-- 2) 给所有正常美工补齐 artist 角色、公开资料、顾客码
-- 3) 普通美工与 Owner 使用同一套业务权限，不再保留 Owner-only RLS
-- 4) 美工到期后进入真正的只读模式；顾客端正常写入不受影响
-- 5) 补齐后来新增的预算、顾客专属码、顾客聊天、美工好友与好友聊天的服务端权限
-- 6) 老板管理端 admin_* 权限保持不变
--
-- 运行位置：Supabase -> SQL Editor
-- 可重复执行。
-- 建议整段一次运行。

begin;

create extension if not exists pgcrypto with schema extensions;

-- =========================================================
-- A. 注册链清理 + 通用邀请码兼容
-- =========================================================

drop trigger if exists trg_require_invite_on_signup on auth.users;
drop trigger if exists trg_create_access_on_signup on auth.users;
drop function if exists public.consume_invite_on_signup();

alter table public.invite_redemptions
  drop constraint if exists invite_redemptions_invite_id_key;

alter table public.invite_redemptions
  drop constraint if exists one_redemption_per_invite;

create unique index if not exists invite_redemptions_invite_user_unique
  on public.invite_redemptions(invite_id, user_id);

-- 统一判断美工写权限：永久，或仍在有效期内。
create or replace function public.artist_write_access_active(p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public, auth
as $$
  select exists (
    select 1
    from public.user_access ua
    where ua.user_id = p_user_id
      and (
        ua.access_type = 'permanent'
        or (ua.valid_until is not null and ua.valid_until > now())
      )
  );
$$;

revoke all on function public.artist_write_access_active(uuid) from public, anon;
grant execute on function public.artist_write_access_active(uuid) to authenticated;

-- 共享表写入时使用：
-- 纯顾客账号始终可写自己的顾客端资料；
-- 只要账号具有 artist 角色，则必须处于有效使用期。
create or replace function public.account_write_access_allowed(p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public, auth
as $$
  select
    p_user_id is not null
    and (
      not exists (
        select 1
        from public.user_roles r
        where r.user_id = p_user_id
          and r.role = 'artist'
      )
      or public.artist_write_access_active(p_user_id)
    );
$$;

revoke all on function public.account_write_access_allowed(uuid) from public, anon;
grant execute on function public.account_write_access_allowed(uuid) to authenticated;


-- =========================================================
-- B. 新美工注册：一次完成角色 / 使用期 / 资料 / 顾客码
-- =========================================================

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

  -- 顾客账号不消耗美工邀请码。
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
    and ic.grant_type = 'days'
    and ic.duration_days = 7
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
  set
    access_type = excluded.access_type,
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


-- =========================================================
-- C. 历史账号补齐，不给陌生账号凭空开通使用期
-- =========================================================

-- 有 user_access 的账号视为美工。
insert into public.user_roles(user_id, role)
select ua.user_id, 'artist'
from public.user_access ua
on conflict do nothing;

-- 顾客 metadata 补 customer 角色。
insert into public.user_roles(user_id, role)
select u.id, 'customer'
from auth.users u
where lower(coalesce(u.raw_user_meta_data ->> 'account_role', '')) = 'customer'
on conflict do nothing;

-- 所有 artist 角色补公开资料。
insert into public.artist_profiles(artist_user_id, public_name)
select
  r.user_id,
  coalesce(nullif(w.data ->> 'title', ''), '莓桃美工')
from public.user_roles r
left join public.workspaces w
  on w.user_id = r.user_id
where r.role = 'artist'
on conflict (artist_user_id) do nothing;

-- 所有美工补一个顾客通用码。
insert into public.artist_customer_access_codes(artist_user_id)
select ap.artist_user_id
from public.artist_profiles ap
join public.user_roles r
  on r.user_id = ap.artist_user_id
 and r.role = 'artist'
on conflict (artist_user_id) do nothing;


-- =========================================================
-- D. 普通美工统一权限 + 到期只读
-- =========================================================

-- 工作台：读不限制，写需要有效期。
drop policy if exists "users_insert_own_workspace" on public.workspaces;
create policy "users_insert_own_workspace"
on public.workspaces
for insert
to authenticated
with check (
  auth.uid() = user_id
  and public.artist_write_access_active(auth.uid())
);

drop policy if exists "users_update_own_workspace" on public.workspaces;
create policy "users_update_own_workspace"
on public.workspaces
for update
to authenticated
using (auth.uid() = user_id)
with check (
  auth.uid() = user_id
  and public.artist_write_access_active(auth.uid())
);

drop policy if exists "users_delete_own_workspace" on public.workspaces;
create policy "users_delete_own_workspace"
on public.workspaces
for delete
to authenticated
using (
  auth.uid() = user_id
  and public.artist_write_access_active(auth.uid())
);

-- 美工公开资料。
drop policy if exists "artists_insert_own_profile" on public.artist_profiles;
create policy "artists_insert_own_profile"
on public.artist_profiles
for insert
to authenticated
with check (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
  and exists (
    select 1
    from public.user_roles r
    where r.user_id = auth.uid()
      and r.role = 'artist'
  )
);

drop policy if exists "artists_update_own_profile" on public.artist_profiles;
create policy "artists_update_own_profile"
on public.artist_profiles
for update
to authenticated
using (auth.uid() = artist_user_id)
with check (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
);

-- 每个美工都可读取自己的顾客码。
drop policy if exists "owner_artist_reads_customer_code"
on public.artist_customer_access_codes;

drop policy if exists "artist_reads_own_customer_code"
on public.artist_customer_access_codes;

create policy "artist_reads_own_customer_code"
on public.artist_customer_access_codes
for select
to authenticated
using (auth.uid() = artist_user_id);

-- 顾客 / 美工读取自己参与的授权关系。
drop policy if exists "customer_reads_own_portal_access"
on public.customer_portal_access;

create policy "customer_reads_own_portal_access"
on public.customer_portal_access
for select
to authenticated
using (
  auth.uid() = customer_user_id
  or auth.uid() = artist_user_id
);

-- 顾客绑定：去掉 Owner-only 特例。
drop policy if exists "customers_bind_artist"
on public.customer_artist_bindings;

create policy "customers_bind_artist"
on public.customer_artist_bindings
for insert
to authenticated
with check (
  auth.uid() = customer_user_id
  and exists (
    select 1
    from public.user_roles r
    where r.user_id = auth.uid()
      and r.role = 'customer'
  )
  and exists (
    select 1
    from public.artist_profiles a
    where a.artist_user_id = artist_user_id
  )
  and public.artist_write_access_active(artist_user_id)
);

-- 顾客档案：所有美工可管理自己的档案，但到期后只能看。
drop policy if exists "artist_customer_participants_read"
on public.artist_customers;

create policy "artist_customer_participants_read"
on public.artist_customers
for select
to authenticated
using (
  auth.uid() = artist_user_id
  or (
    auth.uid() = linked_customer_user_id
    and exists (
      select 1
      from public.customer_portal_access pa
      where pa.customer_user_id = auth.uid()
        and pa.artist_user_id = artist_customers.artist_user_id
    )
  )
);

drop policy if exists "artists_insert_customers"
on public.artist_customers;

create policy "artists_insert_customers"
on public.artist_customers
for insert
to authenticated
with check (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
);

drop policy if exists "artists_update_customers"
on public.artist_customers;

create policy "artists_update_customers"
on public.artist_customers
for update
to authenticated
using (auth.uid() = artist_user_id)
with check (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
);

drop policy if exists "artists_delete_customers"
on public.artist_customers;

create policy "artists_delete_customers"
on public.artist_customers
for delete
to authenticated
using (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
);

-- 顾客余额流水。
drop policy if exists "artist_customer_ledger_participants_read"
on public.artist_customer_ledger;

create policy "artist_customer_ledger_participants_read"
on public.artist_customer_ledger
for select
to authenticated
using (
  auth.uid() = artist_user_id
  or exists (
    select 1
    from public.artist_customers c
    where c.id = artist_customer_id
      and c.linked_customer_user_id = auth.uid()
      and exists (
        select 1
        from public.customer_portal_access pa
        where pa.customer_user_id = auth.uid()
          and pa.artist_user_id = c.artist_user_id
      )
  )
);

drop policy if exists "artists_add_customer_ledger"
on public.artist_customer_ledger;

create policy "artists_add_customer_ledger"
on public.artist_customer_ledger
for insert
to authenticated
with check (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
  and exists (
    select 1
    from public.artist_customers c
    where c.id = artist_customer_id
      and c.artist_user_id = auth.uid()
  )
);

-- 顾客预算：补上到期限制。
drop policy if exists "artists_add_budget_entries"
on public.customer_budget_entries;

create policy "artists_add_budget_entries"
on public.customer_budget_entries
for insert
to authenticated
with check (
  auth.uid() = artist_user_id
  and created_by = auth.uid()
  and public.artist_write_access_active(auth.uid())
  and exists (
    select 1
    from public.customer_artist_bindings b
    where b.artist_user_id = auth.uid()
      and b.customer_user_id = customer_budget_entries.customer_user_id
  )
);

-- DDL 提醒：到期后只读。
drop policy if exists "users_insert_own_order_reminders"
on public.order_reminders;

create policy "users_insert_own_order_reminders"
on public.order_reminders
for insert
to authenticated
with check (
  auth.uid() = user_id
  and public.artist_write_access_active(auth.uid())
);

drop policy if exists "users_update_own_order_reminders"
on public.order_reminders;

create policy "users_update_own_order_reminders"
on public.order_reminders
for update
to authenticated
using (auth.uid() = user_id)
with check (
  auth.uid() = user_id
  and public.artist_write_access_active(auth.uid())
);

drop policy if exists "users_delete_own_order_reminders"
on public.order_reminders;

create policy "users_delete_own_order_reminders"
on public.order_reminders
for delete
to authenticated
using (
  auth.uid() = user_id
  and public.artist_write_access_active(auth.uid())
);


-- =========================================================
-- E. 共享资料：顾客不误伤，美工到期后不可改
-- =========================================================

drop policy if exists "chat_profiles_insert_own"
on public.chat_profiles;

create policy "chat_profiles_insert_own"
on public.chat_profiles
for insert
to authenticated
with check (
  auth.uid() = user_id
  and public.account_write_access_allowed(auth.uid())
);

drop policy if exists "chat_profiles_update_own"
on public.chat_profiles;

create policy "chat_profiles_update_own"
on public.chat_profiles
for update
to authenticated
using (auth.uid() = user_id)
with check (
  auth.uid() = user_id
  and public.account_write_access_allowed(auth.uid())
);

-- 顾客 ↔ 美工聊天：
-- 顾客始终可发；美工只有有效期内可发。
drop policy if exists "chat_participants_send"
on public.chat_messages;

create policy "chat_participants_send"
on public.chat_messages
for insert
to authenticated
with check (
  sender_user_id = auth.uid()
  and auth.uid() in (artist_user_id, customer_user_id)
  and (
    auth.uid() <> artist_user_id
    or public.artist_write_access_active(auth.uid())
  )
  and exists (
    select 1
    from public.customer_artist_bindings b
    where b.artist_user_id = chat_messages.artist_user_id
      and b.customer_user_id = chat_messages.customer_user_id
  )
);

-- 联系人备注：顾客正常可写；美工到期后只读。
drop policy if exists "contact_notes_owner_insert"
on public.contact_notes;

create policy "contact_notes_owner_insert"
on public.contact_notes
for insert
to authenticated
with check (
  auth.uid() = owner_user_id
  and public.account_write_access_allowed(auth.uid())
);

drop policy if exists "contact_notes_owner_update"
on public.contact_notes;

create policy "contact_notes_owner_update"
on public.contact_notes
for update
to authenticated
using (auth.uid() = owner_user_id)
with check (
  auth.uid() = owner_user_id
  and public.account_write_access_allowed(auth.uid())
);

drop policy if exists "contact_notes_owner_delete"
on public.contact_notes;

create policy "contact_notes_owner_delete"
on public.contact_notes
for delete
to authenticated
using (
  auth.uid() = owner_user_id
  and public.account_write_access_allowed(auth.uid())
);


-- =========================================================
-- F. 顾客码 / 顾客专属码
-- =========================================================

create or replace function public.rotate_customer_access_code()
returns text
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_code text;
begin
  if auth.uid() is null then
    raise exception '请先登录';
  end if;

  if not exists (
    select 1
    from public.user_roles r
    where r.user_id = auth.uid()
      and r.role = 'artist'
  ) then
    raise exception '当前账号不是美工账号';
  end if;

  if not public.artist_write_access_active(auth.uid()) then
    raise exception '当前美工账号已进入只读模式';
  end if;

  loop
    v_code := 'GC-' || upper(
      substr(
        encode(extensions.gen_random_bytes(6), 'hex'),
        1,
        12
      )
    );

    begin
      insert into public.artist_customer_access_codes(
        artist_user_id,
        access_code,
        is_active,
        updated_at
      )
      values (
        auth.uid(),
        v_code,
        true,
        now()
      )
      on conflict (artist_user_id) do update
      set
        access_code = excluded.access_code,
        is_active = true,
        updated_at = now();

      exit;
    exception when unique_violation then
      null;
    end;
  end loop;

  return v_code;
end;
$$;

revoke all on function public.rotate_customer_access_code() from public, anon;
grant execute on function public.rotate_customer_access_code() to authenticated;


create or replace function public.ensure_artist_customer_profile_code(
  p_artist_customer_id uuid
)
returns text
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_artist uuid;
  v_existing text;
  v_code text;
begin
  if auth.uid() is null then
    raise exception '请先登录';
  end if;

  if not exists (
    select 1
    from public.user_roles r
    where r.user_id = auth.uid()
      and r.role = 'artist'
  ) then
    raise exception '当前账号不是美工账号';
  end if;

  select c.artist_user_id
    into v_artist
  from public.artist_customers c
  where c.id = p_artist_customer_id
    and c.artist_user_id = auth.uid();

  if v_artist is null then
    raise exception '没有权限读取这个顾客档案';
  end if;

  -- 已存在的码属于历史数据，到期后仍然允许读取。
  select pc.access_code
    into v_existing
  from public.artist_customer_profile_codes pc
  where pc.artist_customer_id = p_artist_customer_id;

  if v_existing is not null then
    return v_existing;
  end if;

  -- 只有“新生成”动作需要有效期。
  if not public.artist_write_access_active(auth.uid()) then
    raise exception '当前美工账号已进入只读模式，不能生成新的顾客专属码';
  end if;

  loop
    v_code := 'CC-' || upper(
      substr(
        encode(extensions.gen_random_bytes(6), 'hex'),
        1,
        12
      )
    );

    begin
      insert into public.artist_customer_profile_codes(
        artist_customer_id,
        artist_user_id,
        access_code
      )
      values (
        p_artist_customer_id,
        v_artist,
        v_code
      );
      exit;
    exception when unique_violation then
      select pc.access_code
        into v_existing
      from public.artist_customer_profile_codes pc
      where pc.artist_customer_id = p_artist_customer_id;

      if v_existing is not null then
        return v_existing;
      end if;
    end;
  end loop;

  return v_code;
end;
$$;

revoke all on function public.ensure_artist_customer_profile_code(uuid) from public, anon;
grant execute on function public.ensure_artist_customer_profile_code(uuid) to authenticated;


-- 已绑定顾客仍可继续使用旧链接；
-- 新顾客不能再绑定一个已经到期的美工。
create or replace function public.claim_customer_access_code(p_code text)
returns jsonb
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_code text;
  v_artist uuid;
  v_customer_record uuid;
  v_linked_customer uuid;
  v_claimed_by uuid;
  v_already_bound boolean := false;
begin
  if auth.uid() is null then
    return jsonb_build_object('success', false, 'reason', 'NOT_SIGNED_IN');
  end if;

  v_code := upper(trim(coalesce(p_code, '')));

  select ac.artist_user_id
    into v_artist
  from public.artist_customer_access_codes ac
  where ac.access_code = v_code
    and ac.is_active = true
  limit 1;

  if v_artist is null then
    select
      pc.artist_user_id,
      pc.artist_customer_id,
      c.linked_customer_user_id,
      pc.claimed_by
    into
      v_artist,
      v_customer_record,
      v_linked_customer,
      v_claimed_by
    from public.artist_customer_profile_codes pc
    join public.artist_customers c
      on c.id = pc.artist_customer_id
     and c.artist_user_id = pc.artist_user_id
    where pc.access_code = v_code
    limit 1;

    if v_artist is null then
      return jsonb_build_object('success', false, 'reason', 'INVALID_CODE');
    end if;

    if (v_claimed_by is not null and v_claimed_by <> auth.uid())
       or (v_linked_customer is not null and v_linked_customer <> auth.uid()) then
      return jsonb_build_object('success', false, 'reason', 'CODE_ALREADY_CLAIMED');
    end if;

    -- 这个专属码本来就属于当前顾客时，允许继续进入，即使美工后来到期。
    if v_claimed_by = auth.uid() or v_linked_customer = auth.uid() then
      v_already_bound := true;
    end if;
  end if;

  if exists (
    select 1
    from public.customer_portal_access pa
    where pa.customer_user_id = auth.uid()
      and pa.artist_user_id = v_artist
  ) then
    v_already_bound := true;
  end if;

  if not v_already_bound
     and not public.artist_write_access_active(v_artist) then
    return jsonb_build_object(
      'success', false,
      'reason', 'ARTIST_READ_ONLY'
    );
  end if;

  if v_customer_record is not null and not v_already_bound then
    update public.artist_customers
    set
      linked_customer_user_id = auth.uid(),
      updated_at = now()
    where id = v_customer_record
      and artist_user_id = v_artist
      and (
        linked_customer_user_id is null
        or linked_customer_user_id = auth.uid()
      );

    update public.artist_customer_profile_codes
    set
      claimed_by = auth.uid(),
      claimed_at = coalesce(claimed_at, now()),
      updated_at = now()
    where artist_customer_id = v_customer_record
      and (
        claimed_by is null
        or claimed_by = auth.uid()
      );
  end if;

  insert into public.user_roles(user_id, role)
  values (auth.uid(), 'customer')
  on conflict do nothing;

  insert into public.customer_portal_access(
    customer_user_id,
    artist_user_id
  )
  values (
    auth.uid(),
    v_artist
  )
  on conflict (customer_user_id, artist_user_id) do nothing;

  insert into public.customer_artist_bindings(
    customer_user_id,
    artist_user_id
  )
  values (
    auth.uid(),
    v_artist
  )
  on conflict do nothing;

  return jsonb_build_object(
    'success', true,
    'artist_user_id', v_artist,
    'artist_customer_id', v_customer_record,
    'code_type',
      case
        when v_customer_record is null then 'artist'
        else 'customer'
      end
  );
end;
$$;

revoke all on function public.claim_customer_access_code(text) from public, anon;
grant execute on function public.claim_customer_access_code(text) to authenticated;


create or replace function public.attach_customer_portal_access_on_signup()
returns trigger
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_role text;
  v_code text;
  v_artist uuid;
  v_customer_record uuid;
  v_linked_customer uuid;
  v_claimed_by uuid;
begin
  v_role := lower(trim(coalesce(new.raw_user_meta_data ->> 'account_role', '')));

  if v_role <> 'customer' then
    return new;
  end if;

  v_code := upper(
    trim(
      coalesce(
        new.raw_user_meta_data ->> 'customer_access_code',
        ''
      )
    )
  );

  if v_code = '' then
    raise exception '注册顾客端需要美工提供的顾客码或顾客专属码';
  end if;

  select ac.artist_user_id
    into v_artist
  from public.artist_customer_access_codes ac
  where ac.access_code = v_code
    and ac.is_active = true
  limit 1;

  if v_artist is null then
    select
      pc.artist_user_id,
      pc.artist_customer_id,
      c.linked_customer_user_id,
      pc.claimed_by
    into
      v_artist,
      v_customer_record,
      v_linked_customer,
      v_claimed_by
    from public.artist_customer_profile_codes pc
    join public.artist_customers c
      on c.id = pc.artist_customer_id
     and c.artist_user_id = pc.artist_user_id
    where pc.access_code = v_code
    limit 1;

    if v_artist is null then
      raise exception '顾客码无效';
    end if;

    if (v_claimed_by is not null and v_claimed_by <> new.id)
       or (v_linked_customer is not null and v_linked_customer <> new.id) then
      raise exception '这个顾客专属码已经绑定其他账号';
    end if;
  end if;

  if not public.artist_write_access_active(v_artist) then
    raise exception '该美工账号当前为只读状态，暂不能新增顾客';
  end if;

  if v_customer_record is not null then
    update public.artist_customers
    set
      linked_customer_user_id = new.id,
      updated_at = now()
    where id = v_customer_record
      and artist_user_id = v_artist
      and (
        linked_customer_user_id is null
        or linked_customer_user_id = new.id
      );

    update public.artist_customer_profile_codes
    set
      claimed_by = new.id,
      claimed_at = coalesce(claimed_at, now()),
      updated_at = now()
    where artist_customer_id = v_customer_record
      and (
        claimed_by is null
        or claimed_by = new.id
      );
  end if;

  insert into public.customer_portal_access(
    customer_user_id,
    artist_user_id
  )
  values (
    new.id,
    v_artist
  )
  on conflict (customer_user_id, artist_user_id) do nothing;

  insert into public.customer_artist_bindings(
    customer_user_id,
    artist_user_id
  )
  values (
    new.id,
    v_artist
  )
  on conflict do nothing;

  return new;
end;
$$;

drop trigger if exists trg_attach_customer_portal_access_on_signup
on auth.users;

create trigger trg_attach_customer_portal_access_on_signup
after insert on auth.users
for each row
execute function public.attach_customer_portal_access_on_signup();


-- =========================================================
-- G. 美工好友：只能由有效美工写，过期后仍可查看
-- =========================================================

drop policy if exists "artist_friendships_read_own"
on public.artist_friendships;

create policy "artist_friendships_read_own"
on public.artist_friendships
for select
to authenticated
using (
  auth.uid() in (requester_user_id, addressee_user_id)
  and exists (
    select 1
    from public.user_roles r
    where r.user_id = auth.uid()
      and r.role = 'artist'
  )
);

create or replace function public.artist_send_friend_request(
  p_artist_code text
)
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
    return jsonb_build_object('success', false, 'reason', 'NOT_SIGNED_IN');
  end if;

  if not exists (
    select 1
    from public.user_roles r
    where r.user_id = v_me
      and r.role = 'artist'
  ) then
    return jsonb_build_object('success', false, 'reason', 'NOT_ARTIST');
  end if;

  if not public.artist_write_access_active(v_me) then
    return jsonb_build_object('success', false, 'reason', 'READ_ONLY');
  end if;

  select
    ap.artist_user_id,
    ap.artist_code,
    coalesce(
      nullif(cp.display_name, ''),
      nullif(ap.public_name, ''),
      '莓桃美工'
    )
  into
    v_target,
    v_target_code,
    v_target_name
  from public.artist_profiles ap
  left join public.chat_profiles cp
    on cp.user_id = ap.artist_user_id
  where upper(ap.artist_code) =
        upper(trim(coalesce(p_artist_code, '')))
  limit 1;

  if v_target is null then
    return jsonb_build_object('success', false, 'reason', 'NOT_FOUND');
  end if;

  if v_target = v_me then
    return jsonb_build_object('success', false, 'reason', 'SELF');
  end if;

  if not exists (
    select 1
    from public.user_roles r
    where r.user_id = v_target
      and r.role = 'artist'
  ) then
    return jsonb_build_object('success', false, 'reason', 'NOT_FOUND');
  end if;

  if not public.artist_write_access_active(v_target) then
    return jsonb_build_object('success', false, 'reason', 'TARGET_READ_ONLY');
  end if;

  select *
    into v_existing
  from public.artist_friendships f
  where
    (
      f.requester_user_id = v_me
      and f.addressee_user_id = v_target
    )
    or
    (
      f.requester_user_id = v_target
      and f.addressee_user_id = v_me
    )
  order by f.created_at desc
  limit 1;

  if v_existing.id is not null then
    if v_existing.status = 'accepted' then
      return jsonb_build_object(
        'success', false,
        'reason', 'ALREADY_FRIENDS'
      );
    end if;

    if v_existing.requester_user_id = v_target
       and v_existing.addressee_user_id = v_me
       and v_existing.status = 'pending' then
      update public.artist_friendships
      set
        status = 'accepted',
        responded_at = now(),
        updated_at = now()
      where id = v_existing.id;

      return jsonb_build_object(
        'success', true,
        'auto_accepted', true,
        'relation_id', v_existing.id,
        'artist_code', v_target_code,
        'artist_name', v_target_name
      );
    end if;

    return jsonb_build_object(
      'success', false,
      'reason', 'ALREADY_PENDING'
    );
  end if;

  insert into public.artist_friendships(
    requester_user_id,
    addressee_user_id
  )
  values (
    v_me,
    v_target
  )
  returning id
  into v_existing.id;

  return jsonb_build_object(
    'success', true,
    'auto_accepted', false,
    'relation_id', v_existing.id,
    'artist_code', v_target_code,
    'artist_name', v_target_name
  );
end;
$$;

revoke all on function public.artist_send_friend_request(text) from public, anon;
grant execute on function public.artist_send_friend_request(text) to authenticated;


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
    return jsonb_build_object('success', false, 'reason', 'NOT_SIGNED_IN');
  end if;

  if not exists (
    select 1
    from public.user_roles r
    where r.user_id = v_me
      and r.role = 'artist'
  ) then
    return jsonb_build_object('success', false, 'reason', 'NOT_ARTIST');
  end if;

  if not public.artist_write_access_active(v_me) then
    return jsonb_build_object('success', false, 'reason', 'READ_ONLY');
  end if;

  select *
    into v_row
  from public.artist_friendships
  where id = p_relation_id
    and addressee_user_id = v_me
    and status = 'pending';

  if v_row.id is null then
    return jsonb_build_object('success', false, 'reason', 'NOT_FOUND');
  end if;

  if p_accept
     and not public.artist_write_access_active(v_row.requester_user_id) then
    return jsonb_build_object(
      'success', false,
      'reason', 'REQUESTER_READ_ONLY'
    );
  end if;

  if p_accept then
    update public.artist_friendships
    set
      status = 'accepted',
      responded_at = now(),
      updated_at = now()
    where id = p_relation_id;

    return jsonb_build_object(
      'success', true,
      'accepted', true
    );
  end if;

  delete from public.artist_friendships
  where id = p_relation_id;

  return jsonb_build_object(
    'success', true,
    'accepted', false
  );
end;
$$;

revoke all on function public.artist_respond_friend_request(uuid, boolean) from public, anon;
grant execute on function public.artist_respond_friend_request(uuid, boolean) to authenticated;


create or replace function public.artist_remove_friend(
  p_relation_id uuid
)
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
    return jsonb_build_object('success', false, 'reason', 'NOT_SIGNED_IN');
  end if;

  if not exists (
    select 1
    from public.user_roles r
    where r.user_id = v_me
      and r.role = 'artist'
  ) then
    return jsonb_build_object('success', false, 'reason', 'NOT_ARTIST');
  end if;

  if not public.artist_write_access_active(v_me) then
    return jsonb_build_object('success', false, 'reason', 'READ_ONLY');
  end if;

  delete from public.artist_friendships
  where id = p_relation_id
    and v_me in (requester_user_id, addressee_user_id);

  get diagnostics v_deleted = row_count;

  return jsonb_build_object(
    'success', v_deleted > 0
  );
end;
$$;

revoke all on function public.artist_remove_friend(uuid) from public, anon;
grant execute on function public.artist_remove_friend(uuid) to authenticated;


-- 好友消息：有效美工可发送；到期后历史仍可读取 / 标记已读。
drop policy if exists "artist_friend_messages_send"
on public.artist_friend_messages;

create policy "artist_friend_messages_send"
on public.artist_friend_messages
for insert
to authenticated
with check (
  sender_user_id = auth.uid()
  and public.artist_write_access_active(auth.uid())
  and exists (
    select 1
    from public.user_roles r
    where r.user_id = auth.uid()
      and r.role = 'artist'
  )
  and exists (
    select 1
    from public.user_roles r
    where r.user_id = recipient_user_id
      and r.role = 'artist'
  )
  and exists (
    select 1
    from public.artist_friendships f
    where f.status = 'accepted'
      and (
        (
          f.requester_user_id = artist_friend_messages.sender_user_id
          and
          f.addressee_user_id = artist_friend_messages.recipient_user_id
        )
        or
        (
          f.requester_user_id = artist_friend_messages.recipient_user_id
          and
          f.addressee_user_id = artist_friend_messages.sender_user_id
        )
      )
  )
);


-- 好友读取也只对真正的 artist 角色开放；到期后仍然可以查看历史。
drop policy if exists "artist_friend_messages_read"
on public.artist_friend_messages;

create policy "artist_friend_messages_read"
on public.artist_friend_messages
for select
to authenticated
using (
  auth.uid() in (sender_user_id, recipient_user_id)
  and exists (
    select 1
    from public.user_roles me
    where me.user_id = auth.uid()
      and me.role = 'artist'
  )
  and exists (
    select 1
    from public.artist_friendships f
    where f.status = 'accepted'
      and (
        (
          f.requester_user_id = artist_friend_messages.sender_user_id
          and f.addressee_user_id = artist_friend_messages.recipient_user_id
        )
        or
        (
          f.requester_user_id = artist_friend_messages.recipient_user_id
          and f.addressee_user_id = artist_friend_messages.sender_user_id
        )
      )
  )
);

drop policy if exists "artist_friend_messages_mark_read"
on public.artist_friend_messages;

create policy "artist_friend_messages_mark_read"
on public.artist_friend_messages
for update
to authenticated
using (
  recipient_user_id = auth.uid()
  and exists (
    select 1
    from public.user_roles me
    where me.user_id = auth.uid()
      and me.role = 'artist'
  )
)
with check (
  recipient_user_id = auth.uid()
  and exists (
    select 1
    from public.user_roles me
    where me.user_id = auth.uid()
      and me.role = 'artist'
  )
);


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
as $
  select
    f.id as relation_id,
    case
      when f.requester_user_id = auth.uid()
        then f.addressee_user_id
      else f.requester_user_id
    end as other_user_id,
    ap.artist_code,
    coalesce(
      nullif(cp.display_name, ''),
      nullif(ap.public_name, ''),
      '莓桃美工'
    ) as artist_name,
    coalesce(cp.avatar_data, '') as avatar_data,
    f.status,
    case
      when f.status = 'pending'
           and f.addressee_user_id = auth.uid()
        then 'incoming'
      when f.status = 'pending'
           and f.requester_user_id = auth.uid()
        then 'outgoing'
      else 'friend'
    end as direction,
    f.created_at
  from public.artist_friendships f
  join public.artist_profiles ap
    on ap.artist_user_id =
      case
        when f.requester_user_id = auth.uid()
          then f.addressee_user_id
        else f.requester_user_id
      end
  left join public.chat_profiles cp
    on cp.user_id = ap.artist_user_id
  where auth.uid() in (
          f.requester_user_id,
          f.addressee_user_id
        )
    and exists (
      select 1
      from public.user_roles me
      where me.user_id = auth.uid()
        and me.role = 'artist'
    )
  order by
    case
      when f.status = 'pending'
           and f.addressee_user_id = auth.uid()
        then 0
      when f.status = 'pending'
        then 1
      else 2
    end,
    f.created_at desc;
$;

revoke all on function public.artist_list_friendships() from public, anon;
grant execute on function public.artist_list_friendships() to authenticated;


drop function if exists public.artist_list_friend_conversations();

create function public.artist_list_friend_conversations()
returns table (
  friend_user_id uuid,
  artist_code text,
  artist_name text,
  avatar_data text,
  last_body text,
  last_at timestamptz,
  unread_count bigint
)
language sql
stable
security definer
set search_path = public, auth
as $
  with friends as (
    select
      case
        when f.requester_user_id = auth.uid()
          then f.addressee_user_id
        else f.requester_user_id
      end as friend_user_id
    from public.artist_friendships f
    where f.status = 'accepted'
      and auth.uid() in (
        f.requester_user_id,
        f.addressee_user_id
      )
      and exists (
        select 1
        from public.user_roles me
        where me.user_id = auth.uid()
          and me.role = 'artist'
      )
  )
  select
    fr.friend_user_id,
    ap.artist_code,
    coalesce(
      nullif(cp.display_name, ''),
      nullif(ap.public_name, ''),
      '莓桃美工'
    ) as artist_name,
    coalesce(cp.avatar_data, '') as avatar_data,
    lm.body as last_body,
    lm.created_at as last_at,
    coalesce(uc.unread_count, 0)::bigint as unread_count
  from friends fr
  join public.artist_profiles ap
    on ap.artist_user_id = fr.friend_user_id
  left join public.chat_profiles cp
    on cp.user_id = fr.friend_user_id
  left join lateral (
    select
      m.body,
      m.created_at
    from public.artist_friend_messages m
    where
      (
        m.sender_user_id = auth.uid()
        and m.recipient_user_id = fr.friend_user_id
      )
      or
      (
        m.sender_user_id = fr.friend_user_id
        and m.recipient_user_id = auth.uid()
      )
    order by m.created_at desc
    limit 1
  ) lm on true
  left join lateral (
    select count(*)::bigint as unread_count
    from public.artist_friend_messages m
    where m.sender_user_id = fr.friend_user_id
      and m.recipient_user_id = auth.uid()
      and m.read_at is null
  ) uc on true
  order by lm.created_at desc nulls last, artist_name;
$;

revoke all on function public.artist_list_friend_conversations() from public, anon;
grant execute on function public.artist_list_friend_conversations() to authenticated;


create or replace function public.artist_mark_friend_messages_read(
  p_friend_user_id uuid
)
returns integer
language plpgsql
security definer
set search_path = public, auth
as $
declare
  v_count integer;
begin
  if auth.uid() is null then
    raise exception '请先登录';
  end if;

  if not exists (
    select 1
    from public.user_roles me
    where me.user_id = auth.uid()
      and me.role = 'artist'
  ) then
    raise exception '当前账号不是美工账号';
  end if;

  if not exists (
    select 1
    from public.artist_friendships f
    where f.status = 'accepted'
      and (
        (
          f.requester_user_id = auth.uid()
          and f.addressee_user_id = p_friend_user_id
        )
        or
        (
          f.requester_user_id = p_friend_user_id
          and f.addressee_user_id = auth.uid()
        )
      )
  ) then
    raise exception '不是好友，不能聊天';
  end if;

  update public.artist_friend_messages
  set read_at = now()
  where sender_user_id = p_friend_user_id
    and recipient_user_id = auth.uid()
    and read_at is null;

  get diagnostics v_count = row_count;
  return v_count;
end;
$;

revoke all on function public.artist_mark_friend_messages_read(uuid) from public, anon;
grant execute on function public.artist_mark_friend_messages_read(uuid) to authenticated;


-- =========================================================
-- H. 最终必要授权
-- =========================================================

grant select, insert, update, delete on table public.workspaces to authenticated;
grant select, insert, delete on table public.user_roles to authenticated;
grant select, insert, update on table public.artist_profiles to authenticated;
grant select on table public.artist_customer_access_codes to authenticated;
grant select on table public.customer_portal_access to authenticated;
grant select, insert, delete on table public.customer_artist_bindings to authenticated;
grant select, insert, update, delete on table public.artist_customers to authenticated;
grant select, insert on table public.artist_customer_ledger to authenticated;
grant select, insert on table public.customer_budget_entries to authenticated;
grant select, insert, update on table public.chat_profiles to authenticated;
grant select, insert on table public.chat_messages to authenticated;
grant update (read_at) on table public.chat_messages to authenticated;
grant select, insert, update, delete on table public.contact_notes to authenticated;
grant select on table public.artist_friendships to authenticated;
grant select, insert on table public.artist_friend_messages to authenticated;
grant update (read_at) on table public.artist_friend_messages to authenticated;

commit;


-- =========================================================
-- I. 收口后快速体检
-- 全部 value=0，且 AUTH_TRIGGER_COUNT=2，即为预期
-- =========================================================

select 'LEGACY_AUTH_TRIGGER_COUNT' as check_name,
       count(*)::bigint as value,
       '0'::text as expected
from pg_trigger
where tgrelid = 'auth.users'::regclass
  and not tgisinternal
  and tgname in (
    'trg_require_invite_on_signup',
    'trg_create_access_on_signup'
  )

union all

select 'AUTH_TRIGGER_COUNT',
       count(*)::bigint,
       '2'
from pg_trigger
where tgrelid = 'auth.users'::regclass
  and not tgisinternal
  and tgname in (
    'trg_handle_new_user_access',
    'trg_attach_customer_portal_access_on_signup'
  )

union all

select 'OWNER_ONLY_POLICY_COUNT',
       count(*)::bigint,
       '0'
from pg_policies
where schemaname = 'public'
  and (
    coalesce(qual, '') ||
    coalesce(with_check, '')
  ) like '%f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8%'

union all

select 'ARTIST_MISSING_ROLE',
       count(*)::bigint,
       '0'
from public.user_access ua
where not exists (
  select 1
  from public.user_roles r
  where r.user_id = ua.user_id
    and r.role = 'artist'
)

union all

select 'ARTIST_MISSING_PROFILE',
       count(*)::bigint,
       '0'
from public.user_access ua
where not exists (
  select 1
  from public.artist_profiles ap
  where ap.artist_user_id = ua.user_id
)

union all

select 'ARTIST_MISSING_CUSTOMER_CODE',
       count(*)::bigint,
       '0'
from public.user_access ua
where not exists (
  select 1
  from public.artist_customer_access_codes ac
  where ac.artist_user_id = ua.user_id
)

order by check_name;
