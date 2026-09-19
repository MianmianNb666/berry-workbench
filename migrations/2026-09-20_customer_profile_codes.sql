-- 莓桃工作台：顾客专属码
-- 两种绑定方式：
-- 1) 先建顾客档案 -> 自动生成该顾客专属码，顾客用码后直接绑定到这位美工 + 这份档案。
-- 2) 顾客先来 -> 继续使用美工通用顾客码，系统先绑定美工并建立占位档案，之后美工再完善档案。

begin;

create extension if not exists pgcrypto;

create table if not exists public.artist_customer_profile_codes (
  artist_customer_id uuid primary key references public.artist_customers(id) on delete cascade,
  artist_user_id uuid not null references auth.users(id) on delete cascade,
  access_code text not null unique,
  claimed_by uuid references auth.users(id) on delete set null,
  claimed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists artist_customer_profile_codes_artist_idx
  on public.artist_customer_profile_codes(artist_user_id, created_at desc);

alter table public.artist_customer_profile_codes enable row level security;

revoke all on table public.artist_customer_profile_codes from anon, authenticated;
grant select on table public.artist_customer_profile_codes to authenticated;

drop policy if exists "artist_reads_own_customer_profile_codes"
on public.artist_customer_profile_codes;

create policy "artist_reads_own_customer_profile_codes"
on public.artist_customer_profile_codes
for select
to authenticated
using (auth.uid() = artist_user_id);


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

  select c.artist_user_id
    into v_artist
  from public.artist_customers c
  where c.id = p_artist_customer_id
    and c.artist_user_id = auth.uid();

  if v_artist is null then
    raise exception '没有权限读取这个顾客档案';
  end if;

  select pc.access_code
    into v_existing
  from public.artist_customer_profile_codes pc
  where pc.artist_customer_id = p_artist_customer_id;

  if v_existing is not null then
    return v_existing;
  end if;

  loop
    v_code := 'CC-' || upper(substr(encode(extensions.gen_random_bytes(6), 'hex'), 1, 12));
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
      -- 如果只是同一档案被并发创建，直接读取已有值。
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


-- 同一个入口同时支持：
-- GC-... 美工通用顾客码
-- CC-... 某一份顾客档案的专属码
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
begin
  if auth.uid() is null then
    return jsonb_build_object('success', false, 'reason', 'NOT_SIGNED_IN');
  end if;

  v_code := upper(trim(coalesce(p_code,'')));

  -- A. 先尝试美工通用顾客码。
  select ac.artist_user_id
    into v_artist
  from public.artist_customer_access_codes ac
  where ac.access_code = v_code
    and ac.is_active = true
  limit 1;

  -- B. 如果不是通用码，再尝试顾客专属码。
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

    -- 先把这份档案绑定到当前顾客。
    -- 这样后面插入 customer_artist_bindings 时，不会再产生重复占位档案。
    update public.artist_customers
    set linked_customer_user_id = auth.uid(),
        updated_at = now()
    where id = v_customer_record
      and artist_user_id = v_artist
      and (linked_customer_user_id is null or linked_customer_user_id = auth.uid());

    update public.artist_customer_profile_codes
    set claimed_by = auth.uid(),
        claimed_at = coalesce(claimed_at, now()),
        updated_at = now()
    where artist_customer_id = v_customer_record
      and (claimed_by is null or claimed_by = auth.uid());
  end if;

  insert into public.user_roles(user_id, role)
  values (auth.uid(), 'customer')
  on conflict do nothing;

  insert into public.customer_portal_access(customer_user_id, artist_user_id)
  values (auth.uid(), v_artist)
  on conflict (customer_user_id, artist_user_id) do nothing;

  insert into public.customer_artist_bindings(customer_user_id, artist_user_id)
  values (auth.uid(), v_artist)
  on conflict do nothing;

  return jsonb_build_object(
    'success', true,
    'artist_user_id', v_artist,
    'artist_customer_id', v_customer_record,
    'code_type', case when v_customer_record is null then 'artist' else 'customer' end
  );
end;
$$;

revoke all on function public.claim_customer_access_code(text) from public, anon;
grant execute on function public.claim_customer_access_code(text) to authenticated;


-- 注册时同样兼容两种码。
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

  v_code := upper(trim(coalesce(new.raw_user_meta_data ->> 'customer_access_code', '')));
  if v_code = '' then
    raise exception '注册顾客端需要美工提供的顾客码或顾客专属码';
  end if;

  -- A. 美工通用顾客码
  select ac.artist_user_id
    into v_artist
  from public.artist_customer_access_codes ac
  where ac.access_code = v_code
    and ac.is_active = true
  limit 1;

  -- B. 顾客专属码
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

    update public.artist_customers
    set linked_customer_user_id = new.id,
        updated_at = now()
    where id = v_customer_record
      and artist_user_id = v_artist
      and (linked_customer_user_id is null or linked_customer_user_id = new.id);

    update public.artist_customer_profile_codes
    set claimed_by = new.id,
        claimed_at = coalesce(claimed_at, now()),
        updated_at = now()
    where artist_customer_id = v_customer_record
      and (claimed_by is null or claimed_by = new.id);
  end if;

  insert into public.customer_portal_access(customer_user_id, artist_user_id)
  values (new.id, v_artist)
  on conflict (customer_user_id, artist_user_id) do nothing;

  insert into public.customer_artist_bindings(customer_user_id, artist_user_id)
  values (new.id, v_artist)
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

commit;
