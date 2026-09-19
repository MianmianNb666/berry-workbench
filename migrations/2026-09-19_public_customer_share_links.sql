-- 莓桃工作台：正式顾客固定匿名链接 + 散客订单匿名链接
-- 运行位置：Supabase -> SQL Editor
--
-- 规则：
-- 1) 每个正式顾客只有一个长期匿名入口。
-- 2) 后续新增并关联到该顾客的订单，会自动出现在同一个链接里。
-- 3) 只有散客订单（未关联顾客档案）才使用单笔订单匿名链接。
-- 4) 匿名页只返回经过清洗的订单信息，不返回金额、余额、内部备注、联系方式或工作台原始 JSON。
-- 5) 美工到期后，已生成链接仍可查看 / 复制；只读状态不能生成新的链接。

begin;

create extension if not exists pgcrypto;


-- =========================================================
-- A. 匿名分享链接表
-- =========================================================

create table if not exists public.customer_public_share_links (
  token text primary key
    default ('SH-' || upper(encode(extensions.gen_random_bytes(18), 'hex'))),
  artist_user_id uuid not null references auth.users(id) on delete cascade,
  artist_customer_id uuid references public.artist_customers(id) on delete cascade,
  order_id text,
  created_at timestamptz not null default now(),
  expires_at timestamptz,
  revoked_at timestamptz
);

-- 精确限定：一条链接只能是“正式顾客链接”或“单笔散客订单链接”中的一种。
alter table public.customer_public_share_links
  drop constraint if exists customer_public_share_target_check;

alter table public.customer_public_share_links
  add constraint customer_public_share_target_check
  check (
    (artist_customer_id is not null)
    <>
    (nullif(trim(order_id), '') is not null)
  );

create index if not exists customer_public_share_artist_idx
  on public.customer_public_share_links(artist_user_id, created_at desc);


-- =========================================================
-- B. 收拢历史重复链接
-- =========================================================

-- 同一正式顾客只保留最新的一条有效长期链接。
with ranked as (
  select
    token,
    row_number() over (
      partition by artist_user_id, artist_customer_id
      order by created_at desc, token desc
    ) as rn
  from public.customer_public_share_links
  where artist_customer_id is not null
    and order_id is null
    and revoked_at is null
)
update public.customer_public_share_links s
set revoked_at = now()
from ranked r
where s.token = r.token
  and r.rn > 1;

-- 同一散客订单只保留最新的一条有效链接。
with ranked as (
  select
    token,
    row_number() over (
      partition by artist_user_id, order_id
      order by created_at desc, token desc
    ) as rn
  from public.customer_public_share_links
  where order_id is not null
    and artist_customer_id is null
    and revoked_at is null
)
update public.customer_public_share_links s
set revoked_at = now()
from ranked r
where s.token = r.token
  and r.rn > 1;

create unique index if not exists customer_public_share_one_per_customer
  on public.customer_public_share_links(artist_user_id, artist_customer_id)
  where artist_customer_id is not null
    and order_id is null
    and revoked_at is null;

create unique index if not exists customer_public_share_one_per_order
  on public.customer_public_share_links(artist_user_id, order_id)
  where order_id is not null
    and artist_customer_id is null
    and revoked_at is null;


-- =========================================================
-- C. RLS
-- =========================================================

alter table public.customer_public_share_links enable row level security;

revoke all on table public.customer_public_share_links from anon, authenticated;
grant select, insert, update, delete on table public.customer_public_share_links to authenticated;

drop policy if exists "artists_read_own_public_share_links"
on public.customer_public_share_links;

create policy "artists_read_own_public_share_links"
on public.customer_public_share_links
for select
to authenticated
using (auth.uid() = artist_user_id);

drop policy if exists "artists_create_own_public_share_links"
on public.customer_public_share_links;

create policy "artists_create_own_public_share_links"
on public.customer_public_share_links
for insert
to authenticated
with check (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
);

drop policy if exists "artists_update_own_public_share_links"
on public.customer_public_share_links;

create policy "artists_update_own_public_share_links"
on public.customer_public_share_links
for update
to authenticated
using (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
)
with check (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
);

drop policy if exists "artists_delete_own_public_share_links"
on public.customer_public_share_links;

create policy "artists_delete_own_public_share_links"
on public.customer_public_share_links
for delete
to authenticated
using (
  auth.uid() = artist_user_id
  and public.artist_write_access_active(auth.uid())
);


-- =========================================================
-- D. 创建 / 读取自己的分享 token
-- =========================================================

create or replace function public.create_customer_public_share(
  p_artist_customer_id uuid default null,
  p_order_id text default null
)
returns text
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_uid uuid := auth.uid();
  v_token text;
  v_orders jsonb;
  v_order jsonb;
  v_order_id text := nullif(trim(coalesce(p_order_id, '')), '');
begin
  if v_uid is null then
    raise exception '请先登录';
  end if;

  -- 必须二选一：正式顾客长期链接，或散客单笔订单链接。
  if (p_artist_customer_id is null and v_order_id is null)
     or
     (p_artist_customer_id is not null and v_order_id is not null)
  then
    raise exception '请选择顾客链接或散客订单链接中的一种';
  end if;

  -- -------------------------------------------------------
  -- 正式顾客：永远复用她自己的长期匿名链接
  -- -------------------------------------------------------
  if p_artist_customer_id is not null then
    if not exists (
      select 1
      from public.artist_customers c
      where c.id = p_artist_customer_id
        and c.artist_user_id = v_uid
    ) then
      raise exception '顾客档案不存在';
    end if;

    select s.token
      into v_token
    from public.customer_public_share_links s
    where s.artist_user_id = v_uid
      and s.artist_customer_id = p_artist_customer_id
      and s.order_id is null
      and s.revoked_at is null
      and (s.expires_at is null or s.expires_at > now())
    order by s.created_at desc
    limit 1;

    -- 到期后也允许继续复制已经存在的链接。
    if v_token is not null then
      return v_token;
    end if;

    -- 只有真的要创建新链接时，才检查美工是否仍有写权限。
    if not public.artist_write_access_active(v_uid) then
      raise exception '当前美工账号已进入只读模式';
    end if;

    loop
      v_token := 'SH-' || upper(encode(extensions.gen_random_bytes(18), 'hex'));

      begin
        insert into public.customer_public_share_links(
          token,
          artist_user_id,
          artist_customer_id,
          order_id
        )
        values (
          v_token,
          v_uid,
          p_artist_customer_id,
          null
        );

        return v_token;

      exception when unique_violation then
        select s.token
          into v_token
        from public.customer_public_share_links s
        where s.artist_user_id = v_uid
          and s.artist_customer_id = p_artist_customer_id
          and s.order_id is null
          and s.revoked_at is null
        order by s.created_at desc
        limit 1;

        if v_token is not null then
          return v_token;
        end if;
      end;
    end loop;
  end if;

  -- -------------------------------------------------------
  -- 散客订单：只允许没有关联正式顾客的订单
  -- -------------------------------------------------------

  select coalesce(w.data -> 'orders', '[]'::jsonb)
    into v_orders
  from public.workspaces w
  where w.user_id = v_uid;

  select o.item
    into v_order
  from jsonb_array_elements(coalesce(v_orders, '[]'::jsonb)) o(item)
  where o.item ->> 'id' = v_order_id
  limit 1;

  if v_order is null then
    raise exception '订单不存在';
  end if;

  if nullif(trim(coalesce(v_order ->> 'artistCustomerId', '')), '') is not null then
    raise exception '这笔订单已关联正式顾客，请使用该顾客自己的匿名链接';
  end if;

  select s.token
    into v_token
  from public.customer_public_share_links s
  where s.artist_user_id = v_uid
    and s.artist_customer_id is null
    and s.order_id = v_order_id
    and s.revoked_at is null
    and (s.expires_at is null or s.expires_at > now())
  order by s.created_at desc
  limit 1;

  -- 到期后也允许继续复制已经存在的散客订单链接。
  if v_token is not null then
    return v_token;
  end if;

  if not public.artist_write_access_active(v_uid) then
    raise exception '当前美工账号已进入只读模式';
  end if;

  loop
    v_token := 'SH-' || upper(encode(extensions.gen_random_bytes(18), 'hex'));

    begin
      insert into public.customer_public_share_links(
        token,
        artist_user_id,
        artist_customer_id,
        order_id
      )
      values (
        v_token,
        v_uid,
        null,
        v_order_id
      );

      return v_token;

    exception when unique_violation then
      select s.token
        into v_token
      from public.customer_public_share_links s
      where s.artist_user_id = v_uid
        and s.artist_customer_id is null
        and s.order_id = v_order_id
        and s.revoked_at is null
      order by s.created_at desc
      limit 1;

      if v_token is not null then
        return v_token;
      end if;
    end;
  end loop;
end;
$$;

revoke all on function public.create_customer_public_share(uuid,text) from public, anon;
grant execute on function public.create_customer_public_share(uuid,text) to authenticated;


-- =========================================================
-- E. 新建正式顾客时自动生成长期匿名入口
-- =========================================================

create or replace function public.ensure_customer_public_share_after_insert()
returns trigger
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_token text;
begin
  if exists (
    select 1
    from public.customer_public_share_links s
    where s.artist_user_id = new.artist_user_id
      and s.artist_customer_id = new.id
      and s.order_id is null
      and s.revoked_at is null
  ) then
    return new;
  end if;

  loop
    v_token := 'SH-' || upper(encode(extensions.gen_random_bytes(18), 'hex'));

    begin
      insert into public.customer_public_share_links(
        token,
        artist_user_id,
        artist_customer_id,
        order_id
      )
      values (
        v_token,
        new.artist_user_id,
        new.id,
        null
      );

      exit;

    exception when unique_violation then
      if exists (
        select 1
        from public.customer_public_share_links s
        where s.artist_user_id = new.artist_user_id
          and s.artist_customer_id = new.id
          and s.order_id is null
          and s.revoked_at is null
      ) then
        exit;
      end if;
    end;
  end loop;

  return new;
end;
$$;

drop trigger if exists trg_ensure_customer_public_share_after_insert
on public.artist_customers;

create trigger trg_ensure_customer_public_share_after_insert
after insert on public.artist_customers
for each row
execute function public.ensure_customer_public_share_after_insert();


-- 给已经存在的正式顾客补长期匿名入口。
insert into public.customer_public_share_links(
  token,
  artist_user_id,
  artist_customer_id,
  order_id
)
select
  'SH-' || upper(encode(extensions.gen_random_bytes(18), 'hex')),
  c.artist_user_id,
  c.id,
  null
from public.artist_customers c
where not exists (
  select 1
  from public.customer_public_share_links s
  where s.artist_user_id = c.artist_user_id
    and s.artist_customer_id = c.id
    and s.order_id is null
    and s.revoked_at is null
)
on conflict do nothing;


-- =========================================================
-- F. 匿名读取
-- =========================================================

create or replace function public.get_customer_public_share(
  p_token text
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_share public.customer_public_share_links%rowtype;
  v_artist_name text;
  v_customer_name text;
  v_workspace jsonb;
  v_orders jsonb := '[]'::jsonb;
  v_updated_at timestamptz;
begin
  select *
    into v_share
  from public.customer_public_share_links s
  where s.token = upper(trim(coalesce(p_token, '')))
    and s.revoked_at is null
    and (s.expires_at is null or s.expires_at > now())
  limit 1;

  if v_share.token is null then
    return jsonb_build_object(
      'success', false,
      'reason', 'NOT_FOUND'
    );
  end if;

  select coalesce(a.public_name, '莓桃美工')
    into v_artist_name
  from public.artist_profiles a
  where a.artist_user_id = v_share.artist_user_id;

  if v_share.artist_customer_id is not null then
    select c.display_name
      into v_customer_name
    from public.artist_customers c
    where c.id = v_share.artist_customer_id
      and c.artist_user_id = v_share.artist_user_id;
  end if;

  select w.data, w.updated_at
    into v_workspace, v_updated_at
  from public.workspaces w
  where w.user_id = v_share.artist_user_id;

  select coalesce(
    jsonb_agg(
      jsonb_build_object(
        'id', o.item ->> 'id',
        'name', o.item ->> 'name',
        'status', o.item ->> 'status',
        'start', o.item ->> 'start',
        'due', o.item ->> 'due',
        'dueTime', o.item ->> 'dueTime',
        'cat', o.item ->> 'cat',
        'progress', coalesce(nullif(o.item ->> 'progress', '')::numeric, 0)
      )
      order by o.ord
    ),
    '[]'::jsonb
  )
  into v_orders
  from jsonb_array_elements(
    coalesce(v_workspace -> 'orders', '[]'::jsonb)
  ) with ordinality as o(item, ord)
  where
    (
      v_share.order_id is not null
      and o.item ->> 'id' = v_share.order_id
    )
    or
    (
      v_share.order_id is null
      and v_share.artist_customer_id is not null
      and o.item ->> 'artistCustomerId' = v_share.artist_customer_id::text
    );

  -- 散客单独入口使用订单里的客户昵称。
  if coalesce(v_customer_name, '') = ''
     and v_share.order_id is not null then
    select o.item ->> 'client'
      into v_customer_name
    from jsonb_array_elements(
      coalesce(v_workspace -> 'orders', '[]'::jsonb)
    ) o(item)
    where o.item ->> 'id' = v_share.order_id
    limit 1;
  end if;

  return jsonb_build_object(
    'success', true,
    'mode', case when v_share.order_id is null then 'customer' else 'order' end,
    'artist_name', coalesce(v_artist_name, '莓桃美工'),
    'customer_name', coalesce(nullif(v_customer_name, ''), '顾客'),
    'orders', v_orders,
    'updated_at', v_updated_at
  );
end;
$$;

revoke all on function public.get_customer_public_share(text) from public;
grant execute on function public.get_customer_public_share(text) to anon, authenticated;

commit;
