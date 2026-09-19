-- 莓桃工作台：顾客免登录分享入口
-- 功能：
-- 1) 美工可针对“某个顾客的全部关联订单”生成免登录链接。
-- 2) 美工也可针对“某一笔订单”单独生成免登录链接。
-- 3) 链接使用随机 token，不暴露用户 UUID。
-- 4) 匿名访问只返回经过清洗的排单 / 订单信息，不返回金额、内部备注、联系方式或工作台原始 JSON。
-- 5) 美工到期后，已生成链接仍可查看；到期美工不能再生成新链接。

begin;

create extension if not exists pgcrypto;

create table if not exists public.customer_public_share_links (
  token text primary key
    default ('SH-' || upper(encode(extensions.gen_random_bytes(18), 'hex'))),
  artist_user_id uuid not null references auth.users(id) on delete cascade,
  artist_customer_id uuid references public.artist_customers(id) on delete cascade,
  order_id text,
  created_at timestamptz not null default now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  constraint customer_public_share_target_check
    check (artist_customer_id is not null or nullif(trim(order_id), '') is not null)
);

create index if not exists customer_public_share_artist_idx
  on public.customer_public_share_links(artist_user_id, created_at desc);


-- 每个“正式顾客”只保留一个长期匿名入口；
-- 每个散客订单也只保留一个订单入口。
delete from public.customer_public_share_links a
using public.customer_public_share_links b
where a.artist_user_id = b.artist_user_id
  and a.artist_customer_id = b.artist_customer_id
  and a.order_id is null
  and b.order_id is null
  and a.revoked_at is null
  and b.revoked_at is null
  and (
    a.created_at > b.created_at
    or (a.created_at = b.created_at and a.token > b.token)
  );

delete from public.customer_public_share_links a
using public.customer_public_share_links b
where a.artist_user_id = b.artist_user_id
  and a.order_id = b.order_id
  and a.order_id is not null
  and a.revoked_at is null
  and b.revoked_at is null
  and (
    a.created_at > b.created_at
    or (a.created_at = b.created_at and a.token > b.token)
  );

create unique index if not exists customer_public_share_one_per_customer
  on public.customer_public_share_links(artist_user_id, artist_customer_id)
  where artist_customer_id is not null
    and order_id is null
    and revoked_at is null;

create unique index if not exists customer_public_share_one_per_order
  on public.customer_public_share_links(artist_user_id, order_id)
  where order_id is not null
    and revoked_at is null;

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
  v_order_customer_id text;
  v_order_id text := nullif(trim(coalesce(p_order_id,'')), '');
begin
  if v_uid is null then
    raise exception '请先登录';
  end if;

  if p_artist_customer_id is null and v_order_id is null then
    raise exception '请选择顾客或订单';
  end if;

  if p_artist_customer_id is not null
     and not exists (
       select 1
       from public.artist_customers c
       where c.id = p_artist_customer_id
         and c.artist_user_id = v_uid
     ) then
    raise exception '顾客档案不存在';
  end if;

  if v_order_id is not null then
    select coalesce(w.data -> 'orders', '[]'::jsonb)
      into v_orders
    from public.workspaces w
    where w.user_id = v_uid;

    select o ->> 'artistCustomerId'
      into v_order_customer_id
    from jsonb_array_elements(coalesce(v_orders, '[]'::jsonb)) o
    where o ->> 'id' = v_order_id
    limit 1;

    if not found then
      raise exception '订单不存在';
    end if;
  end if;

  -- 正式顾客：永远复用她自己的长期匿名链接。
  if p_artist_customer_id is not null and v_order_id is null then
    select s.token
      into v_token
    from public.customer_public_share_links s
    where s.artist_user_id = v_uid
      and s.artist_customer_id = p_artist_customer_id
      and s.order_id is null
      and s.revoked_at is null
      and (s.expires_at is null or s.expires_at > now())
    order by s.created_at
    limit 1;

    if v_token is not null then
      return v_token;
    end if;
  end if;

  -- 散客订单：同一订单也复用自己的订单链接。
  if p_artist_customer_id is null and v_order_id is not null then
    select s.token
      into v_token
    from public.customer_public_share_links s
    where s.artist_user_id = v_uid
      and s.order_id = v_order_id
      and s.revoked_at is null
      and (s.expires_at is null or s.expires_at > now())
    order by s.created_at
    limit 1;

    if v_token is not null then
      return v_token;
    end if;
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
        p_artist_customer_id,
        v_order_id
      );
      exit;
    exception when unique_violation then
      -- 若是“同一顾客 / 同一订单”的唯一索引冲突，直接取已经存在的链接。
      if p_artist_customer_id is not null and v_order_id is null then
        select s.token into v_token
        from public.customer_public_share_links s
        where s.artist_user_id = v_uid
          and s.artist_customer_id = p_artist_customer_id
          and s.order_id is null
          and s.revoked_at is null
        order by s.created_at
        limit 1;
        if v_token is not null then return v_token; end if;
      elsif p_artist_customer_id is null and v_order_id is not null then
        select s.token into v_token
        from public.customer_public_share_links s
        where s.artist_user_id = v_uid
          and s.order_id = v_order_id
          and s.revoked_at is null
        order by s.created_at
        limit 1;
        if v_token is not null then return v_token; end if;
      end if;
    end;
  end loop;

  return v_token;
end;
$$;

revoke all on function public.create_customer_public_share(uuid,text) from public, anon;
grant execute on function public.create_customer_public_share(uuid,text) to authenticated;


-- 新建正式顾客时，自动准备她自己的长期匿名入口。
create or replace function public.ensure_customer_public_share_after_insert()
returns trigger
language plpgsql
security definer
set search_path = public, auth, extensions
as $
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
        token, artist_user_id, artist_customer_id, order_id
      )
      values (
        v_token, new.artist_user_id, new.id, null
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
$;

drop trigger if exists trg_ensure_customer_public_share_after_insert
on public.artist_customers;

create trigger trg_ensure_customer_public_share_after_insert
after insert on public.artist_customers
for each row
execute function public.ensure_customer_public_share_after_insert();

-- 给已经存在的正式顾客补上长期匿名入口。
insert into public.customer_public_share_links(
  token, artist_user_id, artist_customer_id, order_id
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
  where s.token = upper(trim(coalesce(p_token,'')))
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
        'progress', coalesce(nullif(o.item ->> 'progress','')::numeric, 0)
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

  -- 单订单链接如果没有绑定顾客档案，用订单里的客户昵称作为展示名。
  if coalesce(v_customer_name,'') = ''
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
    'customer_name', coalesce(nullif(v_customer_name,''), '顾客'),
    'orders', v_orders,
    'updated_at', v_updated_at
  );
end;
$$;

revoke all on function public.get_customer_public_share(text) from public;
grant execute on function public.get_customer_public_share(text) to anon, authenticated;

commit;
