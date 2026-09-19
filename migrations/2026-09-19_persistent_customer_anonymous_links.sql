-- 莓桃工作台：顾客固定匿名链接
-- 规则：
-- 1) 每个顾客档案只有一个长期匿名入口。
-- 2) 后续新增并关联到该顾客的订单，会自动出现在同一个链接里。
-- 3) 只有“散客订单”（未关联顾客档案）才单独生成订单级免登录链接。
-- 4) 已有关联顾客的订单，不再生成每单独立匿名链接。

begin;

create extension if not exists pgcrypto;

-- 先把历史上同一顾客重复生成的匿名链接收拢，只保留最新的一条。
with ranked as (
  select
    token,
    row_number() over (
      partition by artist_user_id, artist_customer_id
      order by created_at desc
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

create unique index if not exists customer_public_share_one_customer_link
on public.customer_public_share_links(artist_user_id, artist_customer_id)
where artist_customer_id is not null
  and order_id is null
  and revoked_at is null;

-- 给已有顾客档案补一个固定匿名链接。
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
begin
  if v_uid is null then
    raise exception '请先登录';
  end if;

  if not public.artist_write_access_active(v_uid) then
    raise exception '当前美工账号已进入只读模式';
  end if;

  -- 现在只允许二选一：
  -- 顾客固定链接，或散客单笔订单链接。
  if (p_artist_customer_id is null and nullif(trim(coalesce(p_order_id,'')), '') is null)
     or
     (p_artist_customer_id is not null and nullif(trim(coalesce(p_order_id,'')), '') is not null)
  then
    raise exception '请选择顾客链接或散客订单链接中的一种';
  end if;

  -- 顾客固定匿名入口：有就直接返回原来的，不再重复生成。
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
    order by s.created_at desc
    limit 1;

    if v_token is not null then
      return v_token;
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
        exit;
      exception
        when unique_violation then
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

    return v_token;
  end if;

  -- 单笔分享只允许用于“散客订单”。
  select coalesce(w.data -> 'orders', '[]'::jsonb)
    into v_orders
  from public.workspaces w
  where w.user_id = v_uid;

  select o.item
    into v_order
  from jsonb_array_elements(coalesce(v_orders, '[]'::jsonb)) o(item)
  where o.item ->> 'id' = p_order_id
  limit 1;

  if v_order is null then
    raise exception '订单不存在';
  end if;

  if nullif(trim(coalesce(v_order ->> 'artistCustomerId','')), '') is not null then
    raise exception '这笔订单已关联顾客，请使用该顾客自己的匿名链接';
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
        p_order_id
      );
      exit;
    exception when unique_violation then
      null;
    end;
  end loop;

  return v_token;
end;
$$;

revoke all on function public.create_customer_public_share(uuid,text) from public, anon;
grant execute on function public.create_customer_public_share(uuid,text) to authenticated;

commit;
