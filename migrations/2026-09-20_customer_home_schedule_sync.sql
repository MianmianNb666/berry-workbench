-- 莓桃工作台：顾客端首页同步“我的美工”的完整排单
-- 规则：
-- 1) 顾客自己的订单始终显示完整的安全排单字段。
-- 2) 美工为公开排单时：顾客可看到该美工全部订单的安全排单字段。
-- 3) 美工为隐私/匿名排单时：其他顾客的订单仍保留排队位置，但名称显示为“******”，不暴露顾客身份、金额、备注等信息。
-- 4) 只允许当前登录顾客读取自己已经绑定的美工。

begin;

create or replace function public.get_my_customer_schedules()
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_uid uuid := auth.uid();
  v_result jsonb;
begin
  if v_uid is null then
    raise exception '请先登录';
  end if;

  select coalesce(
    jsonb_agg(
      jsonb_build_object(
        'artist_user_id', x.artist_user_id,
        'artist_code', x.artist_code,
        'artist_name', x.artist_name,
        'privacy_mode', x.privacy_mode,
        'customer_record_id', x.customer_record_id,
        'orders', x.orders,
        'updated_at', x.updated_at
      )
      order by x.artist_name, x.artist_code
    ),
    '[]'::jsonb
  )
  into v_result
  from (
    select
      a.artist_user_id,
      a.artist_code,
      coalesce(nullif(a.public_name,''), '莓桃美工') as artist_name,
      coalesce(a.privacy_mode,'private') as privacy_mode,
      c.id as customer_record_id,
      coalesce(
        (
          select jsonb_agg(
            case
              -- 自己的订单：无论公开/隐私，都正常显示
              when c.id is not null
               and o.item ->> 'artistCustomerId' = c.id::text
              then jsonb_build_object(
                'id', o.item ->> 'id',
                'name', o.item ->> 'name',
                'status', o.item ->> 'status',
                'start', o.item ->> 'start',
                'due', o.item ->> 'due',
                'dueTime', o.item ->> 'dueTime',
                'cat', o.item ->> 'cat',
                'progress', coalesce(nullif(o.item ->> 'progress','')::numeric,0),
                'is_own', true,
                'masked', false
              )

              -- 公开排单：其他订单也显示安全排单信息
              when coalesce(a.privacy_mode,'private') = 'public'
              then jsonb_build_object(
                'id', o.item ->> 'id',
                'name', coalesce(nullif(o.item ->> 'name',''),'未命名订单'),
                'status', o.item ->> 'status',
                'start', o.item ->> 'start',
                'due', o.item ->> 'due',
                'dueTime', o.item ->> 'dueTime',
                'cat', o.item ->> 'cat',
                'progress', coalesce(nullif(o.item ->> 'progress','')::numeric,0),
                'is_own', false,
                'masked', false
              )

              -- 隐私/匿名排单：保留位置与时间，其他订单内容打星
              else jsonb_build_object(
                'id', null,
                'name', '******',
                'status', null,
                'start', o.item ->> 'start',
                'due', o.item ->> 'due',
                'dueTime', o.item ->> 'dueTime',
                'cat', null,
                'progress', null,
                'is_own', false,
                'masked', true
              )
            end
            order by
              nullif(o.item ->> 'due','') nulls last,
              nullif(o.item ->> 'dueTime','') nulls last,
              o.ord
          )
          from jsonb_array_elements(coalesce(w.data -> 'orders','[]'::jsonb))
            with ordinality as o(item,ord)
        ),
        '[]'::jsonb
      ) as orders,
      w.updated_at
    from public.customer_portal_access p
    join public.artist_profiles a
      on a.artist_user_id = p.artist_user_id
    left join public.artist_customers c
      on c.artist_user_id = p.artist_user_id
     and c.linked_customer_user_id = v_uid
    left join public.workspaces w
      on w.user_id = p.artist_user_id
    where p.customer_user_id = v_uid
  ) x;

  return v_result;
end;
$$;

revoke all on function public.get_my_customer_schedules() from public, anon;
grant execute on function public.get_my_customer_schedules() to authenticated;

commit;

select
  'get_my_customer_schedules' as check_name,
  case when to_regprocedure('public.get_my_customer_schedules()') is not null then 'OK' else 'MISSING' end as result;
