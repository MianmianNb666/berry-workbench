-- 莓桃工作台：顾客端首页同步已绑定美工的排单
-- 运行位置：Supabase -> SQL Editor
-- 安全规则：只返回当前登录顾客已经绑定的美工，以及订单中明确关联到该顾客档案的公开字段。

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
            jsonb_build_object(
              'id', o.item ->> 'id',
              'name', o.item ->> 'name',
              'status', o.item ->> 'status',
              'start', o.item ->> 'start',
              'due', o.item ->> 'due',
              'dueTime', o.item ->> 'dueTime',
              'cat', o.item ->> 'cat',
              'progress', coalesce(nullif(o.item ->> 'progress','')::numeric,0)
            )
            order by
              nullif(o.item ->> 'due','') nulls last,
              nullif(o.item ->> 'dueTime','') nulls last,
              o.ord
          )
          from jsonb_array_elements(coalesce(w.data -> 'orders','[]'::jsonb))
            with ordinality as o(item,ord)
          where o.item ->> 'artistCustomerId' = c.id::text
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

-- 快速检查
select
  'get_my_customer_schedules' as check_name,
  case when to_regprocedure('public.get_my_customer_schedules()') is not null then 'OK' else 'MISSING' end as result;
