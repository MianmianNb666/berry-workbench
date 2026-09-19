-- 莓桃工作台：当前账号续期记录
-- 运行位置：Supabase -> SQL Editor
-- 作用：让美工端“我的 → 使用期与续期”读取自己的续期历史。

begin;

create or replace function public.get_my_renewal_history()
returns table (
  redeemed_at timestamptz,
  grant_type text,
  duration_days integer,
  old_valid_until timestamptz,
  new_valid_until timestamptz
)
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if auth.uid() is null then
    raise exception '请先登录';
  end if;

  return query
  select
    ir.redeemed_at,
    ir.grant_type,
    ir.duration_days,
    ir.old_valid_until,
    ir.new_valid_until
  from public.invite_redemptions ir
  where ir.user_id = auth.uid()
    and ir.purpose = 'renewal'
  order by ir.redeemed_at desc
  limit 100;
end;
$$;

revoke all on function public.get_my_renewal_history() from public, anon;
grant execute on function public.get_my_renewal_history() to authenticated;

commit;
