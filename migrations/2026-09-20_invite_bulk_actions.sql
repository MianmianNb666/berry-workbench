-- 莓桃管理端：邀请码记录批量停用 / 删除
-- 规则：
-- 1) Owner 可以一次停用多个邀请码。
-- 2) 永久删除只允许“从未使用过”的邀请码。
-- 3) 已经有兑换记录或 used_count > 0 的邀请码不会被删除，避免破坏历史记录。
-- 运行位置：Supabase -> SQL Editor

begin;

create or replace function public.admin_bulk_invites(
  p_invite_ids uuid[],
  p_action text
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_action text := lower(trim(coalesce(p_action,'')));
  v_requested integer := 0;
  v_affected integer := 0;
  v_skipped integer := 0;
begin
  if not public.admin_owner_allowed() then
    raise exception 'not allowed';
  end if;

  if p_invite_ids is null or coalesce(array_length(p_invite_ids,1),0)=0 then
    return jsonb_build_object(
      'success', true,
      'requested', 0,
      'affected', 0,
      'skipped', 0
    );
  end if;

  if v_action not in ('disable','delete') then
    raise exception '批量操作类型无效';
  end if;

  select count(*)
    into v_requested
  from (
    select distinct unnest(p_invite_ids) as id
  ) x;

  if v_action = 'disable' then
    update public.invite_codes i
    set is_active = false
    where i.id in (
      select distinct unnest(p_invite_ids)
    )
      and i.is_active = true;

    get diagnostics v_affected = row_count;

    return jsonb_build_object(
      'success', true,
      'action', 'disable',
      'requested', v_requested,
      'affected', v_affected,
      'skipped', greatest(v_requested-v_affected,0)
    );
  end if;

  -- 删除只允许从未被使用过的邀请码。
  delete from public.invite_codes i
  where i.id in (
    select distinct unnest(p_invite_ids)
  )
    and coalesce(i.used_count,0)=0
    and not exists (
      select 1
      from public.invite_redemptions r
      where r.invite_id=i.id
    );

  get diagnostics v_affected = row_count;
  v_skipped := greatest(v_requested-v_affected,0);

  return jsonb_build_object(
    'success', true,
    'action', 'delete',
    'requested', v_requested,
    'affected', v_affected,
    'skipped', v_skipped
  );
end;
$$;

revoke all
on function public.admin_bulk_invites(uuid[],text)
from public, anon;

grant execute
on function public.admin_bulk_invites(uuid[],text)
to authenticated;

commit;
