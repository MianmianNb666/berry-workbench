-- 2026-09-20: manual admin grants can choose artist/full edition

create or replace function public.admin_grant_access_with_edition(
  p_target_user_id uuid,
  p_days integer,
  p_permanent boolean,
  p_edition text
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  v_before_edition text;
  v_requested text;
  v_result jsonb;
  v_final_edition text;
begin
  if not public.admin_owner_allowed() then
    raise exception 'not allowed';
  end if;

  v_requested := lower(trim(coalesce(p_edition,'')));
  if v_requested not in ('artist','full') then
    raise exception '版本只能是 artist 或 full';
  end if;

  select edition
    into v_before_edition
  from public.user_access
  where user_id = p_target_user_id;

  -- Reuse the existing, tested manual-grant logic.
  v_result := public.admin_grant_access(
    p_target_user_id,
    p_days,
    coalesce(p_permanent,false)
  );

  -- 美工版手动加时不会把已经是一体版的账号降级。
  v_final_edition :=
    case
      when v_requested = 'full' then 'full'
      when v_requested = 'artist' and v_before_edition = 'full' then 'full'
      else 'artist'
    end;

  update public.user_access
  set edition = v_final_edition,
      updated_at = now()
  where user_id = p_target_user_id;

  return coalesce(v_result,'{}'::jsonb)
    || jsonb_build_object(
      'requested_edition', v_requested,
      'edition', v_final_edition
    );
end;
$$;

revoke all on function public.admin_grant_access_with_edition(uuid,integer,boolean,text) from public, anon;
grant execute on function public.admin_grant_access_with_edition(uuid,integer,boolean,text) to authenticated;

select
  'admin_grant_access_with_edition' as check_name,
  case
    when to_regprocedure('public.admin_grant_access_with_edition(uuid,integer,boolean,text)') is not null
    then 'OK'
    else 'MISSING'
  end as result;
