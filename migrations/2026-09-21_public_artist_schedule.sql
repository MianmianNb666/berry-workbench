-- 2026-09-21: fixed public artist schedule link
-- One permanent token per artist. Toggle controls whether the link is active.
-- The public RPC returns only safe schedule fields.

alter table public.artist_profiles
  add column if not exists public_schedule_enabled boolean not null default false,
  add column if not exists public_schedule_token text,
  add column if not exists public_schedule_updated_at timestamptz not null default now();

update public.artist_profiles
set public_schedule_token = replace(gen_random_uuid()::text,'-','')
where public_schedule_token is null
   or trim(public_schedule_token) = '';

alter table public.artist_profiles
  alter column public_schedule_token set not null;

create unique index if not exists artist_profiles_public_schedule_token_uidx
  on public.artist_profiles(public_schedule_token);

-- New artist profiles automatically get one fixed token.
alter table public.artist_profiles
  alter column public_schedule_token
  set default replace(gen_random_uuid()::text,'-','');

-- Keep the "last updated" time tied to actual order-list changes.
create or replace function public.touch_public_schedule_updated_at()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if tg_op = 'INSERT'
     or (old.data->'orders') is distinct from (new.data->'orders') then
    update public.artist_profiles
    set public_schedule_updated_at = now()
    where artist_user_id = new.user_id;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_touch_public_schedule_updated_at on public.workspaces;
create trigger trg_touch_public_schedule_updated_at
after insert or update of data on public.workspaces
for each row
execute function public.touch_public_schedule_updated_at();

create or replace function public.get_public_artist_schedule(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_profile public.artist_profiles%rowtype;
  v_workspace public.workspaces%rowtype;
  v_orders jsonb := '[]'::jsonb;
  v_name text;
  v_theme jsonb := '{}'::jsonb;
begin
  select *
    into v_profile
  from public.artist_profiles
  where public_schedule_token = trim(coalesce(p_token,''))
  limit 1;

  if not found then
    return jsonb_build_object('found', false, 'enabled', false);
  end if;

  select *
    into v_workspace
  from public.workspaces
  where user_id = v_profile.artist_user_id
  limit 1;

  v_name := coalesce(
    nullif(trim(v_workspace.data->>'title'),''),
    nullif(trim(v_profile.public_name),''),
    nullif(trim(v_workspace.data->>'displayName'),''),
    '莓桃美工'
  );
  v_theme := coalesce(v_workspace.data->'theme','{}'::jsonb);

  if v_profile.public_schedule_enabled then
    select coalesce(
      jsonb_agg(
        jsonb_build_object(
          'position', q.ord,
          'name',
            case
              when coalesce(v_profile.privacy_mode,'private') = 'private' then '******'
              else coalesce(nullif(q.item->>'name',''),'未命名需求')
            end,
          'customer_nickname',
            coalesce(
              nullif(q.item->>'client',''),
              (
                select nullif(ac.display_name,'')
                from public.artist_customers ac
                where ac.artist_user_id = v_profile.artist_user_id
                  and ac.id::text = nullif(q.item->>'artistCustomerId','')
                limit 1
              ),
              ''
            ),
          'status', coalesce(nullif(q.item->>'status',''),'待处理'),
          'category', coalesce(q.item->>'cat',''),
          'start_date', coalesce(q.item->>'start',''),
          'due_date', coalesce(q.item->>'due',''),
          'due_time', coalesce(q.item->>'dueTime',''),
          'progress',
            case
              when (q.item->>'progress') ~ '^[0-9]+([.][0-9]+)?$'
                then least(100,greatest(0,(q.item->>'progress')::numeric))
              else 0
            end
        )
        order by q.ord
      ),
      '[]'::jsonb
    )
    into v_orders
    from jsonb_array_elements(coalesce(v_workspace.data->'orders','[]'::jsonb))
      with ordinality as q(item,ord)
    where coalesce(q.item->>'status','') <> '已完成';
  end if;

  return jsonb_build_object(
    'found', true,
    'enabled', v_profile.public_schedule_enabled,
    'artist_name', v_name,
    'privacy_mode', coalesce(v_profile.privacy_mode,'private'),
    'updated_at', v_profile.public_schedule_updated_at,
    'appearance', jsonb_build_object(
      'title', v_name,
      'avatar',
        case
          when coalesce(v_workspace.data->>'avatar','') like 'data:image/%'
            then v_workspace.data->>'avatar'
          else ''
        end,
      'app_icon',
        case
          when coalesce(v_workspace.data->>'appIcon','') like 'data:image/%'
            then v_workspace.data->>'appIcon'
          else ''
        end,
      'theme', jsonb_build_object(
        'accent', coalesce(v_theme->>'accent',''),
        'bg', coalesce(v_theme->>'bg',''),
        'panel', coalesce(v_theme->>'panel',''),
        'text', coalesce(v_theme->>'text','')
      )
    ),
    'orders', v_orders
  );
end;
$$;

revoke all on function public.get_public_artist_schedule(text) from public;
grant execute on function public.get_public_artist_schedule(text) to anon, authenticated;

select
  'public_artist_schedule' as check_name,
  case
    when to_regprocedure('public.get_public_artist_schedule(text)') is not null
     and exists (
       select 1
       from information_schema.columns
       where table_schema='public'
         and table_name='artist_profiles'
         and column_name='public_schedule_token'
     )
    then 'OK'
    else 'MISSING'
  end as result;
