-- 莓桃管理端：邀请码记录支持复制明文
-- 说明：
-- 1) 从这次更新之后新生成的邀请码，会额外保存一份仅 Owner 可通过管理 RPC 读取的明文。
-- 2) 之前已经生成的邀请码数据库里只有 SHA-256 hash，无法反推出原邀请码，所以旧记录不会凭空恢复。
-- 3) 前台仍然使用 hash 校验，邀请码兑换逻辑不变。
-- 运行位置：Supabase -> SQL Editor

begin;

create table if not exists public.admin_invite_plain_codes (
  invite_id uuid primary key references public.invite_codes(id) on delete cascade,
  code text not null,
  created_at timestamptz not null default now()
);

alter table public.admin_invite_plain_codes enable row level security;
revoke all on table public.admin_invite_plain_codes from public, anon, authenticated;


create or replace function public.admin_create_invite(
  p_purpose text,
  p_grant_type text,
  p_duration_days integer default null,
  p_use_mode text default 'single',
  p_max_uses integer default 1,
  p_label text default null,
  p_expires_at timestamptz default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth, extensions
as $$
declare
  v_code text;
  v_hash text;
  v_id uuid;
  v_max_uses integer;
begin
  if not public.admin_owner_allowed() then
    raise exception 'not allowed';
  end if;

  p_purpose := lower(trim(coalesce(p_purpose,'')));
  p_grant_type := lower(trim(coalesce(p_grant_type,'')));
  p_use_mode := lower(trim(coalesce(p_use_mode,'single')));

  if p_purpose not in ('signup','renewal') then
    raise exception '邀请码用途无效';
  end if;

  if p_grant_type not in ('days','permanent') then
    raise exception '授权类型无效';
  end if;

  if p_use_mode not in ('single','multi') then
    raise exception '使用模式无效';
  end if;

  if p_purpose = 'signup' then
    p_grant_type := 'days';
    p_duration_days := 7;
  elsif p_grant_type = 'days'
    and p_duration_days not in (7,30,90,365) then
    raise exception '续期天数仅支持 7 / 30 / 90 / 365 天';
  elsif p_grant_type = 'permanent' then
    p_duration_days := null;
  end if;

  if p_use_mode = 'single' then
    v_max_uses := 1;
  else
    if p_max_uses is not null and p_max_uses < 1 then
      raise exception '使用次数必须大于 0';
    end if;
    v_max_uses := p_max_uses;
  end if;

  loop
    v_code :=
      case when p_purpose = 'signup' then 'BERRY-S-' else 'BERRY-R-' end
      || upper(substr(encode(extensions.gen_random_bytes(8),'hex'),1,16));

    v_hash := encode(
      extensions.digest(v_code,'sha256'),
      'hex'
    );

    begin
      insert into public.invite_codes(
        code_hash,
        label,
        purpose,
        grant_type,
        duration_days,
        is_active,
        expires_at,
        use_mode,
        max_uses,
        used_count
      )
      values (
        v_hash,
        nullif(trim(coalesce(p_label,'')),''),
        p_purpose,
        p_grant_type,
        p_duration_days,
        true,
        p_expires_at,
        p_use_mode,
        v_max_uses,
        0
      )
      returning id into v_id;

      insert into public.admin_invite_plain_codes(invite_id, code)
      values (v_id, v_code)
      on conflict (invite_id) do update
      set code = excluded.code;

      exit;
    exception when unique_violation then
      null;
    end;
  end loop;

  return jsonb_build_object(
    'success', true,
    'id', v_id,
    'code', v_code,
    'purpose', p_purpose,
    'grant_type', p_grant_type,
    'duration_days', p_duration_days,
    'use_mode', p_use_mode,
    'max_uses', v_max_uses,
    'expires_at', p_expires_at
  );
end;
$$;

revoke all
on function public.admin_create_invite(text,text,integer,text,integer,text,timestamptz)
from public, anon;

grant execute
on function public.admin_create_invite(text,text,integer,text,integer,text,timestamptz)
to authenticated;


drop function if exists public.admin_list_invites();

create function public.admin_list_invites()
returns table (
  id uuid,
  label text,
  purpose text,
  grant_type text,
  duration_days integer,
  is_active boolean,
  expires_at timestamptz,
  use_mode text,
  max_uses integer,
  used_count integer,
  created_at timestamptz,
  invite_code text
)
language plpgsql
security definer
set search_path = public, auth
as $$
begin
  if not public.admin_owner_allowed() then
    raise exception 'not allowed';
  end if;

  return query
  select
    i.id,
    i.label,
    i.purpose,
    i.grant_type,
    i.duration_days,
    i.is_active,
    i.expires_at,
    i.use_mode,
    i.max_uses,
    i.used_count,
    i.created_at,
    p.code
  from public.invite_codes i
  left join public.admin_invite_plain_codes p
    on p.invite_id = i.id
  order by i.created_at desc
  limit 300;
end;
$$;

revoke all on function public.admin_list_invites() from public, anon;
grant execute on function public.admin_list_invites() to authenticated;

commit;
