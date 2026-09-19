-- 莓桃工作台：仅允许主用户在开发期把自己的美工身份绑定到自己的顾客端
-- 其他用户仍然不能自我绑定。
-- 运行位置：Supabase -> SQL Editor
-- 运行一次即可。

begin;

create extension if not exists pgcrypto;

do $$
declare
  v_constraint_name text;
begin
  select conname
    into v_constraint_name
  from pg_constraint
  where conrelid = 'public.customer_artist_bindings'::regclass
    and contype = 'c'
    and pg_get_constraintdef(oid) ilike '%customer_user_id%'
    and pg_get_constraintdef(oid) ilike '%artist_user_id%'
  order by conname
  limit 1;

  if v_constraint_name is not null then
    execute format(
      'alter table public.customer_artist_bindings drop constraint %I',
      v_constraint_name
    );
  end if;
end
$$;

alter table public.customer_artist_bindings
  add constraint customer_artist_bindings_no_self_except_owner
  check (
    customer_user_id <> artist_user_id
    or encode(
      digest(customer_user_id::text, 'sha256'),
      'hex'
    ) = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
  );

commit;
