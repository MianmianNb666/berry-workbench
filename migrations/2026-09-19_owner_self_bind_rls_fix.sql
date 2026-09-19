-- 莓桃工作台：修复主用户自绑测试的 RLS
-- 运行位置：Supabase -> SQL Editor
-- 运行一次即可。

begin;

create extension if not exists pgcrypto;

-- 确保主用户同时拥有 customer 角色。
insert into public.user_roles(user_id, role)
select u.id, 'customer'
from auth.users u
where encode(digest(u.id::text, 'sha256'), 'hex') =
  'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
on conflict do nothing;

drop policy if exists "customers_bind_artist"
on public.customer_artist_bindings;

create policy "customers_bind_artist"
on public.customer_artist_bindings
for insert
to authenticated
with check (
  auth.uid() = customer_user_id
  and (
    (
      customer_user_id = artist_user_id
      and encode(
        digest(auth.uid()::text, 'sha256'),
        'hex'
      ) = 'f45d4be87faee1e0f37f0c835d250606ae7587130a96a90c245e74856f1fada8'
    )
    or
    (
      exists (
        select 1
        from public.user_roles r
        where r.user_id = auth.uid()
          and r.role = 'customer'
      )
      and exists (
        select 1
        from public.artist_profiles a
        where a.artist_user_id = artist_user_id
      )
    )
  )
);

commit;
