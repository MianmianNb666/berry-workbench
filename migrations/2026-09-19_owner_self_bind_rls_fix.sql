-- LEGACY SELF-BIND FIX · 已收口
-- 旧版本曾给单一 Owner UUID hash 特殊放行。
-- 当前系统不再需要 Owner-only 的 customer_artist_bindings RLS。
-- 本文件保留为兼容入口，重复执行也只会恢复统一规则。

begin;

drop policy if exists "customers_bind_artist"
on public.customer_artist_bindings;

create policy "customers_bind_artist"
on public.customer_artist_bindings
for insert
to authenticated
with check (
  auth.uid() = customer_user_id
  and exists (
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
  and public.artist_write_access_active(artist_user_id)
);

commit;
