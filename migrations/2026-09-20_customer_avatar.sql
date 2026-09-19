-- 莓桃工作台：顾客头像
-- 运行位置：Supabase -> SQL Editor
-- 给 artist_customers 增加一个压缩后的头像字段。

begin;

alter table public.artist_customers
  add column if not exists avatar_data text not null default '';

commit;
