-- 莓桃顾客端：自定义“我的排单”图标
-- 运行位置：Supabase -> SQL Editor
-- 运行一次即可。

begin;

alter table public.customer_preferences
  add column if not exists queue_icon text not null default '🍓';

update public.customer_preferences
set queue_icon = '🍓'
where queue_icon is null
   or trim(queue_icon) = '';

commit;
