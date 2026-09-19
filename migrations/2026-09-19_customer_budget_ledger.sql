-- 莓桃工作台：美工 / 顾客预算联动账本
-- 运行位置：Supabase -> SQL Editor
-- 运行一次即可。
--
-- 规则：
-- 1) 美工可以给已绑定顾客增加 / 减少预算。
-- 2) 顾客只能查看自己的预算余额和明细，不能修改。
-- 3) 每次调整都保留成一条明细，不直接覆盖历史金额。
-- 4) 即使后续自动解绑，既有预算明细仍然保留。

begin;

create extension if not exists pgcrypto;

create table if not exists public.customer_budget_entries (
  id uuid primary key default gen_random_uuid(),
  artist_user_id uuid not null references auth.users(id) on delete cascade,
  customer_user_id uuid not null references auth.users(id) on delete cascade,
  amount numeric(12,2) not null check (amount <> 0),
  note text not null default '',
  created_by uuid not null default auth.uid(),
  created_at timestamptz not null default now()
);

create index if not exists customer_budget_entries_artist_customer_idx
  on public.customer_budget_entries(artist_user_id, customer_user_id, created_at desc);

create index if not exists customer_budget_entries_customer_idx
  on public.customer_budget_entries(customer_user_id, created_at desc);

alter table public.customer_budget_entries enable row level security;

revoke all on table public.customer_budget_entries from anon, authenticated;
grant select, insert on table public.customer_budget_entries to authenticated;

drop policy if exists "budget_participants_read"
on public.customer_budget_entries;

create policy "budget_participants_read"
on public.customer_budget_entries
for select
to authenticated
using (
  auth.uid() = artist_user_id
  or auth.uid() = customer_user_id
);

drop policy if exists "artists_add_budget_entries"
on public.customer_budget_entries;

create policy "artists_add_budget_entries"
on public.customer_budget_entries
for insert
to authenticated
with check (
  auth.uid() = artist_user_id
  and created_by = auth.uid()
  and exists (
    select 1
    from public.customer_artist_bindings b
    where b.artist_user_id = auth.uid()
      and b.customer_user_id = customer_budget_entries.customer_user_id
  )
);

-- 美工端预算管理需要看到“已经绑定的顾客”。
-- 只返回脱敏后的邮箱标签，不把完整邮箱暴露到前端。
create or replace function public.get_artist_bound_customers()
returns table (
  customer_user_id uuid,
  customer_label text,
  budget_balance numeric
)
language sql
security definer
set search_path = public, auth
as $$
  select
    b.customer_user_id,
    case
      when u.email is null or position('@' in u.email) = 0
        then '顾客 · ' || right(b.customer_user_id::text, 4)
      else
        case
          when length(split_part(u.email, '@', 1)) <= 2
            then left(split_part(u.email, '@', 1), 1) || '***@' || split_part(u.email, '@', 2)
          else
            left(split_part(u.email, '@', 1), 2) || '***@' || split_part(u.email, '@', 2)
        end
    end as customer_label,
    coalesce(sum(e.amount), 0)::numeric as budget_balance
  from public.customer_artist_bindings b
  left join auth.users u
    on u.id = b.customer_user_id
  left join public.customer_budget_entries e
    on e.artist_user_id = b.artist_user_id
   and e.customer_user_id = b.customer_user_id
  where b.artist_user_id = auth.uid()
  group by b.customer_user_id, u.email
  order by min(b.created_at);
$$;

revoke all on function public.get_artist_bound_customers() from public, anon;
grant execute on function public.get_artist_bound_customers() to authenticated;

commit;
