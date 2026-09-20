-- 2026-09-20: artist-managed gift content visible to linked customer

alter table public.artist_customers
  add column if not exists gift_content text not null default '';

comment on column public.artist_customers.gift_content is
  'Artist-managed gift/benefit text shown read-only to the linked customer.';

-- Keep the field bounded even if a client bypasses the UI maxlength.
alter table public.artist_customers
  drop constraint if exists artist_customers_gift_content_length;

alter table public.artist_customers
  add constraint artist_customers_gift_content_length
  check (char_length(gift_content) <= 1000);

select
  'artist_customer_gift_content' as check_name,
  case
    when exists (
      select 1
      from information_schema.columns
      where table_schema='public'
        and table_name='artist_customers'
        and column_name='gift_content'
    )
    then 'OK'
    else 'MISSING'
  end as result;
