-- Cute Cartel: PayMongo hosted checkout
--
-- Orders are created unpaid by place_order, which decrements stock immediately so
-- two buyers cannot both reach PayMongo for the last unit. That reservation is
-- only honest if it expires: a buyer who closes the tab at the GCash screen must
-- not hold stock forever. Hence expires_at plus the cron sweep at the bottom.
--
-- Nothing here trusts the browser. The redirect back from PayMongo proves only
-- that a browser visited a URL; an order becomes paid solely via the signed
-- webhook, which runs with the service role and writes through mark_order_paid.

-- ============ order_items needs to know what it reserved ============
-- order_items only recorded product_name, which is a display string and not a
-- key. Expiry has to put stock back on a specific row, so carry the id.
alter table public.order_items
  add column if not exists product_id uuid references public.products(id);

-- ============ orders: payment lifecycle columns ============
alter table public.orders
  add column if not exists checkout_session_id text,
  add column if not exists checkout_url text,
  add column if not exists expires_at timestamptz,
  add column if not exists paid_at timestamptz;

-- One live session per order. Also makes the webhook's lookup by session id a
-- unique hit rather than a scan.
create unique index if not exists orders_checkout_session_id_key
  on public.orders (checkout_session_id)
  where checkout_session_id is not null;

-- The cron sweep's working set: unpaid orders with a deadline.
create index if not exists orders_unpaid_expiry_idx
  on public.orders (expires_at)
  where payment_status = 'unpaid';

-- 'expired' joins the payment vocabulary. status keeps its existing five values
-- because the customer tracking page renders that list; an expired order is
-- simply a cancelled one that was never paid.
alter table public.orders
  drop constraint if exists orders_payment_status_check;
alter table public.orders
  add constraint orders_payment_status_check
  check (payment_status in ('unpaid', 'paid', 'refunded', 'expired', 'failed'));

-- ============ payment_events ============
-- Keyed by PayMongo's own event id, which is what makes the webhook idempotent:
-- PayMongo retries up to 12 times and disables the endpoint after 3 events
-- exhaust their retries, so a duplicate delivery must be a cheap conflict and a
-- 200, never a second attempt to mark the order paid.
create table if not exists public.payment_events (
  id text primary key,
  order_id uuid references public.orders(id) on delete set null,
  type text not null,
  payload jsonb not null,
  received_at timestamptz not null default now()
);
alter table public.payment_events enable row level security;

-- No customer has any business reading raw provider payloads. The webhook writes
-- with the service role, which bypasses RLS; only the admin can read back.
create policy "admin reads payment events" on public.payment_events
  for select using (public.is_admin());

-- ============ place_order ============
-- Unchanged in contract and in its refusal to trust client prices. Two additions:
-- it stamps the reservation deadline, and it records product_id so the sweep can
-- give the stock back.
create or replace function public.place_order(items jsonb)
returns table (order_id uuid, order_no text, total_cents integer)
language plpgsql
security definer
set search_path = public
as $$
declare
  uid uuid := auth.uid();
  new_order_id uuid;
  new_order_no text;
  running_total integer := 0;
  item record;
  prod record;
begin
  if uid is null then
    raise exception 'You must be signed in to place an order.' using errcode = '42501';
  end if;

  if items is null or jsonb_typeof(items) <> 'array' or jsonb_array_length(items) = 0 then
    raise exception 'Your cart is empty.' using errcode = '22023';
  end if;

  new_order_no := 'CC-' || nextval('public.order_no_seq');

  -- 30 minutes matches the PayMongo checkout session lifetime, so stock frees up
  -- at roughly the moment the buyer's session stops being payable anyway.
  insert into public.orders (user_id, order_no, status, payment_status, total_cents, expires_at)
  values (uid, new_order_no, 'placed', 'unpaid', 0, now() + interval '30 minutes')
  returning id into new_order_id;

  for item in
    -- Collapsing duplicate ids here means a cart listing the same product twice
    -- is still checked against stock once, as a single combined quantity.
    select (e ->> 'id')::uuid as product_id, sum((e ->> 'qty')::integer) as qty
    from jsonb_array_elements(items) as e
    group by 1
  loop
    if item.qty is null or item.qty < 1 then
      raise exception 'Invalid quantity.' using errcode = '22023';
    end if;

    -- FOR UPDATE serialises concurrent checkouts competing for the last unit.
    select id, name, emoji, price_cents, stock, is_active
      into prod
      from public.products
     where id = item.product_id
     for update;

    if not found or not prod.is_active then
      raise exception 'A product in your cart is no longer available.' using errcode = '22023';
    end if;

    if prod.stock < item.qty then
      raise exception 'Only % left of %.', prod.stock, prod.name using errcode = '22023';
    end if;

    insert into public.order_items (order_id, product_id, product_name, emoji, qty, price_cents)
    values (new_order_id, prod.id, prod.name, prod.emoji, item.qty, prod.price_cents);

    update public.products set stock = stock - item.qty where id = prod.id;

    running_total := running_total + (prod.price_cents * item.qty);
  end loop;

  update public.orders set total_cents = running_total where id = new_order_id;

  insert into public.tracking_events (order_id, status, note, location)
  values (new_order_id, 'placed', 'Order placed', 'Online');

  return query select new_order_id, new_order_no, running_total;
end;
$$;

revoke execute on function public.place_order(jsonb) from public, anon;
grant execute on function public.place_order(jsonb) to authenticated;

-- ============ mark_order_paid ============
-- The webhook's only write path. Taking the order row FOR UPDATE first means two
-- concurrent deliveries of the same event serialise, and the second one sees
-- payment_status already 'paid' and does nothing. Returns whether it was the
-- call that actually transitioned the order, so the function stays safe to call
-- repeatedly.
create or replace function public.mark_order_paid(p_order_id uuid, p_session_id text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  current_status text;
begin
  select payment_status into current_status
    from public.orders
   where id = p_order_id
   for update;

  if not found then
    raise exception 'Unknown order %', p_order_id using errcode = '22023';
  end if;

  if current_status = 'paid' then
    return false;
  end if;

  -- A paid order is no longer on a reservation clock, so clear expires_at or the
  -- sweep would eventually claw back stock the buyer has already paid for.
  update public.orders
     set payment_status = 'paid',
         paid_at = now(),
         expires_at = null,
         checkout_session_id = coalesce(checkout_session_id, p_session_id)
   where id = p_order_id;

  insert into public.tracking_events (order_id, status, note, location)
  values (p_order_id, 'placed', 'Payment received', 'Online');

  return true;
end;
$$;

revoke execute on function public.mark_order_paid(uuid, text) from public, anon, authenticated;

-- ============ expire_unpaid_orders ============
-- Restores reserved stock for orders that ran out their clock. Only touches rows
-- that are still unpaid and still have a deadline, so it can run as often as you
-- like and re-running it changes nothing the second time.
create or replace function public.expire_unpaid_orders()
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  expired_count integer := 0;
  ord record;
begin
  for ord in
    select id
      from public.orders
     where payment_status = 'unpaid'
       and expires_at is not null
       and expires_at < now()
     for update skip locked
  loop
    -- skip locked above means an order mid-payment (held by mark_order_paid) is
    -- left alone rather than expired out from under a buyer who is paying.
    update public.products p
       set stock = p.stock + oi.qty
      from public.order_items oi
     where oi.order_id = ord.id
       and oi.product_id = p.id;

    update public.orders
       set status = 'cancelled',
           payment_status = 'expired',
           expires_at = null
     where id = ord.id;

    insert into public.tracking_events (order_id, status, note, location)
    values (ord.id, 'cancelled', 'Payment window expired', 'Online');

    expired_count := expired_count + 1;
  end loop;

  return expired_count;
end;
$$;

revoke execute on function public.expire_unpaid_orders() from public, anon, authenticated;

-- ============ schedule ============
-- Every 5 minutes. Stock comes back within 5 minutes of the 30 minute deadline,
-- which is well inside the tolerance for a small-batch store.
create extension if not exists pg_cron;

select cron.unschedule('expire-unpaid-orders')
 where exists (select 1 from cron.job where jobname = 'expire-unpaid-orders');

select cron.schedule(
  'expire-unpaid-orders',
  '*/5 * * * *',
  $cron$ select public.expire_unpaid_orders(); $cron$
);
