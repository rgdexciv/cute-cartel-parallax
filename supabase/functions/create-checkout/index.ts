// Creates a PayMongo hosted checkout session for an order that place_order has
// already written.
//
// The browser sends one thing: an order id. Everything PayMongo is asked to
// charge for is read back out of the database here, because any amount the
// client could send is an amount the client could forge. This mirrors the rule
// place_order already follows.

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.105.0';

const PAYMONGO_SECRET_KEY = Deno.env.get('PAYMONGO_SECRET_KEY');
const SUPABASE_URL = Deno.env.get('SUPABASE_URL');
const SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
const SITE_URL = Deno.env.get('SITE_URL') ?? 'https://cute-cartel.vercel.app';

const PAYMONGO_API = 'https://api.paymongo.com/v1/checkout_sessions';
const PAYMENT_METHODS = ['card', 'gcash', 'paymaya', 'grab_pay'];

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': SITE_URL,
  'Access-Control-Allow-Headers': 'authorization, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

// PayMongo's error envelope is an array of detail objects. Surfacing their raw
// text to the buyer would leak provider internals, so it is logged and the
// caller gets something they can act on.
function logProviderError(stage: string, detail: unknown): void {
  console.error(`[create-checkout] ${stage}:`, JSON.stringify(detail));
}

Deno.serve(async (req: Request): Promise<Response> => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS_HEADERS });
  if (req.method !== 'POST') return json({ error: 'Method not allowed.' }, 405);

  if (!PAYMONGO_SECRET_KEY || !SUPABASE_URL || !SERVICE_ROLE_KEY) {
    console.error('[create-checkout] missing required environment configuration');
    return json({ error: 'Checkout is not configured. Please contact support.' }, 500);
  }

  // ---- who is asking ----
  const authHeader = req.headers.get('Authorization') ?? '';
  if (!authHeader.startsWith('Bearer ')) {
    return json({ error: 'You must be signed in to pay.' }, 401);
  }

  const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const { data: userData, error: userError } = await admin.auth.getUser(
    authHeader.replace('Bearer ', ''),
  );
  if (userError || !userData?.user) {
    return json({ error: 'Your session has expired. Please sign in again.' }, 401);
  }
  const userId = userData.user.id;

  // ---- what are they paying for ----
  let orderId: string;
  try {
    const body = await req.json();
    orderId = String(body?.order_id ?? '');
  } catch {
    return json({ error: 'Malformed request.' }, 400);
  }
  if (!/^[0-9a-f-]{36}$/i.test(orderId)) {
    return json({ error: 'Malformed request.' }, 400);
  }

  const { data: order, error: orderError } = await admin
    .from('orders')
    .select('id, order_no, user_id, payment_status, total_cents, expires_at, checkout_url, checkout_session_id')
    .eq('id', orderId)
    .maybeSingle();

  if (orderError) {
    logProviderError('order lookup failed', orderError);
    return json({ error: 'Could not start checkout. Please try again.' }, 500);
  }
  // Same response for "no such order" and "not yours" so this cannot be used to
  // probe which order ids exist.
  if (!order || order.user_id !== userId) {
    return json({ error: 'Order not found.' }, 404);
  }
  if (order.payment_status === 'paid') {
    return json({ error: 'This order is already paid.' }, 409);
  }
  if (order.payment_status !== 'unpaid') {
    return json({ error: 'This order can no longer be paid.' }, 409);
  }
  if (order.expires_at && new Date(order.expires_at) <= new Date()) {
    return json({ error: 'This order expired. Please add the items again.' }, 409);
  }

  // A buyer who reloads the page mid-checkout gets the session they already have
  // rather than a second one charging for the same stock.
  if (order.checkout_url && order.checkout_session_id) {
    return json({ checkout_url: order.checkout_url });
  }

  const { data: items, error: itemsError } = await admin
    .from('order_items')
    .select('product_name, emoji, qty, price_cents')
    .eq('order_id', orderId);

  if (itemsError || !items?.length) {
    logProviderError('order items lookup failed', itemsError);
    return json({ error: 'Could not start checkout. Please try again.' }, 500);
  }

  // ---- ask PayMongo for a session ----
  const payload = {
    data: {
      attributes: {
        line_items: items.map((item) => ({
          name: `${item.emoji ?? ''} ${item.product_name}`.trim(),
          amount: item.price_cents,
          currency: 'PHP',
          quantity: item.qty,
        })),
        payment_method_types: PAYMENT_METHODS,
        success_url: `${SITE_URL}/?order=${encodeURIComponent(order.order_no)}`,
        cancel_url: `${SITE_URL}/?cancelled=${encodeURIComponent(order.order_no)}`,
        description: `Cute Cartel ${order.order_no}`,
        reference_number: order.order_no,
        send_email_receipt: true,
        // The webhook resolves the order from here. It never parses the URLs,
        // which a buyer can edit, and never trusts reference_number alone.
        metadata: { order_id: order.id, order_no: order.order_no },
      },
    },
  };

  let session: { id?: string; attributes?: { checkout_url?: string } } | undefined;
  try {
    const response = await fetch(PAYMONGO_API, {
      method: 'POST',
      headers: {
        // Basic auth, secret key as username, empty password.
        Authorization: `Basic ${btoa(`${PAYMONGO_SECRET_KEY}:`)}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    const result = await response.json();
    if (!response.ok) {
      logProviderError(`paymongo returned ${response.status}`, result?.errors ?? result);
      return json({ error: 'Payment provider rejected the order. Please try again.' }, 502);
    }
    session = result?.data;
  } catch (err) {
    logProviderError('paymongo request threw', String(err));
    return json({ error: 'Could not reach the payment provider. Please try again.' }, 502);
  }

  const checkoutUrl = session?.attributes?.checkout_url;
  if (!session?.id || !checkoutUrl) {
    logProviderError('paymongo response missing checkout_url', session);
    return json({ error: 'Payment provider returned an unusable session.' }, 502);
  }

  // Stored before the redirect so the webhook can still find this order by
  // session id even if the buyer never comes back to the site.
  const { error: saveError } = await admin
    .from('orders')
    .update({ checkout_session_id: session.id, checkout_url: checkoutUrl })
    .eq('id', orderId);

  if (saveError) {
    // The session exists at PayMongo but we failed to record it. Better to fail
    // the buyer now than to hand out a session we cannot reconcile later.
    logProviderError('failed to persist checkout session', saveError);
    return json({ error: 'Could not start checkout. Please try again.' }, 500);
  }

  return json({ checkout_url: checkoutUrl });
});
