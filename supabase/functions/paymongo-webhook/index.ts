// Receives PayMongo webhook events. This is the only thing in the system that
// may declare an order paid.
//
// The endpoint is public, so the signature check is the authentication. It runs
// against the raw request bytes before anything is parsed, because parsing and
// re-serialising JSON reorders keys and normalises whitespace, which breaks the
// hash on legitimate deliveries.
//
// PayMongo retries a failed delivery up to 12 times and disables the endpoint
// entirely after 3 events exhaust their retries. So: 2xx for anything we have
// handled or have decided to ignore, non-2xx only when a retry could genuinely
// help.

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.105.0';

const WEBHOOK_SECRET = Deno.env.get('PAYMONGO_WEBHOOK_SECRET');
const SUPABASE_URL = Deno.env.get('SUPABASE_URL');
const SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');

// Rejects a captured request replayed later. PayMongo's own retries arrive well
// inside this, and duplicates are caught by the payment_events primary key
// regardless.
const MAX_SIGNATURE_AGE_SECONDS = 300;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return Array.from(new Uint8Array(signature))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * PayMongo documents the header name, the algorithm (HMAC-SHA256 over the raw
 * body) and the requirement to compare in constant time, but does not publish
 * the layout of the header value itself. Two forms are handled:
 *
 *   1. Structured, as widely reported:  t=<unix>,te=<test sig>,li=<live sig>
 *      with the hash taken over "<t>.<raw body>".
 *   2. A bare hex digest of the raw body.
 *
 * The observed header is logged on every delivery so the real shape can be
 * confirmed against a test-mode event, after which the unused branch here
 * should be deleted rather than left as a permanent guess.
 */
async function verifySignature(
  header: string,
  rawBody: string,
  secret: string,
): Promise<{ ok: boolean; reason?: string }> {
  const parts = header.split(',').map((part) => part.trim());
  const fields = new Map<string, string>();
  for (const part of parts) {
    const index = part.indexOf('=');
    if (index > 0) fields.set(part.slice(0, index), part.slice(index + 1));
  }

  const timestamp = fields.get('t');
  if (timestamp) {
    const age = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
    if (!Number.isFinite(age) || age > MAX_SIGNATURE_AGE_SECONDS) {
      return { ok: false, reason: 'timestamp outside tolerance' };
    }

    const expected = await hmacHex(secret, `${timestamp}.${rawBody}`);
    // Whichever of the test/live signatures the account is sending, only the one
    // computed with our secret can match it.
    for (const field of ['te', 'li']) {
      const candidate = fields.get(field);
      if (candidate && timingSafeEqual(candidate, expected)) return { ok: true };
    }
    return { ok: false, reason: 'no signature field matched' };
  }

  const expected = await hmacHex(secret, rawBody);
  if (timingSafeEqual(header.trim(), expected)) return { ok: true };
  return { ok: false, reason: 'bare digest did not match' };
}

Deno.serve(async (req: Request): Promise<Response> => {
  if (req.method !== 'POST') return json({ error: 'Method not allowed.' }, 405);

  if (!WEBHOOK_SECRET || !SUPABASE_URL || !SERVICE_ROLE_KEY) {
    console.error('[paymongo-webhook] missing required environment configuration');
    // Retrying may succeed once configuration is fixed.
    return json({ error: 'not configured' }, 500);
  }

  const rawBody = await req.text();
  const signature = req.headers.get('Paymongo-Signature');

  if (!signature) {
    console.warn('[paymongo-webhook] rejected delivery with no signature header');
    return json({ error: 'missing signature' }, 401);
  }

  // Temporary, until the header layout is confirmed against a real event. The
  // signature is not a secret; the signing key is, and is not logged.
  console.log('[paymongo-webhook] observed signature header:', signature);

  const verdict = await verifySignature(signature, rawBody, WEBHOOK_SECRET);
  if (!verdict.ok) {
    console.warn('[paymongo-webhook] signature rejected:', verdict.reason);
    return json({ error: 'invalid signature' }, 401);
  }

  let event: any;
  try {
    event = JSON.parse(rawBody);
  } catch {
    // Signed but unparseable. Retrying cannot fix it.
    console.error('[paymongo-webhook] signed payload was not valid JSON');
    return json({ received: true }, 200);
  }

  const eventId: string | undefined = event?.data?.id;
  const eventType: string | undefined = event?.data?.attributes?.type;
  const resource = event?.data?.attributes?.data;

  if (!eventId || !eventType) {
    console.error('[paymongo-webhook] event missing id or type');
    return json({ received: true }, 200);
  }

  const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  // The order id travels in metadata we set when the session was created, so it
  // comes from our own database rather than from anything the buyer can edit.
  const orderId: string | null = resource?.attributes?.metadata?.order_id ?? null;

  // Claim the event first. A duplicate delivery collides on the primary key here
  // and returns before touching the order at all.
  const { error: claimError } = await admin
    .from('payment_events')
    .insert({ id: eventId, order_id: orderId, type: eventType, payload: event });

  if (claimError) {
    if (claimError.code === '23505') {
      console.log('[paymongo-webhook] duplicate event ignored:', eventId);
      return json({ received: true, duplicate: true }, 200);
    }
    // Could not record the event. Let PayMongo retry rather than risk processing
    // it without an audit row.
    console.error('[paymongo-webhook] could not record event:', claimError);
    return json({ error: 'could not record event' }, 500);
  }

  if (eventType === 'checkout_session.payment.paid') {
    if (!orderId) {
      console.error('[paymongo-webhook] paid event carried no order_id:', eventId);
      return json({ received: true }, 200);
    }

    const { data: transitioned, error: paidError } = await admin.rpc('mark_order_paid', {
      p_order_id: orderId,
      p_session_id: resource?.id ?? null,
    });

    if (paidError) {
      console.error('[paymongo-webhook] mark_order_paid failed:', paidError);
      return json({ error: 'could not mark order paid' }, 500);
    }

    console.log(
      transitioned
        ? `[paymongo-webhook] order ${orderId} marked paid`
        : `[paymongo-webhook] order ${orderId} was already paid`,
    );
    return json({ received: true }, 200);
  }

  if (eventType === 'payment.failed') {
    // Left unpaid on purpose: the buyer can retry the same order until the
    // reservation expires, and the sweep returns the stock if they do not.
    console.log('[paymongo-webhook] payment failed for order:', orderId);
    return json({ received: true }, 200);
  }

  // Anything else is recorded and acknowledged. Returning non-2xx for events we
  // simply do not act on would burn retries and eventually disable the endpoint.
  console.log('[paymongo-webhook] unhandled event type acknowledged:', eventType);
  return json({ received: true }, 200);
});
