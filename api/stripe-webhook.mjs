// Jettana — Stripe webhook -> automatic paid unlock
//
// Lives at /api/stripe-webhook on jettana.app.
// Stripe POSTs here the moment a payment succeeds; this hands the
// buyer's email to the Supabase function grant_paid_by_email().
//
// No npm packages. Node's built-in crypto verifies the signature and
// fetch talks to Supabase, so the repo needs no package.json and no
// build step.
//
// Environment variables (Vercel project settings, never in a file):
//   STRIPE_WEBHOOK_SECRET       whsec_... from the Stripe webhook endpoint
//   SUPABASE_URL                https://<project>.supabase.co
//   SUPABASE_SERVICE_ROLE_KEY   service_role key (Supabase > API settings)
//   STRIPE_LIFETIME_PLINK       plink_... of the $19 lifetime link  <-- see note
//
// STRIPE_WEBHOOK_SECRET and STRIPE_LIFETIME_PLINK each accept a
// comma-separated list, so the test-mode and live-mode values can both
// sit there at once:  whsec_testone,whsec_liveone
//
// STRIPE_LIFETIME_PLINK matters: the Tip Jar sends the SAME event type
// to this same endpoint. Without it, a generous tip would unlock
// lifetime access. If it is unset we fall back to a $19 minimum, which
// is weaker — a $19+ tip would still slip through. Set it.

import crypto from 'node:crypto';

const TOLERANCE_SECONDS = 300; // reject replays older than 5 minutes

// Both env vars accept a comma-separated list so the test-mode and
// live-mode values can live side by side permanently. No swapping
// between modes, and nothing to forget to change back.
function envList(name) {
  return (process.env[name] || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function verifyStripeSignature(rawBody, sigHeader, secret) {
  if (!sigHeader || !secret) return false;

  let timestamp = null;
  const candidates = [];
  for (const part of sigHeader.split(',')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key === 't') timestamp = val;
    else if (key === 'v1') candidates.push(val);
  }
  if (!timestamp || candidates.length === 0) return false;

  const age = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (!Number.isFinite(age) || age > TOLERANCE_SECONDS) return false;

  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${rawBody}`, 'utf8')
    .digest('hex');

  const expectedBuf = Buffer.from(expected, 'utf8');
  return candidates.some((given) => {
    const givenBuf = Buffer.from(given, 'utf8');
    if (givenBuf.length !== expectedBuf.length) return false;
    return crypto.timingSafeEqual(givenBuf, expectedBuf);
  });
}

function isLifetimePurchase(session) {
  const wanted = envList('STRIPE_LIFETIME_PLINK');
  if (wanted.length) {
    const link =
      typeof session.payment_link === 'string'
        ? session.payment_link
        : session.payment_link && session.payment_link.id;
    return !!link && wanted.includes(link);
  }
  // Fallback if the payment-link id was never configured.
  return (
    session.currency === 'usd' &&
    typeof session.amount_total === 'number' &&
    session.amount_total >= 1900
  );
}

export async function POST(request) {
  const rawBody = await request.text();
  const signature = request.headers.get('stripe-signature');

  const secrets = envList('STRIPE_WEBHOOK_SECRET');
  const signatureOk = secrets.some((s) => verifyStripeSignature(rawBody, signature, s));

  if (!signatureOk) {
    // 400 tells Stripe the request was rejected. Nothing is trusted
    // before this line — the body is unverified data until now.
    return new Response('invalid signature', { status: 400 });
  }

  let event;
  try {
    event = JSON.parse(rawBody);
  } catch {
    return new Response('bad json', { status: 400 });
  }

  // Ignore everything except a completed checkout. 200 so Stripe stops
  // retrying events we simply do not care about.
  if (event.type !== 'checkout.session.completed') {
    return new Response('ignored: ' + event.type, { status: 200 });
  }

  const session = event.data && event.data.object ? event.data.object : {};

  if (session.payment_status !== 'paid') {
    return new Response('ignored: not paid', { status: 200 });
  }

  if (!isLifetimePurchase(session)) {
    return new Response('ignored: not the lifetime product', { status: 200 });
  }

  const email =
    (session.customer_details && session.customer_details.email) ||
    session.customer_email ||
    null;

  if (!email) {
    // Nothing we can do automatically, but do not make Stripe retry
    // forever. Shows up in the Vercel log so it can be handled by hand.
    console.error('[unlock] no email on session', session.id, event.id);
    return new Response('ignored: no email', { status: 200 });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !serviceKey) {
    console.error('[unlock] missing Supabase env vars');
    return new Response('server not configured', { status: 500 });
  }

  const amount =
    typeof session.amount_total === 'number'
      ? '$' + (session.amount_total / 100).toFixed(2)
      : '';

  try {
    const res = await fetch(`${supabaseUrl}/rest/v1/rpc/grant_paid_by_email`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        apikey: serviceKey,
        Authorization: `Bearer ${serviceKey}`,
      },
      body: JSON.stringify({
        p_email: email,
        p_note: `stripe ${amount} ${event.id}`.trim(),
      }),
    });

    const body = await res.text();

    if (!res.ok) {
      // 500 makes Stripe retry, which is what we want for a transient
      // database problem — the payment is real and must not be dropped.
      console.error('[unlock] supabase refused', res.status, body);
      return new Response('grant failed', { status: 500 });
    }

    // body is 'granted', 'pending', or 'no-email'
    console.log('[unlock]', email, '->', body, '(', event.id, ')');
    return new Response('ok: ' + body, { status: 200 });
  } catch (err) {
    console.error('[unlock] grant threw', err && err.message);
    return new Response('grant error', { status: 500 });
  }
}
