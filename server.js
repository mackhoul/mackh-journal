const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto'); // built-in Node.js module
const fetch   = require('node-fetch');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');

const app = express();

// ── CORS — only allow the known front-end origins ────────
// Uses exact match or path-prefix match to prevent subdomain spoofing
// (e.g. "mackhoul.github.io.evil.com" must NOT pass as "mackhoul.github.io")
function isOriginAllowed(origin) {
  if (!origin) return true; // no origin = same-origin / mobile shell / Render health
  if (origin === 'null') return true; // Telegram Mini App
  if (origin === 'https://mackhoul.github.io') return true;
  // Allow subpaths of the Pages host (origin never includes path, but be safe)
  if (origin.startsWith('https://mackhoul.github.io/')) return true;
  // Allow localhost on any port for local dev
  if (/^http:\/\/localhost(:\d+)?$/.test(origin)) return true;
  if (/^http:\/\/127\.0\.0\.1(:\d+)?$/.test(origin)) return true;
  return false;
}
app.use(cors({
  origin: (origin, cb) => {
    if (isOriginAllowed(origin)) return cb(null, true);
    console.warn('[CORS] blocked origin:', origin);
    cb(new Error('CORS: origin not allowed'));
  }
}));

// ── Stripe ───────────────────────────────────────────────
const STRIPE_SECRET_KEY     = process.env.STRIPE_SECRET_KEY;
const STRIPE_PRICE_ID       = process.env.STRIPE_PRICE_ID;
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
const SITE_URL              = process.env.SITE_URL || 'https://mackhoul.github.io/mackh-journal/';

const stripe = STRIPE_SECRET_KEY ? require('stripe')(STRIPE_SECRET_KEY) : null;
const STRIPE_READY = !!(stripe && STRIPE_PRICE_ID);
console.log(STRIPE_READY ? '💳 Stripe configured' : 'ℹ️  Stripe not configured — subscriptions disabled');

// The webhook MUST be registered before express.json(): Stripe signs the raw
// request body, and a parsed body can no longer be verified.
app.post('/billing/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.status(503).send('Stripe not configured');

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    console.error('[STRIPE] webhook signature failed:', e.message);
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }

  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const s = event.data.object;
        const userId = Number(s.client_reference_id);
        if (userId && s.subscription) {
          const sub = await stripe.subscriptions.retrieve(s.subscription);
          await saveSubscription(userId, sub, s.customer);
          console.log(`[STRIPE] checkout completed → user ${userId} subscribed`);
        }
        break;
      }
      case 'customer.subscription.updated':
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        const userId = Number(sub.metadata?.user_id);
        if (userId) {
          await saveSubscription(userId, sub, sub.customer);
          console.log(`[STRIPE] subscription ${event.type} → user ${userId}: ${sub.status}`);
        }
        break;
      }
    }
    res.json({ received: true });
  } catch (e) {
    console.error('[STRIPE] webhook handling error:', e.message);
    res.status(500).send('Webhook handler failed');
  }
});

app.use(express.json({ limit: '10mb' })); // 10 MB is plenty for a photo

// ── Environment ─────────────────────────────────────────
const BOT_TOKEN            = process.env.BOT_TOKEN;
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
const SUPABASE_ANON_KEY    = process.env.SUPABASE_ANON_KEY; // public key, used by the web front-end

if (!BOT_TOKEN)            console.error('❌ BOT_TOKEN is not set');
if (!SUPABASE_URL)         console.error('❌ SUPABASE_URL is not set');
if (!SUPABASE_SERVICE_KEY) console.error('❌ SUPABASE_SERVICE_ROLE_KEY is not set');

// ── Cloudflare R2 (optional — image storage) ─────────────
// If configured, screenshots go here instead of Supabase Storage:
// 10GB free vs Supabase's 1GB, and zero egress fees.
// If any of these are missing, uploadImage() falls back to Supabase Storage
// automatically — nothing breaks while you're setting R2 up.
const R2_ACCOUNT_ID        = process.env.R2_ACCOUNT_ID;
const R2_ACCESS_KEY_ID     = process.env.R2_ACCESS_KEY_ID;
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY;
const R2_BUCKET            = process.env.R2_BUCKET || 'trade-images';
const R2_PUBLIC_URL        = process.env.R2_PUBLIC_URL; // e.g. https://pub-xxxx.r2.dev (no trailing slash)

const R2_READY = !!(R2_ACCOUNT_ID && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY && R2_PUBLIC_URL);
const r2 = R2_READY ? new S3Client({
  region:      'auto',
  endpoint:    `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: { accessKeyId: R2_ACCESS_KEY_ID, secretAccessKey: R2_SECRET_ACCESS_KEY },
}) : null;
console.log(R2_READY ? '☁️  R2 configured — screenshots will use Cloudflare R2' : 'ℹ️  R2 not configured — screenshots will use Supabase Storage (1GB free limit)');

// ── Telegram auth ────────────────────────────────────────
const AUTH_MAX_AGE_SEC = 24 * 60 * 60; // 24 hours — Telegram's recommended window

function validateTelegramAuth(initData) {
  try {
    const params = new URLSearchParams(initData);
    const hash   = params.get('hash');
    if (!hash) return false;

    // ── Expiry check ──────────────────────────────────
    const authDate = parseInt(params.get('auth_date') || '0', 10);
    if (!authDate) return false;
    const ageSec = Math.floor(Date.now() / 1000) - authDate;
    if (ageSec > AUTH_MAX_AGE_SEC) {
      console.warn('[AUTH] initData expired — age:', ageSec, 's');
      return false;
    }

    params.delete('hash');
    const dataCheckString = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join('\n');
    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
    const computed  = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
    // Constant-time comparison to prevent timing attacks
    return crypto.timingSafeEqual(Buffer.from(computed, 'hex'), Buffer.from(hash, 'hex'));
  } catch (e) {
    console.error('[AUTH] validateTelegramAuth error:', e.message);
    return false;
  }
}

function getUserId(initData) {
  try { return JSON.parse(new URLSearchParams(initData).get('user')).id; }
  catch { return null; }
}

// ── Supabase REST helper ─────────────────────────────────
async function supabase(method, path, body) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    method,
    headers: {
      'Content-Type':  'application/json',
      'apikey':        SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Prefer':        method === 'POST' ? 'resolution=merge-duplicates,return=representation' : '',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Supabase ${method} ${path}: ${err}`);
  }
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

// ── Image upload — Cloudflare R2 (preferred) or Supabase Storage (fallback) ──
async function uploadImage(userId, base64Data) {
  const base64 = base64Data.replace(/^data:image\/\w+;base64,/, '');
  const buffer = Buffer.from(base64, 'base64');
  const path   = `${userId}/${Date.now()}.jpg`;

  if (r2) {
    try {
      console.log('[STORAGE] Uploading to R2...');
      await r2.send(new PutObjectCommand({
        Bucket:      R2_BUCKET,
        Key:         path,
        Body:        buffer,
        ContentType: 'image/jpeg',
      }));
      const publicUrl = `${R2_PUBLIC_URL}/${path}`;
      console.log('[STORAGE] ✓ Image uploaded to R2:', publicUrl);
      return publicUrl;
    } catch (e) {
      console.error('[STORAGE] R2 upload failed, falling back to Supabase:', e.message);
      // fall through to Supabase below rather than losing the screenshot
    }
  }

  try {
    console.log('[STORAGE] Uploading to Supabase Storage...');
    const res = await fetch(`${SUPABASE_URL}/storage/v1/object/trade-images/${path}`, {
      method:  'POST',
      headers: {
        'Content-Type':  'image/jpeg',
        'apikey':        SUPABASE_SERVICE_KEY,
        'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      },
      body: buffer,
    });

    if (!res.ok) {
      const errText = await res.text();
      console.error('[STORAGE] Supabase upload failed:', errText);
      return null;
    }

    const publicUrl = `${SUPABASE_URL}/storage/v1/object/public/trade-images/${path}`;
    console.log('[STORAGE] ✓ Image uploaded to Supabase:', publicUrl);
    return publicUrl;
  } catch (e) {
    console.error('[STORAGE] uploadImage error:', e.message);
    return null;
  }
}

// ── Web auth (Supabase) ──────────────────────────────────
// Verifies a Supabase access token by asking Supabase who it belongs to.
// Cached briefly so we don't call Supabase on every single request.
const tokenCache = new Map(); // token -> { authUser, expires }
const TOKEN_CACHE_MS = 5 * 60 * 1000;

async function verifySupabaseToken(token) {
  const hit = tokenCache.get(token);
  if (hit && hit.expires > Date.now()) return hit.authUser;

  try {
    const res = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: {
        'apikey':        SUPABASE_SERVICE_KEY,
        'Authorization': `Bearer ${token}`,
      },
    });
    if (!res.ok) return null;
    const authUser = await res.json();
    if (!authUser || !authUser.id) return null;

    tokenCache.set(token, { authUser, expires: Date.now() + TOKEN_CACHE_MS });
    if (tokenCache.size > 500) { // keep the cache from growing forever
      for (const [k, v] of tokenCache) if (v.expires <= Date.now()) tokenCache.delete(k);
    }
    return authUser;
  } catch (e) {
    console.error('[AUTH] verifySupabaseToken error:', e.message);
    return null;
  }
}

// Maps a Supabase account to the internal user_id that owns the trades.
// First web login creates the link. Telegram users keep their Telegram id
// as the internal id, so their existing trades stay attached.
async function resolveWebUserId(authUser) {
  const rows = await supabase('GET', `account_links?auth_id=eq.${authUser.id}&select=*`);
  if (rows && rows.length) return Number(rows[0].user_id);

  // New web account — generate an internal id that can't collide with a
  // Telegram id (those are far smaller than this range).
  const newId = Date.now() * 1000 + Math.floor(Math.random() * 1000);
  await supabase('POST', 'account_links', {
    auth_id:  authUser.id,
    user_id:  newId,
    email:    authUser.email || null,
  });
  console.log(`[AUTH] linked new web account ${authUser.email} → user_id ${newId}`);
  return newId;
}

// ── Auth middleware ──────────────────────────────────────
// Accepts either Telegram Mini App auth or a Supabase web session.
async function auth(req, res, next) {
  const initData = req.headers['x-telegram-init-data'];
  if (initData) {
    if (!validateTelegramAuth(initData)) return res.status(401).json({ error: 'Invalid Telegram auth' });
    const userId = getUserId(initData);
    if (!userId)                         return res.status(401).json({ error: 'Cannot parse user id' });
    req.userId = userId;
    return next();
  }

  const bearer = req.headers.authorization;
  if (bearer && bearer.startsWith('Bearer ')) {
    const authUser = await verifySupabaseToken(bearer.slice(7));
    if (!authUser) return res.status(401).json({ error: 'Invalid or expired session' });
    try {
      req.userId  = await resolveWebUserId(authUser);
      req.authUser = authUser;
      return next();
    } catch (e) {
      console.error('[AUTH] resolveWebUserId error:', e.message);
      return res.status(500).json({ error: 'Failed to resolve account' });
    }
  }

  return res.status(401).json({ error: 'No auth header' });
}

// ── Routes ───────────────────────────────────────────────

// Health check — used by Render and for quick "is it alive?" checks
app.get('/', (req, res) => res.json({
  status:  'ok',
  app:     'MackH Trade Journal',
  time:    new Date().toISOString(),
  uptime:  Math.floor(process.uptime()) + 's',
}));

// Debug endpoint — shows config status without exposing secret values
// Useful right after deploy to verify all env vars are set correctly
app.get('/health', (req, res) => res.json({
  status:  'ok',
  uptime:  Math.floor(process.uptime()) + 's',
  time:    new Date().toISOString(),
  config: {
    bot_token:      !!BOT_TOKEN,
    supabase_url:   !!SUPABASE_URL,
    supabase_key:   !!SUPABASE_SERVICE_KEY,
    r2_storage:     R2_READY,
    web_auth:       !!SUPABASE_ANON_KEY,
    stripe:         STRIPE_READY,
    stripe_webhook: !!STRIPE_WEBHOOK_SECRET,
  },
  storage: R2_READY ? 'cloudflare-r2' : 'supabase (1GB free limit — set R2_* env vars to switch)',
  ready: !!(BOT_TOKEN && SUPABASE_URL && SUPABASE_SERVICE_KEY),
}));

// Public config for the web front-end. The anon key is designed to be public
// (it only allows what Row Level Security permits) — the service key is never
// sent here. Serving it from the API keeps keys out of the GitHub repo.
app.get('/config', (req, res) => res.json({
  supabase_url:      SUPABASE_URL || null,
  supabase_anon_key: SUPABASE_ANON_KEY || null,
  web_auth_ready:    !!(SUPABASE_URL && SUPABASE_ANON_KEY),
}));

// GET /trades — fetch all trades for authenticated user
app.get('/trades', auth, async (req, res) => {
  try {
    const rows   = await supabase('GET', `trades?user_id=eq.${req.userId}&select=*&order=created_at.asc`);
    const trades = (rows || []).map(r => {
      const t = r.data || {};
      if (r.img_url) t.img_url = r.img_url;
      return t;
    });
    console.log(`[API] GET /trades → ${trades.length} trade(s) for user ${req.userId}`);
    res.json(trades);
  } catch (e) {
    console.error('[API] GET /trades error:', e.message);
    res.status(500).json({ error: 'Failed to load trades' });
  }
});

// POST /trades — create or update a trade (upsert by id + user_id)
app.post('/trades', auth, async (req, res) => {
  try {
    const trade = { ...req.body };
    if (!trade.id) return res.status(400).json({ error: 'Missing trade id' });

    let imgUrl    = trade.img_url || null;
    let imgFailed = false;

    // If a base64 image is attached, upload it to Storage and replace with URL
    if (trade.img && trade.img.startsWith('data:')) {
      imgUrl = await uploadImage(req.userId, trade.img);
      if (imgUrl) {
        trade.img_url = imgUrl;
      } else {
        imgFailed = true; // upload attempted but failed — tell the client
        console.warn(`[API] POST /trades → image upload failed for trade ${trade.id}, saving trade without photo`);
      }
      delete trade.img; // never store base64 in the database
    }

    await supabase('POST', 'trades?on_conflict=id,user_id', {
      id:         trade.id,
      user_id:    req.userId,
      data:       trade,
      img_url:    imgUrl,
      created_at: new Date().toISOString(),
    });

    console.log(`[API] POST /trades → trade ${trade.id} saved for user ${req.userId}${imgFailed ? ' (without photo)' : ''}`);
    res.json({ ok: true, img_url: imgUrl, img_failed: imgFailed });
  } catch (e) {
    console.error('[API] POST /trades error:', e.message);
    res.status(500).json({ error: 'Failed to save trade' });
  }
});

// DELETE /trades/:id — delete a trade
app.delete('/trades/:id', auth, async (req, res) => {
  // Validate id — must be a numeric timestamp string (our client uses Date.now())
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ error: 'Invalid trade id' });
  try {
    await supabase('DELETE', `trades?id=eq.${req.params.id}&user_id=eq.${req.userId}`);
    console.log(`[API] DELETE /trades/${req.params.id} for user ${req.userId}`);
    res.json({ ok: true });
  } catch (e) {
    console.error('[API] DELETE /trades error:', e.message);
    res.status(500).json({ error: 'Failed to delete trade' });
  }
});

// GET /settings — fetch base capital and goals
app.get('/settings', auth, async (req, res) => {
  try {
    const rows = await supabase('GET', `users?user_id=eq.${req.userId}&select=*`);
    if (!rows || !rows.length) return res.json({ base_capital: 0, goals: [] });
    res.json({
      base_capital: parseFloat(rows[0].base_capital) || 0,
      goals:        rows[0].goals || [],
    });
  } catch (e) {
    console.error('[API] GET /settings error:', e.message);
    res.status(500).json({ error: 'Failed to load settings' });
  }
});

// POST /settings — save base capital and goals
app.post('/settings', auth, async (req, res) => {
  try {
    const { base_capital, goals } = req.body;
    // Validate base_capital is a safe finite number
    const capital = parseFloat(base_capital);
    if (base_capital !== undefined && !isFinite(capital)) {
      return res.status(400).json({ error: 'Invalid base_capital' });
    }
    if (!Array.isArray(goals) && goals !== undefined) {
      return res.status(400).json({ error: 'Invalid goals format' });
    }
    await supabase('POST', 'users?on_conflict=user_id', {
      user_id:      req.userId,
      base_capital: isFinite(capital) ? capital : 0,
      goals:        Array.isArray(goals) ? goals : [],
      updated_at:   new Date().toISOString(),
    });
    console.log(`[API] POST /settings saved for user ${req.userId}`);
    res.json({ ok: true });
  } catch (e) {
    console.error('[API] POST /settings error:', e.message);
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

// ── Subscriptions ────────────────────────────────────────
// Stripe is the source of truth; we mirror just enough to answer
// "is this user allowed in?" without calling Stripe on every request.
async function saveSubscription(userId, sub, customerId) {
  await supabase('POST', 'subscriptions?on_conflict=user_id', {
    user_id:            userId,
    stripe_customer_id: typeof customerId === 'string' ? customerId : customerId?.id || null,
    stripe_sub_id:      sub.id,
    status:             sub.status,
    current_period_end: sub.current_period_end
                          ? new Date(sub.current_period_end * 1000).toISOString()
                          : null,
    updated_at:         new Date().toISOString(),
  });
}

const ACTIVE_STATUSES = ['active', 'trialing'];

async function getSubscription(userId) {
  const rows = await supabase('GET', `subscriptions?user_id=eq.${userId}&select=*`);
  const row  = rows && rows[0];
  if (!row) return { active: false, status: 'none' };
  const notExpired = !row.current_period_end || new Date(row.current_period_end) > new Date();
  return {
    active:  ACTIVE_STATUSES.includes(row.status) && notExpired,
    status:  row.status,
    renews:  row.current_period_end,
  };
}

// GET /billing/status — is this user subscribed?
app.get('/billing/status', auth, async (req, res) => {
  if (!STRIPE_READY) return res.json({ active: false, status: 'disabled', billing_enabled: false });
  try {
    const sub = await getSubscription(req.userId);
    res.json({ ...sub, billing_enabled: true });
  } catch (e) {
    console.error('[BILLING] status error:', e.message);
    res.status(500).json({ error: 'Failed to load subscription' });
  }
});

// POST /billing/checkout — start a Stripe Checkout session
app.post('/billing/checkout', auth, async (req, res) => {
  if (!STRIPE_READY) return res.status(503).json({ error: 'Billing not configured' });
  try {
    const existing = await getSubscription(req.userId);
    if (existing.active) return res.status(400).json({ error: 'Already subscribed' });

    // Reuse the Stripe customer if this user paid before
    const rows = await supabase('GET', `subscriptions?user_id=eq.${req.userId}&select=stripe_customer_id`);
    const customerId = rows?.[0]?.stripe_customer_id || undefined;

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
      client_reference_id: String(req.userId),
      customer: customerId,
      customer_email: customerId ? undefined : (req.authUser?.email || undefined),
      subscription_data: { metadata: { user_id: String(req.userId) } },
      success_url: `${SITE_URL}?checkout=success`,
      cancel_url:  `${SITE_URL}?checkout=cancelled`,
      allow_promotion_codes: true,
    });
    console.log(`[BILLING] checkout session for user ${req.userId}`);
    res.json({ url: session.url });
  } catch (e) {
    console.error('[BILLING] checkout error:', e.message);
    res.status(500).json({ error: 'Failed to start checkout' });
  }
});

// POST /billing/portal — manage or cancel an existing subscription
app.post('/billing/portal', auth, async (req, res) => {
  if (!STRIPE_READY) return res.status(503).json({ error: 'Billing not configured' });
  try {
    const rows = await supabase('GET', `subscriptions?user_id=eq.${req.userId}&select=stripe_customer_id`);
    const customerId = rows?.[0]?.stripe_customer_id;
    if (!customerId) return res.status(404).json({ error: 'No subscription found' });

    const portal = await stripe.billingPortal.sessions.create({
      customer:   customerId,
      return_url: SITE_URL,
    });
    res.json({ url: portal.url });
  } catch (e) {
    console.error('[BILLING] portal error:', e.message);
    res.status(500).json({ error: 'Failed to open billing portal' });
  }
});

// ── Start ────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 MackH Trade Journal server running on port ${PORT}`);
  console.log(`🔑 BOT_TOKEN:            ${BOT_TOKEN            ? '✓ set' : '✗ MISSING'}`);
  console.log(`🗄  SUPABASE_URL:         ${SUPABASE_URL         ? '✓ set' : '✗ MISSING'}`);
  console.log(`🔐 SUPABASE_SERVICE_KEY: ${SUPABASE_SERVICE_KEY ? '✓ set' : '✗ MISSING'}`);
});
