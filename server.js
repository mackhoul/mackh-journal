const express = require('express');
const cors    = require('cors');
const crypto  = require('crypto'); // built-in Node.js module
const fetch   = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// ── Environment ─────────────────────────────────────────
const BOT_TOKEN            = process.env.BOT_TOKEN;
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;

if (!BOT_TOKEN)            console.error('❌ BOT_TOKEN is not set');
if (!SUPABASE_URL)         console.error('❌ SUPABASE_URL is not set');
if (!SUPABASE_SERVICE_KEY) console.error('❌ SUPABASE_SERVICE_ROLE_KEY is not set');

// ── Telegram auth ────────────────────────────────────────
function validateTelegramAuth(initData) {
  try {
    const params = new URLSearchParams(initData);
    const hash   = params.get('hash');
    if (!hash) return false;
    params.delete('hash');
    const dataCheckString = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join('\n');
    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
    const computed  = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
    return computed === hash;
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

// ── Image upload to Supabase Storage ────────────────────
async function uploadImage(userId, base64Data) {
  try {
    console.log('[STORAGE] Processing image for upload...');
    const base64 = base64Data.replace(/^data:image\/\w+;base64,/, '');
    const buffer = Buffer.from(base64, 'base64');
    const path   = `${userId}/${Date.now()}.jpg`;

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
      console.error('[STORAGE] Upload failed:', errText);
      return null;
    }

    const publicUrl = `${SUPABASE_URL}/storage/v1/object/public/trade-images/${path}`;
    console.log('[STORAGE] ✓ Image uploaded:', publicUrl);
    return publicUrl;
  } catch (e) {
    console.error('[STORAGE] uploadImage error:', e.message);
    return null;
  }
}

// ── Auth middleware ──────────────────────────────────────
function auth(req, res, next) {
  const initData = req.headers['x-telegram-init-data'];
  if (!initData)                        return res.status(401).json({ error: 'No auth header' });
  if (!validateTelegramAuth(initData))  return res.status(401).json({ error: 'Invalid Telegram auth' });
  const userId = getUserId(initData);
  if (!userId)                          return res.status(401).json({ error: 'Cannot parse user id' });
  req.userId = userId;
  next();
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
  },
  ready: !!(BOT_TOKEN && SUPABASE_URL && SUPABASE_SERVICE_KEY),
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
    res.status(500).json({ error: e.message });
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
    res.status(500).json({ error: e.message });
  }
});

// DELETE /trades/:id — delete a trade
app.delete('/trades/:id', auth, async (req, res) => {
  try {
    await supabase('DELETE', `trades?id=eq.${req.params.id}&user_id=eq.${req.userId}`);
    console.log(`[API] DELETE /trades/${req.params.id} for user ${req.userId}`);
    res.json({ ok: true });
  } catch (e) {
    console.error('[API] DELETE /trades error:', e.message);
    res.status(500).json({ error: e.message });
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
    res.status(500).json({ error: e.message });
  }
});

// POST /settings — save base capital and goals
app.post('/settings', auth, async (req, res) => {
  try {
    const { base_capital, goals } = req.body;
    await supabase('POST', 'users?on_conflict=user_id', {
      user_id:      req.userId,
      base_capital: base_capital || 0,
      goals:        goals || [],
      updated_at:   new Date().toISOString(),
    });
    console.log(`[API] POST /settings saved for user ${req.userId}`);
    res.json({ ok: true });
  } catch (e) {
    console.error('[API] POST /settings error:', e.message);
    res.status(500).json({ error: e.message });
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
