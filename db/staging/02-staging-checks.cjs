/*
 * Staging checks for the trade deletion guard against the Supabase TEST
 * project, through the real server.js running locally.
 *
 *   node db/staging/02-staging-checks.cjs [server] [csv]
 *
 * Needs: .env.staging (SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY,
 * TEST_USER_A/B_EMAIL/PASSWORD), the migration applied in that project and
 * server.js running locally against it (default http://127.0.0.1:3010).
 * Optional: a CSV export of `trades` made from the test project, for the
 * restore rehearsal.
 *
 * Before any key, password or token leaves this machine it checks, and stops
 * on any mismatch (exit code 2, nothing written):
 *   - SUPABASE_URL is exactly https://<ALLOWED_TEST_REF>.supabase.co and both
 *     keys are JWTs of that project with the expected roles;
 *   - the server is on this computer (127.0.0.1 / localhost / [::1]), its
 *     public /config names the same test project and /health/db reports the
 *     guard and its selftest as working;
 *   - the test users are @example.com addresses;
 *   - the CSV (if given) is fully parsed and valid.
 * No request follows a redirect.
 *
 * Writes only made-up trades of the two test accounts and removes exactly the
 * rows this run created (in `finally`, verified by reading back). The restore
 * rehearsal touches only the (id, user_id) pairs listed in the CSV, and only
 * if the test database holds exactly those rows. The test auth users and their
 * account_links are kept on purpose: the next run signs in with them again.
 * Never prints keys, passwords or tokens. Exit code: 0 all passed, 1 a check
 * failed, 2 stopped before writing anything.
 */
'use strict';
const fs = require('fs');
const path = require('path');

// mackh-journal-test — the only Supabase project this script may touch
const ALLOWED_TEST_REF = 'ibjjethbdgawqnttqmvc';
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);
const BACKUP_COLUMNS = ['id', 'user_id', 'data', 'img_url', 'created_at'];
const GUARD_COLUMNS = ['deleted_at', 'deleted_gen'];
const REQUEST_TIMEOUT_MS = 30000;

// A stop before anything was written: wrong target, bad config or bad CSV
class Stop extends Error {}

// ── report ───────────────────────────────────────────────
function makeReport() {
  const results = [];
  const redact = s => s.replace(/eyJ[\w-]+\.[\w-]+\.[\w-]*/g, '[token]');
  const formatDetail = detail => {
    if (detail === undefined) return '';
    try {
      const s = typeof detail === 'string' ? detail : JSON.stringify(detail);
      return redact(String(s)).slice(0, 400);
    } catch (e) { return '[detail could not be shown]'; }
  };
  // Always records the result; a failed check without detail is still a FAIL
  const check = (name, ok, detail) => {
    results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : formatDetail(detail) });
    return !!ok;
  };
  return { results, check };
}

// ── target checks (no network) ───────────────────────────
function jwtClaims(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  try { return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')); } catch (e) { return null; }
}

function checkSupabaseUrl(value) {
  let u;
  try { u = new URL(value); } catch (e) { throw new Stop('SUPABASE_URL is missing or not a URL'); }
  const m = u.hostname.match(/^([a-z0-9]+)\.supabase\.co$/);
  const bare = u.protocol === 'https:' && !u.port && !u.username && !u.password && u.pathname === '/' && !u.search && !u.hash;
  if (!m || !bare) throw new Stop('SUPABASE_URL must be exactly https://<project-ref>.supabase.co');
  if (m[1] !== ALLOWED_TEST_REF) throw new Stop('SUPABASE_URL is not the allowed test project');
  return u.origin;
}

function checkServerUrl(value) {
  let u;
  try { u = new URL(value); } catch (e) { throw new Stop('server address is not a URL'); }
  const bare = !u.username && !u.password && u.pathname === '/' && !u.search && !u.hash;
  if (u.protocol !== 'http:' || !LOOPBACK_HOSTS.has(u.hostname) || !bare) {
    throw new Stop('server must be a local address such as http://127.0.0.1:3010');
  }
  return u.origin;
}

function checkKeysAndUsers(env) {
  for (const [name, role] of [['SUPABASE_ANON_KEY', 'anon'], ['SUPABASE_SERVICE_ROLE_KEY', 'service_role']]) {
    const c = jwtClaims(env[name]);
    if (!c || c.ref !== ALLOWED_TEST_REF || c.role !== role) throw new Stop(`${name} is not the ${role} key of the allowed test project`);
  }
  for (const who of ['A', 'B']) {
    if (!/^[^@\s]+@example\.com$/.test(env[`TEST_USER_${who}_EMAIL`] || '')) throw new Stop(`TEST_USER_${who}_EMAIL must be a made-up @example.com address`);
    if (!env[`TEST_USER_${who}_PASSWORD`]) throw new Stop(`TEST_USER_${who}_PASSWORD is missing`);
  }
  if (env.TEST_USER_A_EMAIL === env.TEST_USER_B_EMAIL) throw new Stop('test users A and B must be different');
}

// ── CSV backup (no network) ──────────────────────────────
// RFC 4180: quoted fields may hold commas, doubled quotes and line breaks.
function parseCsv(text) {
  text = String(text).replace(/^\uFEFF/, '');
  const records = [];
  let rec = [], cur = '', inQuotes = false, closed = false;
  const endField = () => { rec.push(cur); cur = ''; closed = false; };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c !== '"') cur += c;
      else if (text[i + 1] === '"') { cur += '"'; i++; }
      else { inQuotes = false; closed = true; }
    } else if (c === ',') endField();
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      endField(); records.push(rec); rec = [];
    } else if (closed) throw new Error(`text after a closing quote in record ${records.length + 1}`);
    else if (c === '"') {
      if (cur !== '') throw new Error(`quote inside an unquoted field in record ${records.length + 1}`);
      inQuotes = true;
    } else cur += c;
  }
  if (inQuotes) throw new Error('a quoted field is never closed');
  if (cur !== '' || rec.length || closed) { endField(); records.push(rec); }
  return records;
}

const TS_RE = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?$/;
const TSTZ_RE = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}(?::?\d{2})?)$/;

// `timestamp without time zone` as text, microseconds padded: comparable as a string
function normTimestamp(s) {
  const m = String(s ?? '').match(TS_RE);
  return m ? `${m[1]}T${m[2]}.${(m[3] || '').padEnd(6, '0')}` : null;
}
// `timestamptz` as UTC milliseconds + microsecond digits
function normTimestamptz(s) {
  const m = String(s ?? '').match(TSTZ_RE);
  if (!m) return null;
  let zone = m[4] === 'Z' ? 'Z' : m[4].replace(/^([+-]\d{2})(\d{2})$/, '$1:$2');
  if (/^[+-]\d{2}$/.test(zone)) zone += ':00';
  const frac = (m[3] || '').padEnd(6, '0');
  const ms = Date.parse(`${m[1]}T${m[2]}.${frac.slice(0, 3)}${zone}`);
  return Number.isNaN(ms) ? null : `${ms}.${frac.slice(3)}`;
}

function canon(v) {
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`;
  return JSON.stringify(v);
}

function isValidTradeId(s) {
  return typeof s === 'string' && s.length >= 1 && s.length <= 128 && !/[\u0000-\u001f\u007f]/.test(s);
}

// Fully checks the backup before anything touches the database
function parseBackup(text) {
  let records;
  try { records = parseCsv(text); } catch (e) { throw new Stop('CSV: ' + e.message); }
  const head = records[0] || [];
  const withGuard = head.join(',') === [...BACKUP_COLUMNS, ...GUARD_COLUMNS].join(',');
  if (head.join(',') !== BACKUP_COLUMNS.join(',') && !withGuard) {
    throw new Stop(`CSV: header must be "${BACKUP_COLUMNS.join(',')}" (optionally followed by ",${GUARD_COLUMNS.join(',')}")`);
  }
  const problems = [], rows = [], seen = new Set();
  records.slice(1).forEach((rec, i) => {
    const at = `record ${i + 2}`;
    if (rec.length !== head.length) return problems.push(`${at}: ${rec.length} fields, expected ${head.length}`);
    const v = Object.fromEntries(head.map((h, j) => [h, rec[j]]));
    const row = { id: v.id };
    if (!isValidTradeId(v.id)) problems.push(`${at}: invalid id`);
    if (!/^-?\d{1,18}$/.test(v.user_id) || !Number.isSafeInteger(Number(v.user_id))) problems.push(`${at}: invalid user_id`);
    row.user_id = Number(v.user_id);
    try {
      row.data = JSON.parse(v.data);
      if (!row.data || typeof row.data !== 'object' || Array.isArray(row.data)) problems.push(`${at}: data is not a JSON object`);
    } catch (e) { problems.push(`${at}: data is not valid JSON`); }
    row.img_url = v.img_url === '' ? null : v.img_url;
    row.created_at = normTimestamp(v.created_at);
    if (!row.created_at) problems.push(`${at}: invalid created_at`);
    if (withGuard) {
      row.deleted_at = v.deleted_at === '' ? null : v.deleted_at;
      if (row.deleted_at !== null && !normTimestamptz(row.deleted_at)) problems.push(`${at}: invalid deleted_at`);
      if (!/^\d{1,15}$/.test(v.deleted_gen)) problems.push(`${at}: invalid deleted_gen`);
      row.deleted_gen = Number(v.deleted_gen);
    }
    const key = `${v.id}|${v.user_id}`;
    if (seen.has(key)) problems.push(`${at}: duplicate (id, user_id)`);
    seen.add(key);
    rows.push(row);
  });
  if (!rows.length) problems.push('no data rows');
  if (problems.length) throw new Stop('CSV: ' + problems.slice(0, 5).join('; ') + (problems.length > 5 ? ` (+${problems.length - 5} more)` : ''));
  return { rows, withGuard };
}

// A database row equals the backup row in every restored column
function sameAsBackup(db, b, withGuard) {
  if (!db) return false;
  const guardOk = withGuard
    ? (b.deleted_at === null ? db.deleted_at === null : normTimestamptz(db.deleted_at) === normTimestamptz(b.deleted_at)) && Number(db.deleted_gen) === b.deleted_gen
    : db.deleted_at === null && Number(db.deleted_gen) === 0;
  return db.id === b.id && String(db.user_id) === String(b.user_id) && canon(db.data) === canon(b.data)
    && (db.img_url ?? null) === b.img_url && normTimestamp(db.created_at) === b.created_at && guardOk;
}

// ── run ──────────────────────────────────────────────────
async function run({ env, server, csvText = null, fetch: fetchImpl = globalThis.fetch, log = console.log }) {
  const { results, check } = makeReport();
  const runRows = new Map();                       // rows this run may have created: "user|id" → { u, id }
  const track = (u, id) => runRows.set(`${u}|${id}`, { u, id: String(id) });
  let SB = null, SERVER = null, wrote = false;

  const call = async (url, init) => {
    const r = await fetchImpl(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    const text = await r.text();
    let body = null; try { body = text ? JSON.parse(text) : null; } catch (e) { body = text; }
    return { status: r.status, body };
  };
  const api = (tok, method, p, body) => call(SERVER + p, { method, headers: { 'Content-Type': 'application/json', ...(tok ? { Authorization: 'Bearer ' + tok } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const rest = (h, method, p, body, prefer) => call(`${SB}/rest/v1/${p}`, { method, headers: { ...h, ...(prefer ? { Prefer: prefer } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const headers = key => tok => ({ 'Content-Type': 'application/json', apikey: key, Authorization: 'Bearer ' + (tok || key) });
  const svcH = () => headers(env.SUPABASE_SERVICE_ROLE_KEY)();
  const anonH = () => headers(env.SUPABASE_ANON_KEY)();
  const userH = tok => headers(env.SUPABASE_ANON_KEY)(tok);

  const pairQuery = (id, u) => `trades?id=eq.${encodeURIComponent(id)}&user_id=eq.${u}`;
  const row = async (id, u) => {
    const r = await rest(svcH(), 'GET', `${pairQuery(id, u)}&select=*`);
    if (r.status !== 200 || !Array.isArray(r.body)) throw new Error(`reading trade ${id} failed: HTTP ${r.status}`);
    return r.body[0] || null;
  };
  const activeIds = async tok => {
    const r = await api(tok, 'GET', '/trades');
    if (r.status !== 200 || !Array.isArray(r.body)) throw new Error(`GET /trades failed: HTTP ${r.status}`);
    return r.body.map(t => t.id);
  };
  const has = async (tok, id) => (await activeIds(tok)).includes(id);
  let seq = 0;
  const uid = () => String(Date.now()) + String(100 + (seq++ % 900));

  // An exception inside a section is a FAIL of that section; later sections still run
  const section = async (name, fn) => {
    try { await fn(); } catch (e) { check(`${name}: ran to the end`, false, e.message || String(e)); }
  };

  try {
    // 0. preflight — nothing secret is sent and nothing is written before it passes
    SB = checkSupabaseUrl(env.SUPABASE_URL);
    SERVER = checkServerUrl(server);
    checkKeysAndUsers(env);
    const backup = csvText === null ? null : parseBackup(csvText);
    const cfg = await call(SERVER + '/config', { method: 'GET' }).catch(e => { throw new Stop('server /config unreachable: ' + e.message); });
    let cfgOrigin = null;
    try { cfgOrigin = new URL(cfg.body?.supabase_url).origin; } catch (e) { /* stays null */ }
    if (cfg.status !== 200 || cfgOrigin !== SB) throw new Stop('the local server is not running against the allowed test project');
    const h = await call(SERVER + '/health/db', { method: 'GET' }).catch(e => { throw new Stop('server /health/db unreachable: ' + e.message); });
    if (!(h.status === 200 && h.body?.deletion_guard === true && h.body?.deletion_guard_selftest?.ok === true)) {
      throw new Stop('health: deletion_guard and deletion_guard_selftest.ok must both be true, got ' + JSON.stringify({ status: h.status, deletion_guard: h.body?.deletion_guard, selftest: h.body?.deletion_guard_selftest }));
    }
    check('preflight: test project, local server on it, guard healthy' + (backup ? ', CSV valid' : ''), true);

    const signIn = async who => {
      const r = await call(`${SB}/auth/v1/token?grant_type=password`, { method: 'POST', headers: { 'Content-Type': 'application/json', apikey: env.SUPABASE_ANON_KEY }, body: JSON.stringify({ email: env[`TEST_USER_${who}_EMAIL`], password: env[`TEST_USER_${who}_PASSWORD`] }) });
      if (!r.body?.access_token) throw new Stop(`sign-in failed for test user ${who} (HTTP ${r.status})`);
      return r.body.access_token;
    };
    const A = await signIn('A'), B = await signIn('B');
    if ((await api(null, 'GET', '/trades')).status !== 401) throw new Stop('the server answers /trades without a token');
    wrote = true;                                    // the first signed-in GET may create the account links
    await activeIds(A); await activeIds(B);
    const link = async who => {
      const r = await rest(svcH(), 'GET', `account_links?email=eq.${encodeURIComponent(env[`TEST_USER_${who}_EMAIL`])}&select=user_id`);
      return Array.isArray(r.body) && r.body.length === 1 ? r.body[0].user_id : null;
    };
    const uA = await link('A'), uB = await link('B');
    if (!uA || !uB || uA === uB) throw new Stop('test accounts are not linked to two distinct internal ids');
    check('no token → 401; both test accounts linked to distinct ids', true);
    const save = (tok, u, trade) => { track(u, trade.id); return api(tok, 'POST', '/trades', trade); };

    // 1. save / edit / delete / late save / undo through the real server
    await section('save/delete/undo', async () => {
      const t1 = uid();
      let r = await save(A, uA, { id: t1, pair: 'STG_EURUSD', pnl: '10' });
      check('save', r.status === 200 && r.body?.ok && !r.body?.skipped && await has(A, t1), r);
      r = await save(A, uA, { id: t1, pair: 'STG_EURUSD', pnl: '20' });
      const re = await row(t1, uA);
      check('edit', r.status === 200 && re?.data?.pnl === '20', { status: r.status, pnl: re?.data?.pnl });
      r = await api(A, 'DELETE', `/trades/${t1}`);
      const g1 = r.body?.deletion;
      const r1 = await row(t1, uA);
      check('delete returns a deletion number, hides, wipes content', r.status === 200 && g1 === 1 && !(await has(A, t1)) && r1?.deleted_at && r1?.data?.pnl === undefined && r1?.img_url === null, { r, r1 });
      r = await save(A, uA, { id: t1, pair: 'STG_EURUSD', pnl: 'late' });
      check('late save after delete → skipped, stays deleted', r.body?.skipped === 'deleted' && !(await has(A, t1)) && (await row(t1, uA))?.deleted_at, r);
      r = await save(A, uA, { id: t1, pnl: 'old-client', __restore: true });
      check('old client flag __restore:true does not lift a deletion', r.body?.skipped === 'deleted' && !(await has(A, t1)), r);
      r = await save(A, uA, { id: t1, pair: 'STG_EURUSD', pnl: '20', __restore: g1 });
      const r2 = await row(t1, uA);
      check('undo with the right deletion number restores', r.body?.ok && !r.body?.skipped && await has(A, t1) && r2?.deleted_at === null && r2?.data?.pnl === '20' && !('__restore' in (r2?.data || {})), { r, r2 });
      const g2 = (await api(A, 'DELETE', `/trades/${t1}`)).body?.deletion;
      r = await save(A, uA, { id: t1, pnl: 'stale', __restore: g1 });
      check('old undo (number 1) cannot lift deletion number 2', g2 === 2 && r.body?.skipped === 'deleted' && !(await has(A, t1)), { g2, r });
      r = await save(A, uA, { id: t1, pnl: 'ok', __restore: g2 });
      check('undo of the latest deletion works', r.body?.ok && !r.body?.skipped && await has(A, t1), r);
    });

    // 2. ids and owners
    await section('ids and owners', async () => {
      const imp = 'import.' + uid();
      await save(A, uA, { id: imp, pnl: '1' });
      const r = await api(A, 'DELETE', `/trades/${encodeURIComponent(imp)}`);
      check('non-numeric id can be saved and deleted', r.status === 200 && !(await has(A, imp)), r);
      const shared = uid();
      await save(A, uA, { id: shared, owner: 'A', pnl: '1' });
      await save(B, uB, { id: shared, owner: 'B', pnl: '2' });
      await api(B, 'DELETE', `/trades/${shared}`);
      const bTrades = (await api(B, 'GET', '/trades')).body;
      check('same id: B deleting does not touch A', await has(A, shared) && !(await has(B, shared)) && Array.isArray(bTrades) && !bTrades.some(t => t.owner === 'A'));
    });

    // 3. permissions: the guard functions and direct writes are refused for anon and signed-in users
    await section('permissions', async () => {
      // A real refusal: 401/403 with Postgres "insufficient privilege" (42501). A 5xx or any other error is a FAIL.
      const denied = r => (r.status === 401 || r.status === 403) && r.body?.code === '42501';
      const noRowsOrDenied = r => denied(r) || (r.status === 200 && Array.isArray(r.body) && r.body.length === 0);
      const brief = r => ({ status: r.status, code: r.body?.code ?? null });
      const target = uid();
      await save(A, uA, { id: target, pnl: 'perm' });
      const original = await row(target, uA);
      if (!original || original.deleted_at !== null) throw new Error('could not create the target trade');
      const unchanged = async () => canon(await row(target, uA)) === canon(original);
      for (const [role, h] of [['anon key', anonH()], ['signed-in user token', userH(A)]]) {
        const probe = 'stg-probe-' + uid();
        track(uA, probe);
        let r = await rest(h, 'POST', 'rpc/mj_save_trade', { p_id: probe, p_user_id: uA, p_data: { id: probe, hacked: true }, p_img_url: null, p_restore_gen: null });
        check(`${role}: mj_save_trade refused, nothing written`, denied(r) && !(await row(probe, uA)), brief(r));
        r = await rest(h, 'POST', 'rpc/mj_delete_trade', { p_id: target, p_user_id: uA });
        check(`${role}: mj_delete_trade refused, trade untouched`, denied(r) && await unchanged(), brief(r));
        r = await rest(h, 'POST', 'rpc/mj_guard_selftest', {});
        check(`${role}: mj_guard_selftest refused`, denied(r), brief(r));
        const ins = 'stg-probe-' + uid();
        track(uA, ins);
        r = await rest(h, 'POST', 'trades', { id: ins, user_id: uA, data: { id: ins, hacked: true } }, 'return=representation');
        check(`${role}: direct INSERT into trades refused, nothing written`, denied(r) && !(await row(ins, uA)), brief(r));
        r = await rest(h, 'PATCH', pairQuery(target, uA), { data: { id: target, hacked: true } }, 'return=representation');
        check(`${role}: direct UPDATE of trades changes nothing`, noRowsOrDenied(r) && await unchanged(), brief(r));
        r = await rest(h, 'DELETE', pairQuery(target, uA), null, 'return=representation');
        check(`${role}: direct DELETE from trades removes nothing`, noRowsOrDenied(r) && await unchanged(), brief(r));
        r = await rest(h, 'GET', 'trades?select=id&limit=5');
        check(`${role}: direct read of trades returns no rows (RLS)`, r.status === 200 && Array.isArray(r.body) && r.body.length === 0, brief(r));
      }
    });

    // 4. real concurrency through PostgREST
    await section('concurrency', async () => {
      const sleep = ms => new Promise(res => setTimeout(res, ms));
      const raceFails = [];
      for (let round = 0; round < 8; round++) {
        const x = uid();
        await save(A, uA, { id: x, pnl: 'base' });
        const ops = [];
        const delAt = Math.floor(Math.random() * 10);
        for (let i = 0; i < 10; i++) {
          ops.push((async () => { await sleep(Math.random() * 40); return save(A, uA, { id: x, pnl: 'p' + i }); })());
          if (i === delAt) ops.push((async () => { await sleep(Math.random() * 40); return api(A, 'DELETE', `/trades/${x}`); })());
        }
        const res = await Promise.all(ops);
        const rr = await row(x, uA);
        const ok = res.every(o => o.status === 200) && rr?.deleted_at && rr?.data?.pnl === undefined && !(await has(A, x));
        if (!ok) raceFails.push({ round, statuses: res.map(o => o.status), row: rr });
      }
      check('8 rounds: 10 parallel saves + 1 delete → always deleted, never re-created', raceFails.length === 0, raceFails);
      const y = uid();
      await save(A, uA, { id: y, pnl: '1' });
      const dels = await Promise.all(Array.from({ length: 5 }, () => api(A, 'DELETE', `/trades/${y}`)));
      const gens = dels.map(d => d.body?.deletion).sort((a, b) => a - b);
      check('5 parallel deletes get distinct numbers 1..5', JSON.stringify(gens) === '[1,2,3,4,5]' && (await row(y, uA))?.deleted_gen === 5, gens);
      const z = uid();
      await save(A, uA, { id: z, pnl: '1' });
      const gz = (await api(A, 'DELETE', `/trades/${z}`)).body?.deletion;
      const [undoRes, delRes] = await Promise.all([save(A, uA, { id: z, pnl: 'undo', __restore: gz }), api(A, 'DELETE', `/trades/${z}`)]);
      check('undo racing a newer delete always ends deleted', !(await has(A, z)) && (await row(z, uA))?.deleted_at, { undoRes: undoRes.body, delRes: delRes.body });
      const many = Array.from({ length: 20 }, () => uid());
      await Promise.all(many.map((id, i) => save(A, uA, { id, pnl: String(i) })));
      const got = await activeIds(A);
      check('20 parallel saves of different trades all stored', many.every(id => got.includes(id)), { missing: many.filter(id => !got.includes(id)).length });
    });

    // 5. health after all that
    await section('health afterwards', async () => {
      const h2 = await api(null, 'GET', '/health/db');
      check('health still both true afterwards', h2.status === 200 && h2.body?.deletion_guard === true && h2.body?.deletion_guard_selftest?.ok === true, { status: h2.status, deletion_guard: h2.body?.deletion_guard });
    });

    // 6. restore rehearsal: only the (id, user_id) pairs of the CSV, only if the database holds exactly them
    if (backup) await section('restore from CSV', () => restoreRehearsal(backup));
  } catch (e) {
    check(e instanceof Stop ? 'STOP: ' + e.message : 'run aborted', false, e instanceof Stop ? undefined : (e.message || String(e)));
  } finally {
    if (runRows.size) await cleanup().catch(e => check('cleanup of this run\'s test rows', false, e.message || String(e)));
  }

  async function restoreRehearsal({ rows, withGuard }) {
    const key = r => `${r.id}|${r.user_id}`;
    const keys = new Set(rows.map(key));
    const owners = [...new Set(rows.map(r => r.user_id))];
    const othersOf = async () => {
      const r = await rest(svcH(), 'GET', `trades?user_id=in.(${owners.join(',')})&select=*`);
      if (r.status !== 200 || !Array.isArray(r.body)) throw new Error(`reading the owners' other trades failed: HTTP ${r.status}`);
      return r.body.filter(x => !keys.has(key(x))).map(canon).sort();
    };
    // Snapshot and compare before deleting anything
    const snapshot = [];
    for (const b of rows) snapshot.push(await row(b.id, b.user_id));
    const differ = rows.filter((b, i) => !sameAsBackup(snapshot[i], b, withGuard)).map(key);
    if (!check(`restore: the test database holds exactly the ${rows.length} CSV rows before deleting`, differ.length === 0, { differ })) return;
    const othersBefore = await othersOf();

    const deleted = [];
    let failure = null;
    try {
      for (const b of rows) {
        const r = await rest(svcH(), 'DELETE', pairQuery(b.id, b.user_id), null, 'return=representation');
        if (r.status !== 200 || !Array.isArray(r.body) || r.body.length !== 1) throw new Error(`deleting ${key(b)} answered HTTP ${r.status}`);
        deleted.push(b);
      }
      const payload = rows.map(b => ({ id: b.id, user_id: b.user_id, data: b.data, img_url: b.img_url, created_at: b.created_at, ...(withGuard ? { deleted_at: b.deleted_at, deleted_gen: b.deleted_gen } : {}) }));
      const ins = await rest(svcH(), 'POST', 'trades', payload, 'return=minimal');
      if (ins.status >= 300) throw new Error(`insert answered HTTP ${ins.status}`);
    } catch (e) { failure = e.message; }

    const back = [];
    for (const b of rows) back.push(await row(b.id, b.user_id));
    const wrong = rows.filter((b, i) => !sameAsBackup(back[i], b, withGuard)).map(key);
    const othersSame = canon(await othersOf()) === canon(othersBefore);
    const ok = check(`restore: ${rows.length} CSV rows deleted and restored identically (all columns incl. created_at)`, !failure && deleted.length === rows.length && wrong.length === 0, { failure, deleted: deleted.length, wrong });
    check('restore: other trades of the same owners untouched', othersSame);
    if (ok) return;
    // Put the original rows back exactly as they were before the rehearsal
    const put = await rest(svcH(), 'POST', 'trades?on_conflict=id,user_id', snapshot, 'resolution=merge-duplicates,return=minimal');
    const after = [];
    for (const b of rows) after.push(await row(b.id, b.user_id));
    const notBack = rows.filter((b, i) => canon(after[i]) !== canon(snapshot[i])).map(key);
    check('restore: original rows put back after the failed rehearsal', put.status < 300 && notBack.length === 0, { status: put.status, notBack });
  }

  async function cleanup() {
    const byUser = new Map();
    for (const { u, id } of runRows.values()) byUser.set(u, [...(byUser.get(u) || []), id]);
    const inList = ids => encodeURIComponent(`(${ids.map(id => `"${id.replace(/["\\]/g, '\\$&')}"`).join(',')})`);
    const errors = [], left = [];
    for (const [u, ids] of byUser) {
      for (let i = 0; i < ids.length; i += 40) {
        const chunk = ids.slice(i, i + 40);
        const d = await rest(svcH(), 'DELETE', `trades?user_id=eq.${u}&id=in.${inList(chunk)}`, null, 'return=representation');
        if (d.status !== 200) errors.push({ user_id: u, status: d.status });
        const g = await rest(svcH(), 'GET', `trades?user_id=eq.${u}&id=in.${inList(chunk)}&select=id`);
        if (g.status !== 200 || !Array.isArray(g.body)) { errors.push({ user_id: u, verify: g.status }); left.push(...chunk.map(id => `${u}|${id} (unconfirmed)`)); }
        else left.push(...g.body.map(x => `${u}|${x.id}`));
      }
    }
    check(`cleanup: the ${runRows.size} test rows of this run are gone (read back)`, errors.length === 0 && left.length === 0, { errors, left_behind: left });
  }

  const failed = results.filter(x => x.result === 'FAIL').length;
  const exitCode = !failed ? 0 : (wrote ? 1 : 2);
  log(results);
  log(exitCode === 0 ? `All ${results.length} checks passed`
    : exitCode === 2 ? 'STOPPED before writing anything'
    : `${failed} check(s) FAILED`);
  log('Kept on purpose: the two test auth users and their account_links (reused by the next run).');
  return { results, exitCode };
}

module.exports = { run, parseCsv, parseBackup, normTimestamp, sameAsBackup, makeReport, ALLOWED_TEST_REF };

if (require.main === module) {
  const env = {};
  const envFile = path.join(__dirname, '..', '..', '.env.staging');
  for (const line of fs.readFileSync(envFile, 'utf8').replace(/^\uFEFF/, '').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/); if (m) env[m[1]] = m[2].trim();
  }
  const csvPath = process.argv[3] || null;
  run({
    env,
    server: process.argv[2] || 'http://127.0.0.1:3010',
    csvText: csvPath ? fs.readFileSync(csvPath, 'utf8') : null,
    log: x => (Array.isArray(x) ? console.table(x) : console.log(x)),
  }).then(r => process.exit(r.exitCode), e => { console.error('ERROR', e.message); process.exit(1); });
}
