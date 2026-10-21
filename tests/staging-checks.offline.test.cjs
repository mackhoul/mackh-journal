/*
 * Offline check of the staging script's safeguards (db/staging/02-staging-checks.cjs).
 * Runs the real script against an in-memory fake Supabase (a small PostgREST
 * subset with RLS and function privileges) and a fake local server with the
 * deletion-guard rules. No network, no keys, no real database.
 *
 * Run:  node tests/staging-checks.offline.test.cjs
 */
const S = require('../db/staging/02-staging-checks.cjs');

const REF = S.ALLOWED_TEST_REF;
const SB = `https://${REF}.supabase.co`;
const SRV = 'http://127.0.0.1:3010';
const jwt = claims => 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify(claims)).toString('base64url') + '.sig';
const KEYS = { anon: jwt({ ref: REF, role: 'anon' }), service: jwt({ ref: REF, role: 'service_role' }) };
const baseEnv = () => ({
  SUPABASE_URL: SB, SUPABASE_ANON_KEY: KEYS.anon, SUPABASE_SERVICE_ROLE_KEY: KEYS.service,
  TEST_USER_A_EMAIL: 'test-a@example.com', TEST_USER_A_PASSWORD: 'pw-a',
  TEST_USER_B_EMAIL: 'test-b@example.com', TEST_USER_B_PASSWORD: 'pw-b',
});
const canon = v => Array.isArray(v) ? `[${v.map(canon).join(',')}]` : v && typeof v === 'object' ? `{${Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}` : JSON.stringify(v);

// Made-up backup rows; one data field spans two lines and holds quotes and a comma
const FIXTURES = [
  { id: '1700000000001', user_id: 900001, data: { id: '1700000000001', pnl: '10', pair: 'TEST_EURUSD' }, img_url: 'https://example.test/a.jpg', created_at: '2026-10-21T20:12:31.254071' },
  { id: '1700000000001', user_id: 900002, data: { id: '1700000000001', pnl: '7', pair: 'TEST_OTHER_OWNER' }, img_url: null, created_at: '2026-10-21T20:12:31.254071' },
  { id: '1700000000002', user_id: 900001, data: { id: '1700000000002', pnl: '-5' }, img_url: null, created_at: '2026-10-21T20:12:31.25' },
  { id: 'import.42', user_id: 900001, data: { id: 'import.42', note: 'say "hi", ok' }, img_url: null, created_at: '2026-10-21T20:12:31' },
].map(r => ({ ...r, deleted_at: null, deleted_gen: 0 }));
// Same owner, not in the CSV: must never be touched
const UNRELATED = { id: 'keep-me', user_id: 900001, data: { id: 'keep-me', pnl: '99' }, img_url: null, created_at: '2026-10-20T10:00:00', deleted_at: null, deleted_gen: 0 };

const q = s => s === null ? '' : `"${String(s).replace(/"/g, '""')}"`;
const csvOf = (rows, { guard = false } = {}) => [
  'id,user_id,data,img_url,created_at' + (guard ? ',deleted_at,deleted_gen' : ''),
  ...rows.map(r => [r.id, r.user_id, q(JSON.stringify(r.data, null, 1)), r.img_url === null ? '' : r.img_url, r.created_at.replace('T', ' ')]
    .concat(guard ? [r.deleted_at === null ? '' : r.deleted_at, r.deleted_gen] : []).join(',')),
].join('\r\n') + '\r\n';
const CSV = csvOf(FIXTURES);

function world(faults = {}) {
  const key = (id, u) => `${id}|${u}`;
  const store = new Map();
  for (const r of [...FIXTURES, UNRELATED, ...(faults.extraRows || [])]) store.set(key(r.id, r.user_id), JSON.parse(JSON.stringify(r)));
  if (faults.mutate) faults.mutate(store);
  const initial = canon([...store.values()].sort((a, b) => key(a.id, a.user_id) < key(b.id, b.user_id) ? -1 : 1));
  const U = { A: 1760000000000001, B: 1760000000000002 };
  const TOK = { A: jwt({ ref: REF, role: 'authenticated', sub: 'a' }), B: jwt({ ref: REF, role: 'authenticated', sub: 'b' }) };
  const calls = [];
  const resp = (status, body) => ({ status, text: async () => body === undefined ? '' : typeof body === 'string' ? body : JSON.stringify(body) });

  const parseFilter = v => {
    if (v.startsWith('eq.')) { const x = v.slice(3); return s => s === x; }
    if (v === 'is.null') return s => s === 'null';
    if (v.startsWith('in.(') && v.endsWith(')')) {
      const items = []; let cur = '', inQ = false, quoted = false;
      for (const c of v.slice(4, -1) + ',') {
        if (inQ) { if (c === '"') inQ = false; else cur += c; }
        else if (c === '"') { inQ = true; quoted = true; }
        else if (c === ',') { items.push(cur); cur = ''; quoted = false; }
        else cur += c;
      }
      return s => items.includes(s);
    }
    throw new Error('fake PostgREST: unsupported filter ' + v);
  };
  const select = params => {
    const tests = [];
    for (const [k, v] of params) if (['id', 'user_id', 'deleted_at'].includes(k)) tests.push([k, parseFilter(v)]);
    return [...store.values()].filter(r => tests.every(([k, t]) => t(r[k] === null ? 'null' : String(r[k]))));
  };

  async function server(u, init) {
    const m = init.method, p = u.pathname;
    if (p === '/config') return faults.config ? faults.config() : resp(200, { supabase_url: SB, supabase_anon_key: KEYS.anon, web_auth_ready: true });
    if (p === '/health/db') return faults.health ? faults.health() : resp(200, { ok: true, deletion_guard: true, deletion_guard_selftest: { ok: true } });
    const a = init.headers?.Authorization;
    const uid = a === 'Bearer ' + TOK.A ? U.A : a === 'Bearer ' + TOK.B ? U.B : null;
    if (!uid) return resp(401, { error: 'Unauthorized' });
    if (p === '/trades' && m === 'GET') {
      return resp(200, [...store.values()].filter(r => r.user_id === uid && r.deleted_at === null).map(r => ({ ...r.data, ...(r.img_url ? { img_url: r.img_url } : {}) })));
    }
    if (p === '/trades' && m === 'POST') {
      const t = JSON.parse(init.body);
      const restore = Number.isSafeInteger(t.__restore) && t.__restore > 0 ? t.__restore : null;
      delete t.__restore;
      const r = store.get(key(t.id, uid));
      if (!r) store.set(key(t.id, uid), { id: String(t.id), user_id: uid, data: t, img_url: null, created_at: '2026-10-21T12:00:00.123456', deleted_at: null, deleted_gen: 0 });
      else if (r.deleted_at === null || (restore !== null && r.deleted_gen === restore)) Object.assign(r, { data: t, deleted_at: null });
      else return resp(200, { ok: true, skipped: 'deleted' });
      return resp(200, { ok: true, img_url: null, img_failed: false });
    }
    if (p.startsWith('/trades/') && m === 'DELETE') {
      const id = decodeURIComponent(p.slice('/trades/'.length));
      const r = store.get(key(id, uid));
      const gen = (r?.deleted_gen || 0) + 1;
      store.set(key(id, uid), { id, user_id: uid, data: { id, deleted: true }, img_url: null, created_at: r?.created_at || '2026-10-21T12:00:00', deleted_at: '2026-10-21T12:00:01.000001+00:00', deleted_gen: gen });
      return resp(200, { ok: true, deletion: gen });
    }
    return resp(404, {});
  }

  async function supabase(u, init) {
    const m = init.method, p = u.pathname, h = init.headers || {};
    const bearer = (h.Authorization || '').replace(/^Bearer /, '');
    const role = bearer === KEYS.service ? 'service' : bearer === KEYS.anon ? 'anon' : Object.values(TOK).includes(bearer) ? 'user' : null;
    const prefer = h.Prefer || '';
    if (p === '/auth/v1/token') {
      const b = JSON.parse(init.body);
      const who = b.email === 'test-a@example.com' && b.password === 'pw-a' ? 'A' : b.email === 'test-b@example.com' && b.password === 'pw-b' ? 'B' : null;
      return who ? resp(200, { access_token: TOK[who] }) : resp(400, { error: 'invalid_grant' });
    }
    if (p === '/rest/v1/account_links' && role === 'service') {
      const email = (u.searchParams.get('email') || '').replace(/^eq\./, '');
      return resp(200, email === 'test-a@example.com' ? [{ user_id: U.A }] : email === 'test-b@example.com' ? [{ user_id: U.B }] : []);
    }
    if (p.startsWith('/rest/v1/rpc/')) {
      if (faults.rpc) return faults.rpc(p, role);
      return role === 'service' ? resp(200, null) : resp(role === 'anon' ? 401 : 403, { code: '42501', message: 'permission denied for function ' + p.slice(13) });
    }
    if (p !== '/rest/v1/trades') return resp(404, {});
    const f = faults.trades && faults.trades(m, u, role, init);
    if (f) return f;
    if (role !== 'service') {
      if (m === 'GET' || m === 'PATCH' || m === 'DELETE') return resp(200, []);
      return resp(role === 'anon' ? 401 : 403, { code: '42501', message: 'new row violates row-level security policy for table "trades"' });
    }
    if (m === 'GET') return resp(200, JSON.parse(JSON.stringify(select(u.searchParams))));
    if (m === 'DELETE') {
      const rows = select(u.searchParams);
      for (const r of rows) store.delete(key(r.id, r.user_id));
      return prefer.includes('return=representation') ? resp(200, rows) : resp(204);
    }
    if (m === 'POST') {
      const body = [].concat(JSON.parse(init.body));
      const merge = u.searchParams.has('on_conflict') && prefer.includes('merge-duplicates');
      if (!merge && body.some(r => store.has(key(r.id, r.user_id)))) return resp(409, { code: '23505' });
      for (const r of body) {
        const row = { img_url: null, created_at: '2026-10-21T12:00:00', deleted_at: null, deleted_gen: 0, ...(merge ? store.get(key(r.id, r.user_id)) : {}), ...r, id: String(r.id) };
        // Postgres keeps timestamps as values: text comes back in one canonical form
        row.created_at = row.created_at.replace(' ', 'T').replace(/(\.\d*?)0+$/, '$1').replace(/\.$/, '');
        if (row.deleted_at) row.deleted_at = row.deleted_at.replace(' ', 'T').replace(/\+00$/, '+00:00');
        store.set(key(r.id, r.user_id), faults.onInsert && !merge ? faults.onInsert(row) : row);
      }
      return resp(201);
    }
    return resp(405, {});
  }

  const fetch = async (url, init = {}) => {
    const u = new URL(url);
    calls.push({ origin: u.origin, method: init.method, path: u.pathname, search: decodeURIComponent(u.search), auth: !!init.headers?.Authorization, apikey: !!init.headers?.apikey, redirect: init.redirect });
    if (u.origin === SRV) return server(u, init);
    if (u.origin === SB) return supabase(u, init);
    return resp(200, {});   // any other host "answers": the script must never ask it
  };
  const snapshot = () => canon([...store.values()].sort((a, b) => key(a.id, a.user_id) < key(b.id, b.user_id) ? -1 : 1));
  return { fetch, calls, store, initial, snapshot, resp, U };
}

const go = (w, over = {}) => S.run({ env: { ...baseEnv(), ...(over.env || {}) }, server: over.server || SRV, csvText: 'csv' in over ? over.csv : CSV, fetch: w.fetch, log: () => {} });
const failed = r => r.results.filter(x => x.result === 'FAIL').map(x => x.check);
const results = [];
const check = (name, ok, detail) => results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok || detail === undefined ? '' : String(JSON.stringify(detail)).slice(0, 400) });

(async () => {
  // ── report helper (finding 6) ──
  const rep = S.makeReport();
  let threw = null;
  try { rep.check('edit', false); rep.check('x', false, { tok: 'Bearer ' + KEYS.service }); } catch (e) { threw = e.message; }
  check('check() without detail records FAIL instead of throwing', !threw && rep.results[0].result === 'FAIL' && rep.results[0].detail === '', { threw, r: rep.results });
  check('check() hides tokens in details', !rep.results[1].detail.includes('eyJ') && rep.results[1].detail.includes('[token]'), rep.results[1]);

  // ── happy path ──
  let w = world();
  let r = await go(w);
  check('happy path: every check passes, exit 0', r.exitCode === 0 && failed(r).length === 0, failed(r));
  check('happy path: database ends exactly as it started (run rows removed, backup rows identical, unrelated row kept)', w.snapshot() === w.initial);
  check('happy path: only the test project and the local server are contacted', w.calls.every(c => c.origin === SB || c.origin === SRV), [...new Set(w.calls.map(c => c.origin))]);
  check('every request refuses redirects', w.calls.every(c => c.redirect === 'error'));
  const firstSecret = w.calls.findIndex(c => c.auth || c.apikey);
  check('no key or token is sent before /config and /health/db of the local server were checked', firstSecret === 2 && w.calls[0].path === '/config' && w.calls[1].path === '/health/db', w.calls.slice(0, 3));
  const svcDeletes = w.calls.filter(c => c.origin === SB && c.method === 'DELETE' && c.path === '/rest/v1/trades');
  check('every DELETE names exact ids (never a whole owner)', svcDeletes.length > 0 && svcDeletes.every(c => /[?&]id=(eq|in)\./.test(c.search)), svcDeletes.map(c => c.search));
  check('permission checks cover 3 functions + insert/update/delete/read for both roles', r.results.filter(x => /^(anon key|signed-in user token):/.test(x.check)).length === 14);
  check('restore check compares created_at too', r.results.some(x => /incl\. created_at/.test(x.check) && x.result === 'PASS'));

  // CSV export made after the migration (with deletion columns) also restores identically
  const marker = { id: '1700000000009', user_id: 900002, data: { id: '1700000000009', deleted: true }, img_url: null, created_at: '2026-10-21T20:12:31.254071', deleted_at: '2026-10-21 20:30:00.123456+00', deleted_gen: 3 };
  w = world({ extraRows: [{ ...marker, deleted_at: '2026-10-21T20:30:00.123456+00:00' }] });
  r = await go(w, { csv: csvOf([...FIXTURES, marker], { guard: true }) });
  check('post-migration CSV (deleted_at, deleted_gen) restores identically', r.exitCode === 0 && w.snapshot() === w.initial, failed(r));

  // ── target checks (finding 1): stop with no request at all ──
  const noNetwork = async (name, over) => {
    const w0 = world();
    const r0 = await go(w0, over);
    check(`STOP, no request sent: ${name}`, r0.exitCode === 2 && w0.calls.length === 0 && r0.results.some(x => x.check.startsWith('STOP')), { exit: r0.exitCode, calls: w0.calls.length, failed: failed(r0) });
  };
  await noNetwork('another Supabase project', { env: { SUPABASE_URL: 'https://unapprovedref.supabase.co' } });
  await noNetwork('SUPABASE_URL with a path', { env: { SUPABASE_URL: SB + '/rest/v1/' } });
  await noNetwork('SUPABASE_URL over http', { env: { SUPABASE_URL: `http://${REF}.supabase.co` } });
  await noNetwork('remote server', { server: 'https://other-server.invalid' });
  await noNetwork('server with a path', { server: SRV + '/api' });
  await noNetwork('server look-alike host', { server: 'http://127.0.0.1.evil.test:3010' });
  await noNetwork('service key of another project', { env: { SUPABASE_SERVICE_ROLE_KEY: jwt({ ref: 'otherproject', role: 'service_role' }) } });
  await noNetwork('anon key in place of the service key', { env: { SUPABASE_SERVICE_ROLE_KEY: KEYS.anon } });
  await noNetwork('key that is not a JWT', { env: { SUPABASE_ANON_KEY: 'sb_publishable_xxx' } });
  await noNetwork('real-looking test user email', { env: { TEST_USER_A_EMAIL: 'andrei@gmail.com' } });
  await noNetwork('missing password', { env: { TEST_USER_B_PASSWORD: '' } });

  // the server is asked only public, key-less questions before it is trusted
  const keyless = async (name, faults) => {
    const w0 = world(faults);
    const r0 = await go(w0);
    check(`STOP before any key leaves: ${name}`, r0.exitCode === 2 && w0.calls.every(c => !c.auth && !c.apikey && c.origin === SRV) && w0.snapshot() === w0.initial, { exit: r0.exitCode, calls: w0.calls });
  };
  await keyless('local server runs against another project', { config: () => w.resp(200, { supabase_url: 'https://otherproject.supabase.co' }) });
  await keyless('local server /config redirects', { config: () => w.resp(302, '') });
  await keyless('local server has no Supabase configured', { config: () => w.resp(200, { supabase_url: null }) });
  await keyless('guard off in /health/db', { health: () => w.resp(200, { ok: true, deletion_guard: false }) });
  await keyless('selftest not ok', { health: () => w.resp(200, { ok: true, deletion_guard: true, deletion_guard_selftest: { ok: false } }) });
  await keyless('/health/db 503', { health: () => w.resp(503, { ok: false }) });

  // ── CSV checked fully before any request (finding 2) ──
  const lines = CSV.split('\r\n');
  const badCsv = {
    'invalid JSON in data': CSV.replace('""pnl"": ""-5""', '""pnl"": -5,,'),
    'unterminated quote': CSV.slice(0, -10),
    'wrong header': CSV.replace('img_url,created_at', 'image,created_at'),
    'duplicate (id, user_id)': CSV + lines[1] + '\r\n',
    'bad created_at': CSV.replace('2026-10-21 20:12:31.25', '21.10.2026'),
    'missing field': CSV + '123,900001,"{}"\r\n',
    'blank line in the middle': CSV.replace('\r\n1700000000002', '\r\n\r\n1700000000002'),
    'text after a closing quote': CSV.replace('"{', 'x"{'),
    'data is an array': CSV + '555,900001,"[1]",,2026-10-21 10:00:00\r\n',
    'header only': lines[0] + '\r\n',
    'empty file': '',
  };
  for (const [name, csv] of Object.entries(badCsv)) await noNetwork('bad CSV — ' + name, { csv });
  const parsed = S.parseBackup(CSV);
  check('CSV parser: quotes, commas and a line break inside a field', parsed.rows.length === 4 && parsed.rows[3].data.note === 'say "hi", ok' && parsed.rows[1].img_url === null && parsed.rows[2].created_at === '2026-10-21T20:12:31.250000', parsed.rows);

  // database differs from the CSV → nothing of the backup is deleted
  w = world({ mutate: st => { st.get('1700000000002|900001').data.pnl = '-6'; } });
  r = await go(w);
  check('database differs from the CSV → restore stops before deleting, data unchanged', failed(r).length === 1 && /holds exactly/.test(failed(r)[0]) && w.snapshot() === w.initial && r.exitCode === 1, failed(r));
  w = world({ mutate: st => st.delete('import.42|900001') });
  r = await go(w);
  check('a CSV row missing in the database → restore stops before deleting', failed(r).length === 1 && w.snapshot() === w.initial, failed(r));

  // restored created_at differs (finding 4) → FAIL, and the original rows are put back
  w = world({ onInsert: row => (row.created_at === '2026-10-21T20:12:31.254071' && !row.deleted_at ? { ...row, created_at: '2000-01-01T00:00:00' } : row) });
  r = await go(w);
  check('restored created_at differs → FAIL', failed(r).some(x => /restored identically/.test(x)), failed(r));
  check('…and the original rows are put back afterwards', r.results.some(x => /put back/.test(x.check) && x.result === 'PASS'), r.results.filter(x => /restore/.test(x.check)));
  check('…database ends exactly as it started', w.snapshot() === w.initial);

  // the insert fails after the delete → FAIL, original rows put back
  w = world({ trades: (m, u, role) => (m === 'POST' && role === 'service' && !u.searchParams.has('on_conflict') ? w.resp(500, { message: 'boom' }) : null) });
  r = await go(w);
  check('restore insert fails → FAIL, original rows put back, nothing lost', failed(r).length === 1 && /restored identically/.test(failed(r)[0]) && w.snapshot() === w.initial, failed(r));

  // ── permissions (finding 5) ──
  w = world({ rpc: () => w.resp(503, { message: 'Service Unavailable' }) });
  r = await go(w);
  const rpcFails = failed(r).filter(x => /mj_/.test(x));
  check('RPC answering 503 is a FAIL, not "permission denied"', rpcFails.length === 6 && r.exitCode === 1, failed(r));
  w = world({ rpc: (p, role) => w.resp(role === 'anon' ? 401 : 403, { code: 'PGRST301', message: 'JWT expired' }) });
  r = await go(w);
  check('401/403 with a non-permission error code is a FAIL', failed(r).filter(x => /mj_/.test(x)).length === 6, failed(r));
  w = world({ trades: (m, u, role, init) => {
    if (m === 'POST' && role === 'anon') { const b = JSON.parse(init.body); w.store.set(`${b.id}|${b.user_id}`, { ...b, img_url: null, created_at: '2026-10-21T12:00:00', deleted_at: null, deleted_gen: 0 }); return w.resp(201, [b]); }
    if (m === 'PATCH' && role === 'user') return w.resp(200, [{ changed: true }]);
    return null;
  } });
  r = await go(w);
  check('anon INSERT that succeeds → FAIL', failed(r).includes('anon key: direct INSERT into trades refused, nothing written'), failed(r));
  check('user UPDATE that changes a row → FAIL', failed(r).includes('signed-in user token: direct UPDATE of trades changes nothing'), failed(r));
  check('…the row the probe managed to insert is still removed by cleanup', w.snapshot() === w.initial && r.results.some(x => /^cleanup/.test(x.check) && x.result === 'PASS'));

  // ── cleanup (finding 3) ──
  w = world({ trades: (m, u, role) => (m === 'DELETE' && role === 'service' && u.searchParams.get('id')?.startsWith('in.') ? w.resp(503, { message: 'down' }) : null) });
  r = await go(w);
  const cl = r.results.find(x => /^cleanup/.test(x.check));
  check('cleanup answering 503 → FAIL, exit 1, left-over rows listed', cl?.result === 'FAIL' && r.exitCode === 1 && /left_behind/.test(cl.detail) && /1760000000000001\|/.test(cl.detail), cl);
  w = world({ trades: (m, u, role) => (m === 'DELETE' && role === 'service' && u.searchParams.get('id')?.startsWith('in.') ? w.resp(200, []) : null) });
  r = await go(w);
  check('cleanup that says 200 but deletes nothing → FAIL (read back)', r.results.find(x => /^cleanup/.test(x.check))?.result === 'FAIL');
  w = world({ trades: (m, u, role) => {
    if (!(m === 'DELETE' && role === 'service' && u.searchParams.get('id')?.startsWith('in.'))) return null;
    const ids = u.searchParams.get('id').slice(4, -1).split(',').map(s => s.replace(/^"|"$/g, ''));
    for (const id of ids) w.store.delete(`${id}|${u.searchParams.get('user_id').slice(3)}`);
    return w.resp(500, { message: 'timeout after commit' });
  } });
  r = await go(w);
  check('cleanup that deletes but answers 500 → still FAIL (status is checked)', r.results.find(x => /^cleanup/.test(x.check))?.result === 'FAIL' && r.exitCode === 1);

  // an exception inside a section is reported, later sections run, cleanup still runs
  let reads = 0;
  w = world({ trades: (m, u, role) => (m === 'GET' && role === 'service' && ++reads === 2 ? w.resp(503, { message: 'down' }) : null) });
  r = await go(w);
  check('exception in a section → named FAIL, later sections still run, cleanup still runs', failed(r).includes('save/delete/undo: ran to the end') && r.results.some(x => /parallel deletes/.test(x.check)) && r.results.some(x => /^cleanup/.test(x.check) && x.result === 'PASS') && r.exitCode === 1, failed(r));
  w = world();
  r = await S.run({ env: baseEnv(), server: SRV, csvText: null, fetch: async (url, init) => { const res = await w.fetch(url, init); if (url.includes('account_links')) throw new TypeError('fetch failed'); return res; }, log: () => {} });
  check('abort after sign-in still runs cleanup and exits 1', r.exitCode === 1 && r.results.some(x => x.check === 'run aborted'), r.results);

  console.table(results);
  const bad = results.filter(x => x.result === 'FAIL').length;
  console.log(bad ? `${bad} check(s) FAILED` : `All ${results.length} checks passed`);
  process.exit(bad ? 1 : 0);
})().catch(e => { console.error('ERROR', e); process.exit(1); });
