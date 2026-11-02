/*
 * Server check of what a backup file may write: runs the real POST /trades and
 * POST /settings handlers from server.js in a sandbox with a small fake database
 * (no network, no npm packages, no Supabase). The database decides at the moment
 * of the write, so a value that appeared after the check above it still stays.
 * Real PostgREST is not involved: the exact requests are asserted here and have
 * to be run on the test Supabase before a release.
 * MJ_SERVER may point at another copy of server.js.
 *
 * Run:  node tests/import-add-only.server.test.cjs
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('node:assert/strict');

const source = fs.readFileSync(process.env.MJ_SERVER || path.join(__dirname, '..', 'server.js'), 'utf8');
const slice = (a, b) => {
  const i = source.indexOf(a), j = source.indexOf(b, i);
  assert.ok(i >= 0 && j > i, 'server.js has ' + a);
  return source.slice(i, j);
};
const part = slice('let deletionGuard = null', '// GET /settings') + slice('// POST /settings', '// ── Subscriptions');

const UID = 9;
const IGNORE = 'resolution=ignore-duplicates,return=representation';

function pgError(status, body) {
  const e = new Error('Supabase: ' + JSON.stringify(body));
  e.status = status; e.pg = body; return e;
}

// A row in `rows` is { id, data, img_url, deleted_at }. `appear` runs just before an
// insert, as if another device wrote between the check and this write.
function setup({ guard = true, rows = [], users = null, appear = null, failProbe = null, uploaded = 'https://img/new.jpg' } = {}) {
  const routes = {}, calls = [], uploads = [];
  const db = new Map(rows.map(r => [String(r.id), { img_url: null, deleted_at: null, ...r }]));
  const state = { users };
  const store = async (method, p, body, prefer) => {
    calls.push({ method, path: p, body, prefer });
    if (p === 'trades?select=deleted_gen&limit=1') {
      if (failProbe) throw failProbe;
      if (!guard) throw pgError(400, { code: '42703', message: 'column trades.deleted_gen does not exist' });
      return [];
    }
    if (method === 'GET' && p.startsWith('trades?id=eq.')) {
      if (!guard) assert.ok(!p.includes('deleted_at'), 'no such column without the migration: ' + p);
      const id = decodeURIComponent(p.slice('trades?id=eq.'.length, p.indexOf('&')));
      assert.ok(p.includes(`user_id=eq.${UID}`), 'only this account: ' + p);
      return db.has(id) ? [db.get(id)] : [];
    }
    if (method === 'POST' && p === 'trades?on_conflict=id,user_id') {
      if (prefer !== IGNORE) throw new Error('an upsert would replace the row: ' + prefer);
      if (appear) { appear(db); appear = null; }
      if (db.has(String(body.id))) return [];
      db.set(String(body.id), { ...body, deleted_at: null });
      return [db.get(String(body.id))];
    }
    if (method === 'POST' && p === 'rpc/mj_save_trade') { db.set(String(body.p_id), { id: body.p_id, data: body.p_data, img_url: body.p_img_url, deleted_at: null }); return 'saved'; }
    if (method === 'POST' && p === 'users?on_conflict=user_id') {
      if (prefer === undefined) { state.users = { ...body }; return [state.users]; }             // the ordinary save
      assert.equal(prefer, IGNORE, 'a fill never replaces the row');
      if (appear) { appear(state); appear = null; }
      if (state.users) return [];
      state.users = { ...body };
      return [state.users];
    }
    if (method === 'PATCH' && p.startsWith(`users?user_id=eq.${UID}&or=`)) {
      if (appear) { appear(state); appear = null; }
      if (!state.users) return null;
      if (p.endsWith('or=(base_capital.is.null,base_capital.eq.0)')) { if (!(parseFloat(state.users.base_capital) > 0)) Object.assign(state.users, body); return null; }
      if (p.endsWith('or=(goals.is.null,goals.eq."[]")')) { if (!(state.users.goals || []).length) Object.assign(state.users, body); return null; }
      throw new Error('unknown filter: ' + p);
    }
    if (method === 'GET' && p.startsWith(`users?user_id=eq.${UID}`)) return state.users ? [state.users] : [];
    throw new Error('unexpected request ' + method + ' ' + p);
  };
  const ctx = {
    app: Object.fromEntries(['get', 'post', 'delete'].map(m => [m, (p, auth, h) => { routes[m + ' ' + p] = h; }])),
    auth: () => {}, console: { log() {}, warn() {}, error() {} },
    uploadImage: async (u, img) => { uploads.push(img); return uploaded; }, shortErr: e => String(e?.message || e),
    Date, Number, JSON, Object, String, Array, encodeURIComponent, parseFloat, isFinite, RegExp,
    supabase: store,
  };
  vm.createContext(ctx); vm.runInContext(part, ctx);
  const call = async (route, req) => {
    let status = 200, body;
    const res = { status: n => { status = n; return res; }, json: b => { body = JSON.parse(JSON.stringify(b)); return res; } };
    await routes[route]({ userId: UID, params: {}, query: {}, ...req }, res);
    return { status, body };
  };
  return { call, calls, uploads, db, state, wrote: () => calls.filter(c => c.method !== 'GET').map(c => c.path) };
}
const addOnly = (s, body) => s.call('post /trades', { body, query: { add_only: '1' } });
const fill = (s, body) => s.call('post /settings', { body, query: { fill_empty: '1' } });
const OLD = { id: 'x', data: { id: 'x', pnl: '999', notes: 'newer' } };

let n = 0, failed = 0;
const T = async (id, fn) => {
  try { await fn(); n++; console.log('PASS ' + id); }
  catch (e) { failed++; console.log('FAIL ' + id + ' :: ' + String(e.message).split('\n')[0].slice(0, 140)); }
};

(async () => {
  // Trades
  await T('add only: a new trade is inserted and the answer is an ordinary success', async () => {
    const s = setup();
    const r = await addOnly(s, { id: 'n1', pnl: '7' });
    assert.equal(r.status, 200); assert.equal(r.body.ok, true); assert.equal(r.body.skipped, undefined);
    assert.equal(s.db.get('n1').data.pnl, '7'); assert.equal(s.db.get('n1').user_id, UID);
  });
  await T('add only: never goes through the saving function, which would replace the row', async () => {
    const s = setup();
    await addOnly(s, { id: 'n1', pnl: '7' });
    assert.ok(!s.calls.some(c => c.path === 'rpc/mj_save_trade'));
    assert.equal(s.calls.find(c => c.path === 'trades?on_conflict=id,user_id').prefer, IGNORE);
  });
  await T('add only: an existing trade stays and comes back in the answer', async () => {
    const s = setup({ rows: [OLD] });
    const r = await addOnly(s, { id: 'x', pnl: '7' });
    assert.equal(r.body.skipped, 'exists'); assert.equal(r.body.trade.pnl, '999');
    assert.equal(s.db.get('x').data.pnl, '999'); assert.deepEqual(s.wrote(), []);
  });
  await T('add only: a trade that appears right before the insert stays too', async () => {
    const s = setup({ appear: db => db.set('x', { ...OLD, img_url: null, deleted_at: null }) });
    const r = await addOnly(s, { id: 'x', pnl: '7' });
    assert.equal(r.body.skipped, 'exists'); assert.equal(r.body.trade.pnl, '999');
    assert.equal(s.db.get('x').data.pnl, '999');
  });
  await T('add only: a deleted trade stays deleted', async () => {
    const s = setup({ rows: [{ id: 'x', data: { id: 'x', deleted: true }, deleted_at: '2026-11-01' }] });
    const r = await addOnly(s, { id: 'x', pnl: '7' });
    assert.equal(r.body.skipped, 'deleted'); assert.equal(r.body.trade, undefined);
    assert.deepEqual(s.wrote(), []);
  });
  await T('add only: deleted right before the insert stays deleted too', async () => {
    const s = setup({ appear: db => db.set('x', { id: 'x', data: { id: 'x', deleted: true }, deleted_at: '2026-11-01' }) });
    const r = await addOnly(s, { id: 'x', pnl: '7' });
    assert.equal(r.body.skipped, 'deleted');
  });
  await T('add only: no picture is uploaded for a trade that is not going to be saved', async () => {
    const s = setup({ rows: [OLD] });
    await addOnly(s, { id: 'x', img: 'data:image/png;base64,AAAA' });
    assert.equal(s.uploads.length, 0);
  });
  await T('add only: a new trade with a picture stores the address, never the picture', async () => {
    const s = setup();
    const r = await addOnly(s, { id: 'n1', img: 'data:image/png;base64,AAAA' });
    assert.equal(r.body.img_url, 'https://img/new.jpg');
    assert.equal(s.db.get('n1').img_url, 'https://img/new.jpg'); assert.equal('img' in s.db.get('n1').data, false);
  });
  await T('add only: the stored picture address comes back with the existing trade', async () => {
    const s = setup({ rows: [{ ...OLD, img_url: 'https://img/old.jpg' }] });
    const r = await addOnly(s, { id: 'x' });
    assert.equal(r.body.trade.img_url, 'https://img/old.jpg');
  });
  await T('add only: the undo field is neither stored nor answered', async () => {
    const s = setup({ rows: [{ id: 'x', data: { id: 'x', __restore: 4 } }] });
    assert.equal('__restore' in (await addOnly(s, { id: 'x' })).body.trade, false);
    const t = setup();
    await addOnly(t, { id: 'n1', __restore: 4 });
    assert.equal('__restore' in t.db.get('n1').data, false);
  });
  await T('add only: an id is encoded and the look-up stays inside this account', async () => {
    const s = setup();
    await addOnly(s, { id: 'a&user_id=eq.1' });
    const look = s.calls.find(c => c.method === 'GET' && c.path.startsWith('trades?id=eq.')).path;
    assert.ok(look.startsWith('trades?id=eq.a%26user_id%3Deq.1&user_id=eq.9'), look);
  });
  await T('add only: the id rule is the same as for any save', async () => {
    const s = setup();
    assert.equal((await addOnly(s, { pnl: '1' })).status, 400);
    assert.equal((await addOnly(s, { id: 'x'.repeat(129) })).status, 400);
    assert.deepEqual(s.wrote(), []);
  });
  await T('add only: without the migration it works the same, with no deletion column', async () => {
    const s = setup({ guard: false, rows: [OLD] });
    assert.equal((await addOnly(s, { id: 'x', pnl: '7' })).body.skipped, 'exists');
    assert.equal((await addOnly(s, { id: 'n1', pnl: '7' })).body.ok, true);
    assert.equal(s.db.get('x').data.pnl, '999'); assert.ok(s.db.has('n1'));
  });
  await T('add only: a failed check of the database stops the request, nothing is written', async () => {
    const s = setup({ failProbe: pgError(503, { message: 'Service Unavailable' }) });
    assert.equal((await addOnly(s, { id: 'n1' })).status, 500);
    assert.deepEqual(s.wrote(), []);
  });
  await T('an ordinary save is unchanged: it goes through the saving function and replaces', async () => {
    const s = setup({ rows: [OLD] });
    const r = await s.call('post /trades', { body: { id: 'x', pnl: '8' } });
    assert.equal(r.body.ok, true); assert.equal(r.body.skipped, undefined);
    assert.ok(s.calls.some(c => c.path === 'rpc/mj_save_trade')); assert.equal(s.db.get('x').data.pnl, '8');
  });

  // Settings
  await T('fill: an account without a row gets both values', async () => {
    const s = setup();
    const r = await fill(s, { base_capital: 700, goals: [{ id: 'g' }] });
    assert.equal(r.body.base_capital, 700); assert.deepEqual(r.body.goals.map(g => g.id), ['g']);
    assert.equal(s.state.users.user_id, UID);
  });
  await T('fill: values already there stay and come back in the answer', async () => {
    const s = setup({ users: { base_capital: 9000, goals: [{ id: 'remote' }] } });
    const r = await fill(s, { base_capital: 700, goals: [{ id: 'g' }] });
    assert.equal(r.body.base_capital, 9000); assert.deepEqual(r.body.goals.map(g => g.id), ['remote']);
    assert.equal(s.state.users.base_capital, 9000);
  });
  await T('fill: each value is checked on its own, whatever the other one holds', async () => {
    const a = setup({ users: { base_capital: 9000, goals: [] } });
    const ra = await fill(a, { base_capital: 700, goals: [{ id: 'g' }] });
    assert.equal(ra.body.base_capital, 9000); assert.deepEqual(ra.body.goals.map(g => g.id), ['g']);
    const b = setup({ users: { base_capital: 0, goals: [{ id: 'remote' }] } });
    const rb = await fill(b, { base_capital: 700, goals: [{ id: 'g' }] });
    assert.equal(rb.body.base_capital, 700); assert.deepEqual(rb.body.goals.map(g => g.id), ['remote']);
  });
  await T('fill: a null in the database counts as empty', async () => {
    const s = setup({ users: { base_capital: null, goals: null } });
    const r = await fill(s, { base_capital: 700, goals: [{ id: 'g' }] });
    assert.equal(r.body.base_capital, 700); assert.deepEqual(r.body.goals.map(g => g.id), ['g']);
  });
  await T('fill: the filter is part of the write, so a value set right before it stays', async () => {
    const s = setup({ users: { base_capital: 0, goals: [] }, appear: st => { if (st.users) st.users.base_capital = 9000; } });
    const r = await fill(s, { base_capital: 700, goals: [] });
    assert.equal(s.state.users.base_capital, 9000); assert.equal(r.body.base_capital, 9000);
    const p = s.calls.filter(c => c.method === 'PATCH');
    assert.equal(p.length, 1); assert.deepEqual(Object.keys(p[0].body).sort(), ['base_capital', 'updated_at']);
  });
  await T('fill: a row created right before the insert is not replaced', async () => {
    const s = setup({ appear: st => { st.users = { base_capital: 9000, goals: [{ id: 'remote' }] }; } });
    const r = await fill(s, { base_capital: 700, goals: [{ id: 'g' }] });
    assert.equal(r.body.base_capital, 9000); assert.deepEqual(r.body.goals.map(g => g.id), ['remote']);
  });
  await T('fill: nothing to fill means nothing is sent to the row', async () => {
    const s = setup({ users: { base_capital: 0, goals: [] } });
    const r = await fill(s, { base_capital: 0, goals: [] });
    assert.equal(s.calls.filter(c => c.method === 'PATCH').length, 0);
    assert.equal(r.body.base_capital, 0); assert.deepEqual(r.body.goals, []);
  });
  await T('fill: wrong values are refused before any write', async () => {
    const s = setup();
    assert.equal((await fill(s, { base_capital: 'abc', goals: [] })).status, 400);
    assert.equal((await fill(s, { base_capital: 1, goals: 'x' })).status, 400);
    assert.deepEqual(s.wrote(), []);
  });
  await T('an ordinary settings save is unchanged: it writes both values', async () => {
    const s = setup({ users: { base_capital: 9000, goals: [{ id: 'remote' }] } });
    const r = await s.call('post /settings', { body: { base_capital: 700, goals: [] } });
    assert.equal(r.body.ok, true); assert.equal(s.state.users.base_capital, 700); assert.deepEqual(s.state.users.goals, []);
  });

  if (failed) { console.error(failed + ' failed, ' + n + ' passed'); process.exit(1); }
  console.log('All ' + n + ' import add-only server checks passed');
})().catch(e => { console.error(e); process.exit(1); });
