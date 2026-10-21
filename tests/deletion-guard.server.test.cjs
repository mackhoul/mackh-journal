/*
 * Server check of the deletion guard: runs the real GET/POST/DELETE /trades
 * handlers and hasDeletionGuard from server.js in a sandbox with a fake
 * database function (no network, no npm packages, no Supabase).
 *
 * Run:  node tests/deletion-guard.server.test.cjs
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const part = source.slice(source.indexOf('let deletionGuard = null'), source.indexOf('// GET /settings'));

function pgError(status, body, pathText) {
  const e = new Error(`Supabase GET ${pathText}: ${JSON.stringify(body)}`);
  e.status = status; e.pg = body; return e;
}
function setup(db) {
  const routes = {}, calls = [];
  let now = 1_000_000;
  class FakeDate extends Date { static now() { return now; } }
  const ctx = {
    app: Object.fromEntries(['get', 'post', 'delete'].map(m => [m, (p, auth, h) => { routes[m + ' ' + p] = h; }])),
    auth: () => {}, console: { log() {}, warn() {}, error() {} },
    uploadImage: async () => null, shortErr: e => String(e?.message || e),
    Date: FakeDate, Number, JSON, Object, String, encodeURIComponent, RegExp,
    supabase: async (method, p, body) => { calls.push({ method, path: p, body }); return db(method, p, body); },
  };
  vm.createContext(ctx); vm.runInContext(part, ctx);
  const call = async (route, req) => {
    let status = 200, body; const res = { status: n => { status = n; return res; }, json: b => { body = b; return res; } };
    await routes[route]({ userId: 9, params: {}, ...req }, res);
    return { status, body };
  };
  return { call, calls, tick: ms => { now += ms; } };
}

const results = [];
const check = (name, ok, detail) => results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : JSON.stringify(detail) });

(async () => {
  // 1. Any probe failure other than "column deleted_gen does not exist" must not fall back to unprotected writes
  const failures = {
    '503 temporary error': pgError(503, { message: 'Service Unavailable' }, 'trades?select=deleted_gen&limit=1'),
    '403 permission denied': pgError(403, { code: '42501', message: 'permission denied for table trades' }, 'trades?select=deleted_gen&limit=1'),
    'network error': new Error('fetch failed (trades?select=deleted_gen&limit=1)'),
    '42703 about another column': pgError(400, { code: '42703', message: 'column trades.other does not exist' }, 'trades?select=deleted_gen&limit=1'),
  };
  for (const [name, err] of Object.entries(failures)) {
    const s = setup((m, p) => { if (p === 'trades?select=deleted_gen&limit=1') throw err; return 'saved'; });
    const r = await s.call('post /trades', { body: { id: '100', pnl: '5' } });
    const raw = s.calls.some(c => c.path.startsWith('trades?on_conflict') || (c.method === 'DELETE'));
    check(`probe ${name}: request fails, no unprotected write`, r.status === 500 && !raw, { r, calls: s.calls.map(c => c.path) });
  }

  // 2. Migration not applied (real 42703 for deleted_gen): legacy mode, re-checked after 10 s
  let applied = false;
  const db2 = (m, p, body) => {
    if (p === 'trades?select=deleted_gen&limit=1') {
      if (!applied) throw pgError(400, { code: '42703', message: 'column trades.deleted_gen does not exist' }, p);
      return [];
    }
    if (p === 'rpc/mj_save_trade') return 'saved';
    if (p === 'rpc/mj_delete_trade') return 3;
    return [];
  };
  const s2 = setup(db2);
  let r = await s2.call('post /trades', { body: { id: '101', pnl: '5' } });
  check('no migration: legacy upsert works', r.status === 200 && s2.calls.some(c => c.path === 'trades?on_conflict=id,user_id'));
  applied = true;
  s2.tick(5_000);
  await s2.call('post /trades', { body: { id: '102', pnl: '5' } });
  check('no migration: OFF trusted only briefly', s2.calls.filter(c => c.path === 'trades?on_conflict=id,user_id').length === 2);
  s2.tick(6_000);
  await s2.call('post /trades', { body: { id: '103', pnl: '5' } });
  check('migration run: guarded path within ~10 s, no restart', s2.calls.some(c => c.path === 'rpc/mj_save_trade' && c.body.p_id === '103'));

  // 3. Guarded paths
  const deletedIds = new Set();
  const s3 = setup((m, p, body) => {
    if (p === 'trades?select=deleted_gen&limit=1') return [];
    if (p === 'rpc/mj_save_trade') return deletedIds.has(String(body.p_id)) && body.p_restore_gen !== 4 ? 'deleted' : 'saved';
    if (p === 'rpc/mj_delete_trade') { deletedIds.add(String(body.p_id)); return 4; }
    if (p.startsWith('trades?user_id=eq.9')) return [{ id: '1', data: { id: '1', pnl: '1', __restore: 4 }, img_url: null }];
    return [];
  });
  r = await s3.call('get /trades', {});
  const getPath = s3.calls.find(c => c.path.startsWith('trades?user_id=eq.9'))?.path || '';
  check('GET hides deleted rows and strips the undo field', getPath.includes('deleted_at=is.null') && r.body[0] && !('__restore' in r.body[0]), { getPath, body: r.body });
  r = await s3.call('delete /trades/:id', { params: { id: 'import.42' } });
  check('DELETE answers with the deletion number', r.status === 200 && r.body.deletion === 4 && s3.calls.some(c => c.path === 'rpc/mj_delete_trade'), r);
  r = await s3.call('post /trades', { body: { id: 'import.42', pnl: '7' } });
  check('late save of a deleted trade: 200 skipped (old clients drop it)', r.status === 200 && r.body.skipped === 'deleted', r);
  const before = s3.calls.length;
  r = await s3.call('post /trades', { body: { id: 'import.42', pnl: '8', __restore: 4 } });
  const rpc = s3.calls.slice(before).find(c => c.path === 'rpc/mj_save_trade');
  check('undo passes the deletion number, field not stored', r.body.ok && !r.body.skipped && rpc.body.p_restore_gen === 4 && !('__restore' in rpc.body.p_data), rpc.body);
  await s3.call('post /trades', { body: { id: 'x1', pnl: '1', __restore: true } });
  await s3.call('post /trades', { body: { id: 'x2', pnl: '1', __restore: '4' } });
  const gens = s3.calls.filter(c => c.path === 'rpc/mj_save_trade' && ['x1', 'x2'].includes(c.body.p_id)).map(c => c.body.p_restore_gen);
  check('only a positive integer counts as an undo number', JSON.stringify(gens) === '[null,null]', gens);
  r = await s3.call('delete /trades/:id', { params: { id: 'bad\u0001id' } });
  check('invalid id still rejected', r.status === 400);

  console.table(results);
  const failed = results.filter(x => x.result === 'FAIL').length;
  console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error('ERROR', e); process.exit(1); });
