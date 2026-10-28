/*
 * Server check of the strategy document routes: runs the real GET/POST/DELETE
 * /strategy-docs handlers from server.js in a sandbox with a fake database
 * (no network, no npm packages, no Supabase).
 *
 * Run:  node tests/strategy-docs.server.test.cjs
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const idRule = source.slice(source.indexOf('function isValidTradeId'), source.indexOf('// POST /trades'));
const part = source.slice(source.indexOf('// ── Strategy documents'), source.indexOf('// GET /settings'));

function pgError(status, code) { const e = new Error('Supabase: ' + code); e.status = status; e.pg = { code, message: code }; return e; }
function setup(db) {
  const routes = {}, calls = [];
  const ctx = {
    app: Object.fromEntries(['get', 'post', 'delete'].map(m => [m, (p, auth, h) => { routes[m + ' ' + p] = h; }])),
    auth: () => {}, console: { log() {}, warn() {}, error() {} },
    Number, JSON, Object, String, Array, RegExp,
    supabase: async (method, p, body) => { calls.push({ method, path: p, body }); return db(method, p, body); },
  };
  vm.createContext(ctx); vm.runInContext(idRule + '\n' + part, ctx);
  const call = async (route, req) => {
    let status = 200, body; const res = { status: n => { status = n; return res; }, json: b => { body = b; return res; } };
    await routes[route]({ userId: 9, params: {}, query: {}, body: {}, ...req }, res);
    return { status, body };
  };
  return { call, calls };
}

const results = [];
const check = (name, ok, detail) => results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : JSON.stringify(detail) });

(async () => {
  // GET: the account's rows only, deletion marks without content
  let t = setup(async () => [
    { id: 'str_1', kind: 'strategy', data: { name: 'A' }, v: '12', deleted_at: null },
    { id: 'note_1', kind: 'note', data: { text: 'old' }, v: 3, deleted_at: '2026-10-28T10:00:00Z' },
  ]);
  let r = await t.call('get /strategy-docs', {});
  check('GET asks only for this account', /user_id=eq\.9&/.test(t.calls[0].path), t.calls[0]);
  check('GET returns documents with numeric versions', r.body.docs[0].v === 12 && r.body.docs[0].data.name === 'A', r.body);
  check('GET returns a deletion mark without content', r.body.docs[1].deleted === true && JSON.stringify(r.body.docs[1].data) === '{}', r.body);

  // POST goes through mj_save_doc with the account from auth, never from the body
  t = setup(async (m, p) => (p === 'rpc/mj_save_doc' ? 'saved' : null));
  r = await t.call('post /strategy-docs', { body: { id: 'str_1', kind: 'strategy', data: { name: 'B' }, v: 5, user_id: 777 } });
  check('POST saves through mj_save_doc', t.calls[0].path === 'rpc/mj_save_doc' && r.body.outcome === 'saved', { calls: t.calls, r });
  check('POST uses the signed-in account, not the body', t.calls[0].body.p_user_id === 9, t.calls[0].body);
  for (const [name, body] of [
    ['no id', { kind: 'note', data: {}, v: 1 }],
    ['numeric id', { id: 5, kind: 'note', data: {}, v: 1 }],
    ['id with a control character', { id: 'a\nb', kind: 'note', data: {}, v: 1 }],
    ['unknown kind', { id: 'a', kind: 'trade', data: {}, v: 1 }],
    ['version 0', { id: 'a', kind: 'note', data: {}, v: 0 }],
    ['fractional version', { id: 'a', kind: 'note', data: {}, v: 1.5 }],
    ['array data', { id: 'a', kind: 'note', data: [], v: 1 }],
  ]) {
    const tt = setup(async () => 'saved');
    const rr = await tt.call('post /strategy-docs', { body });
    check(`POST refuses ${name}`, rr.status === 400 && tt.calls.length === 0, rr);
  }
  t = setup(async () => 'saved');
  r = await t.call('post /strategy-docs', { body: { id: 'a', kind: 'strategy', data: { text: 'x'.repeat(400 * 1024) }, v: 1 } });
  check('POST refuses a document over the size limit', r.status === 413 && t.calls.length === 0, r.status);
  for (const outcome of ['same', 'stale', 'deleted', 'immutable', 'conflict']) {
    t = setup(async () => outcome);
    r = await t.call('post /strategy-docs', { body: { id: 'a', kind: 'note', data: {}, v: 1 } });
    check(`POST passes the outcome «${outcome}» to the app`, r.status === 200 && r.body.outcome === outcome, r);
  }

  // DELETE: kind and version from the query, account from auth
  t = setup(async () => 'deleted');
  r = await t.call('delete /strategy-docs/:id', { params: { id: 'note_1' }, query: { kind: 'note', v: '44' } });
  check('DELETE goes through mj_delete_doc', t.calls[0].path === 'rpc/mj_delete_doc' && t.calls[0].body.p_v === 44 && t.calls[0].body.p_user_id === 9 && r.body.outcome === 'deleted', { calls: t.calls, r });
  t = setup(async () => 'deleted');
  r = await t.call('delete /strategy-docs/:id', { params: { id: 'note_1' }, query: { kind: 'note' } });
  check('DELETE without a version is refused', r.status === 400 && t.calls.length === 0, r);

  // Before the migration: 503, so the app keeps the documents on the device
  for (const code of ['42P01', 'PGRST205', 'PGRST202', '42883']) {
    t = setup(async () => { throw pgError(404, code); });
    r = await t.call('get /strategy-docs', {});
    check(`missing store (${code}) → 503`, r.status === 503 && r.body.error === 'strategy_store_unavailable', r);
  }
  t = setup(async () => { throw pgError(500, 'XX000'); });
  r = await t.call('post /strategy-docs', { body: { id: 'a', kind: 'note', data: {}, v: 1 } });
  check('other database error → 500, not 503', r.status === 500, r);

  console.table(results);
  const failed = results.filter(x => x.result === 'FAIL').length;
  console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
  process.exit(failed ? 1 : 0);
})();
