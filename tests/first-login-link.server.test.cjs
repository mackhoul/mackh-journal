/*
 * Server check of the first web login: runs the real resolveWebUserId and
 * supabase() helper from server.js in a sandbox with a fake database that
 * behaves like PostgREST on account_links (primary key auth_id). No network,
 * no npm packages, no Supabase.
 *
 * Run:  node tests/first-login-link.server.test.cjs
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
const between = (from, to) => source.slice(source.indexOf(from), source.indexOf(to));
const linkPart = between('async function resolveWebUserId', '// ── Auth middleware');
const helperPart = between('// ── Supabase REST helper', '// ── Image upload');

// Fake account_links table. Each request waits a turn, so requests started
// together all read before any of them writes — like parallel HTTP requests.
// A POST without its own Prefer gets the helper's default (merge-duplicates).
function setup({ links = {}, loseRowAfterInsert = false, failAfterStore = false, sharedTable = null } = {}) {
  const table = sharedTable || new Map(Object.entries(links));
  const calls = [], logs = [];
  let failed = false;
  const turn = () => new Promise(r => setTimeout(r, 0));
  const db = async (method, p, body, prefer) => {
    calls.push({ method, path: p, body, prefer });
    await turn();
    if (method === 'GET' && p.startsWith('account_links?auth_id=eq.')) {
      const id = p.slice('account_links?auth_id=eq.'.length).split('&')[0];
      return table.has(id) ? [{ ...table.get(id) }] : [];
    }
    if (method === 'POST' && p.startsWith('account_links')) {
      const mode = prefer || 'resolution=merge-duplicates,return=representation';
      if (table.has(body.auth_id) && /ignore-duplicates/.test(mode)) return [];
      table.set(body.auth_id, { ...body });
      if (loseRowAfterInsert) table.delete(body.auth_id);
      // the row is stored but the answer is lost (timeout, dropped connection)
      if (failAfterStore && !failed) { failed = true; throw new Error('network error after the insert'); }
      return [{ ...body }];
    }
    throw new Error(`unexpected request ${method} ${p}`);
  };
  const ctx = {
    supabase: db, Date, Math, Number, String, JSON, Error,
    console: { log: m => logs.push(String(m)), warn() {}, error() {} },
  };
  vm.createContext(ctx); vm.runInContext(linkPart, ctx);
  return { resolve: u => ctx.resolveWebUserId(u), table, calls, logs };
}

const results = [];
const check = (name, ok, detail) => results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : JSON.stringify(detail) });

(async () => {
  const a = { id: '11111111-1111-1111-1111-111111111111', email: 'a@example.com' };
  const b = { id: '22222222-2222-2222-2222-222222222222', email: 'b@example.com' };

  // 1. First login: the app sends /trades, /settings, ... at once
  let s = setup();
  let ids = await Promise.all([1, 2, 3, 4, 5].map(() => s.resolve(a)));
  const stored = Number(s.table.get(a.id)?.user_id);
  check('parallel first login: every request gets the same user_id', new Set(ids).size === 1, ids);
  check('parallel first login: that user_id is the stored link', ids.every(id => id === stored), { ids, stored });
  check('parallel first login: "linked new web account" logged once',
    s.logs.filter(l => l.includes('linked new web account')).length === 1, s.logs);
  check('link POST never overwrites an existing link',
    s.calls.filter(c => c.method === 'POST').every(c => /ignore-duplicates/.test(c.prefer || '')), s.calls.map(c => c.prefer));

  // 1b. (review ad36a0b) Two server processes share only the database: each runs its
  //     own copy of resolveWebUserId (no shared memory), two and then six first
  //     requests of one account overlap across them
  const shared = new Map();
  const p1 = setup({ sharedTable: shared }), p2 = setup({ sharedTable: shared });
  const pair = await Promise.all([p1.resolve(a), p2.resolve(a)]);
  check('two processes, two first requests: one user_id, the stored one',
    pair[0] === pair[1] && pair[0] === Number(shared.get(a.id).user_id), { pair, stored: shared.get(a.id) });
  const sharedB = new Map();
  const q1 = setup({ sharedTable: sharedB }), q2 = setup({ sharedTable: sharedB });
  const group = await Promise.all([q1, q2, q1, q2, q1, q2].map(p => p.resolve(b)));
  check('two processes, six first requests: one user_id, the stored one, no POST overwrote it',
    new Set(group).size === 1 && group[0] === Number(sharedB.get(b.id).user_id)
      && [...q1.calls, ...q2.calls].filter(c => c.method === 'POST').every(c => /ignore-duplicates/.test(c.prefer || '')), { group });

  // 2. Two accounts logging in at the same time stay apart
  s = setup();
  const [ra, rb] = await Promise.all([s.resolve(a), s.resolve(b), s.resolve(a), s.resolve(b)]).then(r => [r[0], r[1]]);
  check('two new accounts at once: different ids, each one stored',
    ra !== rb && ra === Number(s.table.get(a.id).user_id) && rb === Number(s.table.get(b.id).user_id),
    { ra, rb, table: [...s.table.values()] });

  // 3. Existing link: read only, nothing written
  s = setup({ links: { [a.id]: { auth_id: a.id, user_id: '1700000000000123', email: a.email } } });
  ids = await Promise.all([s.resolve(a), s.resolve(a)]);
  check('existing link: stored id returned, no write',
    ids.every(id => id === 1700000000000123) && !s.calls.some(c => c.method === 'POST'), { ids, calls: s.calls });

  // 4. Link missing even after the insert: fail instead of using an id nobody stored
  s = setup({ loseRowAfterInsert: true });
  let threw = false, got;
  try { got = await s.resolve(a); } catch { threw = true; }
  check('no stored link after insert: request fails, no made-up id', threw, { got });

  // 4b. (review ad36a0b) The link POST fails with an unknown outcome: that request
  //     fails; the next one uses the stored link, never the lost made-up id
  s = setup({ failAfterStore: true });
  let firstFailed = false;
  try { await s.resolve(a); } catch { firstFailed = true; }
  const next = await s.resolve(a);
  check('unknown outcome of the link write: that request fails, the next uses the stored id',
    firstFailed && next === Number(s.table.get(a.id).user_id), { firstFailed, next, stored: s.table.get(a.id) });

  // 4c. (review ad36a0b) Parallel first requests that write a trade and settings:
  //     a later request of the same account finds both under its one owner
  s = setup();
  const owned = [];                                             // rows written under the id each request got
  await Promise.all([
    s.resolve(a).then(id => owned.push({ table: 'trades', id: 'first-trade', user_id: id })),
    s.resolve(a).then(id => owned.push({ table: 'users', user_id: id, base_capital: 1000 })),
    s.resolve(a).then(() => null),
  ]);
  const later = await s.resolve(a);
  check('parallel first writes (trade + settings): all under the owner a later request uses',
    owned.length === 2 && owned.every(r => r.user_id === later), { owned, later });

  // 4d. The auth middleware: Telegram users never go through the web link; a failed
  //     link answers 500 and the route does not run with any id
  const authPart = between('async function auth(', '// ── Routes');
  const runAuth = async ({ headers, resolve }) => {
    let status = 200, nextCalled = false, resolveCalls = 0;
    const actx = {
      validateTelegramAuth: () => true, getUserId: () => 424242,
      verifySupabaseToken: async () => ({ id: a.id, email: a.email }),
      resolveWebUserId: async u => { resolveCalls++; return resolve(u); },
      console: { log() {}, warn() {}, error() {} },
    };
    vm.createContext(actx); vm.runInContext(authPart, actx);
    const req = { headers }, res = { status: n => { status = n; return res; }, json: () => res };
    await actx.auth(req, res, () => { nextCalled = true; });
    return { status, nextCalled, resolveCalls, userId: req.userId };
  };
  let r = await runAuth({ headers: { 'x-telegram-init-data': 'ok' }, resolve: () => 1 });
  check('Telegram request: own Telegram id, web link never touched', r.nextCalled && r.userId === 424242 && r.resolveCalls === 0, r);
  r = await runAuth({ headers: { authorization: 'Bearer t' }, resolve: () => { throw new Error('link failed'); } });
  check('web request with a failed link: 500, route not run, no user id', r.status === 500 && !r.nextCalled && r.userId === undefined, r);

  // 5. The helper sends the Prefer it is given; other POSTs keep merge-duplicates
  const sent = [];
  const hctx = {
    SUPABASE_URL: 'https://test.invalid', SUPABASE_SERVICE_KEY: 'k', JSON, Error,
    fetch: async (url, opts) => { sent.push({ url, prefer: opts.headers.Prefer }); return { ok: true, text: async () => '[]' }; },
  };
  vm.createContext(hctx); vm.runInContext(helperPart, hctx);
  await hctx.supabase('POST', 'trades?on_conflict=id,user_id', {});
  await hctx.supabase('POST', 'account_links?on_conflict=auth_id', {}, 'resolution=ignore-duplicates,return=representation');
  await hctx.supabase('GET', 'account_links?auth_id=eq.x');
  check('helper: default POST still merge-duplicates', sent[0].prefer === 'resolution=merge-duplicates,return=representation', sent[0]);
  check('helper: explicit Prefer is sent as given', sent[1].prefer === 'resolution=ignore-duplicates,return=representation', sent[1]);
  check('helper: GET has no Prefer', sent[2].prefer === '', sent[2]);

  console.table(results);
  const failed = results.filter(x => x.result === 'FAIL').length;
  console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error('ERROR', e); process.exit(1); });
