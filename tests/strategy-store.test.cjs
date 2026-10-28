/*
 * Strategies on the device and on the server: runs the real STRATEGIES block
 * of index.html (documents, send queue, merge, revisions, text import,
 * numbers) in a sandbox with a fake API and fake per-account storage.
 *
 * Run:  node tests/strategy-store.test.cjs
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const cut = (from, to) => { const a = html.indexOf(from), b = html.indexOf(to, a); if (a < 0 || b < 0) throw new Error('block not found: ' + from); return html.slice(a, b); };
const COSTS = cut('function costNum(', '// The account\'s last choice');
const STRAT = cut('const SDOC_KEY', '//  STRATEGIES — screens');
const SAMPLE = fs.readFileSync(path.join(__dirname, 'fixtures', 'strategy-sample.md'), 'utf8');

function sandbox() {
  const store = new Map();                     // localStorage stand-in
  const server = { docs: new Map(), calls: [], down: false, status: 200, hold: null };
  const ctx = {
    lang: 'ru', dataOwner: 'web:A', ownerEpoch: 1, trades: [], warnings: [],
    console: { log() {}, warn() {}, error() {} },
    Number, Math, String, JSON, Object, Array, Date, Set, Map, Promise, RegExp, Error, isNaN, parseFloat, encodeURIComponent, decodeURIComponent,
    crypto: { randomUUID: () => require('crypto').randomUUID() },
    setTimeout: () => 0, clearTimeout: () => {},  // the tests drive the runner by hand
    window: { addEventListener() {} },
    scopedKey: (k, o) => (o ? 'mj:' + o + ':' + k : null),
    toastWarn: t => ctx.warnings.push(t),
  };
  ctx.isCurrentOwner = (o, e) => o === ctx.dataOwner && e === ctx.ownerEpoch;
  ctx.lsGet = (k, o = ctx.dataOwner) => store.get(ctx.scopedKey(k, o)) ?? null;
  ctx.lsSet = (k, v, o = ctx.dataOwner) => { store.set(ctx.scopedKey(k, o), v); return true; };
  ctx.lsJSON = (k, f, o = ctx.dataOwner) => { try { const v = ctx.lsGet(k, o); return v ? JSON.parse(v) : f; } catch (e) { return f; } };
  // the fake server answers like mj_save_doc / mj_delete_doc, per account
  const key = (owner, id) => owner + '|' + id;
  ctx.api = async (method, p, body) => {
    const owner = ctx.dataOwner;                 // the account of the request = signed in when it was sent
    server.calls.push({ method, p, body, owner });
    if (server.hold) await server.hold;
    if (server.down) { ctx.api._lastStatus = server.status; return null; }
    ctx.api._lastStatus = 200;
    if (method === 'GET') return { docs: [...server.docs.entries()].filter(([k]) => k.startsWith(owner + '|')).map(([, d]) => ({ ...d, data: d.deleted ? {} : d.data })) };
    if (method === 'POST') {
      const cur = server.docs.get(key(owner, body.id));
      if (!cur) { server.docs.set(key(owner, body.id), { id: body.id, kind: body.kind, data: body.data, v: body.v, deleted: false }); return { ok: true, outcome: 'saved' }; }
      if (cur.kind !== body.kind) return { ok: true, outcome: 'conflict' };
      if (cur.deleted) return { ok: true, outcome: 'deleted' };
      if (body.v === cur.v) return { ok: true, outcome: JSON.stringify(cur.data) === JSON.stringify(body.data) ? 'same' : 'collision' };
      if (body.v < cur.v) return { ok: true, outcome: 'stale' };
      if (body.kind === 'revision' && JSON.stringify(cur.data.content) !== JSON.stringify(body.data.content)) return { ok: true, outcome: 'immutable' };
      cur.data = body.data; cur.v = body.v; return { ok: true, outcome: 'saved' };
    }
    if (method === 'DELETE') {
      const u = new URL('http://x' + p), id = decodeURIComponent(u.pathname.split('/')[2]), v = Number(u.searchParams.get('v'));
      const cur = server.docs.get(key(owner, id));
      if (!cur) { server.docs.set(key(owner, id), { id, kind: u.searchParams.get('kind'), data: {}, v, deleted: true }); return { ok: true, outcome: 'deleted' }; }
      cur.deleted = true; cur.data = {}; cur.v = Math.max(cur.v, v); return { ok: true, outcome: 'deleted' };
    }
  };
  vm.createContext(ctx);
  vm.runInContext(COSTS + '\n' + STRAT + '\n;globalThis.__s = () => ({ sdocs, sdocStatus, sdocError });', ctx);
  return { ctx, store, server, docs: () => ctx.__s().sdocs, status: () => ctx.__s().sdocStatus, err: () => ctx.__s().sdocError };
}

const results = [];
const check = (name, ok, detail) => results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : String(JSON.stringify(detail)).slice(0, 300) });
const strategyData = (name, extra) => ({ name, version: '', sections: [{ id: 'sec_1', name: 'Вход', ordered: false, rules: ['BOS M5'] }], checklist: [], passport: {}, archived: false, ...extra });

(async () => {
  // ── text import ──
  {
    const { ctx } = sandbox();
    const r = ctx.parseStrategyText(SAMPLE);
    const names = r.sections.map(s => s.name);
    check('import: headings become sections', names.join('|') === 'Условия|Контекст и BIAS|Модель входа|Стоп и цели|Когда не торгую', names);
    const all = r.sections.flatMap(s => s.rules).concat(r.checklist);
    check('import: no task marks left', !all.some(x => /^\s*(\[[ xX✓✔vV]?\]|[☐☑☒□▢✅])/.test(x)), all.filter(x => /^\s*(\[|[☐☑☒□▢✅])/.test(x)));
    check('import: a range in brackets is kept', all.some(x => x.includes('[0,62–0,79]')), all);
    check('import: percent, minus and RR are kept', all.some(x => x.includes('1%')) && all.some(x => x.includes('−1,25')) && all.some(x => x.includes('1:2')), all);
    check('import: literal HTML stays text', all.some(x => x.includes('<script>alert(1)</script>')), all);
    check('import: checklist goes apart', r.checklist.length === 3 && r.checklist[0] === 'BIAS записан и не отменён.', r.checklist);
    check('import: numbered points keep order', r.sections.find(s => s.name === 'Модель входа').ordered === true);
    check('import: a long line is one point', all.some(x => x.length > 300), all.map(x => x.length));
    check('import: the source is kept whole', r.rawText === SAMPLE);
    const free = ctx.parseStrategyText('Торгую только Лондон.\nРиск 1%.\n\nНе торгую на новостях.');
    check('import: text without headings stays one section', free.sections.length === 1 && free.sections[0].rules.length === 3 && free.warnings.length >= 1, free);
    let threw = false; try { ctx.parseStrategyText('   '); } catch (e) { threw = true; }
    check('import: empty text is refused', threw);
    check('task mark only at the start', ctx.stripTaskMarker('- [ ] OTE [0,62–0,79] [x]') === 'OTE [0,62–0,79] [x]', ctx.stripTaskMarker('- [ ] OTE [0,62–0,79] [x]'));
    check('task marks: ☑ and [x]', ctx.stripTaskMarker('☑ готово') === 'готово' && ctx.stripTaskMarker('[x] готово') === 'готово');
  }

  // ── save, send, retry ──
  {
    const t = sandbox();
    const s = t.ctx.sdocPut('strategy', strategyData('A'));
    check('save: kept on the device first', JSON.parse(t.store.get('mj:web:A:strategy_docs_v1'))[s.id].data.name === 'A');
    check('save: unsent until the server confirms', t.ctx.sdocUnsent().length === 1 && t.status() === 'pending');
    await t.ctx.sdocSync();
    check('sync: delivered and confirmed', t.ctx.sdocUnsent().length === 0 && t.status() === 'synced' && t.server.docs.size === 1);
    // a lost answer: the server got it, the app retries the same version → «same», no duplicate
    t.docs()[s.id].sv = 0;
    await t.ctx.sdocSync();
    check('retry of a delivered version: no duplicate', t.server.docs.size === 1 && t.ctx.sdocUnsent().length === 0);
    // offline: stays unsent with an honest status
    t.server.down = true; t.server.status = 0;
    t.ctx.sdocPut('strategy', strategyData('A2'), s.id);
    await t.ctx.sdocSync();
    check('offline: stays unsent, status offline', t.ctx.sdocUnsent().length === 1 && t.status() === 'offline');
    t.server.status = 503;
    await t.ctx.sdocSync();
    check('server without the table: status unavailable', t.status() === 'unavailable');
    t.server.down = false;
    await t.ctx.sdocSync();
    check('back online: delivered', t.ctx.sdocUnsent().length === 0 && [...t.server.docs.values()][0].data.name === 'A2');
    // reload after closing the app: the device copy is read back
    const again = t.ctx.sdocRead();
    check('reopen: read back from the device', again[s.id].data.name === 'A2');
  }

  // ── an edit made while a request is on its way is not lost ──
  {
    const t = sandbox();
    const s = t.ctx.sdocPut('strategy', strategyData('v1'));
    let release; t.server.hold = new Promise(r => { release = r; });
    const p = t.ctx.sdocSync();
    t.ctx.sdocPut('strategy', strategyData('v2'), s.id);
    release(); t.server.hold = null;
    await p;
    check('edit during a request: the newer version is sent too', [...t.server.docs.values()][0].data.name === 'v2' && t.ctx.sdocUnsent().length === 0);
  }

  // ── two devices of one account take the same version number for different text ──
  const fixed = ms => class extends Date { static now() { return ms; } };
  {
    const a = sandbox(), b = sandbox();
    b.server.docs = a.server.docs;                                                        // one account, two devices
    a.ctx.Date = fixed(1000);
    const id = a.ctx.sdocPut('strategy', strategyData('base')).id;
    await a.ctx.sdocSync();
    await b.ctx.loadStrategies();
    a.ctx.Date = fixed(1001); b.ctx.Date = fixed(1001);
    const av = a.ctx.sdocPut('strategy', strategyData('edit A'), id).v, bv = b.ctx.sdocPut('strategy', strategyData('edit B'), id).v;
    await a.ctx.sdocSync(); await b.ctx.sdocSync();
    const srv = a.server.docs.get('web:A|' + id);
    check('equal version, other text: not confirmed as «same»', av === bv && srv.data.name === b.docs()[id].data.name && b.ctx.sdocUnsent().length === 0 && b.status() === 'synced', { av, bv, server: srv.data.name, deviceB: b.docs()[id].data.name, status: b.status() });
    check('equal version, other text: sent again with a higher number', srv.v === bv + 1 && srv.data.name === 'edit B', srv);
    await a.ctx.sdocLoadServer();
    check('equal version, other text: the other device ends with the account copy', a.docs()[id].data.name === 'edit B' && a.ctx.sdocUnsent().length === 0, a.docs()[id].data.name);
  }
  // ── two tabs on one device: the same number is noticed in the device storage ──
  {
    const a = sandbox(), b = sandbox();
    b.ctx.lsGet = (k, o = b.ctx.dataOwner) => a.store.get(b.ctx.scopedKey(k, o)) ?? null;   // one device storage
    b.ctx.lsSet = (k, v, o = b.ctx.dataOwner) => { a.store.set(b.ctx.scopedKey(k, o), v); return true; };
    b.server.docs = a.server.docs;
    a.ctx.Date = fixed(2000); b.ctx.Date = fixed(2000);
    const id = a.ctx.sdocPut('strategy', strategyData('base')).id;
    await a.ctx.sdocSync();
    vm.runInContext('sdocs = sdocRead()', b.ctx);
    a.ctx.Date = fixed(2001); b.ctx.Date = fixed(2001);
    const av = a.ctx.sdocPut('strategy', strategyData('edit A'), id).v, bv = b.ctx.sdocPut('strategy', strategyData('edit B'), id).v;
    check('equal version on the device: tab B keeps its edit under its own number', b.docs()[id].data.name === 'edit B' && bv > av, { av, bv, tabB: b.docs()[id].data.name });
    await a.ctx.sdocSync(); await b.ctx.sdocSync();
    check('equal version on the device: tab B’s edit reaches the account', a.server.docs.get('web:A|' + id).data.name === 'edit B' && b.ctx.sdocUnsent().length === 0, a.server.docs.get('web:A|' + id).data.name);
  }

  // ── a stale answer is about the version sent, not about an edit made meanwhile ──
  {
    const t = sandbox(), real = t.ctx.api;
    const s = t.ctx.sdocPut('strategy', strategyData('sent old edit'));
    let release; const hold = new Promise(r => { release = r; });
    let posts = 0;
    // every save is stale (another device is ahead) and the reload has no network
    t.ctx.api = async (method) => {
      if (method === 'POST') { posts++; await hold; t.ctx.api._lastStatus = 200; return { ok: true, outcome: 'stale' }; }
      t.ctx.api._lastStatus = 0; return null;
    };
    const p = t.ctx.sdocSync();
    t.ctx.sdocPut('strategy', strategyData('new edit during request'), s.id);
    release(); await p;
    check('stale + failed reload: the newer edit stays unsent', t.docs()[s.id].data.name === 'new edit during request' && t.ctx.sdocUnsent().length === 1 && t.status() !== 'synced', { doc: t.docs()[s.id], status: t.status() });
    await t.ctx.sdocSync();                                    // the later retry, still no reload
    check('stale + failed reload: still not «in the account» on the next run', t.ctx.sdocUnsent().length === 1 && t.status() !== 'synced', t.status());
    check('stale: no immediate resend loop', posts === 3, posts);
    t.ctx.api = real;                                          // the network is back
    await t.ctx.sdocSync();
    check('stale: the newer edit is delivered when the network is back', [...t.server.docs.values()][0]?.data.name === 'new edit during request' && t.ctx.sdocUnsent().length === 0 && t.status() === 'synced', t.status());
  }

  // ── device storage full: nothing is shown as saved or sent ──
  {
    const t = sandbox();
    const s = t.ctx.sdocPut('strategy', strategyData('kept'));
    const n = t.ctx.sdocPut('note', { strategyId: s.id, text: 'old note' });
    await t.ctx.sdocSync();
    const posts = () => t.server.calls.filter(c => c.method !== 'GET').length, before = posts();
    const realSet = t.ctx.lsSet;
    t.ctx.lsSet = () => { const e = new Error('quota'); e.name = 'QuotaExceededError'; throw e; };
    const fresh = t.ctx.sdocPut('note', { strategyId: s.id, text: 'new note' });
    check('storage full: a new document is not kept', fresh === null && t.err() === 'storage' && t.ctx.sdocAll('note').length === 1, { fresh, err: t.err() });
    const edit = t.ctx.sdocPut('strategy', strategyData('edited'), s.id);
    check('storage full: an edit is taken back', edit === null && t.docs()[s.id].data.name === 'kept' && t.ctx.sdocUnsent().length === 0, t.docs()[s.id].data.name);
    check('storage full: a deletion is taken back', t.ctx.sdocRemove(n.id) === false && t.err() === 'storage' && t.ctx.sdocAll('note').length === 1);
    await t.ctx.sdocSync();
    check('storage full: nothing is sent, status not «sending»', posts() === before && t.status() === 'synced', { sent: posts() - before, status: t.status() });
    check('storage full: the form says it, not a generic toast', t.ctx.warnings.length === 0, t.ctx.warnings);
    t.ctx.lsSet = realSet;
    const ok = t.ctx.sdocPut('note', { strategyId: s.id, text: 'new note' });
    check('space freed: the same save works', !!ok && t.err() === '' && t.ctx.sdocUnsent().length === 1);
  }

  // ── a refused save is not a confirmed one ──
  {
    const t = sandbox(), real = t.ctx.api;
    const d = t.ctx.sdocPut('strategy', strategyData('not stored'));
    let calls = 0;
    t.ctx.api = async () => { calls++; t.ctx.api._lastStatus = 200; return { ok: true, outcome: 'immutable' }; };
    await t.ctx.sdocSync();
    check('refused: not confirmed, honest status', t.status() === 'refused' && t.docs()[d.id].sv === 0 && t.docs()[d.id].data.name === 'not stored', { status: t.status(), doc: t.docs()[d.id] });
    await t.ctx.sdocSync();
    check('refused: not resent automatically', calls === 1 && t.ctx.sdocUnsent().length === 0 && t.status() === 'refused', { calls, status: t.status() });
    check('refused: remembered after reopening', t.ctx.sdocRead()[d.id].bad === d.v && t.ctx.sdocRead()[d.id].sv === 0);
    t.ctx.api = real;
    t.ctx.sdocPut('strategy', strategyData('edited again'), d.id);
    await t.ctx.sdocSync();
    check('refused: the next edit is sent again', t.status() === 'synced' && [...t.server.docs.values()][0]?.data.name === 'edited again', t.status());
  }

  // ── another device ──
  {
    const t = sandbox();
    const s = t.ctx.sdocPut('strategy', strategyData('mine'));
    await t.ctx.sdocSync();
    const srv = [...t.server.docs.values()][0];
    srv.data = strategyData('from phone'); srv.v += 1000;     // a newer save from another device
    t.ctx.sdocPut('strategy', strategyData('older edit here'), s.id);
    t.docs()[s.id].v = srv.v - 1;                              // this device's edit is older
    await t.ctx.sdocSync();
    check('stale: the newer version from another device is shown', t.docs()[s.id].data.name === 'from phone' && t.ctx.sdocUnsent().length === 0, t.docs()[s.id]);
    const n = t.ctx.sdocPut('note', { strategyId: s.id, text: 'x' });
    await t.ctx.sdocSync();
    t.server.docs.get('web:A|' + n.id).deleted = true;         // deleted on another device
    t.ctx.sdocPut('note', { strategyId: s.id, text: 'late edit' }, n.id);
    await t.ctx.sdocSync();
    check('a note deleted elsewhere does not come back', t.docs()[n.id].del === true && t.ctx.sdocAll('note').length === 0);
  }

  // ── deletions ──
  {
    const t = sandbox();
    const n = t.ctx.sdocPut('note', { strategyId: 's', text: 'наблюдение' });
    t.ctx.sdocRemove(n.id);
    await t.ctx.sdocSync();
    check('note deleted before it was sent: server keeps only a mark', t.server.docs.get('web:A|' + n.id).deleted === true && t.server.calls.filter(c => c.method === 'POST').length === 0);
    const s = t.ctx.sdocPut('strategy', strategyData('S'));
    check('a strategy can not be deleted (archived instead)', t.ctx.sdocRemove(s.id) === false);
  }

  // ── account switch while saving ──
  {
    const t = sandbox();
    const s = t.ctx.sdocPut('strategy', strategyData('A strategy'));
    let release; t.server.hold = new Promise(r => { release = r; });
    const p = t.ctx.sdocSync();
    // sign out, sign in as B (setDataOwner bumps the epoch and calls stratReset)
    t.ctx.dataOwner = 'web:B'; t.ctx.ownerEpoch++; t.ctx.stratReset();
    release(); t.server.hold = null;
    await p;
    check('switch: nothing of A in B\'s memory', Object.keys(t.docs()).length === 0, Object.keys(t.docs()));
    check('switch: B\'s device storage untouched', !t.store.has('mj:web:B:strategy_docs_v1'));
    check('switch: A\'s copy stays on A\'s device', !!JSON.parse(t.store.get('mj:web:A:strategy_docs_v1'))[s.id]);
    await t.ctx.loadStrategies();
    check('switch: B does not see A\'s strategy from the server', t.ctx.sdocAll('strategy').length === 0);
    t.ctx.dataOwner = 'web:A'; t.ctx.ownerEpoch++; t.ctx.stratReset();
    await t.ctx.loadStrategies();
    check('back to A: A\'s strategy is there', t.ctx.sdocAll('strategy').length === 1 && t.ctx.sdocUnsent().length === 0);
  }

  // ── revisions and trades ──
  {
    const t = sandbox();
    const s = t.ctx.sdocPut('strategy', strategyData('H4 → M5'));
    const link1 = t.ctx.stratTradeLink(s.id, null);
    check('trade link: points to a frozen revision', !!link1.strategyRevId && t.docs()[link1.strategyRevId].kind === 'revision' && link1.strategyName === 'H4 → M5');
    const link2 = t.ctx.stratTradeLink(s.id, null);
    check('same rules: the same revision is reused', link2.strategyRevId === link1.strategyRevId && t.ctx.sdocAll('revision').length === 1);
    const changed = strategyData('H4 → M5'); changed.sections[0].rules = ['BOS M5', 'OTE 0,62–0,79'];
    t.ctx.sdocPut('strategy', changed, s.id);
    const link3 = t.ctx.stratTradeLink(s.id, null);
    check('changed rules: a new revision', link3.strategyRevId !== link1.strategyRevId);
    check('the old revision keeps the old rules', JSON.stringify(t.docs()[link1.strategyRevId].data.content.sections[0].rules) === '["BOS M5"]');
    const kept = t.ctx.stratTradeLink(s.id, { strategyId: s.id, strategyRevId: link1.strategyRevId, strategyName: 'H4 → M5' });
    check('editing a trade keeps its revision', kept.strategyRevId === link1.strategyRevId);
    check('no strategy: empty link', t.ctx.stratTradeLink('', link1).strategyId === null);
    const rev = t.docs()[link1.strategyRevId];
    check('revision content can not be changed', t.ctx.sdocPut('revision', { ...rev.data, content: { ...rev.data.content, name: 'X' } }, rev.id) === null);
    check('revision notes can be added', !!t.ctx.sdocPut('revision', { ...rev.data, results: 'проверено' }, rev.id));
    await t.ctx.sdocSync();
    const order = t.server.calls.filter(c => c.method === 'POST').map(c => c.body.kind);
    check('revisions are sent before the strategy', order.indexOf('revision') < order.indexOf('strategy'), order);
    const fixed = t.ctx.stratEnsureRevision(s.id, { label: 'v1.1', what: 'добавил OTE', why: 'после разбора' });
    check('a fixed revision with notes is a new copy', fixed !== link3.strategyRevId && t.docs()[fixed].data.auto === false && t.docs()[fixed].data.label === 'v1.1');

    // numbers: only the strategy's own trades, in the period
    const today = new Date().toISOString().split('T')[0], old = '2020-01-01';
    t.ctx.trades.push(
      { id: '1', strategyId: s.id, result: 'win', pnl: '125', commission: '4.5', swap: '-1.25', pnlMode: 'gross', date: today, byPlan: true },
      { id: '2', strategyId: s.id, result: 'loss', pnl: '-40', pnlMode: 'gross', date: today },
      { id: '3', strategyId: s.id, result: 'win', pnl: '', date: today },
      { id: '4', strategyId: 'other', result: 'win', pnl: '999', date: today },
      { id: '5', result: 'win', pnl: '50', date: today },
      { id: '6', strategyId: s.id, result: 'win', pnl: '10', date: old },
    );
    const st = t.ctx.stratStats(t.ctx.stratTrades(s.id, 7));
    check('stats: only this strategy and period', st.count === 3, st);
    check('stats: total uses commission and swap', st.total === 79.25, st);
    check('stats: trades without money are counted apart', st.noMoney === 1 && st.withMoney === 2, st);
    check('stats: preliminary totals are counted', st.prelim === 1, st);
    check('stats: all time includes the old trade', t.ctx.stratStats(t.ctx.stratTrades(s.id, 'all')).count === 4);
    check('stats: empty selection is empty, not the journal', t.ctx.stratStats(t.ctx.stratTrades('nope', 'all')).count === 0);
  }

  console.table(results);
  const failed = results.filter(x => x.result === 'FAIL').length;
  console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
