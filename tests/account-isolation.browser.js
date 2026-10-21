/*
 * Account isolation regression check (audit item 1).
 *
 * How to run:
 *   1. Serve the project:  python -m http.server 8080
 *   2. Open http://localhost:8080/index.html?test=1 in a browser.
 *      If this origin was used before, first run  localStorage.clear()  in the
 *      console and reload, so the page does not boot with an old session.
 *   3. Paste this whole file into the DevTools console. It prints PASS/FAIL per check.
 *
 * Everything runs against an in-page mock backend with two fictional accounts
 * (A and B). window.fetch is replaced before any test step, so no request
 * reaches Render or Supabase. localStorage of this origin is cleared at the
 * start and at the end.
 */
(async () => {
  const b64u = o => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  const TOK = { A: 'e30.' + b64u({ sub: 'uid-A' }) + '.x', B: 'e30.' + b64u({ sub: 'uid-B' }) + '.x' };
  const M = { users: {}, log: [], delay: {}, down: {}, expired: null, refreshTo: null, imgUrl: null };
  const userOf = a => a === 'Bearer ' + TOK.A ? 'A' : a === 'Bearer ' + TOK.B ? 'B' : null;
  window.fetch = async (url, opt = {}) => {
    const u = new URL(url, location.href), H = opt.headers || {}, method = opt.method || 'GET';
    const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'Content-Type': 'application/json' } });
    if (u.pathname === '/config') return json({ web_auth_ready: true, supabase_url: 'https://mock.supabase.test', supabase_anon_key: 'x' });
    if (u.pathname === '/health') return json({ status: 'ok' });
    if (u.host === 'mock.supabase.test') {
      const b = JSON.parse(opt.body || '{}');
      if (b.refresh_token) return M.refreshTo ? json({ access_token: TOK[M.refreshTo], refresh_token: 'r' }) : json({ error: 'bad' }, 400);
      const who = (b.email || '').toLowerCase().startsWith('a') ? 'A' : 'B';
      return json({ access_token: TOK[who], refresh_token: 'r' + who, user: { id: 'uid-' + who, email: b.email } });
    }
    const user = userOf(H['Authorization'] || '');
    const body = opt.body ? JSON.parse(opt.body) : null;
    const key = method + ' ' + u.pathname.replace(/\/trades\/.+/, '/trades/:id') + ' ' + user;
    M.log.push({ user, method, path: u.pathname, id: body?.id || (u.pathname.split('/')[2] || null) });
    if (!user || M.expired === user) return json({ error: 'expired' }, 401);
    if (M.delay[key]) await new Promise(r => setTimeout(r, M.delay[key]));
    if (M.down[user]) throw new TypeError('Failed to fetch');
    const U = (M.users[user] ||= { trades: {}, settings: { base_capital: 0, goals: [] } });
    if (u.pathname === '/trades' && method === 'GET') return json(Object.values(U.trades));
    if (u.pathname === '/trades' && method === 'POST') { U.trades[body.id] = body; return json(M.imgUrl ? { ok: true, img_url: M.imgUrl } : { ok: true }); }
    if (u.pathname.startsWith('/trades/') && method === 'DELETE') { delete U.trades[u.pathname.split('/')[2]]; return json({ ok: true }); }
    if (u.pathname === '/settings' && method === 'GET') return json(U.settings);
    if (u.pathname === '/settings' && method === 'POST') { U.settings = body; return json({ ok: true }); }
    if (u.pathname === '/billing/status') return json({ billing_enabled: false });
    return json({ error: 'not found' }, 404);
  };
  // The page asks Render for /config on boot; pin the mock config so a late
  // answer to that request cannot redirect sign-in calls during the test.
  const MOCK_CFG = { web_auth_ready: true, supabase_url: 'https://mock.supabase.test', supabase_anon_key: 'x' };
  supaConfig = MOCK_CFG;
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const reset = (users = {}) => { localStorage.clear(); Object.assign(M, { users, log: [], delay: {}, down: {}, expired: null, refreshTo: null, imgUrl: null }); };
  const login = async who => { saveWebSession({ access_token: TOK[who], refresh_token: 'r' + who, email: who.toLowerCase() + '@test' }); document.getElementById('authGate').classList.remove('show'); await startApp(); };
  const posts = () => M.log.filter(x => x.method === 'POST').map(x => x.user + ':' + x.id);
  const notice = () => document.getElementById('legacyNotice');
  const btn = t => [...notice().querySelectorAll('button')].find(b => b.textContent.includes(t));
  const results = [];
  const check = (name, ok, detail) => results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : JSON.stringify(detail) });
  const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

  // 1. Legacy shared cache/queue from an older version: B must not see or upload A's trade
  reset();
  const a = { id: 'A-101', pair: 'ACCOUNT_A', market: 'forex', result: 'win', pnl: '10', date: '2026-10-20' };
  localStorage.setItem('trades_v3', JSON.stringify([a]));
  localStorage.setItem('pending_trades_v3', JSON.stringify([a]));
  localStorage.setItem('ideas_v1', JSON.stringify([{ id: 'I-1', pair: 'XAUUSD' }]));
  await login('B'); await sleep(5600);
  check('legacy: B sees no A trade', eq(trades.map(t => t.id), []), trades);
  check('legacy: nothing uploaded under B', eq(posts(), []), posts());
  check('legacy: old keys kept', ['trades_v3', 'pending_trades_v3', 'ideas_v1'].every(k => localStorage.getItem(k) !== null));
  check('legacy: notice shown to B', !notice().hidden);

  // 2. "Not mine" hides it for B only; A moves the data in after confirming
  btn('Не мои')?.click() ?? btn('Not mine')?.click();
  check('legacy: hidden for B', notice().hidden);
  M.log = []; await login('A');
  check('legacy: notice shown to A', !notice().hidden);
  (btn('Перенести') || btn('Move')).click();
  check('legacy: confirm step uploads nothing yet', eq(posts(), []), posts());
  (btn('Да') || btn('Yes')).click(); await sleep(500);
  check('legacy: moved trade uploaded under A only', eq(posts(), ['A:A-101']), posts());
  check('legacy: A sees the moved trade and idea', trades.some(t => t.id === 'A-101') && ideas.some(x => x.id === 'I-1'));
  check('legacy: old keys still kept after move', ['trades_v3', 'pending_trades_v3', 'ideas_v1'].every(k => localStorage.getItem(k) !== null));
  await login('B');
  check('legacy: claimed items not offered to B again', notice().hidden);

  // 3. A's slow first load answers after the page switched to B
  reset({ A: { trades: { 'A-1': { id: 'A-1', pair: 'A_SERVER' } }, settings: { base_capital: 1000, goals: [] } },
          B: { trades: { 'B-1': { id: 'B-1', pair: 'B_SERVER' } }, settings: { base_capital: 50, goals: [] } } });
  M.delay = { 'GET /trades A': 2500, 'GET /settings A': 2500 };
  const slowA = login('A'); await sleep(300); await login('B'); await slowA; await sleep(300);
  check('late answer: B memory unchanged', eq(trades.map(t => t.id), ['B-1']) && baseCapital === 50, { trades, baseCapital });
  check('late answer: B cache unchanged', eq(lsJSON('trades_v3', [], 'web:uid-B').map(t => t.id), ['B-1']));

  // 4. A's queue is being sent when the page switches to B
  reset(); await login('A');
  const q = ['A-q1', 'A-q2', 'A-q3'].map(id => ({ id, pair: 'EURUSD', result: 'win', pnl: '1' }));
  lsSet('pending_trades_v3', JSON.stringify(q)); trades.push(...q); safeLocalStorageSet('trades_v3', trades);
  M.log = []; M.delay = { 'POST /trades A': 800 };
  const run = syncPendingQueue(); await sleep(1000); await login('B'); await run; await sleep(1200);
  check('queue: nothing sent under B', !posts().some(p => p.startsWith('B:')), posts());
  check('queue: unsent items stay with A', lsJSON('pending_trades_v3', [], 'web:uid-A').length > 0);
  M.delay = {}; await login('A'); await syncPendingQueue();
  check('queue: A finishes later under A', eq(Object.keys(M.users.A.trades).sort(), ['A-q1', 'A-q2', 'A-q3']) && !Object.keys(M.users.B?.trades || {}).length);

  // 5. A's session dies (401, refresh fails); B signs in through the form on the same page
  reset({ A: { trades: { 'A-1': { id: 'A-1' } }, settings: { base_capital: 1000, goals: [] } },
          B: { trades: { 'B-1': { id: 'B-1' } }, settings: { base_capital: 50, goals: [] } } });
  await login('A'); M.expired = 'A'; await api('GET', '/trades');
  check('401: journal detached from A', dataOwner === null && trades.length === 0);
  supaConfig = MOCK_CFG;
  document.getElementById('authEmail').value = 'b@test'; document.getElementById('authPass').value = 'secret1';
  await doAuth();
  check('401: B signs in and sees only B', dataOwner === 'web:uid-B' && eq(trades.map(t => t.id), ['B-1']), { dataOwner, trades });
  check('401: A cache kept', eq(lsJSON('trades_v3', [], 'web:uid-A').map(t => t.id), ['A-1']));
  supaConfig = MOCK_CFG; M.expired = 'B'; M.refreshTo = 'A';
  check('refresh: token of another account refused', (await refreshWebSession()) === false);
  supaConfig = MOCK_CFG; M.refreshTo = 'B'; M.expired = null;
  check('refresh: same account accepted', (await refreshWebSession()) === true);

  // 6. A's delete retry fires after B signed in
  reset({ A: { trades: { 'A-del': { id: 'A-del' } }, settings: { base_capital: 0, goals: [] } } });
  await login('A'); M.down = { A: true }; M.log = [];
  trades = trades.filter(t => t.id !== 'A-del'); await deleteTradeSync('A-del');
  await login('B'); await sleep(3400);
  check('delete retry: not sent under B', !M.log.some(x => x.method === 'DELETE' && x.user === 'B'), M.log);

  // 7. A's save answers (with img_url) after the switch
  reset(); await login('A');
  M.delay = { 'POST /trades A': 1200 }; M.imgUrl = 'https://img.test/a.jpg';
  const t = { id: 'A-img', pair: 'GBPUSD', result: 'win', pnl: '3', img: 'data:image/jpeg;base64,AAAA' };
  trades.push(t); const saving = syncTrade(t); await sleep(200); await login('B'); await saving;
  const ac = lsJSON('trades_v3', [], 'web:uid-A').find(x => x.id === 'A-img');
  check('late save: B memory untouched', !trades.some(x => x.id === 'A-img'));
  check('late save: img_url lands in A cache', ac && ac.img_url === M.imgUrl && !ac.img, ac);

  // 8. Owner rule matches the server
  check('owner: telegram', ownerFromIdentity(true, { id: 12345 }, null) === 'tg:12345');
  check('owner: telegram ignores web session', ownerFromIdentity(true, { id: 7 }, { access_token: TOK.A }) === 'tg:7');
  check('owner: web session without uid', ownerFromIdentity(false, null, { access_token: TOK.A }) === 'web:uid-A');
  check('owner: broken token gives no owner', ownerFromIdentity(false, null, { access_token: 'garbage' }) === null);

  // 9. Ideas, idea draft and dismissed insights are per account; no owner writes nothing
  reset(); await login('A');
  ideas = [{ id: 'IA' }]; saveIdeasLocal(); lsSet('idea_draft_v1', JSON.stringify({ pair: 'D' })); dismissInsight('x', 1);
  await login('B');
  check('per-account: B has no A ideas/draft/dismissals', !ideas.length && !hasIdeaDraft() && !Object.keys(getDismissedInsights()).length);
  await login('A');
  check('per-account: A keeps them', ideas.length === 1 && hasIdeaDraft() && 'x' in getDismissedInsights());
  const before = Object.keys(localStorage).length;
  setDataOwner(null); safeLocalStorageSet('trades_v3', [{ id: 'x' }]); addToPendingQueue({ id: 'x' }); await loadData();
  check('signed out: nothing written', Object.keys(localStorage).length === before);

  localStorage.clear();
  console.table(results);
  const failed = results.filter(r => r.result === 'FAIL').length;
  console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
  return { total: results.length, failed, results };
})();
