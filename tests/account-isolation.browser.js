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
  const TOK = { A: 'e30.' + b64u({ sub: 'uid-A' }) + '.x', B: 'e30.' + b64u({ sub: 'uid-B' }) + '.x', A2: 'e30.' + b64u({ sub: 'uid-A', v: 2 }) + '.y' };
  const M = { users: {}, log: [], delay: {}, down: {}, expired: null, refreshTo: null, imgUrl: null };
  const userOf = a => a === 'Bearer ' + TOK.A || a === 'Bearer ' + TOK.A2 ? 'A' : a === 'Bearer ' + TOK.B ? 'B' : null;
  window.fetch = async (url, opt = {}) => {
    const u = new URL(url, location.href), H = opt.headers || {}, method = opt.method || 'GET';
    const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'Content-Type': 'application/json' } });
    if (u.pathname === '/config') return json({ web_auth_ready: true, supabase_url: 'https://mock.supabase.test', supabase_anon_key: 'x' });
    if (u.pathname === '/health') return json({ status: 'ok' });
    if (u.host === 'mock.supabase.test') {
      const b = JSON.parse(opt.body || '{}');
      if (b.refresh_token) {
        M.refreshCalls = (M.refreshCalls || 0) + 1;
        if (M.refreshDelay) await new Promise(r => setTimeout(r, M.refreshDelay));
        if (M.rotate) {                       // one-time refresh tokens: a reused one is rejected
          if (M.usedRefresh.includes(b.refresh_token)) return json({ error: 'refresh token already used' }, 400);
          M.usedRefresh.push(b.refresh_token);
          return json({ access_token: TOK.A2, refresh_token: 'rA2' });
        }
        return M.refreshTo ? json({ access_token: TOK[M.refreshTo], refresh_token: 'r' + M.refreshTo }) : json({ error: 'bad' }, 400);
      }
      const who = (b.email || '').toLowerCase().startsWith('a') ? 'A' : 'B';
      return json({ access_token: TOK[who], refresh_token: 'r' + who, user: { id: 'uid-' + who, email: b.email } });
    }
    const user = userOf(H['Authorization'] || '');
    const body = opt.body ? JSON.parse(opt.body) : null;
    const key = method + ' ' + u.pathname.replace(/\/trades\/.+/, '/trades/:id') + ' ' + user;
    M.log.push({ user, method, path: u.pathname, id: body?.id || (u.pathname.split('/')[2] || null) });
    if (M.delay[key]) await new Promise(r => setTimeout(r, M.delay[key]));
    // checked after the delay: a token can expire while a request is in flight
    if (!user || M.expired === user || (M.expiredToken && H['Authorization'] === 'Bearer ' + M.expiredToken)) return json({ error: 'expired' }, 401);
    if (M.down[user]) throw new TypeError('Failed to fetch');
    const U = (M.users[user] ||= { trades: {}, settings: { base_capital: 0, goals: [] } });
    if (u.pathname === '/trades' && method === 'GET') return json(Object.values(U.trades));
    if (u.pathname === '/trades' && method === 'POST') { U.trades[body.id] = body; return json(M.imgUrl ? { ok: true, img_url: M.imgUrl } : { ok: true }); }
    if (u.pathname.startsWith('/trades/') && method === 'DELETE') { delete U.trades[u.pathname.split('/')[2]]; return json({ ok: true }); }
    if (u.pathname === '/settings' && method === 'GET') return json(U.settings);
    if (u.pathname === '/settings' && method === 'POST') { U.settings = body; return json({ ok: true }); }
    if (u.pathname === '/billing/status') return json(M.billing ? { billing_enabled: true, active: user === 'A', renews: user === 'A' ? '2026-12-01' : null } : { billing_enabled: false });
    if (u.pathname === '/billing/checkout' || u.pathname === '/billing/portal') return json({ url: '#checkout-' + user });
    return json({ error: 'not found' }, 404);
  };
  // The page asks Render for /config on boot; pin the mock config so a late
  // answer to that request cannot redirect sign-in calls during the test.
  const MOCK_CFG = { web_auth_ready: true, supabase_url: 'https://mock.supabase.test', supabase_anon_key: 'x' };
  supaConfig = MOCK_CFG;
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const reset = (users = {}) => { localStorage.clear(); Object.assign(M, { users, log: [], delay: {}, down: {}, expired: null, expiredToken: null, refreshTo: null, refreshDelay: 0, refreshCalls: 0, rotate: false, usedRefresh: [], billing: false, imgUrl: null }); supaConfig = MOCK_CFG; };
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

  // 10. (review 1) A's save is in flight, B signs in, then the old request gets 401
  reset(); await login('A');
  M.delay = { 'POST /trades A': 800 }; M.refreshTo = 'B';
  const pt = { id: 'A-private-401', pair: 'A_PRIVATE', pnl: '42' };
  trades.push(pt); const save401 = syncTrade(pt);
  await sleep(100); M.expired = 'A'; await login('B'); await save401; await sleep(300);
  check('review 1: late 401 for A never re-sent under B', !posts().some(p => p.startsWith('B:A-')) && !(M.users.B?.trades || {})['A-private-401'], { posts: posts(), b: M.users.B?.trades });
  check('review 1: A trade stays in A queue', lsJSON('pending_trades_v3', [], 'web:uid-A').some(t => t.id === 'A-private-401'));
  check('review 1: B stays signed in', dataOwner === 'web:uid-B' && !!webSession);

  // 11. (review 3) A's token refresh finishes after B signed in
  reset(); await login('A');
  M.expired = 'A'; M.refreshTo = 'A'; M.refreshDelay = 800;
  const callA = api('GET', '/trades');
  await sleep(200); M.expired = null; await login('B'); await callA; await sleep(200);
  check('review 3: stale A refresh leaves B signed in', dataOwner === 'web:uid-B' && !!webSession && ownerFromIdentity(false, null, webSession) === 'web:uid-B', { dataOwner, hasSession: !!webSession });

  // 12. (review 2) an idea form opened in A cannot write its draft into B
  reset(); await login('A');
  openIdeaModal(); openModal('ideaModal');
  const ip = document.getElementById('iPair'); ip.value = 'A_PRIVATE_DRAFT'; ip.dispatchEvent(new Event('input'));
  check('review 2: A draft saved for A', lsJSON('idea_draft_v1', null, 'web:uid-A')?.pair === 'A_PRIVATE_DRAFT');
  M.expired = 'A'; await api('GET', '/trades');               // A's session dies, refresh fails
  M.expired = null; supaConfig = MOCK_CFG;
  document.getElementById('authEmail').value = 'b@test'; document.getElementById('authPass').value = 'secret1';
  await doAuth();
  ip.dispatchEvent(new Event('input')); saveIdeaDraft();       // stray events after the switch
  check('review 2: A form closed and emptied', !document.getElementById('ideaModal').classList.contains('open') && ip.value === '');
  check('review 2: B has no draft from A form', dataOwner === 'web:uid-B' && lsGet('idea_draft_v1', 'web:uid-B') === null);
  check('review 2: A draft kept for A', lsJSON('idea_draft_v1', null, 'web:uid-A')?.pair === 'A_PRIVATE_DRAFT');
  openIdeaModal(); ip.value = 'B_DRAFT'; ip.dispatchEvent(new Event('input'));
  check('review 2: B can still save its own draft', lsJSON('idea_draft_v1', null, 'web:uid-B')?.pair === 'B_DRAFT');
  closeModal('ideaModal');

  // 13. (review 4) old draft vs. the account's own draft
  reset();
  localStorage.setItem('idea_draft_v1', JSON.stringify({ pair: 'OLD_DRAFT' }));
  localStorage.setItem('pending_trades_v3', JSON.stringify([{ id: 'L-1', pair: 'X', pnl: '1', result: 'win' }]));
  await login('A');
  lsSet('idea_draft_v1', JSON.stringify({ pair: 'A_OWN' })); renderLegacyNotice();
  (btn('Перенести') || btn('Move')).click(); (btn('Да') || btn('Yes')).click(); await sleep(300);
  const claim1 = JSON.parse(localStorage.getItem('mj:legacy_claim'));
  check('review 4: draft not marked moved when not copied', claim1.draft === false && lsJSON('idea_draft_v1', null)?.pair === 'A_OWN', claim1);
  check('review 4: old draft still offered with explicit replace', !notice().hidden && !!(btn('Заменить') || btn('Replace')));
  (btn('Заменить') || btn('Replace'))?.click(); (btn('Да') || btn('Yes'))?.click(); await sleep(100);
  const claim2 = JSON.parse(localStorage.getItem('mj:legacy_claim')) || {};
  check('review 4: replace copies, then marks it moved', claim2.draft === true && lsJSON('idea_draft_v1', null)?.pair === 'OLD_DRAFT' && localStorage.getItem('idea_draft_v1') !== null, claim2);

  // 14. (extended 1) another tab changes the shared session
  reset(); await login('A');
  localStorage.setItem('web_session_v1', JSON.stringify({ access_token: TOK.A2, refresh_token: 'rA2', email: 'a@test' }));
  window.dispatchEvent(new StorageEvent('storage', { key: 'web_session_v1' }));
  check('tabs: same-account token from another tab is picked up', dataOwner === 'web:uid-A' && webSession?.access_token === TOK.A2);
  localStorage.setItem('web_session_v1', JSON.stringify({ access_token: TOK.B, refresh_token: 'rB', email: 'b@test' }));
  window.dispatchEvent(new StorageEvent('storage', { key: 'web_session_v1' }));
  check('tabs: other tab signs in to B — this tab stops, does not become B', dataOwner === null && webSession === null && document.getElementById('authGate').classList.contains('show'));
  check('tabs: the other tab\'s stored session is left alone', JSON.parse(localStorage.getItem('web_session_v1')).access_token === TOK.B);
  reset(); await login('A');
  M.expired = 'A'; M.refreshTo = 'A'; M.refreshDelay = 500;
  const callR = api('GET', '/trades');
  await sleep(100);
  // another tab signs in to B; its storage event has not been delivered yet
  localStorage.setItem('web_session_v1', JSON.stringify({ access_token: TOK.B, refresh_token: 'rB', email: 'b@test' }));
  await callR;
  check('tabs: late refresh does not write A over the stored B', JSON.parse(localStorage.getItem('web_session_v1') || 'null')?.access_token === TOK.B);

  // 15. (extended 2) a file read / image compression finishing after a switch
  const NativeReader = window.FileReader;
  class SlowReader extends NativeReader {
    readAsDataURL(f) { setTimeout(() => super.readAsDataURL(f), 500); }
    readAsText(f) { setTimeout(() => super.readAsText(f), 500); }
  }
  const png = await new Promise(r => { const c = document.createElement('canvas'); c.width = c.height = 4; c.toBlob(r, 'image/png'); });
  window.FileReader = SlowReader;
  try {
    reset({ B: { trades: { 'B-1': { id: 'B-1' } }, settings: { base_capital: 0, goals: [] } } }); await login('A');
    let confirms = 0; const nativeConfirm = window.confirm; window.confirm = () => { confirms++; return true; };
    const file = new File([JSON.stringify({ trades: [{ id: 'A-import', pnl: '1' }] })], 'a.json', { type: 'application/json' });
    importJSON({ files: [file], value: '' });
    await login('B'); await sleep(800);
    window.confirm = nativeConfirm;
    check('import: a file read for A is not applied to B', confirms === 0 && !trades.some(t => t.id === 'A-import') && !lsJSON('trades_v3', [], 'web:uid-B').some(t => t.id === 'A-import'), { confirms });
    reset(); await login('A');
    openAddTrade(); processImgFile(new File([png], 'a.png', { type: 'image/png' }));
    openIdeaModal(); processIdeaImgFile(new File([png], 'b.png', { type: 'image/png' }));
    openQuickAdd(); processQImgFile(new File([png], 'c.png', { type: 'image/png' }));
    await login('B'); openAddTrade(); openIdeaModal(); openQuickAdd(); await sleep(1500);
    check('images: late A images do not land in B forms', currentImg === null && ideaCurrentImg === null && qCurrentImg === null && !lsJSON('idea_draft_v1', null, 'web:uid-B')?.img,
      { currentImg: !!currentImg, ideaCurrentImg: !!ideaCurrentImg, qCurrentImg: !!qCurrentImg });
    closeModal('addModal'); closeModal('ideaModal'); closeModal('quickModal');
  } finally { window.FileReader = NativeReader; }

  // 16. (extended 3) subscription status and checkout answer after a switch
  reset(); M.billing = true; await login('A'); await sleep(100);
  M.delay = { 'GET /billing/status A': 600 };
  const subA = loadSubscription(); await sleep(50); await login('B'); await sleep(100); await subA;
  check('billing: A status never shown for B', !!subState && subState.active === false, subState);
  await login('A'); await sleep(100);
  subState = { billing_enabled: true, active: false };
  M.delay = { 'POST /billing/checkout A': 600 };
  const hashBefore = location.hash;
  const pay = onSubButton(); await sleep(50); await login('B'); await pay; await sleep(100);
  check('billing: checkout link made for A is not opened after a switch', location.hash === hashBefore, location.hash);
  if (location.hash !== hashBefore) history.replaceState({}, '', location.pathname + location.search);

  // 17. (extended 4) two parallel 401s with one-time refresh tokens
  reset(); await login('A');
  M.rotate = true; M.expiredToken = TOK.A;
  const [r1, r2] = await Promise.all([api('GET', '/trades'), api('GET', '/settings')]);
  check('parallel 401: one refresh, both calls retried, session kept',
    M.refreshCalls === 1 && !!r1 && !!r2 && webSession?.access_token === TOK.A2 && dataOwner === 'web:uid-A',
    { calls: M.refreshCalls, r1: !!r1, r2: !!r2, renewed: webSession?.access_token === TOK.A2, dataOwner });

  // 18. (extended 5) wrong-shaped old data does not break the home screen
  reset();
  localStorage.setItem('pending_trades_v3', '{}'); localStorage.setItem('ideas_v1', '{}'); localStorage.setItem('mj:legacy_claim', '"broken"');
  let renderError = null;
  try { await login('A'); renderHome(); } catch (e) { renderError = e.message; }
  check('damaged old data: home renders', renderError === null, renderError);
  check('damaged old data: reported and left unchanged', !notice().hidden && /поврежден|damaged/i.test(notice().textContent)
    && localStorage.getItem('pending_trades_v3') === '{}' && localStorage.getItem('ideas_v1') === '{}');

  // 19. (extended 6) ideas that do not fit are not marked as moved
  reset();
  localStorage.setItem('ideas_v1', JSON.stringify([{ id: 'OLD-IDEA', pair: 'EURUSD' }]));
  await login('A');
  const nativeSet = Storage.prototype.setItem;
  Storage.prototype.setItem = function (k, v) {
    if (k === 'mj:web:uid-A:ideas_v1') { const e = new Error('quota'); e.name = 'QuotaExceededError'; throw e; }
    return nativeSet.call(this, k, v);
  };
  try { (btn('Перенести') || btn('Move'))?.click(); (btn('Да') || btn('Yes'))?.click(); await sleep(200); }
  finally { Storage.prototype.setItem = nativeSet; }
  const claim3 = legacyClaim();
  check('quota: a failed idea copy is not claimed', !claim3.ideas.includes('OLD-IDEA') && legacyUnclaimed().ideas.some(x => x.id === 'OLD-IDEA'), claim3);

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
