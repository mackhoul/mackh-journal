/*
 * Trade save / delete regression check.
 *
 * How to run:
 *   1. Serve the project:  python -m http.server 8080
 *   2. Open http://127.0.0.1:8080/index.html?test=1 (use 127.0.0.1, not localhost:
 *      another local server may answer on localhost). If this origin was used
 *      before, run localStorage.clear() in the console first and reload.
 *   3. Paste this whole file into the DevTools console (takes about a minute).
 *
 * Runs against an in-page mock backend with fictional accounts A and B.
 * window.fetch is replaced before any step; no request reaches Render or
 * Supabase. localStorage of this origin is cleared at the start and the end.
 * "Reload" is simulated: the page's timers are cleared and memory is rebuilt
 * from storage and the server, as on a real restart.
 */
(async () => {
  const b64u = o => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  const TOK = { A: 'e30.' + b64u({ sub: 'uid-A' }) + '.x', B: 'e30.' + b64u({ sub: 'uid-B' }) + '.x' };
  const userOf = a => a === 'Bearer ' + TOK.A ? 'A' : a === 'Bearer ' + TOK.B ? 'B' : null;
  const M = { srv: {}, log: [], order: [], delay: {}, down: false, failPnl: null };
  window.fetch = async (url, opt = {}) => {
    const u = new URL(url, location.href), method = opt.method || 'GET', H = opt.headers || {};
    const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'Content-Type': 'application/json' } });
    if (u.pathname === '/config') return json({ web_auth_ready: true, supabase_url: 'https://mock.supabase.test', supabase_anon_key: 'x' });
    if (u.host === 'mock.supabase.test') return json({ error: 'no' }, 400);
    const user = userOf(H['Authorization'] || '');
    const body = opt.body ? JSON.parse(opt.body) : null;
    const key = method + ' ' + u.pathname.replace(/\/trades\/.+/, '/trades/:id');
    M.log.push({ user, method, path: u.pathname, id: body?.id || decodeURIComponent(u.pathname.split('/')[2] || '') || null, pnl: body?.pnl, img_url: body?.img_url, hasImg: !!body?.img, qv: body?.__qv });
    if (M.failPnl && body && body.pnl === M.failPnl) throw new TypeError('Failed to fetch');
    if (M.delay[key]) await new Promise(r => setTimeout(r, M.delay[key]));
    if (M.down) throw new TypeError('Failed to fetch');
    if (!user) return json({ error: 'No auth header' }, 401);
    const S = (M.srv[user] ||= {});
    if (u.pathname === '/trades' && method === 'GET') return json(Object.values(S).map(x => JSON.parse(JSON.stringify(x))));
    if (u.pathname === '/trades' && method === 'POST') {
      const t = { ...body }; let img = t.img_url || null;
      if (t.img && String(t.img).startsWith('data:')) { img = 'https://img.test/' + t.id + '-' + M.order.length + '.jpg'; }
      delete t.img; if (img) t.img_url = img; else delete t.img_url;
      S[t.id] = t; M.order.push(user + ' POST ' + t.id + ' pnl=' + t.pnl);
      return json({ ok: true, img_url: img, img_failed: false });
    }
    if (u.pathname.startsWith('/trades/') && method === 'DELETE') {
      const id = decodeURIComponent(u.pathname.split('/')[2]);
      if (!/^\d+$/.test(id) && !M.allowAnyId) return json({ error: 'Invalid trade id' }, 400);   // what the server did before the fix
      delete S[id]; M.order.push(user + ' DELETE ' + id); return json({ ok: true });
    }
    if (u.pathname === '/settings') return json({ base_capital: 0, goals: [] });
    if (u.pathname === '/billing/status') return json({ billing_enabled: false });
    return json({ error: 'nf' }, 404);
  };
  supaConfig = { web_auth_ready: true, supabase_url: 'https://mock.supabase.test', supabase_anon_key: 'x' };
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  // Fallbacks so the same file also runs on versions before this fix (to show it fails there)
  const qList = () => typeof getQueue === 'function' ? getQueue() : lsJSON('pending_trades_v3', []);
  const tombs = () => typeof getTombs === 'function' ? getTombs() : [];
  const login = async (who = 'A') => { saveWebSession({ access_token: TOK[who], refresh_token: 'r' + who, email: who.toLowerCase() + '@test' }); document.getElementById('authGate').classList.remove('show'); await startApp(); };
  const reload = async (who = 'A') => { clearTimeout(undoTimer); clearTimeout(syncPendingQueue._retryTimer); undoTrade = null; setDataOwner(null); await login(who); };
  const fresh = (srvA = {}, srvB = {}) => { localStorage.clear(); Object.assign(M, { srv: { A: JSON.parse(JSON.stringify(srvA)), B: JSON.parse(JSON.stringify(srvB)) }, log: [], order: [], delay: {}, down: false, failPnl: null, allowAnyId: false }); };
  const T1 = (id, extra = {}) => ({ id, pair: 'EURUSD', market: 'forex', result: 'win', pnl: '10', date: '2026-10-20', notes: 'n', ...extra });
  const ids = () => trades.map(t => t.id).sort();
  const cacheIds = () => lsJSON('trades_v3', []).map(t => t.id).sort();
  const queue = () => qList().map(q => q.id + ':' + q.pnl);
  const srvA = () => Object.keys(M.srv.A || {}).sort();
  const results = [];
  const check = (name, ok, detail) => results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : JSON.stringify(detail) });
  const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

  // 1. Delete a synced trade online; the undo window passes; reload
  fresh({ '1001': T1('1001') }); await login();
  deleteTrade('1001');
  check('delete online: gone from memory and cache at once', !ids().includes('1001') && !cacheIds().includes('1001'));
  await sleep(5400);
  check('delete online: server deleted after the undo window', !srvA().includes('1001'), M.order);
  await reload();
  check('delete online: still gone after reload', !ids().includes('1001'));

  // 2. App closed inside the undo window — deletion survives and is delivered later
  fresh({ '1002': T1('1002') }); await login();
  deleteTrade('1002'); await sleep(200);
  await reload();
  check('closed in undo window: not back after reload', !ids().includes('1002') && !cacheIds().includes('1002'), { ids: ids() });
  await sleep(5500); await syncPendingQueue();
  check('closed in undo window: deletion delivered afterwards', !srvA().includes('1002'), M.order);

  // 3. Delete while the server is unreachable; reload while still offline; reconnect
  fresh({ '1003': T1('1003') }); await login();
  M.down = true; await deleteTradeSync('1003');
  await reload();
  check('offline delete: hidden after reload while offline', !ids().includes('1003'));
  M.down = false; await syncPendingQueue(); await reload();
  check('offline delete: delivered after reconnect, stays deleted', !srvA().includes('1003') && !ids().includes('1003'), { srv: srvA(), ids: ids() });

  // 4. Delete a trade that was never sent (still queued)
  fresh(); await login();
  M.down = true; const p4 = T1('1004'); trades.push(p4); await syncTrade(p4);
  await deleteTradeSync('1004');
  check('delete unsent: removed from the queue', !queue().some(q => q.startsWith('1004')));
  M.down = false; await syncPendingQueue(); await reload();
  check('delete unsent: server never received it, not back', !M.order.some(o => o.includes('POST 1004')) && !srvA().includes('1004') && !ids().includes('1004'), { order: M.order, ids: ids() });

  // 5. A slow page load answers after a delete
  fresh({ '1005': T1('1005'), '1055': T1('1055') }); await login();
  M.delay = { 'GET /trades': 1200 };
  const slow = loadData(); await sleep(100);
  await deleteTradeSync('1005');
  await slow; M.delay = {};
  check('late load after delete: not back in memory or cache', !ids().includes('1005') && !cacheIds().includes('1005'), { ids: ids(), cache: cacheIds() });

  // 6. Delete while the save of the same trade is still in flight
  fresh(); await login();
  M.delay = { 'POST /trades': 800 };
  const n6 = T1('1006'); trades.push(n6); const saving6 = syncTrade(n6);
  await sleep(100); await deleteTradeSync('1006'); await saving6; M.delay = {}; await syncPendingQueue();
  await reload();
  check('delete during save: server ends without it', !srvA().includes('1006') && !ids().includes('1006'), M.order);

  // 7. Edit v2 while v1 is being sent; v2's own attempt fails — v2 must still win
  fresh(); await login();
  M.down = true; const v1 = T1('1007'); trades.push(v1); await syncTrade(v1); M.down = false;
  M.delay = { 'POST /trades': 800 }; M.failPnl = '99';
  const run7 = syncPendingQueue(); await sleep(100);
  const v2 = { ...v1, pnl: '99' }; trades[trades.findIndex(t => t.id === '1007')] = v2;
  addToPendingQueue(v2); safeLocalStorageSet('trades_v3', trades);    // what syncTrade stores first
  await run7; M.delay = {};
  check('edit during send: newer version stays queued', queue().includes('1007:99'), queue());
  M.failPnl = null; await syncPendingQueue(); await reload();
  check('edit during send: server and journal end with the newest version', M.srv.A['1007']?.pnl === '99' && trades.find(t => t.id === '1007')?.pnl === '99', { srv: M.srv.A['1007']?.pnl });

  // 8. Two quick edits online with a slow server: the last one lands last
  fresh({ '1008': T1('1008') }); await login();
  M.delay = { 'POST /trades': 400 };
  const a8 = { ...T1('1008'), pnl: '20' }, b8 = { ...T1('1008'), pnl: '30' };
  trades[0] = a8; const s1 = syncTrade(a8); await sleep(50);
  trades[0] = b8; const s2 = syncTrade(b8); await Promise.all([s1, s2]); M.delay = {};
  check('quick edits: server keeps the last edit', M.srv.A['1008']?.pnl === '30' && !queue().length, { order: M.order, srv: M.srv.A['1008']?.pnl });

  // 9. A queued local edit vs. an older server copy on load
  fresh({ '1009': T1('1009') }); await login();
  M.down = true; const e9 = { ...T1('1009'), pnl: '99' }; trades[0] = e9; await syncTrade(e9); M.down = false;
  M.delay = { 'POST /trades': 600 };
  const load9 = loadData(); await sleep(50); await load9;
  check('pending edit vs load: journal shows the local edit', trades.find(t => t.id === '1009')?.pnl === '99', trades);
  M.delay = {}; await syncPendingQueue();
  check('pending edit vs load: server, memory and cache agree', M.srv.A['1009']?.pnl === '99' && lsJSON('trades_v3', []).find(t => t.id === '1009')?.pnl === '99');

  // 10. Screenshot kept / replaced / removed when editing
  fresh({ '1010': T1('1010', { img_url: 'https://img.test/old.jpg' }) }); await login();
  openEditTrade('1010'); document.getElementById('tNotes').value = 'new note'; saveTrade(); await sleep(300);
  check('edit notes: screenshot link kept', M.srv.A['1010']?.img_url === 'https://img.test/old.jpg' && M.srv.A['1010']?.notes === 'new note', M.srv.A['1010']);
  openEditTrade('1010'); currentImg = 'data:image/jpeg;base64,AAAA'; saveTrade(); await sleep(300);
  check('replace screenshot: new one uploaded', M.srv.A['1010']?.img_url && M.srv.A['1010'].img_url !== 'https://img.test/old.jpg', M.srv.A['1010']);
  openEditTrade('1010'); removeImg(); saveTrade(); await sleep(300);
  check('remove screenshot: link cleared on purpose', !M.srv.A['1010']?.img_url, M.srv.A['1010']);
  closeModal('addModal');

  // 11. Two sync runs at once send each trade once
  fresh(); await login();
  M.down = true; for (const id of ['1111', '1112']) { const t = T1(id); trades.push(t); await syncTrade(t); } M.down = false; M.log = [];
  M.delay = { 'POST /trades': 300 };
  await Promise.all([syncPendingQueue(), syncPendingQueue()]); M.delay = {};
  const posts11 = M.log.filter(x => x.method === 'POST').map(x => x.id);
  check('parallel runs: each trade sent once', eq(posts11.slice().sort(), ['1111', '1112']), posts11);
  check('queue marker never sent to the server', !M.log.some(x => x.qv !== undefined));

  // 12. Create while the server is down, reload offline, reconnect
  fresh(); await login();
  M.down = true; const c12 = T1('1012'); trades.push(c12); await syncTrade(c12);
  await reload();
  check('offline create: kept after reload', ids().includes('1012'));
  renderTrades();
  check('offline create: marked as not sent', /Не отправлено|Not sent/.test(document.getElementById('allTrades').textContent));
  M.down = false; await syncPendingQueue(); renderTrades();
  check('offline create: delivered after reconnect', srvA().includes('1012') && !queue().length && !/Не отправлено|Not sent/.test(document.getElementById('allTrades').textContent));

  // 13. Undo restores the trade and sends no deletion
  fresh({ '1013': T1('1013') }); await login(); M.log = [];
  deleteTrade('1013'); await sleep(300); undoDelete(); await sleep(5500); await syncPendingQueue();
  check('undo: trade back, no deletion sent', ids().includes('1013') && srvA().includes('1013') && !M.log.some(x => x.method === 'DELETE'), M.log);

  // 14. Server refuses to delete a non-numeric id (behaviour before the server fix)
  fresh({ 'imp-1': T1('imp-1') }); await login();
  await deleteTradeSync('imp-1'); await reload();
  check('refused delete: stays deleted on this device', !ids().includes('imp-1'));
  check('refused delete: recorded as not delivered', tombs().some(x => x.id === 'imp-1' && x.rejected && !x.done));
  M.allowAnyId = true; await syncPendingQueue();
  check('refused delete: delivered once the server accepts the id', !srvA().includes('imp-1') && tombs().some(x => x.id === 'imp-1' && x.done));

  // 15. A cached trade that is on neither the server nor the queue is shown, labelled, not uploaded
  fresh(); lsSet('trades_v3', JSON.stringify([T1('1015')]), 'web:uid-A'); await login(); await sleep(5600);
  renderTrades();
  check('cache-only trade: shown and labelled, not uploaded', ids().includes('1015') && /Нет на сервере|Not on server/.test(document.getElementById('allTrades').textContent) && !srvA().includes('1015'));

  // 16. Account isolation: A's pending delete/save are never delivered under B
  fresh({ '1016': T1('1016') }, {}); await login('A');
  M.down = true; await deleteTradeSync('1016'); const s16 = T1('1616'); trades.push(s16); await syncTrade(s16);
  M.down = false; await reload('B'); await syncPendingQueue(); await sleep(300);
  check('isolation: nothing of A sent under B', !M.log.some(x => x.user === 'B' && (x.method === 'DELETE' || x.method === 'POST')), M.log.filter(x => x.user === 'B'));
  await reload('A'); await syncPendingQueue();
  check('isolation: A delivers its own pending delete and save', !srvA().includes('1016') && srvA().includes('1616'), srvA());

  // 17. Queue entries written by the previous version (no version marker) are delivered
  fresh(); lsSet('pending_trades_v3', JSON.stringify([T1('1017')]), 'web:uid-A'); await login(); await syncPendingQueue();
  check('old queue entries: delivered and cleared', srvA().includes('1017') && !queue().length);

  // 18. Plain online save and edit
  fresh(); await login();
  const n18 = T1('1018'); trades.push(n18); await syncTrade(n18);
  const e18 = { ...n18, pnl: '25' }; trades[0] = e18; await syncTrade(e18); await reload();
  check('normal save and edit', M.srv.A['1018']?.pnl === '25' && trades.find(t => t.id === '1018')?.pnl === '25' && !queue().length);

  localStorage.clear();
  console.table(results);
  const failed = results.filter(r => r.result === 'FAIL').length;
  console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
  return { total: results.length, failed, results };
})();
