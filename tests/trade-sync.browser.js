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
    const D = (M.deleted[user] ||= new Set());
    const G = (M.gens[user] ||= {});
    const undoOk = b => Number.isInteger(b.__restore) && b.__restore === G[b.id];
    if (M.lateWrite && method === 'POST' && u.pathname === '/trades' && user) {
      // the client gives up (timeout), but the server finishes the write later
      setTimeout(() => {
        if (M.guard && D.has(body.id) && !undoOk(body)) { M.order.push(user + ' POST(late,ignored) ' + body.id); return; }
        const S = (M.srv[user] ||= {}); const t = { ...body }; delete t.img; delete t.__restore; S[t.id] = t; M.order.push(user + ' POST(late) ' + t.id);
      }, M.lateWrite);
      throw new TypeError('timeout');
    }
    const snap = (M.snapshotGet && method === 'GET' && u.pathname === '/trades' && user) ? Object.values(M.srv[user] || {}).map(x => JSON.parse(JSON.stringify(x))) : null;
    if (M.delay[key]) await new Promise(r => setTimeout(r, M.delay[key]));
    if (snap && !M.down) return json(snap);
    if (M.down) throw new TypeError('Failed to fetch');
    if (!user) return json({ error: 'No auth header' }, 401);
    const S = (M.srv[user] ||= {});
    if (u.pathname === '/trades' && method === 'GET') return json(Object.values(S).map(x => JSON.parse(JSON.stringify(x))));
    if (u.pathname === '/trades' && method === 'POST') {
      if (M.guard && D.has(body.id) && !undoOk(body)) { M.order.push(user + ' POST(ignored) ' + body.id); return json({ ok: true, skipped: 'deleted' }); }
      if (M.guard && D.has(body.id)) { D.delete(body.id); M.order.push(user + ' RESTORE ' + body.id + ' gen=' + body.__restore); }
      const t = { ...body }; delete t.__restore; let img = t.img_url || null;
      if (t.img && String(t.img).startsWith('data:')) { img = 'https://img.test/' + t.id + '-' + M.order.length + '.jpg'; }
      delete t.img; if (img) t.img_url = img; else delete t.img_url;
      S[t.id] = t; M.order.push(user + ' POST ' + t.id + ' pnl=' + t.pnl);
      return json({ ok: true, img_url: img, img_failed: false });
    }
    if (u.pathname.startsWith('/trades/') && method === 'DELETE') {
      const id = decodeURIComponent(u.pathname.split('/')[2]);
      if (!M.guard && !/^\d+$/.test(id) && !M.allowAnyId) return json({ error: 'Invalid trade id' }, 400);   // what the server did before the fix
      delete S[id]; M.order.push(user + ' DELETE ' + id);
      if (M.guard) { D.add(id); G[id] = (G[id] || 0) + 1; return json({ ok: true, deletion: G[id] }); }
      return json({ ok: true });
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
  const fresh = (srvA = {}, srvB = {}) => { localStorage.clear(); Object.assign(M, { srv: { A: JSON.parse(JSON.stringify(srvA)), B: JSON.parse(JSON.stringify(srvB)) }, log: [], order: [], delay: {}, down: false, failPnl: null, allowAnyId: false, lateWrite: 0, snapshotGet: false, guard: false, deleted: {}, gens: {} }); };
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

  // 31. (staging UI) the "Undo" link can really be clicked: a click at its centre lands on
  // the link itself, not on the page behind the toast; a hidden toast catches no clicks
  const hitAtCentre = el => { const r = el.getBoundingClientRect(); return document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2); };
  fresh({ '1031': T1('1031') }); await login(); M.log = [];
  deleteTrade('1031'); await sleep(400);                            // toast shown (transition .22s)
  const link31 = document.querySelector('#toast .toast-undo');
  const hit31 = link31 && hitAtCentre(link31);
  check('undo link: a click at its centre reaches the link', !!link31 && hit31 === link31, { hit: hit31 && (hit31.id || hit31.className || hit31.tagName) });
  if (hit31) hit31.click();                                         // what a real click at that point does
  await sleep(300); await syncPendingQueue();
  check('undo link: clicking it brings the trade back, no deletion sent', ids().includes('1031') && srvA().includes('1031') && !M.log.some(x => x.method === 'DELETE'), M.log);
  fresh({ '1032': T1('1032') }); await login();
  deleteTrade('1032'); await sleep(5600);                           // window over, toast hidden
  const link32 = document.querySelector('#toast .toast-undo');
  check('undo link: a hidden toast does not catch clicks', !link32 || hitAtCentre(link32) !== link32);

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

  // 19. (review 1) "Undo" left over from A must not restore A's trade into B
  fresh({ '1019': T1('1019', { pair: 'A_PRIVATE' }) }); await login('A');
  deleteTrade('1019'); await sleep(200);
  await login('B');                                   // same page, the undo toast is still there
  undoDelete(); await sleep(300); await syncPendingQueue();
  check('undo after switch: nothing of A restored or sent under B',
    !M.log.some(x => x.user === 'B' && x.method === 'POST' && x.id === '1019') && !Object.keys(M.srv.B || {}).includes('1019') && !ids().includes('1019')
    && !document.getElementById('toast').classList.contains('show'), { b: Object.keys(M.srv.B || {}), ids: ids() });
  await reload('A'); await sleep(5500); await syncPendingQueue();
  check('undo after switch: A still delivers its own deletion', !srvA().includes('1019'), M.order);

  // 20. (review 2) a load that started before a confirmed edit must not roll it back
  fresh({ '1020': T1('1020') }); await login();
  M.snapshotGet = true; M.delay = { 'GET /trades': 900 };
  const load20 = loadData(); await sleep(100);       // GET took its snapshot (pnl 10)
  M.delay = {};
  const e20 = { ...T1('1020'), pnl: '99' }; trades[trades.findIndex(t => t.id === '1020')] = e20; await syncTrade(e20);
  const queuedBefore = queue().length;
  await load20; M.snapshotGet = false;
  check('late load after confirmed edit: journal and cache keep the edit', queuedBefore === 0 && M.srv.A['1020']?.pnl === '99'
    && trades.find(t => t.id === '1020')?.pnl === '99' && lsJSON('trades_v3', []).find(t => t.id === '1020')?.pnl === '99',
    { queuedBefore, srv: M.srv.A['1020']?.pnl, mem: trades.find(t => t.id === '1020')?.pnl });

  // 21. (review 3) a save the client gave up on lands on the server after the deletion
  fresh(); await login();
  const t21 = T1('1021'); trades.push(t21);
  M.lateWrite = 600; await syncTrade(t21); M.lateWrite = 0;
  await deleteTradeSync('1021');
  await sleep(900);
  const ghost = srvA().includes('1021');
  await loadData(); await syncPendingQueue();
  check('late save after delete: re-created copy is deleted again', ghost && !srvA().includes('1021') && !ids().includes('1021'), { ghost, order: M.order, srv: srvA() });

  // 22. (review) a local-only trade confirmed during a slow load, after another trade was deleted
  fresh({ '1022': T1('1022', { pair: 'Y' }) });
  lsSet('trades_v3', JSON.stringify([T1('1021x', { pnl: '10' }), T1('1022', { pair: 'Y' })]), 'web:uid-A');
  await login();                                       // X (1021x) is local-only, Y is on the server
  M.snapshotGet = true; M.delay = { 'GET /trades': 900 };
  const load22 = loadData(); await sleep(100);         // snapshot without X
  M.delay = {};
  await deleteTradeSync('1022');                       // replaces the trades array
  const x99 = { ...trades.find(t => t.id === '1021x'), pnl: '99' };
  trades[trades.findIndex(t => t.id === '1021x')] = x99; await syncTrade(x99);
  const q22 = queue().length;
  await load22; M.snapshotGet = false;
  check('late load, local-only trade confirmed meanwhile: keeps 99', q22 === 0 && M.srv.A['1021x']?.pnl === '99'
    && trades.find(t => t.id === '1021x')?.pnl === '99' && lsJSON('trades_v3', []).find(t => t.id === '1021x')?.pnl === '99' && !ids().includes('1022'),
    { q22, srv: M.srv.A['1021x']?.pnl, mem: trades.find(t => t.id === '1021x')?.pnl, cache: lsJSON('trades_v3', []).find(t => t.id === '1021x')?.pnl });

  // ── With the database deletion guard (server after the migration) ──
  // 23. a late save after a confirmed delete — no reload, no next load
  fresh(); M.guard = true; await login();
  const t23 = T1('1023'); trades.push(t23);
  M.lateWrite = 600; await syncTrade(t23); M.lateWrite = 0;
  await deleteTradeSync('1023'); await sleep(900); await syncPendingQueue();
  check('guard: late save after delete does not re-create it (no reload)', !srvA().includes('1023') && M.order.some(o => o.includes('POST(late,ignored) 1023')), M.order);
  localStorage.clear(); await reload();
  check('guard: still gone for a device with empty storage', !ids().includes('1023') && !srvA().includes('1023'));

  // 24. an old client's queued save of a trade that is deleted on the server
  fresh({ '1024': T1('1024') }); M.guard = true; await login();
  await deleteTradeSync('1024');
  localStorage.clear(); lsSet('pending_trades_v3', JSON.stringify([T1('1024', { pnl: '55' })]), 'web:uid-A');   // queue written by an older version
  await reload(); await syncPendingQueue();
  check('guard: old queued save of a deleted trade is dropped', !srvA().includes('1024') && !queue().length && !ids().includes('1024') && tombs().some(x => x.id === '1024' && x.done), { srv: srvA(), q: queue(), ids: ids() });

  // 25. another device edits a trade this device already deleted: the deletion wins
  fresh({ '1025': T1('1025') }); M.guard = true; await login();
  await deleteTradeSync('1025');
  localStorage.clear(); await reload();                // "second device" never saw the deletion
  trades.push(T1('1025', { pnl: '77' })); await syncTrade(trades[trades.length - 1]);
  check('guard: edit of a trade deleted elsewhere is not saved, removed here', !srvA().includes('1025') && !ids().includes('1025') && !queue().length);

  // 26. explicit undo after the deletion already reached the server
  fresh({ '1026': T1('1026') }); M.guard = true; await login();
  const t26 = trades.find(t => t.id === '1026');
  await deleteTradeSync('1026');
  undoTrade = t26; undoCtx = { owner: dataOwner, epoch: ownerEpoch };   // undo still offered
  undoDelete(); await sleep(300); await syncPendingQueue();
  check('guard: explicit undo restores a delivered deletion', srvA().includes('1026') && ids().includes('1026') && !('__restore' in (M.srv.A['1026'] || {})), M.srv.A['1026']);
  await reload();
  check('guard: restored trade survives reload, flag not stored', ids().includes('1026') && !('__restore' in (trades.find(t => t.id === '1026') || {})));

  // 27. normal flow with the guard: create, edit, delete with undo window, no early delete
  fresh(); M.guard = true; await login();
  const n27 = T1('1027'); trades.push(n27); await syncTrade(n27);
  const e27 = { ...n27, pnl: '45' }; trades[0] = e27; await syncTrade(e27);
  check('guard: create and edit', M.srv.A['1027']?.pnl === '45' && !queue().length);
  M.log = []; deleteTrade('1027'); await sleep(300); await loadData(); await syncPendingQueue();
  check('guard: no delete sent inside the undo window', !M.log.some(x => x.method === 'DELETE'), M.log.filter(x => x.method === 'DELETE'));
  await sleep(5400);
  check('guard: delete sent after the window', !srvA().includes('1027') && M.order.some(o => o === 'A DELETE 1027'));
  const n27b = T1('1028'); trades.push(n27b); await syncTrade(n27b); deleteTrade('1028'); await sleep(200); undoDelete(); await sleep(5500); await syncPendingQueue();
  check('guard: undo inside the window keeps the trade', srvA().includes('1028') && ids().includes('1028'));

  // 29. (review 2) an old undo cannot lift a newer deletion
  fresh({ '1031': T1('1031') }); M.guard = true; await login();
  const t31 = trades.find(t => t.id === '1031');
  await deleteTradeSync('1031');                                   // deletion no. 1 delivered from here
  M.gens.A['1031'] = 2;                                             // meanwhile another device deleted it again (no. 2)
  undoTrade = t31; undoCtx = { owner: dataOwner, epoch: ownerEpoch };
  undoDelete(); await sleep(300); await syncPendingQueue();
  check('guard: old undo (no. 1) does not lift deletion no. 2', !srvA().includes('1031') && !ids().includes('1031') && M.order.some(o => o.includes('POST(ignored) 1031')), M.order);

  // 30. (review 3) an older save's "deleted" answer must not wipe a newer undo from the queue
  fresh({ '1030': T1('1030') }); M.guard = true; await login();
  const t30 = trades.find(t => t.id === '1030');
  await deleteTradeSync('1030');                                   // no. 1 delivered from here
  lsSet('pending_trades_v3', JSON.stringify([T1('1030', { pnl: 'old' })]), 'web:uid-A');   // an older save still queued
  M.delay = { 'POST /trades': 600 };
  const run30 = syncPendingQueue(); await sleep(100);              // the older save is in flight
  undoTrade = t30; undoCtx = { owner: dataOwner, epoch: ownerEpoch };
  undoDelete();                                                     // queues the undo of no. 1
  await run30; M.delay = {}; await sleep(300); await syncPendingQueue();
  check('guard: newer undo survives the older save\'s answer and is delivered',
    srvA().includes('1030') && M.srv.A['1030']?.pnl === '10' && ids().includes('1030') && !queue().length && M.order.some(o => o.startsWith('A RESTORE 1030')), { order: M.order, srv: M.srv.A['1030'], q: queue() });

  // 28. account isolation with the guard: A's deletion does not affect B's trade with the same id
  fresh({ '1029': T1('1029') }, { '1029': T1('1029', { pair: 'B_OWN' }) }); M.guard = true; await login('A');
  await deleteTradeSync('1029'); await reload('B'); await syncPendingQueue();
  check('guard: deletion stays within the account', !srvA().includes('1029') && Object.keys(M.srv.B).includes('1029') && ids().includes('1029'));

  localStorage.clear();
  console.table(results);
  const failed = results.filter(r => r.result === 'FAIL').length;
  console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
  return { total: results.length, failed, results };
})();
