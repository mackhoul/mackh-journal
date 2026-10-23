/*
 * Two REAL browser tabs of one account (review ad36a0b, P2).
 *
 * Both tabs run the app with the same fake API: the fake server keeps its
 * state in localStorage under "__mock_srv" (shared by the tabs, never read by
 * the app), so a deletion made in one tab is the server state the other tab
 * sees. The 'storage' event between the tabs is the browser's own.
 *
 * How to run (no Render, no Supabase):
 *   1. Make a copy of index.html where `const SERVER = ...` is replaced by
 *      'http://127.0.0.1:9' (unreachable) and serve the copy with this file,
 *      e.g.  python -m http.server <port> --bind 127.0.0.1
 *   2. Open http://127.0.0.1:<port>/index.html?test=1 in TWO tabs.
 *   3. In each tab, load this file (paste it, or
 *      `eval(await (await fetch('two-tabs.browser.js')).text())`), then run
 *      `await TT.start()` — in the first tab call `TT.reset({...trades})`
 *      before that, once.
 *   4. Drive the scenario from the console of each tab; `TT.state()` shows
 *      memory, cache, queue, deletion records, this tab's requests, the
 *      visible sync status and whether the journal list shows a trade.
 *
 * Scenario used for the review (both tabs started with trades 3001, 3002):
 *   tab 2: openEditTrade('3001')                    (edit form open)
 *   tab 1: deleteTrade('3001'); wait 6 s           (deletion delivered)
 *   tab 2: TT.state()  → 3001 gone from memory, list and cache; no request sent
 *   tab 2: change P&L, saveTrade(); TT.state() → no POST, not queued, not cached,
 *          warning shown instead of "Сделка обновлена"
 *   tab 2: await loadData(); TT.state()  → 3001 does not come back
 *   tab 1: deleteTrade('3002'); tab 2: TT.state() → hidden
 *   tab 1: undoDelete();        tab 2: TT.state() → back
 *   wait 6 s: no DELETE of 3002 from either tab; the server still has 3002
 *   tab 1: deleteTrade('3002'); tab 2 → hidden again
 *   tab 2: location.reload(), TT.start() → state matches the server
 */
(() => {
  const SRV = '__mock_srv';
  const b64u = o => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  const TOKEN = 'e30.' + b64u({ sub: 'uid-A' }) + '.x';
  const read = () => JSON.parse(localStorage.getItem(SRV) || '{"trades":{},"deleted":{},"gens":{}}');
  const write = s => localStorage.setItem(SRV, JSON.stringify(s));
  const calls = [];

  window.fetch = async (url, opt = {}) => {
    const u = new URL(url, location.href), method = opt.method || 'GET';
    const json = (b, status = 200) => new Response(JSON.stringify(b), { status, headers: { 'Content-Type': 'application/json' } });
    if (u.pathname === '/config') return json({ web_auth_ready: true, supabase_url: 'https://mock.supabase.test', supabase_anon_key: 'x' });
    if (u.host === 'mock.supabase.test') return json({ error: 'no' }, 400);
    const body = opt.body ? JSON.parse(opt.body) : null;
    calls.push({ method, path: u.pathname, id: body?.id || decodeURIComponent(u.pathname.split('/')[2] || '') || null, pnl: body?.pnl, at: Date.now() });
    const s = read();
    if (u.pathname === '/trades' && method === 'GET') return json(Object.values(s.trades));
    if (u.pathname === '/trades' && method === 'POST') {
      // same rule as the server's deletion guard: a save never re-creates a deleted
      // trade, only an undo naming the latest deletion does
      const restore = Number.isSafeInteger(body.__restore) && body.__restore > 0 ? body.__restore : null;
      delete body.__restore;
      if (s.deleted[body.id] && restore !== s.gens[body.id]) return json({ ok: true, skipped: 'deleted' });
      delete s.deleted[body.id]; s.trades[body.id] = body; write(s);
      return json({ ok: true, img_url: null, img_failed: false });
    }
    if (u.pathname.startsWith('/trades/') && method === 'DELETE') {
      const id = decodeURIComponent(u.pathname.split('/')[2]);
      delete s.trades[id]; s.deleted[id] = true; s.gens[id] = (s.gens[id] || 0) + 1; write(s);
      return json({ ok: true, deletion: s.gens[id] });
    }
    if (u.pathname === '/settings') return json({ base_capital: 0, goals: [] });
    if (u.pathname === '/billing/status') return json({ billing_enabled: false });
    return json({ error: 'not found' }, 404);
  };
  supaConfig = { web_auth_ready: true, supabase_url: 'https://mock.supabase.test', supabase_anon_key: 'x' };

  window.TT = {
    // first tab only, once: clean test storage and put trades on the fake server
    reset(trades = {}) {
      localStorage.clear();
      write({ trades: JSON.parse(JSON.stringify(trades)), deleted: {}, gens: {} });
    },
    async start() {
      saveWebSession({ access_token: TOKEN, refresh_token: 'rA', email: 'a@test' });
      document.getElementById('authGate').classList.remove('show');
      await startApp();
      await new Promise(r => setTimeout(r, 300));
      return TT.state();
    },
    calls,
    state() {
      renderTrades();
      const list = (document.getElementById('allTrades')?.textContent || '') + (document.getElementById('homeTrades')?.textContent || '');
      return {
        memory: trades.map(t => t.id + ':' + t.pnl).sort(),
        cache: lsJSON('trades_v3', []).map(t => t.id + ':' + t.pnl).sort(),
        queue: getQueue().map(q => q.id + ':' + q.pnl),
        tombs: getTombs().map(t => t.id + (t.done ? ':done' : ':open')),
        server: Object.keys(read().trades).sort(),
        sent: calls.filter(c => c.method !== 'GET').map(c => c.method + ' ' + c.id + (c.pnl ? ':' + c.pnl : '')),
        status: syncStatus + ' / ' + (document.getElementById('syncDot')?.title || ''),
        toast: document.getElementById('toast')?.textContent || '',
        listShows: Object.keys(read().trades).concat(trades.map(t => t.id), ['3001', '3002']).filter((v, i, a) => a.indexOf(v) === i && list.includes(v)).sort(),
        notSentLabels: (list.match(/Не отправлено|Нет на сервере|Not sent|Not on server/g) || []).length,
      };
    },
  };
})();
