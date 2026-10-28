/*
 * Money result after costs (F1) and older trades keeping their cost mode (F2),
 * through the real forms: quick entry, the full form's edit with its steps,
 * the home counters, the «profitable / losing» window and the capital.
 *
 * How to run (no Render, no Supabase):
 *   1. Make a copy of index.html where `const SERVER = ...` is replaced by
 *      'http://127.0.0.1:9' (unreachable) and serve the copy with this file.
 *   2. Open http://127.0.0.1:<port>/index.html?test=1 (clear localStorage of
 *      that origin and reload first), then paste this file into the console or
 *      `await eval(await (await fetch('net-results.browser.js')).text())`.
 * window.fetch is replaced by an in-page fake server with one fictional
 * account; localStorage of this origin is cleared at start and end.
 */
(async () => {
  const b64u = o => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  const TOK = 'e30.' + b64u({ sub: 'uid-N' }) + '.x';
  const today = new Date().toISOString().split('T')[0];
  // older trades: no pnlMode; one with costs written down, one without, one with a decimal comma
  const SRV = {
    L1: { id: 'L1', pair: 'EURUSD', market: 'forex', session: 'London', dir: 'buy', result: 'win', pnl: '125', commission: '4.5', swap: '-1.25', date: today, notes: '' },
    L2: { id: 'L2', pair: 'GBPUSD', market: 'forex', session: 'London', dir: 'buy', result: 'win', pnl: '125', date: today, notes: '' },
    L3: { id: 'L3', pair: 'USDJPY', market: 'forex', session: 'London', dir: 'sell', result: 'win', pnl: '125', commission: '4,5', swap: '0', date: today, notes: '' },
  };
  const posted = [];
  window.fetch = async (url, opt = {}) => {
    const u = new URL(url, location.href), method = opt.method || 'GET';
    const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'Content-Type': 'application/json' } });
    if (u.pathname === '/config') return json({ web_auth_ready: true, supabase_url: 'https://mock.supabase.test', supabase_anon_key: 'x' });
    if ((opt.headers || {})['Authorization'] !== 'Bearer ' + TOK) return json({ error: 'expired' }, 401);
    const body = opt.body ? JSON.parse(opt.body) : null;
    if (u.pathname === '/trades' && method === 'GET') return json(Object.values(SRV));
    if (u.pathname === '/trades' && method === 'POST') { posted.push(body); SRV[body.id] = body; return json({ ok: true }); }
    if (u.pathname.startsWith('/trades/') && method === 'DELETE') { delete SRV[decodeURIComponent(u.pathname.split('/')[2])]; return json({ ok: true }); }
    if (u.pathname.startsWith('/strategy-docs')) return json({ error: 'strategy_store_unavailable' }, 503);
    if (u.pathname === '/settings') return json({ base_capital: 0, goals: [] });
    if (u.pathname === '/billing/status') return json({ billing_enabled: false });
    if (u.pathname === '/ideas') return json([]);
    return json({ error: 'not found' }, 404);
  };
  supaConfig = { web_auth_ready: true, supabase_url: 'https://mock.supabase.test', supabase_anon_key: 'x' };
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const settle = async () => { await sleep(500); document.getAnimations().forEach(a => { try { a.finish(); } catch (e) {} }); await sleep(30); };
  const $ = s => document.querySelector(s);
  const results = [];
  const check = (name, ok, detail) => results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : JSON.stringify(detail)?.slice(0, 300) });
  const tradeOf = id => trades.find(t => t.id === id);
  const typeIn = (id, v) => { const el = document.getElementById(id); el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); };
  // the full form: open the edit, walk the steps, save
  const editAndSave = async (id, change) => {
    openEditTrade(id); await settle();
    if (change) await change();
    stepNext(1); await settle();
    typeIn('tNotes', 'правка заметки');
    stepNext(2); await settle(); stepNext(3); await settle(); stepNext(1); await settle();
    saveTrade(); await settle();
    return tradeOf(id);
  };

  localStorage.clear();
  saveWebSession({ access_token: TOK, refresh_token: 'rN', email: 'n@test' });
  document.getElementById('authGate').classList.remove('show');
  await startApp(); await settle();

  // ── F2: an older trade keeps «not set» unless the trader decides ──
  openEditTrade('L1'); await settle();
  check('older trade with costs: the form preview shows the P&L, not 119.25', /125\.00/.test($('#tCostTotal').textContent) && !/119\.25/.test($('#tCostTotal').textContent), $('#tCostTotal').textContent);
  closeModal('addModal'); await settle();
  let t = await editAndSave('L1');
  check('older trade with costs, notes edited, steps walked: no mode written', t.pnlMode === undefined && tradeNet(t) === 125 && t.notes === 'правка заметки', { mode: t.pnlMode, net: tradeNet(t) });
  check('older trade with costs: the costs kept as they were', t.commission === '4.5' && t.swap === '-1.25', { c: t.commission, s: t.swap });
  check('the server got it without a mode', posted.at(-1)?.id === 'L1' && !('pnlMode' in posted.at(-1)), posted.at(-1));
  t = await editAndSave('L2');
  check('older trade without costs, notes edited: no mode, 125', t.pnlMode === undefined && tradeNet(t) === 125);
  t = await editAndSave('L3', async () => { typeIn('tCommission', '4.50'); });
  check('the same commission typed as 4.50 (was 4,5): not a change, no mode, kept 4,5', t.pnlMode === undefined && t.commission === '4,5' && tradeNet(t) === 125, { mode: t.pnlMode, c: t.commission });
  // real decisions
  t = await editAndSave('L1', async () => { typeIn('tCommission', '5'); });
  check('commission really changed: the shown mode applies (gross), 118.75', t.pnlMode === 'gross' && tradeNet(t) === 118.75, { mode: t.pnlMode, net: tradeNet(t) });
  t = await editAndSave('L2', async () => { typeIn('tCommission', '0'); });
  check('empty → 0 is a change: gross, total 125, swap still empty', t.pnlMode === 'gross' && tradeNet(t) === 125 && t.swap === '', { mode: t.pnlMode, s: t.swap });
  t = await editAndSave('L3', async () => {
    const sw = document.getElementById('tPnlNet'); sw.checked = true; sw.dispatchEvent(new Event('change', { bubbles: true }));
    stepNext(1); await settle(); stepNext(0); await settle();          // the choice survives the steps
  });
  check('the switch used, then steps back and forth: net is kept, 125', t.pnlMode === 'net' && tradeNet(t) === 125, { mode: t.pnlMode });

  // ── F1: wins and losses after costs, through quick entry (own dates; the home date filter shows only them) ──
  const D1 = '2026-01-15', D2 = '2026-01-16';
  const money = n => '$' + n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const quick = async (date, res, pnl, comm, swap) => {
    openQuickAdd(); await settle();
    setQuick('result', res); document.getElementById('qPair').value = 'XAUUSD'; document.getElementById('qDate').value = date;
    typeIn('qPnl', pnl); typeIn('qCommission', comm); typeIn('qSwap', swap);
    const preview = $('#qCostTotal').textContent;
    saveQuickTrade(); await settle();
    return { t: trades.find(x => x.date === date), preview };
  };
  const q1 = await quick(D1, 'win', '1', '2', '0');
  goPage('home', document.querySelector('.nb')); calState.home.date = D1; renderHome(); await settle();
  check('Win +1, commission 2: preview −$1.00', /−\$1\.00/.test(q1.preview), q1.preview);
  check('home: 0 wins, 1 loss, win rate 0%', $('#kpiWins').textContent === '0' && $('#kpiLosses').textContent === '1' && /0\.0%/.test($('#kpiWinsCtx').textContent), { w: $('#kpiWins').textContent, l: $('#kpiLosses').textContent, ctx: $('#kpiWinsCtx').textContent });
  check('the marked result is kept', q1.t.result === 'win' && q1.t.pnlMode === 'gross');
  openFilterModal('loss'); await settle();
  check('«losing trades» window lists it, like the counter', document.querySelectorAll('#filterModalList .tc').length === 1, document.querySelectorAll('#filterModalList .tc').length);
  closeModal('filterModal'); await settle();
  // commission 2 → 0 through the edit: a win again, the mark untouched
  openEditTrade(q1.t.id); await settle();
  typeIn('tCommission', '0'); saveTrade(); await settle(); renderHome(); await settle();
  check('commission 2 → 0: a win again, the mark untouched', $('#kpiWins').textContent === '1' && $('#kpiLosses').textContent === '0' && tradeOf(q1.t.id).result === 'win', { w: $('#kpiWins').textContent, l: $('#kpiLosses').textContent });
  // capital: +119.25, then commission 10 and swap +1 → 116 (deposit 1000)
  calState.home.date = null; baseCapital = 1000;
  const cap0 = computeCapital();
  const q2 = await quick(D2, 'win', '125', '4,50', '-1,25');
  renderHome(); await settle();
  check('125 − 4.50 − 1.25 = 119.25, capital +119.25', tradeNet(q2.t) === 119.25 && $('#balAmount').textContent.startsWith(money(cap0 + 119.25)), { net: tradeNet(q2.t), cap: $('#balAmount').textContent, want: money(cap0 + 119.25) });
  openEditTrade(q2.t.id); await settle();
  typeIn('tCommission', '10'); typeIn('tSwap', '1');
  const pv = $('#tCostTotal').textContent;
  saveTrade(); await settle(); renderHome(); await settle();
  check('commission 10, swap +1: preview and total 116, capital +116', /116\.00/.test(pv) && tradeNet(tradeOf(q2.t.id)) === 116 && $('#balAmount').textContent.startsWith(money(cap0 + 116)), { pv, cap: $('#balAmount').textContent });
  await loadData(); await settle(); baseCapital = 1000; renderHome(); await settle();
  const back = tradeOf(q2.t.id);
  check('loaded again from the server: the same values', back && back.commission === '10' && back.swap === '1' && back.pnlMode === 'gross' && tradeNet(back) === 116, back);
  calState.home.date = null;

  localStorage.clear();
  console.table(results);
  const failed = results.filter(r => r.result === 'FAIL').length;
  console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
  return { total: results.length, failed, results };
})();
