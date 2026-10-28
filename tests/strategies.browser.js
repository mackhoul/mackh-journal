/*
 * Strategies in the real app: create, edit, link to trades, revisions,
 * notes and weeks, reload / sign-in again, account switch, server outages.
 *
 * How to run (no Render, no Supabase):
 *   1. Make a copy of index.html where `const SERVER = ...` is replaced by
 *      'http://127.0.0.1:9' (unreachable) and serve the copy with this file.
 *   2. Open http://127.0.0.1:<port>/index.html?test=1 (clear localStorage of
 *      that origin and reload first), then paste this file into the console or
 *      `await eval(await (await fetch('strategies.browser.js')).text())`.
 * window.fetch is replaced by an in-page fake server with two fictional
 * accounts (A, B); localStorage of this origin is cleared at start and end.
 */
(async () => {
  const b64u = o => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  const TOK = { A: 'e30.' + b64u({ sub: 'uid-A' }) + '.x', B: 'e30.' + b64u({ sub: 'uid-B' }) + '.x' };
  const M = { users: {}, log: [], down: false, unavailable: false, hold: null, confirm: true };
  const userOf = a => a === 'Bearer ' + TOK.A ? 'A' : a === 'Bearer ' + TOK.B ? 'B' : null;
  window.fetch = async (url, opt = {}) => {
    const u = new URL(url, location.href), H = opt.headers || {}, method = opt.method || 'GET';
    const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { 'Content-Type': 'application/json' } });
    if (u.pathname === '/config') return json({ web_auth_ready: true, supabase_url: 'https://mock.supabase.test', supabase_anon_key: 'x' });
    if (u.pathname === '/health') return json({ status: 'ok' });
    const user = userOf(H['Authorization'] || '');
    const body = opt.body ? JSON.parse(opt.body) : null;
    M.log.push({ user, method, path: u.pathname, id: body?.id, kind: body?.kind });
    if (!user) return json({ error: 'expired' }, 401);
    const U = (M.users[user] ||= { trades: {}, docs: {} });
    if (u.pathname.startsWith('/strategy-docs')) {
      if (M.hold) await M.hold;
      if (M.down) throw new TypeError('Failed to fetch');
      if (M.unavailable) return json({ error: 'strategy_store_unavailable' }, 503);
      if (method === 'GET') return json({ docs: Object.values(U.docs) });
      if (method === 'POST') {
        const cur = U.docs[body.id]; let outcome = 'saved';
        if (!cur) U.docs[body.id] = { id: body.id, kind: body.kind, data: body.data, v: body.v, deleted: false };
        else if (cur.kind !== body.kind) outcome = 'conflict';
        else if (cur.deleted) outcome = 'deleted';
        else if (body.v === cur.v) outcome = JSON.stringify(cur.data) === JSON.stringify(body.data) ? 'same' : 'collision';
        else if (body.v < cur.v) outcome = 'stale';
        else if (body.kind === 'revision' && JSON.stringify(cur.data.content) !== JSON.stringify(body.data.content)) outcome = 'immutable';
        else { cur.data = body.data; cur.v = body.v; }
        return json({ ok: true, outcome });
      }
      if (method === 'DELETE') {
        const id = decodeURIComponent(u.pathname.split('/')[2]), v = Number(u.searchParams.get('v')), cur = U.docs[id];
        if (!cur) U.docs[id] = { id, kind: u.searchParams.get('kind'), data: {}, v, deleted: true };
        else { cur.deleted = true; cur.data = {}; cur.v = Math.max(cur.v, v); }
        return json({ ok: true, outcome: 'deleted' });
      }
    }
    if (u.pathname === '/trades' && method === 'GET') return json(Object.values(U.trades));
    if (u.pathname === '/trades' && method === 'POST') { U.trades[body.id] = body; return json({ ok: true }); }
    if (u.pathname.startsWith('/trades/') && method === 'DELETE') { delete U.trades[decodeURIComponent(u.pathname.split('/')[2])]; return json({ ok: true }); }
    if (u.pathname === '/settings') return json({ base_capital: 0, goals: [] });
    if (u.pathname === '/billing/status') return json({ billing_enabled: false });
    if (u.pathname === '/ideas') return json([]);
    return json({ error: 'not found' }, 404);
  };
  supaConfig = { web_auth_ready: true, supabase_url: 'https://mock.supabase.test', supabase_anon_key: 'x' };
  const realConfirm = window.confirm;
  window.confirm = () => M.confirm;
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const settle = async () => { await sleep(650); document.getAnimations().forEach(a => { try { a.finish(); } catch (e) {} }); await sleep(30); };
  const login = async who => { saveWebSession({ access_token: TOK[who], refresh_token: 'r' + who, email: who.toLowerCase() + '@test' }); document.getElementById('authGate').classList.remove('show'); await startApp(); await settle(); };
  const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
  const click = async el => { if (!el) throw new Error('missing element'); el.click(); await settle(); };
  const results = [];
  const check = (name, ok, detail) => results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : JSON.stringify(detail)?.slice(0, 300) });
  const strategies = () => sdocAll('strategy');
  const sample = await new Promise(res => { const x = new XMLHttpRequest(); x.open('GET', 'tests/fixtures/strategy-sample.md'); x.onload = () => res(x.status === 200 ? x.responseText : null); x.onerror = () => res(null); x.send(); })
    || '# Контекст\n- [ ] H4 — главный ТФ.\n- [x] OTE [0,62–0,79].\n\n# Модель входа\n1. BOS M5\n2. ☑ Лимит в OTE\n\n# Чеклист перед входом\n- [ ] BIAS записан.';

  localStorage.clear();
  await login('A');
  openStrategies(); await settle();

  // ── empty start, optional everywhere ──
  check('empty: three ways to start', $$('#stratRoot .sr-path').length === 3);
  openAddTrade(); await settle();
  check('trade form: no strategy field while there are none', $('#tStrategyGroup').hidden === true);
  closeModal('addModal');

  // ── template: section names only ──
  await click($('#stratRoot [data-sa=start-template]'));
  $('#srNewName').value = 'Шаблонная';
  await click($('[data-sf=create] button[type=submit]'));
  let s = sdocs[SU.id].data;
  check('template: six sections, all empty', s.sections.length === 6 && s.sections.every(x => x.rules.length === 0), s.sections);
  check('template: no risk, RR, instruments or hours set', Object.values(s.passport).every(v => v === '') && s.checklist.length === 0, s.passport);
  check('template: empty section shows a draft prompt', !!$('#srCardHold .sr-blank'));

  // ── blank: one section, no extra columns ──
  await click($('#stratRoot [data-sa=new]'));
  await click($('#stratModal [data-sa=start-blank]'));
  $('#srNewName').value = 'Короткая';
  await click($('[data-sf=create] button[type=submit]'));
  check('blank: one section', sdocs[SU.id].data.sections.length === 1);
  check('blank: no step rail', !$('.sr-steps') && $('.sr-route').classList.contains('single'));

  // ── from text: preview, correct, create a separate strategy ──
  await click($('#stratRoot [data-sa=new]'));
  await click($('#stratModal [data-sa=start-text]'));
  $('#srImpName').value = 'H4 → M5';
  $('#srImpText').value = sample;
  await click($('[data-sf=parse] button[type=submit]'));
  const previewText = $$('#stratModal .sr-prev textarea').map(t => t.value).join('\n');
  check('import preview: task marks gone', !/^\s*(\[[ xX]?\]|[☐☑□])/m.test(previewText), previewText.slice(0, 200));
  check('import preview: range kept', previewText.includes('[0,62–0,79]'));
  check('import preview: source shown whole', $('#stratModal .sr-src textarea').value === sample);
  $('#srPrevT0').value = 'Мои условия';
  await click($('[data-sf=import] button[type=submit]'));
  s = sdocs[SU.id].data;
  check('import: separate strategy, earlier ones stay', strategies().length === 3 && s.name === 'H4 → M5', strategies().map(x => x.data.name));
  check('import: corrected title used', s.sections[0].name === 'Мои условия');
  check('import: source kept', s.source && s.source.text === sample);
  check('import: nothing of the text ran as code', !$('#stratRoot script') && !window.__xss);

  // ── edit a section: add, move, save ──
  await click($('.sr-step[data-step="1"]'));
  await click($('#srCardHold [data-sa=edit]'));
  const before = sdocs[SU.id].data.sections[1].rules.slice();
  await click($('#srCardHold [data-sa=row-add]'));
  const rows = $$('#srCardHold textarea[name=rule]');
  rows[rows.length - 1].value = 'Новый пункт';
  rows[rows.length - 1].dispatchEvent(new Event('input', { bubbles: true }));
  await click($$('#srCardHold [data-sa=row-up]').pop());
  // leaving with unsaved edits asks first
  M.confirm = false;
  await click($('.sr-step[data-step="2"]'));
  check('dirty edit: refusing to leave keeps the editor', SU.editing && !!$('#srCardHold form'));
  M.confirm = true;
  await click($('#srCardHold button[type=submit]'));
  const after = sdocs[SU.id].data.sections[1].rules;
  check('edit: new point saved in its new place', after.length === before.length + 1 && after[after.length - 2] === 'Новый пункт', after);
  await settle();
  check('edit: delivered to the account', M.users.A.docs[SU.id]?.data.sections[1].rules.includes('Новый пункт'));
  check('status: saved to the account', $('#stratStatus').textContent.includes('аккаунт') || $('#stratStatus').textContent.includes('account'));

  // ── fast: fold right after a section switch, quick steps in the window ──
  {
    const moves = srMoves();
    srGoStep(2);                                                   // no pause: the old card is still leaving
    const bodies = $$('#srCardBody').length, leaving = $$('#srCardHold > .sr-leaving').length;
    $('#srCardHold > .sr-swap:not(.sr-leaving) [data-sa=fold]').click();
    await settle();
    const body = $('#srCardBody'), btn = $('#srCardHold [data-sa=fold]');
    check('fast fold: one card body while the old card leaves', bodies === 1 && (!moves || leaving === 1), { bodies, leaving, moves });
    check('fast fold: the visible section folds, state matches the screen', SU.collapsed === true && body.hidden === true && btn.getAttribute('aria-expanded') === 'false', { collapsed: SU.collapsed, hidden: body.hidden, aria: btn.getAttribute('aria-expanded') });
    btn.click(); await settle();
    check('fast fold: opens again', SU.collapsed === false && !$('#srCardBody').hidden && $('#srCardHold [data-sa=fold]').getAttribute('aria-expanded') === 'true');
    // the window: text → preview → back to the text, without pauses
    await click($('#stratRoot [data-sa=new]'));
    $('#stratModal [data-sa=start-text]').click();
    $('#srImpName').value = 'Быстро'; $('#srImpText').value = '## Вход\n- BOS M5';
    $('[data-sf=parse] button[type=submit]').click();
    const forms = $$('#stratModal [data-sf]').length, stale = $$('#stratModal .sr-leaving [id], #stratModal .sr-leaving [data-sa]').length;
    $('#stratModal [data-sa=back-text]').click();
    await settle();
    check('fast window steps: one live form, the leaving copy has no ids or hooks', forms === 1 && (!moves || stale === 0) && $$('#stratModal .sr-leaving').length === 0, { forms, stale, moves });
    check('fast window steps: ends on the text with focus inside the window', !!$('#stratModal [data-sf=parse]') && $('#stratModal').contains(document.activeElement), document.activeElement?.outerHTML?.slice(0, 80));
    stratCloseDialog(true); await settle();
  }

  // ── trades: without and with a strategy ──
  const H4 = SU.id;
  openQuickAdd(); await settle();
  check('quick form: strategy field offered', $('#qStrategyGroup').hidden === false);
  setQuick('result', 'win'); $('#qPnl').value = '50'; $('#qPair').value = 'EURUSD';
  saveQuickTrade(); await settle();
  const tNo = trades[trades.length - 1];
  check('trade without strategy: no link', !tNo.strategyId);
  openAddTrade(); await settle();
  $('#tPair').value = 'XAUUSD'; setTrade('result', 'win'); $('#tPnl').value = '125'; $('#tCommission').value = '4,50'; $('#tSwap').value = '-1,25';
  stepNext(1); await settle();
  $('#tStrategy').value = H4;
  saveTrade(); await settle();
  const t1 = trades[trades.length - 1];
  check('trade with strategy: linked to a frozen revision', t1.strategyId === H4 && !!t1.strategyRevId && sdocs[t1.strategyRevId]?.kind === 'revision', t1);
  check('trade keeps setup and «by plan» fields apart', 'setup' in t1 && 'byPlan' in t1);
  const rev1 = JSON.stringify(sdocs[t1.strategyRevId].data.content);
  // change the rules: the recorded trade keeps its revision
  await click($('.sr-step[data-step="0"]'));
  await click($('#srCardHold [data-sa=edit]'));
  $$('#srCardHold textarea[name=rule]')[0].value = 'Правило после изменения';
  await click($('#srCardHold button[type=submit]'));
  check('rules changed: the old trade\'s revision did not change', JSON.stringify(sdocs[t1.strategyRevId].data.content) === rev1);
  openEditTrade(t1.id); await settle();
  stepNext(1); await settle();
  check('editing the trade shows its strategy', $('#tStrategy').value === H4);
  saveTrade(); await settle();
  const t1b = trades.find(t => t.id === t1.id);
  check('editing the trade keeps its revision', t1b.strategyRevId === t1.strategyRevId);
  openAddTrade(); await settle();
  $('#tPair').value = 'EURUSD'; setTrade('result', 'loss'); $('#tPnl').value = '-40';
  stepNext(1); await settle(); $('#tStrategy').value = H4; saveTrade(); await settle();
  const t2 = trades[trades.length - 1];
  check('a new trade gets the new rules', t2.strategyRevId !== t1.strategyRevId && sdocs[t2.strategyRevId].data.content.sections[0].rules[0] === 'Правило после изменения');
  openDetail(t1.id); await settle();
  check('trade window names the strategy', $('#detailBody').textContent.includes('H4 → M5'));
  stratShowRevision(t1.strategyRevId); await settle();
  check('trade window opens the rules it was recorded with', !$('#stratModalBody').textContent.includes('Правило после изменения'));
  stratCloseDialog(true); await settle(); closeModal('detailModal');

  // ── numbers of the strategy: its own trades ──
  openStrategies(); await settle();
  await click($('#srTab-trades'));
  const kpis = $$('#srPanel .sr-kpi b').map(b => b.textContent);
  check('trades tab: only linked trades', kpis[0] === '2', kpis);
  check('trades tab: total with commission and swap', kpis[1].includes('79.25'), kpis);

  // ── home totals: preliminary like the cards (the −40 trade has no costs yet) ──
  goPage('home', document.querySelector('.nb')); renderHome(); await settle();
  {
    const pre = /предв\.|prelim\./, pending = trades.filter(tradeCostsPending).length;
    check('home: day total, capital and P&L marked preliminary', pending > 0 && pre.test($('#dmTotal').textContent) && pre.test($('#dmBadge').textContent) && pre.test($('#balAmount').textContent) && pre.test($('#kpiPnl').textContent),
      { pending, day: $('#dmTotal').textContent, badge: $('#dmBadge').textContent, cap: $('#balAmount').textContent, kpi: $('#kpiPnl').textContent });
    const today = new Date().toISOString().split('T')[0];
    const sum = trades.filter(t => t.date === today).reduce((s, t) => s + (tradeNet(t) || 0), 0);
    check('home: the day total is still the same sum', $('#dmTotal').textContent.includes(Math.abs(sum).toFixed(2)), { sum, day: $('#dmTotal').textContent });
  }
  openStrategies(); await settle();

  // ── notes, hypotheses, week ──
  await click($('#srTab-notes'));
  await click($('#srPanel [data-sa=note-new]'));
  $('#srN-text').value = 'Вошёл раньше BOS M5'; $('#srN-text').dispatchEvent(new Event('input', { bubbles: true }));
  await click($('[data-sf=note] button[type=submit]'));
  check('note saved', sdocAll('note', d => d.data.strategyId === H4).length === 1);
  const noteId = sdocAll('note')[0].id;
  await click($(`#srPanel [data-sa=note-edit][data-id="${noteId}"]`));
  $('#srN-text').value = 'Вошёл раньше BOS M5 — дважды';
  await click($('[data-sf=note] button[type=submit]'));
  check('note edited after saving', sdocs[noteId].data.text.endsWith('дважды'));
  await click($('#srTab-hypotheses'));
  await click($('#srPanel [data-sa=hyp-new]'));
  $('#srH-title').value = 'Вход от 0,705'; $('#srH-text').value = '20 сделок';
  await click($('[data-sf=hyp] button[type=submit]'));
  check('hypothesis saved with its status', sdocAll('hypothesis')[0]?.data.status === 'testing');
  await click($('#srTab-week'));
  $('#srWk-worked').value = 'Ждал BOS'; $('#srWk-worked').dispatchEvent(new Event('input', { bubbles: true }));
  check('week: unsaved changes are shown', $('#srWeekState').textContent.includes('несохранённые') || $('#srWeekState').textContent.includes('Unsaved'));
  await click($('[data-sf=week] button[type=submit]'));
  check('week: saved for this strategy and week', sdocs['wk:' + H4 + ':' + srWeekStart()]?.data.worked === 'Ждал BOS');

  // ── device storage full and no network: nothing claims «saved» ──
  {
    const realSetItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function (k, v) { if (String(k).includes('strategy_docs_v1')) { const e = new Error('full'); e.name = 'QuotaExceededError'; throw e; } return realSetItem.call(this, k, v); };
    M.down = true;
    $('#toast').textContent = '';
    // the week (still on its tab)
    $('#srWk-next').value = 'Неделя не сохранилась'; $('#srWk-next').dispatchEvent(new Event('input', { bubbles: true }));
    await click($('[data-sf=week] button[type=submit]'));
    check('storage full: the week stays unsaved and says why', SU.weekDirty === true && !$('[data-sf=week] .ferr').hidden && sdocs['wk:' + H4 + ':' + srWeekStart()]?.data.next !== 'Неделя не сохранилась', { dirty: SU.weekDirty, state: $('#srWeekState').textContent });
    check('storage full: no «Итог недели сохранён»', !$('#toast').textContent.includes('сохранён'), $('#toast').textContent);
    Storage.prototype.setItem = realSetItem; M.down = false;
    await click($('[data-sf=week] button[type=submit]'));
    await sdocSync();
    check('space freed: the same week saves', SU.weekDirty === false && sdocs['wk:' + H4 + ':' + srWeekStart()]?.data.next === 'Неделя не сохранилась' && !sdocUnsent().length);
    M.down = true;
    // a note in its window
    Storage.prototype.setItem = function (k, v) { if (String(k).includes('strategy_docs_v1')) { const e = new Error('full'); e.name = 'QuotaExceededError'; throw e; } return realSetItem.call(this, k, v); };
    $('#toast').textContent = '';
    await click($('#srTab-notes'));
    await click($('#srPanel [data-sa=note-new]'));
    $('#srN-text').value = 'Не потерять этот текст'; $('#srN-text').dispatchEvent(new Event('input', { bubbles: true }));
    await click($('[data-sf=note] button[type=submit]'));
    const err = $('[data-sf=note] .ferr');
    check('storage full: the note window stays open with its text', $('#stratModal').classList.contains('open') && $('#srN-text')?.value === 'Не потерять этот текст' && SU.dlgDirty === true);
    check('storage full: the form says why', !!err && !err.hidden && /памят|storage/i.test(err.textContent), err?.textContent);
    check('storage full: no «Наблюдение сохранено», not kept as a note', !$('#toast').textContent.includes('сохранено') && sdocAll('note').length === 1, { toast: $('#toast').textContent, notes: sdocAll('note').length });
    check('storage full: nothing waits to be sent', sdocUnsent().length === 0 && !$('#stratStatus').textContent.includes('сохранено на устройстве'), $('#stratStatus').textContent);
    Storage.prototype.setItem = realSetItem;
    M.down = false;
    await click($('[data-sf=note] button[type=submit]'));
    check('space freed: the same note saves', !$('#stratModal').classList.contains('open') && sdocAll('note').length === 2);
    const extra = sdocAll('note').find(d => d.data.text === 'Не потерять этот текст');
    if (extra) sdocRemove(extra.id);
    await settle();
  }
  await click($('#srTab-notes'));
  await click($(`#srPanel [data-sa=note-edit][data-id="${noteId}"]`));
  await click($('#stratModal [data-sa=note-del]'));
  await settle();
  check('note deleted, on the account too', !sdocAll('note').length && M.users.A.docs[noteId]?.deleted === true);

  // ── fixed revision and history ──
  await click($('#stratRoot [data-sa=fix]'));
  $('#srF-label').value = 'v1.1'; $('#srF-what').value = 'Изменил первое правило'; $('#srF-why').value = 'После разбора';
  await click($('[data-sf=fix] button[type=submit]'));
  check('history: fixed revision listed', $('#srPanel').textContent.includes('v1.1') && $('#srPanel').textContent.includes('После разбора'));

  // ── sign in again / another device ──
  await settle();
  const ids = Object.keys(sdocs).sort();
  setDataOwner(null); await login('A'); openStrategies(); await settle();
  check('sign in again: everything is back', JSON.stringify(Object.keys(sdocs).sort()) === JSON.stringify(ids));
  Object.keys(localStorage).filter(k => k.includes('strategy_docs_v1')).forEach(k => localStorage.removeItem(k));
  setDataOwner(null); await login('A'); openStrategies(); await settle();
  check('a device without a copy gets it from the account', strategies().length === 3 && sdocAll('week').length === 1, strategies().length);
  check('trade link still resolves after that', !!sdocs[t1.strategyRevId]);

  // ── another account ──
  setDataOwner(null); await login('B'); openStrategies(); await settle();
  check('account B: sees none of A\'s strategies', strategies().length === 0 && !!$('#stratRoot .sr-path'));
  await click($('#stratRoot [data-sa=start-blank]'));
  $('#srNewName').value = 'Стратегия B';
  await click($('[data-sf=create] button[type=submit]'));
  check('account B: its own strategy on its own account', Object.values(M.users.B.docs).some(d => d.data.name === 'Стратегия B') && !Object.values(M.users.A.docs).some(d => d.data.name === 'Стратегия B'));
  // switch while a save is on its way
  let release; M.hold = new Promise(r => { release = r; });
  srOpen(strategies()[0].id); stratRender();
  srSaveStrategy({ ...sdocs[SU.id].data, name: 'B — в пути' });
  await sleep(500);
  setDataOwner(null); await login('A'); openStrategies();
  release(); M.hold = null; await settle(); await settle();
  check('switch during a save: A sees nothing of B', !strategies().some(d => String(d.data.name).startsWith('B')));
  check('switch during a save: B\'s change landed in B only', !Object.values(M.users.A.docs).some(d => String(d.data.name).startsWith('B')));

  // ── outages: honest status, sent later without duplicates ──
  M.unavailable = true;
  srOpen(H4); stratRender();
  srSaveStrategy({ ...sdocs[H4].data, name: 'H4 → M5 (offline)' }); await settle();
  check('server without strategies: status says so', /не принимает|does not take/.test($('#stratStatus').textContent), $('#stratStatus').textContent);
  check('server without strategies: kept on the device', sdocUnsent().length === 1);
  M.unavailable = false; M.down = true;
  await sdocSync(); await settle();
  check('offline: status says it will send later', /Нет связи|Offline/.test($('#stratStatus').textContent), $('#stratStatus').textContent);
  M.down = false;
  const postsBefore = M.log.filter(x => x.method === 'POST' && x.path === '/strategy-docs').length;
  await sdocSync(); await settle();
  check('back: delivered once', M.users.A.docs[H4].data.name === 'H4 → M5 (offline)' && M.log.filter(x => x.method === 'POST' && x.path === '/strategy-docs').length === postsBefore + 1);
  check('back: status saved to the account', /аккаунт|account/.test($('#stratStatus').textContent));

  // ── archive: out of the trade form, trades keep it ──
  await click($('#stratRoot [data-sa=archive]'));
  openAddTrade(); await settle(); stepNext(1); await settle();
  check('archived: not offered for a new trade', ![...$('#tStrategy').options].some(o => o.value === H4));
  closeModal('addModal');
  openEditTrade(t1.id); await settle(); stepNext(1); await settle();
  check('archived: an old trade still shows it', $('#tStrategy').value === H4);
  closeModal('addModal');
  check('archived: trades keep their link', trades.find(t => t.id === t1.id).strategyId === H4);

  // ── window: Escape closes, focus returns ──
  srOpen(H4); stratRender(); await settle();
  const opener = $('#stratRoot [data-sa=passport]'); opener.focus(); opener.click(); await settle();
  check('window open', $('#stratModal').classList.contains('open'));
  document.activeElement.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
  await settle();
  check('Escape closes the window', !$('#stratModal').classList.contains('open'));
  check('focus returns to the button that opened it', document.activeElement === opener || document.activeElement?.dataset?.sa === 'passport', document.activeElement?.outerHTML?.slice(0, 80));

  window.confirm = realConfirm;
  localStorage.clear();
  console.table(results);
  const failed = results.filter(r => r.result === 'FAIL').length;
  console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
  return { total: results.length, failed, results };
})();
