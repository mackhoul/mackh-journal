/*
 * Insight quality: money and rule-following are two separate verdicts.
 * A winning trade with a broken rule stays a broken rule; a losing trade by
 * the rules is not a mistake; an unknown answer is not «clean». The planned
 * E model is not the money, a win rate is not a profit, costs are not blamed
 * without data, a preliminary total gives no confident praise, every fired
 * card is reachable through «Все» and a user's text is shown as text.
 *
 * Runs the real generateInsights / getInsightDetail / renderInsights /
 * openInsightDetail of index.html in a sandbox with made-up trades, RU and EN.
 *
 * Run:  node tests/insights-quality.test.cjs
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8').replace(/\r\n/g, '\n');
const cut = (from, to) => { const a = html.indexOf(from), b = html.indexOf(to, a); if (a < 0 || b < 0) throw new Error('block not found: ' + from); return html.slice(a, b); };
const code = [
  cut('function costNum(', '// The account\'s last choice'),
  cut('function parseRR(rr){', 'function fmt('),
  cut('function calcStats(list){', '// Honest period-over-period'),
  cut('const MISTAKES_LABELS =', 'function escapeHtmlNl('),
  cut('function plural(n, one, few, many){', '\n}\n') + '\n}\n',
  cut('function getDismissedInsights(){', 'function renderHome(){'),
  cut('function renderInsights(showAll){', 'function renderGoalsBanner(){'),
].join('\n');

function sandbox({ list, lang = 'ru', capital = 0, quick = true, storage = {} }) {
  const store = new Map(Object.entries(storage).map(([k, v]) => [k, JSON.stringify(v)]));
  const nodes = new Map();
  const el = () => ({ style: {}, textContent: '', innerHTML: '', children: [], classList: { add() {}, remove() {} }, appendChild(n) { this.children.push(n); } });
  const ctx = {
    Math, Number, String, Date, Object, Array, Set, Map, JSON, parseFloat, isNaN, isFinite,
    lang, trades: list, baseCapital: capital, appSettings: { quickInAnalytics: quick },
    _insightsShowAll: false, _dismissedOpen: false,
    lsJSON: (k, f) => store.has(k) ? JSON.parse(store.get(k)) : f, lsSet: (k, v) => store.set(k, v),
    T: k => k, openModal() {}, closeModal() {},
    document: { getElementById(id) { if (!nodes.has(id)) nodes.set(id, el()); return nodes.get(id); }, createElement: el },
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  vm.runInContext(code, ctx);
  return { ctx, nodes, store };
}

const results = [];
const check = (name, ok, detail) => results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : String(JSON.stringify(detail)).slice(0, 400) });

let n = 0;
const tr = o => ({ id: 'f' + (++n), date: '2026-10-28', pair: 'EURUSD', result: 'win', pnl: '10', pnlMode: 'gross', commission: '0', swap: '0', ...o });
const many = (k, o) => Array.from({ length: k }, () => tr(o));
const sample = (w, l, extra = {}) => [...many(w, { ...extra, result: 'win', pnl: '10' }), ...many(l, { ...extra, result: 'loss', pnl: '-10' })];
const td = (ctx, t) => typeof ctx.tradeDiscipline === 'function' ? ctx.tradeDiscipline(t) : 'missing';
const CLEAN = { byPlan: true, emotional: false, checklistScore: 1 };
const BROKE = { byPlan: false, emotional: true, checklistScore: 0.5 };

function run(list, opts = {}) {
  const s = sandbox({ list, ...opts });
  let ins = [], error = null;
  try { ins = s.ctx.generateInsights(); } catch (e) { error = e.message; }
  const details = ins.map(i => { try { return s.ctx.getInsightDetail(i); } catch (e) { return { content: { why: ['ERR ' + e.message], fix: [] } }; } });
  return { ...s, ins, error, details };
}
const cardText = r => r.ins.map(i => [i.text, i.meta, i.rec].filter(Boolean).join(' | ')).join('\n');
const detailText = r => r.details.map(d => [...(d.content.why || []), ...(d.content.fix || [])].join(' | ')).join('\n');
const allText = r => cardText(r) + '\n' + detailText(r);
const byId = (r, id) => r.ins.find(i => i.id === id);
const byPrefix = (r, p) => r.ins.find(i => (i.id || '').startsWith(p));

// ── 1. B/E is 0R, not a full loss ──
{
  const list = many(30, { pnl: '0', result: 'be', rr: '1:2' });
  const r = run(list);
  const e = byPrefix(r, 'strategy_expectancy');
  check('30 B/E: the model gives exactly 0R', r.ctx.calcExpectancy(list) === 0, r.ctx.calcExpectancy(list));
  check('… the E card is not the negative one and says E = 0.00R, a zero without a sign', e && e.id !== 'strategy_expectancy_bad' && /E = 0\.00R/.test(e.text), e);
  check('… no text speaks of 30 losses or of losing money', !/30 убытк|последние 30|теряет деньги|loses money|last 30 losses/i.test(allText(r)), allText(r));
  const unmarked = [...many(10, { result: 'win', rr: '1:2' }), ...many(10, { result: 'loss', pnl: '-10', rr: '1:2' }), ...many(10, { result: undefined, rr: '1:2' })];
  check('a trade without a marked result is left out of the model, not counted as a loss', Math.abs(r.ctx.calcExpectancy(unmarked) - 0.5) < 1e-9, r.ctx.calcExpectancy(unmarked));
}
// ── 2. a mathematical zero is not negative ──
{
  const list = sample(10, 20, { rr: '1:2' });
  const r = run(list);
  check('10 Win + 20 Loss at 1:2: the model is exactly 0', r.ctx.calcExpectancy(list) === 0, r.ctx.calcExpectancy(list));
  check('… no negative E card and no «-0.00R»', !byId(r, 'strategy_expectancy_bad') && !/[−-]0\.00R/.test(cardText(r)), cardText(r));
}
// ── 3. money, not win rate ──
{
  const r = run([tr({ setup: 'Range', pnl: '100' }), ...many(2, { setup: 'Range', pnl: '-10', result: 'loss' })]);
  const c = byPrefix(r, 'range_wr');
  check('Range +100, −10, −10: the card shows +$80, the good branch', c && c.id === 'range_wr_good' && /\+\$80/.test(c.text), c);
  check('… nothing calls it losing', !/убыточ|losing|unprofitable/i.test(cardText(r)), cardText(r));
  const o = run([tr({ setup: 'Off-plan', pnl: '100' }), ...many(2, { setup: 'Off-plan', pnl: '-10', result: 'loss' })]);
  const oc = byId(o, 'offplan_wr');
  check('Off-plan +100, −10, −10: the card shows +$80 and is not called losing', oc && /\+\$80/.test(oc.text) && !/убыточ|unprofitable/i.test(oc.text + oc.meta), oc);
  check('… a profit off the plan stays a plan break, the card says so', oc && oc.type !== 'good' && /вне плана/i.test(oc.rec || '') , oc);
}
{
  const r = run([...many(2, { setup: 'Range', pnl: '1' }), tr({ setup: 'Range', pnl: '-100', result: 'loss' })]);
  const c = byPrefix(r, 'range_wr');
  check('Range +1, +1, −100: the card shows −$98, not «working»', c && c.id === 'range_wr' && /−\$98/.test(c.text) && !/работает|working/i.test(cardText(r)), cardText(r));
  check('… no card about this money is «good»', !r.ins.some(i => i.type === 'good'), r.ins.map(i => [i.id, i.type]));
  check('… no advice to add size, scale or prove an edge (cards and details)', !/объём|размер позиц|масштаб|add size|scale|доказан|proven/i.test(allText(r)), allText(r));
}
// ── 4. sessions: loss concentration is reachable ──
{
  const r = run(many(3, { session: 'London', pnl: '-10', result: 'loss' }));
  const c = byId(r, 'sess_loss_London');
  check('three London losses: the loss-concentration card shows', c && /London/.test(c.text) && /3 из 3/.test(c.text), r.ins.map(i => i.id));
}
// ── 5. clean vs broken: a real 0% ──
{
  const r = run([...many(2, { ...CLEAN, pnl: '10' }), ...many(2, { ...BROKE, pnl: '-10', result: 'loss' })]);
  const c = byId(r, 'clean_trades');
  check('clean 100% against broken 0%: the comparison shows', c && /100 п\.п\./.test(c.text), r.ins.map(i => [i.id, i.text]));
}
// ── 6. violations without clean trades / with an empty checklist ──
{
  const r = run(many(4, { ...BROKE, pnl: '-10', result: 'loss' }));
  check('4 of 4 with broken rules and no clean trade: the violations card shows', !!byId(r, 'dirty_trades'), r.ins.map(i => i.id));
  const x = run([...many(2, CLEAN), ...many(4, { byPlan: false, checklistScore: null, pnl: '-10', result: 'loss' })]);
  const d = byId(x, 'dirty_trades');
  check('«not by plan» with an empty checklist is still a violation', d && /4 из 6/.test(d.text), x.ins.map(i => [i.id, i.text]));
  const ctx = x.ctx;
  check('… per trade: byPlan=false, no checklist → broken', td(ctx, { byPlan: false, checklistScore: null }) === 'dirty');
  check('… per trade: «Нарушил план» with byPlan=true → broken', td(ctx, { byPlan: true, checklistScore: 1, mistakes: ['broke_plan'] }) === 'dirty');
  check('… per trade: setup Off-plan → broken', td(ctx, { byPlan: true, checklistScore: 1, setup: 'Off-plan' }) === 'dirty');
}
// ── 7. profitable violations, losing rule-following, unknown answers ──
{
  const ctx = run(many(3, {})).ctx;
  check('a profitable trade with a broken rule is broken', td(ctx, { ...BROKE, pnl: '50' }) === 'dirty');
  check('a losing trade by the rules is clean, not a violation', td(ctx, { ...CLEAN, pnl: '-50', result: 'loss' }) === 'clean');
  check('no plan answer and no checklist: unknown, not clean', td(ctx, { byPlan: null, checklistScore: null }) === null);
  check('by plan but no checklist: unknown, not clean', td(ctx, { byPlan: true, checklistScore: null }) === null);
  check('only marked emotional, otherwise by the rules: not clean and not a rule break', td(ctx, { ...CLEAN, emotional: true }) === null);
  check('another mistake mark alone is not a rule break', td(ctx, { ...CLEAN, mistakes: ['early_entry'] }) === 'clean');
}
{
  // three broken trades all closed in profit, two clean losses
  const r = run([...many(3, { ...BROKE, pnl: '20', setup: 'Trend' }), ...many(2, { ...CLEAN, pnl: '-10', result: 'loss', setup: 'Trend' })]);
  const d = byId(r, 'dirty_trades');
  check('3 profitable violations of 5: counted as violations, with their money apart', d && /3 из 5/.test(d.text) && /Прибыльных нарушений 3, убыточных 0/.test(d.meta) && /\+\$60/.test((byId(r, 'dirty_profit') || {}).meta || ''), d);
  check('… no «clean trades are better» praise from them', !r.ins.some(i => i.id === 'clean_trades' && i.type === 'good'), r.ins.map(i => [i.id, i.type]));
  check('… the profitable setup with violations is not «good»', !r.ins.some(i => (i.id || '').startsWith('best_setup') && i.type === 'good'), r.ins.map(i => [i.id, i.type]));
  const dp = byId(r, 'dirty_profit');
  check('… the winning rule breaks have their own card, which says the profit does not confirm the rules', dp && /не подтвержда/.test(dp.rec || '') && dp.type !== 'good', dp);
}
{
  // share of violations under a half: the profitable ones still get a card
  const r = run([...many(2, { ...BROKE, pnl: '30' }), ...many(4, { ...CLEAN, pnl: '10' })]);
  const p = byId(r, 'dirty_profit');
  check('2 profitable violations among 6: a neutral card counts them', p && /2 из 2/.test(p.text) && /\+\$60/.test(p.meta) && p.type !== 'good', r.ins.map(i => [i.id, i.text, i.meta]));
}
// ── 8. costs are not blamed without data ──
{
  const r = run([...many(15, { pnl: '1', rr: '1:2' }), ...many(15, { pnl: '-2', result: 'loss', rr: '1:2' })]);
  const e = byPrefix(r, 'strategy_expectancy');
  check('costs 0, total −$15: the E card does not say costs ate the edge', e && e.id === 'strategy_expectancy_costs' && !/съеда|eat|комиссии и свопы/i.test(e.rec || '') && /\$0\.00/.test(e.rec || ''), e);
  const c = run(many(30, { pnl: '1', commission: '2', rr: '1:2' }));
  const ce = byPrefix(c, 'strategy_expectancy');
  check('commission 2 on +1 each: the card shows the costs from the records', ce && /\$60\.00/.test(ce.rec || '') && /\+\$30\.00/.test(ce.rec || ''), ce);
}
// ── 9. drawdown ──
{
  const r = run([tr({ date: '2026-10-26', pnl: '100' }), tr({ date: '2026-10-27', pnl: '-50', result: 'loss' }), tr({ date: '2026-10-28', pnl: '0', result: 'be' })], { capital: 0 });
  check('unknown starting capital: no account drawdown percent', !byId(r, 'drawdown') && !/просадк|drawdown/i.test(cardText(r)), cardText(r));
  const k = run([tr({ pnl: '-150', result: 'loss' }), tr({ pnl: '0', result: 'be' }), tr({ pnl: '0', result: 'be' })], { capital: 1000 });
  const d = byId(k, 'drawdown');
  check('capital 1000, −150: the largest drawdown in the history is 15.0%, the current one apart', d && /15\.0%/.test(d.text) && /за историю/.test(d.text) && /сейчас 15\.0%/.test(d.meta), d);
  const back = run([tr({ date: '2026-10-26', pnl: '-150', result: 'loss' }), tr({ date: '2026-10-27', pnl: '200' }), tr({ date: '2026-10-28', pnl: '0', result: 'be' })], { capital: 1000 });
  const b = byId(back, 'drawdown');
  check('… after a recovery the current drawdown is 0%', b && /сейчас 0\.0%/.test(b.meta), b);
  const past = run([tr({ pnl: '-120', result: 'loss' }), tr({ pnl: '-50', result: 'loss' }), tr({ pnl: '0', result: 'be' })], { capital: 100 });
  const p = byId(past, 'drawdown');
  check('capital 100 with −170 of losses: the capital does not fit, no percent at all', p && !/\d%/.test(p.text + p.meta) && /больше начального капитала/.test(p.text), p);
}
{
  const r = run(many(3, { setup: 'Range', pnl: '10' }));
  check('counts are declined: «по 3 сделкам», not «по 3 сделки»', /по 3 сделкам,/.test((byPrefix(r, 'range_wr') || {}).text || ''), byPrefix(r, 'range_wr'));
}
// ── 10. preliminary and almost-missing money ──
{
  const r = run(many(3, { setup: 'Range', pnl: '1', commission: '', swap: '' }));
  check('three Range +1 with costs not given: no «good» card', !r.ins.some(i => i.type === 'good'), r.ins.map(i => [i.id, i.type]));
  const c = byPrefix(r, 'range_wr');
  check('… the Range card is marked preliminary', c && /предв\./.test(c.text + c.meta), c);
  const b = byPrefix(r, 'best_setup');
  check('… the setup card is marked preliminary too', b && /предв\./.test(b.meta), b);
  const one = run([tr({ pnl: '1', rr: '1:2' }), ...many(29, { pnl: '', rr: '1:2' })]);
  const e = byPrefix(one, 'strategy_expectancy');
  check('one known P&L of 30: no «good» E card, the share of known money is told', e && e.type !== 'good' && /1 из 30/.test(e.text + e.meta + (e.rec || '')), e);
  check('… and no detail speaks of a proven edge', !/доказан|proven|математически прибыльна|mathematically profitable/i.test(detailText(one)), detailText(one));
}
// ── 11. dismissal is per setup ──
{
  const list = [...many(3, { setup: 'Trend', pnl: '10' }), ...many(3, { setup: 'Range', pnl: '-10', result: 'loss' })];
  const before = run(list);
  const trend = byPrefix(before, 'best_setup');
  check('the best-setup card has its own id per setup', trend && trend.id !== 'best_setup' && trend.id.startsWith('best_setup_'), trend && trend.id);
  const dismissed = { best_setup: { count: 3, ts: Date.now(), text: 'old' } };
  dismissed[trend.id.replace('Trend', 'Range')] = { count: 3, ts: Date.now(), text: 'Range' };
  const r = run(list, { storage: { dismissed_insights_v1: dismissed } });
  check('a dismissed Range (and the old shared id) does not hide Trend', !!byPrefix(r, 'best_setup_') && /Trend/.test(byPrefix(r, 'best_setup_').text), r.ins.map(i => i.id));
  const d2 = { [trend.id]: { count: 3, ts: Date.now(), text: 'Trend' } };
  const r2 = run(list, { storage: { dismissed_insights_v1: d2 } });
  check('… dismissing Trend itself hides it', !byPrefix(r2, 'best_setup_'), r2.ins.map(i => i.id));
}
// ── 12. «Все» shows every fired card ──
const crowded = [
  ...sample(3, 1, { session: 'London', setup: 'Trend', ...CLEAN }),
  ...sample(1, 5, { session: 'New York', setup: 'Range', ...BROKE, mistakes: ['early_entry'] }),
  ...many(3, { session: 'Asia', setup: 'Off-plan', pnl: '-40', result: 'loss', ...BROKE, mistakes: ['early_entry'] }),
];
{
  const r = run(crowded, { capital: 100 });
  check('crowded journal: more than 7 cards fire and none is cut off', r.ins.length > 7, r.ins.map(i => i.id));
  r.ctx.renderInsights(true);
  const shown = (r.nodes.get('insightsWrap').innerHTML.match(/class="insight-card /g) || []).length;
  check('… «Все» renders every one of them', shown === r.ins.length, { shown, all: r.ins.length });
  r.ctx.renderInsights(false);
  const home = r.nodes.get('insightsWrap').innerHTML;
  check('… the home view shows one card and offers the rest', (home.match(/class="insight-card /g) || []).length === 1 && new RegExp('Ещё ' + (r.ins.length - 1)).test(home), home.slice(0, 200));
  check('… the scope of the sample is written under the cards', /Вся история/.test(home) && /все стратегии вместе/.test(home), home.slice(-300));
}
// ── 13. a user's text is text ──
{
  const r = run(many(3, { setup: '<em data-audit-marker="true">Review</em>', pnl: '10' }));
  r.ctx.renderInsights(true);
  const h = r.nodes.get('insightsWrap').innerHTML;
  check('HTML in a setup name is shown as text in the card', !/<em data-audit-marker/.test(h) && /&lt;em data-audit-marker/.test(h), h.slice(0, 300));
  const card = byPrefix(r, 'best_setup');
  check('… the card id is safe inside onclick', card && /^[A-Za-z0-9_\-]+$/.test(card.id), card && card.id);
  r.ctx.openInsightDetail(card.id);
  const body = r.nodes.get('insightDetailBody').innerHTML;
  check('… and in the detail window', !/<em data-audit-marker/.test(body), body.slice(0, 300));
  const m = run(many(3, { mistakes: ["x');alert(1);('"], pnl: '-10', result: 'loss' }));
  const mc = byPrefix(m, 'mistake_');
  check('a made-up mistake key cannot break out of the onclick string', mc && /^[A-Za-z0-9_\-]+$/.test(mc.id), mc && mc.id);
}
// ── 14. wording: percentage points, no prescriptions, no made-up causes ──
{
  const c = run([...sample(3, 1, CLEAN), ...sample(1, 3, BROKE)]);
  const cc = byId(c, 'clean_trades');
  check('clean 75% vs broken 25%: «50 п.п.», not «50% лучше»', cc && /50 п\.п\./.test(cc.text) && !/50% лучше/.test(cc.text), cc);
  const e = run([...sample(1, 3, { emotional: true }), ...sample(3, 1, { emotional: false })]);
  const ec = byId(e, 'emotional');
  check('emotional 25% vs 75%: «50 п.п.»', ec && /50 п\.п\./.test(ec.text), ec);
  const en = run([...sample(1, 3, { emotional: true }), ...sample(3, 1, { emotional: false })], { lang: 'en' });
  check('… in English «50 pp»', /50 pp/.test((byId(en, 'emotional') || {}).text || ''), byId(en, 'emotional'));
  const small = run([tr({ emotional: true, pnl: '-10', result: 'loss' }), tr({ emotional: true, pnl: '' }), tr({ emotional: false, pnl: '10' }), tr({ emotional: false, pnl: '' })]);
  check('emotional groups with one known result each: no comparison', !byId(small, 'emotional'), small.ins.map(i => i.id));
}

// ── 15. every type, both languages: no prescriptions, no broken text ──
const scenarios = {
  sessions: [...sample(2, 1, { session: 'London' }), ...sample(1, 2, { session: 'New York' }), ...sample(1, 2, { session: 'Asia' })],
  sessLoss: many(3, { session: 'London', pnl: '-10', result: 'loss' }),
  setups: [...many(3, { setup: 'Trend', pnl: '10', ...CLEAN }), ...many(3, { setup: 'Range', pnl: '-10', result: 'loss' })],
  offplan: many(3, { setup: 'Off-plan', pnl: '-10', result: 'loss' }),
  rangeGood: many(3, { setup: 'Range', pnl: '10', ...CLEAN }),
  clean: [...sample(3, 1, CLEAN), ...sample(1, 3, BROKE)],
  dirty: [...many(2, { ...CLEAN, pnl: '10' }), ...many(5, { ...BROKE, pnl: '-10', result: 'loss' })],
  dirtyProfit: [...many(2, { ...BROKE, pnl: '30' }), ...many(4, { ...CLEAN, pnl: '10' })],
  mistakes: ['early_entry', 'late_entry', 'no_confirm', 'overtrade', 'broke_plan'].map(k => many(3, { mistakes: [k], pnl: '-10', result: 'loss' })),
  noData: many(5, {}),
  eBad: sample(10, 20, { rr: '1:1' }),
  eOk: sample(15, 15, { rr: '1:1.2' }),
  eCosts: many(30, { rr: '1:2', pnl: '1', commission: '2' }),
  eNoMoney: many(30, { pnl: '', rr: '1:2' }),
  eGood: [...many(15, { rr: '1:3', pnl: '30', ...CLEAN }), ...many(15, { rr: '1:3', pnl: '-10', result: 'loss', ...CLEAN })],
  eOneMoney: [tr({ pnl: '1', rr: '1:2' }), ...many(29, { pnl: '', rr: '1:2' })],
  emotional: [...sample(1, 3, { emotional: true }), ...sample(3, 1, { emotional: false })],
  drawdown: [[tr({ pnl: '-150', result: 'loss' }), tr({ pnl: '0', result: 'be' }), tr({ pnl: '0', result: 'be' })], 1000],
  crowded: [crowded, 100],
};
const FORBIDDEN = /увелич\S* (объём|размер)|добавля\S* объём|масштабир|0[.,]5\s?%|BOS\/CHOCH|доказан|edge работает|ваш edge|proven|edge works|add size|scale (size|gradually)|increase size|психолог|ликвидност|волатильност|концентрац\S* внимания|psycholog|liquidity|volatility|не торгуйте|пропускайте сессию|skip the session|halve|вдвое|лимит 2 сделки|max 2 trades|срочно|urgently/i;
const seen = new Set();
for (const lang of ['ru', 'en']) {
  for (const [name, sc] of Object.entries(scenarios)) {
    const sets = name === 'mistakes' ? sc.map(l => [l, 0]) : typeof sc[1] === 'number' ? [sc] : [[sc, 0]];
    for (const [list, capital] of sets) {
      const r = run(list, { lang, capital });
      if (r.error) { check(`${lang} ${name}: generator throws`, false, r.error); continue; }
      r.ins.forEach(i => seen.add((i.id || '').replace(/_(London|New York|Asia)$/, '').replace(/^(best_setup|worst_setup|mistake)_.*/, '$1')));
      const text = allText(r);
      const bad = text.match(FORBIDDEN);
      check(`${lang} ${name}: no prescription, made-up cause or proven-edge claim`, !bad, bad && bad[0] + ' … ' + text.slice(Math.max(0, bad.index - 120), bad.index + 80));
      check(`${lang} ${name}: no undefined / NaN / null% in cards and details`, !/undefined|NaN|null%|\bnull\b/.test(text), text.slice(0, 300));
      if (lang === 'en') check(`en ${name}: no Russian words in cards and details`, !/[А-Яа-яЁё]/.test(text), (text.match(/.{0,60}[А-Яа-яЁё].{0,40}/) || [''])[0]);
      r.ctx.renderInsights(true);
      r.ins.forEach(i => {
        r.ctx.openInsightDetail(i.id);
        const body = r.nodes.get('insightDetailBody').innerHTML;
        if (!(lang === 'ru' ? /Что это значит/.test(body) : /What this means/.test(body))) check(`${lang} ${name} ${i.id}: the detail heading is neutral`, false, body.slice(0, 200));
      });
    }
  }
}
const TYPES = ['best_sess', 'worst_sess', 'sess_loss', 'best_setup', 'worst_setup', 'offplan_wr', 'range_wr', 'range_wr_good', 'clean_trades', 'dirty_trades', 'dirty_profit', 'mistake',
  'strategy_no_data', 'strategy_expectancy_bad', 'strategy_expectancy_ok', 'strategy_expectancy_costs', 'strategy_expectancy_good', 'emotional', 'drawdown'];
const missing = TYPES.filter(t => !seen.has(t));
check('every insight type fired in at least one scenario', !missing.length, { missing, seen: [...seen] });

console.table(results);
const failed = results.filter(x => x.result === 'FAIL').length;
console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
process.exit(failed ? 1 : 0);
