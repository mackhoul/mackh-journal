/*
 * Insights and goals with the money result after costs: a trade without a P&L
 * stays unknown (not B/E, not a 0% win rate), the planned-R model on the marked
 * results is not given out as the profit after costs, and a win rate that waits
 * on a missing cost says «предв.». Runs the real generateInsights and
 * getGoalProgress of index.html in a sandbox with made-up trades.
 *
 * Run:  node tests/net-results-insights.test.cjs
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const cut = (from, to) => { const a = html.indexOf(from), b = html.indexOf(to, a); if (a < 0 || b < 0) throw new Error('block not found: ' + from); return html.slice(a, b); };
const ctx = {
  lang: 'ru', Math, Number, String, Date, Object, Array, Set, JSON, parseFloat, isNaN,
  trades: [], baseCapital: 0, appSettings: { quickInAnalytics: true },
  parseRR: v => { const n = Number(String(v || '').replace('1:', '')); return n > 0 ? n : null; },
  isInsightDismissed: () => false, calcDiscipline: () => null,
};
vm.createContext(ctx);
vm.runInContext([
  cut('function costNum(', '// The account\'s last choice'),
  cut('function calcStats(list){', '// Expectancy ='),
  cut('function calcExpectancy(list){', '// Honest period-over-period'),
  cut('function generateInsights(){', 'function renderHome(){'),
  cut('function getGoalProgress(g){', '// ═══'),
].join('\n') + '\n;globalThis.__set = (k, v) => { if (k === "trades") trades = v; if (k === "lang") lang = v; };', ctx);

const results = [];
const check = (name, ok, detail) => results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : String(JSON.stringify(detail)).slice(0, 300) });
let n = 0;
const tr = o => ({ id: 'x' + (n++), date: '2026-10-28', pair: 'EURUSD', session: 'London', result: 'win', pnlMode: 'gross', commission: '0', swap: '0', ...o });
const many = (k, o) => Array.from({ length: k }, () => tr(o));
const run = (list, lang = 'ru') => {
  ctx.__set('trades', list); ctx.__set('lang', lang);
  try { return { ins: ctx.generateInsights(), error: null }; } catch (e) { return { ins: [], error: e.message }; }
};
const all = r => r.ins.map(i => [i.text, i.meta, i.rec].join(' | ')).join('\n');
const has = (r, s) => all(r).includes(s);
const broken = r => /undefined|null%|NaN/.test(all(r));

// ── unknown P&L: no crash, no made-up rates ──
{
  const r = run([...many(3, { setup: 'Trend', pnl: '10' }), ...many(3, { setup: 'Range', pnl: '' })]);
  check('three Trend with P&L, three Range without: insights do not throw', r.error === null, r.error);
  check('… the Range group without P&L is not «weak» and has no rate', !has(r, 'Слабый сетап') && !has(r, '"Range" (WR'), all(r));
  check('… nothing reads undefined / null% / NaN', !broken(r), all(r));
}
{
  const r = run([...many(3, { setup: 'Trend', session: 'London', pnl: '' }), ...many(3, { setup: 'Range', session: 'New York', pnl: '' })]);
  check('only trades without P&L: no throw, no session or setup rate', r.error === null && !/\(WR |сессия:|сетап:/i.test(all(r)) && !broken(r), r.error || all(r));
}
{
  const r = run([...many(3, { session: 'London', pnl: '-10' }), ...many(3, { session: 'New York', pnl: '' })]);
  check('one session known, one without P&L: no best / worst between them', r.error === null && !has(r, 'Лучшая сессия') && !has(r, 'Худшая сессия') && !broken(r), r.error || all(r));
}
{
  const r = run([...many(3, { setup: 'Trend', pnl: '-10', result: 'win' }), ...many(3, { setup: 'Range', pnl: '10' })]);
  check('a real 0% win rate (three known losses) is still shown as 0%', has(r, 'Слабый сетап: "Trend" (WR 0%)') && has(r, '3 убытков из 3'), all(r));
}
{
  const r = run([...many(2, { setup: 'Trend', pnl: '-10' }), tr({ setup: 'Trend', pnl: '' }), ...many(3, { setup: 'Range', pnl: '10' })]);
  check('two known losses + one without P&L: too few known results for a setup verdict', !has(r, 'Слабый сетап') && !broken(r), all(r));
}
{
  const r = run([...many(3, { setup: 'Trend', pnl: '0', result: 'be' }), tr({ setup: 'Trend', pnl: '' }), ...many(3, { setup: 'Range', pnl: '10' })]);
  check('three real B/E + one without P&L: the setup counts 0% of 3 known', has(r, 'Слабый сетап: "Trend" (WR 0%)') && has(r, '0 убытков из 3'), all(r));
}

// ── the planned model on the marked results and the money after costs ──
{
  const r = run(many(30, { pnl: '1', commission: '2', swap: '0', rr: '1:2' }));
  const s = r.ins.find(i => /E = /.test(i.text)) || {};
  check('30 marked Win, −$1 each after costs: not «profitable», no advice to scale', r.error === null && !has(r, 'прибыльная') && !/масштабируйте постепенно/.test(all(r)), all(r));
  check('… the E line names its basis: the marked results', /по отметкам/.test(s.text || ''), s.text);
  check('… the money after costs is apart: WR 0%, −$30.00', /после расходов: WR 0%, P&L −\$30\.00/.test(s.meta || ''), s.meta);
  check('… and the marked rate is not called the money one', /^По отметкам: Win 100%/.test(s.meta || ''), s.meta);
  check('… the insight warns, the advice speaks of the total after costs', s.type === 'warn' && /после расходов/.test(s.rec || ''), { type: s.type, rec: s.rec });
  const en = run(many(30, { pnl: '1', commission: '2', swap: '0', rr: '1:2' }), 'en').ins.find(i => /E = /.test(i.text)) || {};
  check('… the same in English', /marked results/.test(en.text || '') && /after costs: WR 0%, P&L −\$30\.00/.test(en.meta || '') && /after costs/.test(en.rec || '') && !/scale gradually/.test(en.rec || ''), en);
}
{
  const r = run(many(30, { pnl: '1', commission: '0', swap: '0', rr: '1:2' }));
  const s = r.ins.find(i => /E = /.test(i.text)) || {};
  check('the same 30 with costs given as 0: +$30.00, the model and the money agree', s.type === 'good' && /после расходов: WR 100%, P&L \+\$30\.00/.test(s.meta || '') && !/предв/.test(s.meta || ''), s);
}

{
  const r = run(many(30, { pnl: '', rr: '1:2' }));
  const s = r.ins.find(i => /E = /.test(i.text)) || {};
  check('30 marked Win without any P&L: the money is «unknown», not $0.00 eaten by costs', r.error === null && /итог после расходов неизвестен/.test(s.text || '') && /после расходов: WR —, P&L \$0\.00/.test(s.meta || '') && !/съедают/.test(s.rec || '') && !/масштабируйте постепенно/.test(all(r)), s);
}

// ── preliminary: a cost still missing ──
{
  const list = many(30, { pnl: '1', commission: '2', swap: '', rr: '1:2' });
  const s = run(list).ins.find(i => /E = /.test(i.text)) || {};
  check('swap not given: the money part says «предв.»', /после расходов: WR 0%, P&L −\$30\.00 предв\./.test(s.meta || ''), s.meta);
  list.forEach(t => { t.swap = '2'; });
  const s2 = run(list).ins.find(i => /E = /.test(i.text)) || {};
  check('swap +2 typed in: a win after costs, no longer preliminary', /после расходов: WR 100%, P&L \+\$30\.00/.test(s2.meta || '') && !/предв/.test(s2.meta || ''), s2.meta);
}

// ── win-rate goal ──
{
  const g = { type: 'winrate', target: '60' };
  ctx.__set('lang', 'ru');
  ctx.__set('trades', many(3, { pnl: '' }));
  const u = ctx.getGoalProgress(g);
  check('win-rate goal, only trades without P&L: «—», not 0%', /Сейчас — \/ цель 60%/.test(u.label) && u.pct === 0, u);
  ctx.__set('trades', many(3, { pnl: '-5' }));
  const z = ctx.getGoalProgress(g);
  check('win-rate goal, three known losses: a real 0.0%', /Сейчас 0\.0% \/ цель 60%/.test(z.label) && z.pct === 0, z);
}

console.table(results);
const failed = results.filter(x => x.result === 'FAIL').length;
console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
process.exit(failed ? 1 : 0);
