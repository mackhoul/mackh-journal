/*
 * Money result after costs: wins, losses and win rates follow the P&L after
 * commission and swap (tradeNet), not the result marked in the form. Runs the
 * real functions of index.html (costs, counters, streaks, calendar, week,
 * strategy numbers, expectancy) in a sandbox with made-up trades.
 *
 * Run:  node tests/net-results.test.cjs
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const cut = (from, to) => { const a = html.indexOf(from), b = html.indexOf(to, a); if (a < 0 || b < 0) throw new Error('block not found: ' + from); return html.slice(a, b); };
const ctx = {
  lang: 'ru', Math, Number, String, Date, Object, Array, Set, JSON, parseFloat, isNaN,
  journalToday: () => require('../insights-learning.js').day(Date.now(), 'UTC'),
  trades: [], baseCapital: 0, weekOffset: 0, appSettings: { quickInAnalytics: true },
  parseRR: v => { const n = Number(String(v || '').replace('1:', '')); return n > 0 ? n : null; },
};
vm.createContext(ctx);
vm.runInContext([
  cut('function costNum(', '// The account\'s last choice'),
  cut('function computeCapital(', '// Maps internal setup key'),
  cut('function calcStats(list){', '// Expectancy ='),
  cut('function calcStreaks(){', '// ═══'),
  cut('function stratStats(list){', '// ═══'),
  cut('function getTradesByDate(){', 'function buildCalendar('),
  cut('function tradeR(t){', 'function renderExpectancy('),
  cut('function weekRange(offset=0){', 'function weekLabel('),
].join('\n') + '\n;globalThis.__set = (k, v) => { if (k === "trades") trades = v; if (k === "baseCapital") baseCapital = v; };', ctx);

const results = [];
const check = (name, ok, detail) => results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : String(JSON.stringify(detail)).slice(0, 300) });
const outcome = t => typeof ctx.tradeOutcome === 'function' ? ctx.tradeOutcome(t) : 'missing';
const today = new Date().toISOString().split('T')[0];
const tr = (o) => ({ id: String(Math.random()), date: today, ...o });

// ── the matrix of the task ──
const M = [
  ['gross 125, commission 4.50, swap −1.25', tr({ pnl: '125', commission: '4.5', swap: '-1.25', pnlMode: 'gross', result: 'win' }), 119.25, 'win'],
  ['net 125, the same costs: not taken twice', tr({ pnl: '125', commission: '4.5', swap: '-1.25', pnlMode: 'net', result: 'win' }), 125, 'win'],
  ['gross 1, commission 2, swap 0, marked Win', tr({ pnl: '1', commission: '2', swap: '0', pnlMode: 'gross', result: 'win' }), -1, 'loss'],
  ['gross 0, commission 2, swap 0, marked B/E', tr({ pnl: '0', commission: '2', swap: '0', pnlMode: 'gross', result: 'be' }), -2, 'loss'],
  ['gross 2, commission 2, swap 0, marked Win', tr({ pnl: '2', commission: '2', swap: '0', pnlMode: 'gross', result: 'win' }), 0, 'be'],
  ['gross −1, commission 0, swap +2, marked Loss', tr({ pnl: '-1', commission: '0', swap: '2', pnlMode: 'gross', result: 'loss' }), 1, 'win'],
  ['gross, a cost empty: the known ones count', tr({ pnl: '10', commission: '', swap: '-1', pnlMode: 'gross', result: 'win' }), 9, 'win'],
  ['gross, costs given as 0', tr({ pnl: '10', commission: '0', swap: '0', pnlMode: 'gross', result: 'win' }), 10, 'win'],
  ['older trade, costs without a mode', tr({ pnl: '125', commission: '4.5', swap: '-1.25', result: 'win' }), 125, 'win'],
];
M.forEach(([name, t, net, out]) => {
  check(`${name}: total ${net}`, ctx.tradeNet(t) === net, ctx.tradeNet(t));
  check(`${name}: result ${out}`, outcome(t) === out, outcome(t));
});
check('a cost empty: still preliminary, the empty field stays empty', ctx.tradeCostsPending(M[6][1]) && M[6][1].commission === '');
check('costs given as 0: not preliminary', !ctx.tradeCostsPending(M[7][1]));
const noPnl = tr({ pnl: '', commission: '2', swap: '0', pnlMode: 'gross', result: 'win' });
check('no P&L, costs given: no known result (not 0, not Win)', outcome(noPnl) === null);

// ── counters and win rate ──
{
  const s = ctx.calcStats([M[2][1]]);
  check('one trade +1 before costs, −1 after: 0 wins, 1 loss, win rate 0%', s.wins === 0 && s.losses === 1 && s.wr === 0 && s.pnl === -1, s);
  const n = ctx.calcStats([noPnl]);
  check('no P&L: counted as a record, not in the win rate', n.total === 1 && n.known === 0 && n.unknown === 1 && n.wins === 0 && n.losses === 0 && n.wr === null, n);
  const mix = ctx.calcStats([M[0][1], M[2][1], M[4][1], noPnl]);
  check('win rate over trades with a known result: 1 of 3', mix.total === 4 && mix.known === 3 && mix.wins === 1 && mix.losses === 1 && Math.abs(mix.wr - 100 / 3) < 1e-9, mix);
  const t = { ...M[2][1] };
  t.commission = '0';
  check('commission 2 → 0: the loss is a win again, the marked result untouched', ctx.calcStats([t]).wins === 1 && t.result === 'win');
}

// ── strategy numbers ──
{
  const st = ctx.stratStats(M.slice(2, 6).map(x => x[1]).concat([noPnl]));
  check('strategy: by the result after costs', st.byResult.win === 1 && st.byResult.loss === 2 && st.byResult.be === 1 && st.byResult.none === 1, st.byResult);
  check('strategy: share of wins over known results', st.winShare === 0.25, st.winShare);
}

// ── streaks, calendar, week ──
{
  const d = n => new Date(Date.now() - n * 864e5).toISOString().split('T')[0];
  ctx.__set('trades', [
    tr({ date: d(3), pnl: '50', pnlMode: 'gross', commission: '1', swap: '0', result: 'win' }),
    tr({ date: d(2), pnl: '40', pnlMode: 'gross', commission: '1', swap: '0', result: 'win' }),
    tr({ date: d(1), pnl: '1', pnlMode: 'gross', commission: '2', swap: '0', result: 'win' }),   // −1 after costs
  ]);
  const s = ctx.calcStreaks();
  check('win streak: a marked Win that lost money ends it', s.wins.cur === 0 && s.wins.best === 2, s.wins);
  const map = ctx.getTradesByDate();
  check('calendar: the day counts a loss, not a win', map[d(1)].wins === 0 && map[d(1)].losses === 1, map[d(1)]);
  ctx.__set('trades', [M[2][1], M[0][1], noPnl]);
  const w = ctx.weekStats();
  check('week: wins and win rate after costs', w.wins === 1 && w.wr === 50 && w.list.length === 3, { wins: w.wins, wr: w.wr });
}

// ── money figures stay as they were ──
{
  const e = ctx.calcExpStats([M[2][1], M[5][1]]);
  check('expectancy in money, profit factor, average win/loss unchanged', e.expUsd === 0 && e.pf === 1 && e.avgWin === 1 && e.avgLoss === 1, e);
  const t = tr({ pnl: '125', commission: '4.5', swap: '-1.25', pnlMode: 'gross', result: 'win' });
  ctx.__set('trades', [t]); ctx.__set('baseCapital', 1000);
  check('capital with deposit 1000 and a 119.25 trade: 1119.25', ctx.computeCapital() === 1119.25, ctx.computeCapital());
  t.commission = '10'; t.swap = '1';
  check('commission 10, swap +1: 116, capital 1116', ctx.tradeNet(t) === 116 && ctx.computeCapital() === 1116, ctx.computeCapital());
}

console.table(results);
const failed = results.filter(x => x.result === 'FAIL').length;
console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
process.exit(failed ? 1 : 0);
