/*
 * Trade costs: the money result of a trade with commission and swap.
 * Runs the real functions from index.html (the TRADE COSTS block) in a sandbox.
 *
 * Run:  node tests/trade-costs.test.cjs
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const start = html.indexOf('//  TRADE COSTS');
const end = html.indexOf('// The account\'s last choice', start);
if (start < 0 || end < 0) throw new Error('TRADE COSTS block not found in index.html');
const ctx = { lang: 'ru', Number, Math, String, isNaN, parseFloat };
vm.createContext(ctx);
vm.runInContext(html.slice(start, end).replace(/^[^\n]*\n/, ''), ctx);

const results = [];
const check = (name, got, want) => {
  const ok = Object.is(got, want) || (typeof want === 'number' && Math.abs(got - want) < 1e-9);
  results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : `got ${got}, want ${want}` });
};
const net = t => ctx.tradeNet(t);

// The agreed example: 125, commission 4.50, swap −1.25
check('gross: 125 − 4.50 + (−1.25) = 119.25', net({ pnl: '125', commission: '4.5', swap: '-1.25', pnlMode: 'gross' }), 119.25);
check('net: 125 stays 125 with the same costs', net({ pnl: '125', commission: '4.5', swap: '-1.25', pnlMode: 'net' }), 125);
check('older trade without a mode: P&L as it is', net({ pnl: '125', commission: '4.5', swap: '-1.25' }), 125);
check('older trade without costs', net({ pnl: '-40' }), -40);
check('positive swap is added', net({ pnl: '10', commission: '1', swap: '2', pnlMode: 'gross' }), 11);
check('explicit zeros', net({ pnl: '10', commission: '0', swap: '0', pnlMode: 'gross' }), 10);
check('a small win becomes a loss after commission', net({ pnl: '3', commission: '4.5', swap: '0', pnlMode: 'gross' }), -1.5);
check('comma decimal in a cost', net({ pnl: '125', commission: '4,50', swap: '-1,25', pnlMode: 'gross' }), 119.25);
check('no P&L: no number', Number.isNaN(net({ pnl: '', commission: '4', pnlMode: 'gross' })), true);
check('rounded to cents', net({ pnl: '0.1', commission: '0.2', swap: '0', pnlMode: 'gross' }), -0.1);

check('pending: both costs empty', ctx.tradeCostsPending({ pnl: '125', pnlMode: 'gross' }), true);
check('pending: swap empty', ctx.tradeCostsPending({ pnl: '125', commission: '4.5', swap: '', pnlMode: 'gross' }), true);
check('complete: both given', ctx.tradeCostsPending({ pnl: '125', commission: '4.5', swap: '-1.25', pnlMode: 'gross' }), false);
check('complete: explicit zeros', ctx.tradeCostsPending({ pnl: '125', commission: '0', swap: '0', pnlMode: 'gross' }), false);
check('never pending in net mode', ctx.tradeCostsPending({ pnl: '125', pnlMode: 'net' }), false);
check('never pending for an older trade', ctx.tradeCostsPending({ pnl: '125' }), false);

const r = ctx.readCosts('4,50', '-1,25');
check('readCosts normalises the comma', r.commission + '|' + r.swap, '4.5|-1.25');
check('readCosts keeps empty as empty', JSON.stringify(ctx.readCosts('', '')), JSON.stringify({ commission: '', swap: '' }));
check('readCosts keeps an explicit 0', ctx.readCosts('0', '0').commission, '0');
check('readCosts refuses a negative commission', !!ctx.readCosts('-1', '').error, true);
check('readCosts refuses text', !!ctx.readCosts('abc', '').error, true);
check('readCosts refuses a text swap', !!ctx.readCosts('', 'x').error, true);

check('form line: preliminary', /предварительно/.test(ctx.costTotalText('125', '4.5', '', 'gross')), true);
check('form line: net', /уже чистый/.test(ctx.costTotalText('125', '4.5', '-1.25', 'net')), true);
check('form line: total', /\+\$119\.25/.test(ctx.costTotalText('125', '4.5', '-1.25', 'gross')), true);

console.table(results);
const failed = results.filter(x => x.result === 'FAIL').length;
console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
process.exit(failed ? 1 : 0);
