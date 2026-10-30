/*
 * Follow-up to the insight fixes (Codex FOLLOWUP-REVIEW items 1–6 and the stale R:R):
 * an empty checklist answer is unknown, never a «No»; one explicit «No» is not a full
 * checklist; a green verdict needs every trade confirmed by the rules, so profitable rule
 * breaks never get it; a quick «by plan» answer counts in the plan answers; a single
 * profitable rule break has its own card; a stop at the entry or on the wrong side leaves
 * no old R:R to be saved.
 *
 * Reuses the sandbox of tests/insights-quality.test.cjs (the real index.html code).
 * Run:  node tests/insights-followup.test.cjs
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const src = fs.readFileSync(path.join(__dirname, 'insights-quality.test.cjs'), 'utf8');
const prefix = src.slice(0, src.indexOf('// ── 1. B/E'));
const { run, tr, many, sandbox } = new Function('require', '__dirname', prefix + '\nreturn {run,tr,many,sandbox};')(require, __dirname);
const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8').replace(/\r\n/g, '\n');
const cut = (from, to) => { const a = html.indexOf(from), b = html.indexOf(to, a); if (a < 0 || b < 0) throw new Error('block not found: ' + from); return html.slice(a, b); };

const results = [];
const check = (name, ok, detail) => results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : String(JSON.stringify(detail)).slice(0, 400) });
const byId = (r, id) => r.ins.find(i => i.id === id);
const ALL_YES = { liq: true, str: true, htf: true, news: true, risk: true };
const CLEAN = { byPlan: true, emotional: false, checklistScore: 1, checklistDetail: ALL_YES };
const ctx0 = run(many(3, {})).ctx;
const disc = t => ctx0.tradeDiscipline(t);

// ── 1. an empty answer is unknown, not «No» ──
check('one «Yes», four left empty (score 0.2): not a rule break', disc({ byPlan: true, emotional: false, checklistScore: 0.2, checklistDetail: { liq: true } }) === null);
check('… and no violations card for three such trades', !byId(run(many(3, { byPlan: true, emotional: false, checklistScore: 0.2, checklistDetail: { liq: true } })), 'dirty_trades'));
check('one «Yes», four explicit «No»: a rule break', disc({ byPlan: true, checklistScore: 0.2, checklistDetail: { liq: true, str: false, htf: false, news: false, risk: false } }) === 'dirty');
check('an untouched checklist saved as 0 % with no item answered: unknown', disc({ byPlan: true, emotional: false, checklistScore: 0, checklistDetail: {} }) === null && ctx0.checklistScoreOf({ checklistScore: 0, checklistDetail: {} }) === null);
check('an older record with only a score keeps it', ctx0.checklistScoreOf({ checklistScore: 0.5 }) === 0.5 && disc({ byPlan: true, checklistScore: 0.4 }) === 'dirty' && disc({ byPlan: true, emotional: false, checklistScore: 0.9 }) === 'clean');

// ── 2. one explicit «No» is not a full checklist ──
check('four «Yes» + risk «No» (score 0.8): not clean', disc({ byPlan: true, emotional: false, checklistScore: 0.8, checklistDetail: { ...ALL_YES, risk: false } }) === null);
check('… and not counted as a rule break either', disc({ byPlan: true, emotional: false, checklistScore: 0.8, checklistDetail: { ...ALL_YES, risk: false } }) !== 'dirty');
check('all five «Yes», by plan, calm: clean', disc(CLEAN) === 'clean');
check('four «Yes», one left empty (score 0.8), no «No»: clean', disc({ ...CLEAN, checklistScore: 0.8, checklistDetail: { liq: true, str: true, htf: true, news: true } }) === 'clean');

// ── 3. the green verdict needs every trade confirmed by the rules ──
{
  const r = run(many(30, { byPlan: false, rr: '1:2', setup: 'Range' }));
  check('30 profitable explicit plan breaks: no card is green', !r.ins.some(i => i.type === 'good'), r.ins.map(i => [i.id, i.type]));
  const e = byId(r, 'strategy_expectancy_good');
  check('… the E card tells the money as a number and 0 of 30 confirmed', e && e.type === 'info' && /подтверждено 0 из 30/.test(e.text) && /с нарушением правил 30/.test(e.rec || ''), e);
  const u = run(many(30, { rr: '1:2', setup: 'Range' }));
  check('30 profitable trades without plan answers: no green either', !u.ins.some(i => i.type === 'good'), u.ins.map(i => [i.id, i.type]));
  const c = run(many(3, { ...CLEAN, setup: 'Range', pnl: '10' }));
  check('three confirmed clean profitable Range trades with costs given: green', (byId(c, 'range_wr_good') || {}).type === 'good', byId(c, 'range_wr_good'));
  const mix = run([...many(2, { ...CLEAN, setup: 'Range', pnl: '10' }), tr({ setup: 'Range', pnl: '10' })]);
  check('… one of them without answers: no longer green', (byId(mix, 'range_wr_good') || {}).type === 'info', byId(mix, 'range_wr_good'));
}

// ── 5. a quick «by plan» answer counts in the plan answers, not as a full checklist ──
{
  const quick = many(3, { quickTrade: true, byPlan: true, emotional: false, checklistScore: null, checklistDetail: {} });
  check('quick «by plan» without a checklist: not clean (no checklist was made up)', quick.every(t => disc(t) === null));
  const s = sandbox({ list: quick });
  vm.runInContext(cut('function calcDiscipline(){', 'function calcStreaks(){'), s.ctx);
  const d = s.ctx.calcDiscipline();
  check('… but it counts in «По плану»: 3 of 3 answered', d && d.byPlan === 3, d);
  const full = sandbox({ list: [...many(2, { byPlan: true, checklistScore: 0, checklistDetail: {} }), tr({ byPlan: true, checklistScore: 1, checklistDetail: ALL_YES })] });
  vm.runInContext(cut('function calcDiscipline(){', 'function calcStreaks(){'), full.ctx);
  const fd = full.ctx.calcDiscipline();
  check('untouched full-form checklists (0 %) are left out of «Чеклист»: 1 of 1 full', fd && fd.clFull === 1 && fd.score === 100, fd);
}

// ── 6. a single profitable rule break gets its own card ──
{
  const list = [tr({ byPlan: false, pair: 'GBPUSD', pnl: '50' }), ...many(3, CLEAN)];
  const r = run(list);
  const p = byId(r, 'dirty_profit');
  check('one profitable rule break among four trades: its own card', p && /закрыта в плюсе/.test(p.text) && /GBPUSD 2026-10-28: \+\$50\.00/.test(p.meta) && p.type === 'warn', r.ins.map(i => [i.id, i.text, i.meta]));
  check('… and no share-of-violations card for it (no duplicate)', !byId(r, 'dirty_trades'), r.ins.map(i => i.id));
  const en = run(list, { lang: 'en' });
  check('… in English', /closed in profit/.test((byId(en, 'dirty_profit') || {}).text || ''), byId(en, 'dirty_profit'));
  const hidden = run(list, { storage: { dismissed_insights_v1: { dirty_profit: { count: 1, ts: Date.now(), text: 'x' } } } });
  check('… «Got it» hides it until the next profitable rule break', !byId(hidden, 'dirty_profit'), hidden.ins.map(i => i.id));
  const next = run([...list, tr({ byPlan: false, pnl: '20' })], { storage: { dismissed_insights_v1: { dirty_profit: { count: 1, ts: Date.now(), text: 'x' } } } });
  check('… and the next one brings it back', !!byId(next, 'dirty_profit'), next.ins.map(i => i.id));
}

// ── the checklist score of the form ──
{
  const ctx = { checklist: [{ id: 'liq' }, { id: 'str' }, { id: 'htf' }, { id: 'news' }, { id: 'risk' }], checklistState: {}, tForm: {}, document: { getElementById: () => null }, Math, Object };
  vm.createContext(ctx);
  vm.runInContext(cut('function updateCLScore(){', '// ── Tags'), ctx);
  ctx.updateCLScore();
  check('form: nothing answered → no score (not 0 %)', ctx.tForm.checklistScore === null && JSON.stringify(ctx.tForm.checklistDetail) === '{}', ctx.tForm);
  ctx.checklistState = { liq: true, risk: false };
  vm.runInContext('checklistState = this.checklistState', ctx);
  ctx.updateCLScore();
  check('form: one «Yes», one «No» → 1 of 5, the answers kept', ctx.tForm.checklistScore === 0.2 && ctx.tForm.checklistDetail.risk === false, ctx.tForm);
  vm.runInContext('checklistState = {}; tForm = {legacyCL: 0.6}', ctx);
  ctx.updateCLScore();
  check('form: editing an older trade that has only a score keeps that score', ctx.tForm.checklistScore === 0.6 && ctx.tForm.checklistDetail === undefined, ctx.tForm);
  vm.runInContext('checklistState = {liq:true}', ctx);
  ctx.updateCLScore();
  check('… until an item is answered', ctx.tForm.checklistScore === 0.2 && ctx.tForm.checklistDetail.liq === true, ctx.tForm);
}

// ── R:R: no old value after a bad stop; the stop on the right side ──
{
  const fields = { tEntry: { value: '100' }, tSL: { value: '90' }, tTP: { value: '120' }, rrManualInput: { value: '' } };
  const ctx = { rrManualMode: false, tForm: { dir: 'buy' }, document: { getElementById: k => fields[k] }, fmtRR: n => String(Math.round(n * 100) / 100), setRRDisplay: v => { ctx.display = v; }, isNaN, Math };
  vm.createContext(ctx);
  vm.runInContext(cut('function calcRR(){', '// ── Checklist'), ctx);
  const rr = (dir, e, sl, tp) => { ctx.tForm.dir = dir; fields.tEntry.value = e; fields.tSL.value = sl; fields.tTP.value = tp; ctx.calcRR(); return [ctx.tForm.rrCalc, ctx.display]; };
  check('buy 100 / SL 90 / TP 120 → 1:2', rr('buy', '100', '90', '120').join() === '1:2,1:2');
  check('… SL moved to 100 (= entry): no R:R on screen and none to save', rr('buy', '100', '100', '120').join() === ',', [ctx.tForm.rrCalc, ctx.display]);
  check('buy with the stop above the entry: no R:R', rr('buy', '100', '110', '120')[0] === null);
  check('buy with the target below the entry: no R:R', rr('buy', '100', '90', '80')[0] === null);
  check('sell 100 / SL 110 / TP 80 → 1:2', rr('sell', '100', '110', '80')[0] === '1:2');
  check('sell with buy-side prices: no R:R', rr('sell', '100', '90', '120')[0] === null);
  check('a field cleared: no R:R', rr('buy', '100', '', '120')[0] === null);
  vm.runInContext('rrManualMode = true', ctx);
  ctx.tForm.rrCalc = '1:3'; fields.rrManualInput.value = '1:3';
  rr('buy', '100', '100', '120');
  check('manual R:R: bad points do not overwrite the typed value', ctx.tForm.rrCalc === '1:3' && fields.rrManualInput.value === '1:3', ctx.tForm);
}

// ── Codex review R2: the costs of net records are not zero ──
{
  const e = r => r.ins.find(i => i.id === 'strategy_expectancy_costs') || {};
  const net = e(run(many(30, { pnl: '-1', pnlMode: 'net', commission: '2', swap: '0', rr: '1:2' })));
  check('30 net records −1 with commission 2: costs $60 told, before costs +$30', /комиссии \$60\.00/.test(net.rec || '') && /До расходов итог \+\$30\.00/.test(net.rec || '') && !/комиссии \$0\.00/i.test(net.rec || ''), net.rec);
  const credit = e(run(many(30, { pnl: '-1', pnlMode: 'net', commission: '0', swap: '2', rr: '1:2' })));
  check('net with a swap credit: the swap is counted (before costs −$90)', /свопы \+\$60\.00/.test(credit.rec || '') && /−\$90\.00/.test(credit.rec || ''), credit.rec);
  const old = e(run(many(30, { pnl: '-1', pnlMode: undefined, commission: '2', swap: '0', rr: '1:2' })));
  check('older records without a mode: no made-up total before costs', /не восстановить/.test(old.rec || '') && !/До расходов итог/.test(old.rec || ''), old.rec);
  const part = e(run(many(30, { pnl: '1', commission: '2', swap: '', rr: '1:2' })));
  check('a swap left empty: no claim about before costs, no «предв..»', /не восстановить/.test(part.rec || '') && !/\.\./.test((part.text || '') + (part.rec || '')), part);
  const en = e(run(many(30, { pnl: '-1', pnlMode: 'net', commission: '2', swap: '0', rr: '1:2' }), { lang: 'en' }));
  check('… in English', /Before costs the total is \+\$30\.00; commissions \$60\.00/.test(en.rec || ''), en.rec);
}
// ── Codex review R5 / R6 ──
{
  const z = run(many(30, { pnl: '0', result: 'be', rr: '1:2' })).ins.find(i => /E = /.test(i.text)) || {};
  check('a zero E has no sign: «E = 0.00R»', /E = 0\.00R/.test(z.text || '') && !/[+−-]0\.00R/.test(z.text || ''), z.text);
  const eq = byId(run(many(3, { pnl: '-10', result: 'loss' }), { capital: 30 }), 'drawdown');
  check('capital 30, losses 30: «равны», not «больше», no percent', eq && /равны начальному капиталу/.test(eq.text) && !/\d%/.test(eq.text + eq.meta), eq);
  const over = byId(run(many(3, { pnl: '-20', result: 'loss' }), { capital: 30 }), 'drawdown');
  check('capital 30, losses 60: «больше»', over && /больше начального капитала/.test(over.text), over);
}

console.table(results);
const failed = results.filter(x => x.result === 'FAIL').length;
console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
process.exit(failed ? 1 : 0);
