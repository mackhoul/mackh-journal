/*
 * Insights v2, stage 2 (INSIGHTS-V2-SPEC cards 1–21 and 27): every card carries one doable
 * step and the trades it is about; the comparison of «by the rules» and «with a broken rule»
 * is shown also when the rule breaks earned more; two rule breaks are a repetition; one
 * Off-plan trade is enough to look at; a mistake counts once per trade; losing trades marked
 * «by plan» are not mistakes; plan answers are compared over two windows of 20 in one
 * strategy; missing data is named, never counted as a mistake or as following the rules.
 *
 * Reuses the sandbox of tests/insights-quality.test.cjs (the real index.html code).
 * Run:  node tests/insights-stage2.test.cjs
 */
const fs = require('fs');
const path = require('path');

const src = fs.readFileSync(path.join(__dirname, 'insights-quality.test.cjs'), 'utf8');
const prefix = src.slice(0, src.indexOf('// ── 1. B/E'));
const { run, tr, many } = new Function('require', '__dirname', prefix + '\nreturn {run,tr,many};')(require, __dirname);

const results = [];
const check = (name, ok, detail) => results.push({ check: name, result: ok ? 'PASS' : 'FAIL', detail: ok ? '' : String(JSON.stringify(detail)).slice(0, 400) });
const byId = (r, id) => r.ins.find(i => i.id === id || (id === 'plan_dynamics' && i.id.startsWith('plan_dynamics_')));
const ALL_YES = { liq: true, str: true, htf: true, news: true, risk: true };
const CLEAN = { byPlan: true, emotional: false, checklistScore: 1, checklistDetail: ALL_YES };
const BROKE = { byPlan: false };
let day = 0;
// one trade a day, in order: the windows follow the dates
const dated = (k, o) => Array.from({ length: k }, () => tr({ date: new Date(Date.UTC(2026, 0, 1 + day++)).toISOString().slice(0, 10), ...o }));

// ── every card: one step, and its trades exist ──
{
  const list = [
    ...many(4, { session: 'London', setup: 'Trend', ...CLEAN, pnl: '10' }),
    ...many(4, { session: 'New York', setup: 'Range', ...BROKE, pnl: '-10', result: 'loss', mistakes: ['early_entry', 'early_entry'] }),
    ...many(3, { session: 'Asia', setup: 'Off-plan', pnl: '30', ...BROKE }),
    ...many(2, { byPlan: true, pnl: '-5', result: 'loss' }),
  ];
  const r = run(list, { capital: 100 });
  const ids = new Set(list.map(t => t.id));
  check('a crowded journal: every card has one step', r.ins.length > 8 && r.ins.every(i => typeof i.act === 'string' && i.act.length > 10), r.ins.filter(i => !i.act).map(i => i.id));
  check('… every listed trade exists', r.ins.every(i => (i.tradeIds || []).every(id => ids.has(id))), r.ins.map(i => [i.id, i.tradeIds]));
  check('… the cards about groups of trades link to them', ['best_sess_', 'sess_loss_', 'offplan_wr', 'dirty_trades', 'dirty_profit', 'clean_trades', 'plan_losses', 'mistake_', 'drawdown'].every(p => (r.ins.find(i => i.id.startsWith(p)) || {}).tradeIds?.length), r.ins.map(i => [i.id, (i.tradeIds || []).length]));
  check('… a mistake repeated inside one trade counts once: 4 trades', /в 4 из/.test((r.ins.find(i => i.id.startsWith('mistake_')) || {}).text || ''), r.ins.find(i => i.id.startsWith('mistake_')));
  r.ctx.renderInsights(true);
  const h = r.nodes.get('insightsWrap').innerHTML;
  check('… the card shows «Действие» and a «Сделки: N» button', /<span>Действие<\/span>/.test(h) && /class="insight-trades-btn"[^>]*>Сделки: \d+/.test(h), h.slice(0, 300));
  r.ctx.openInsightDetail('dirty_profit');
  const body = r.nodes.get('insightDetailBody').innerHTML;
  check('… the detail window shows the card’s own step and «Открыть сделки»', /Откройте одну из этих сделок/.test(body) && /Открыть сделки: 3/.test(body), body.slice(0, 400));
}

// ── 9. the comparison is shown when the rule breaks earned more ──
{
  const r = run([...many(3, { ...CLEAN, pnl: '5' }), tr({ ...CLEAN, pnl: '-5', result: 'loss' }), ...many(3, { ...BROKE, pnl: '50' })]);
  const c = byId(r, 'clean_trades');
  check('rule breaks earned more: the comparison still shows, neutral', c && c.type === 'info' && /Более высокий заработок нарушений/.test(c.rec || ''), c);
  check('… and its trades are the winning rule breaks', c && c.tradeIds.length === 3, c && c.tradeIds);
}

// ── 10. two rule breaks are a repetition, with the most frequent reason ──
{
  const r = run([...many(8, CLEAN), ...many(2, { ...BROKE, pnl: '-10', result: 'loss' }), tr({ byPlan: null })]);
  const d = byId(r, 'dirty_trades');
  check('2 of 10 rated with a broken rule: the card shows (no 50 % needed), not alert', d && d.type === 'warn' && /В 2 из 10 оценённых/.test(d.text) && /ещё 1 без оценки/.test(d.text), d);
  check('… it names the most frequent reason', d && /чаще всего — ответ «не по плану» \(2\)/.test(d.meta), d && d.meta);
  check('one rule break alone: no repetition card', !byId(run([...many(8, CLEAN), tr({ ...BROKE, pnl: '-10', result: 'loss' })]), 'dirty_trades'));
}

// ── 6. one Off-plan trade is enough to look at ──
{
  const r = run([tr({ setup: 'Off-plan', pnl: '20' }), ...many(3, CLEAN)]);
  const o = byId(r, 'offplan_wr');
  check('one Off-plan trade: its card shows, a profit is not praise', o && /Вне плана \(Off-plan\) 1 сделка, итог \+\$20\.00/.test(o.text) && o.type !== 'good', o);
  const u = byId(run([tr({ setup: 'Off-plan', pnl: '' }), ...many(3, CLEAN)]), 'offplan_wr');
  check('… without a P&L: «итог неизвестен», not $0', u && /итог неизвестен/.test(u.text), u);
}

// ── 7–8. Range at zero: neutral ──
{
  const r = run([tr({ setup: 'Range', pnl: '10' }), tr({ setup: 'Range', pnl: '-10', result: 'loss' }), ...many(2, CLEAN)]);
  const z = byId(r, 'range_wr_flat');
  check('Range total 0: a neutral card, no praise, no loss warning', z && z.type === 'info' && /итог \$0\.00/.test(z.text), r.ins.map(i => [i.id, i.type, i.text]));
  const big = tr({ setup: 'Range', pnl: '-100', result: 'loss' });
  const b = byId(run([tr({ setup: 'Range', pnl: '1' }), big, ...many(2, CLEAN)]), 'range_wr');
  check('Range in loss: the trade with the largest loss comes first', b && b.tradeIds.length === 2 && b.tradeIds[0] === big.id && /−\$99/.test(b.text), b);
}

// ── 12. not enough data for the model, also at 30+ records without an R:R ──
{
  const r = run(many(30, { rr: '' }));
  const s = byId(r, 'strategy_no_data');
  check('30 records without an R:R: the data card, with the counts', s && /результат отмечен у 30, R:R указан у 0/.test(s.text) && /нужны отмеченный результат и R:R/.test(s.meta), s);
  const few = byId(run(many(5, { rr: '1:2' })), 'strategy_no_data');
  check('5 records: «5 из 30», no call to trade more', few && /5 из 30/.test(few.meta) && /Дополните существующие записи/.test(few.act), few);
}

// ── 20. losing trades marked «by plan» ──
{
  const r = run([tr({ byPlan: true, pnl: '-20', result: 'loss' }), tr({ ...CLEAN, pnl: '-10', result: 'loss' }), tr({ byPlan: true, mistakes: ['broke_plan'], pnl: '-30', result: 'loss' }), tr({ byPlan: null, pnl: '-40', result: 'loss' }), ...many(2, CLEAN)]);
  const p = byId(r, 'plan_losses');
  check('2 losing trades by plan (a «Нарушил план» and an unanswered one are left out)', p && /В 2 убыточных сделках вы отметили соблюдение плана/.test(p.text) && /итог −\$30\.00/.test(p.meta) && /с полным чеклистом 1, только ответ «по плану» 1/.test(p.meta), p);
  check('… a loss alone is not called a mistake', p && /не подтверждает ошибку/.test(p.rec) && p.type === 'info', p);
  const one = byId(run([tr({ byPlan: true, pnl: '-20', result: 'loss' }), ...many(2, CLEAN)]), 'plan_losses');
  check('… one trade: «В 1 убыточной сделке»', one && /^В 1 убыточной сделке/.test(one.text), one);
  const en = byId(run([tr({ byPlan: true, pnl: '-20', result: 'loss' }), ...many(2, CLEAN)], { lang: 'en' }), 'plan_losses');
  check('… in English', en && /You marked a losing trade as following the plan/.test(en.text), en);
}

// ── 21. plan answers over two windows of 20 ──
{
  const prev = [...dated(12, { byPlan: true }), ...dated(8, { byPlan: false })];
  const between = dated(2, { byPlan: null });   // dated between the two periods
  const cur = [...dated(16, { byPlan: true }), ...dated(4, { byPlan: false })];
  const after = dated(3, { byPlan: null });     // after the last answer: outside the periods
  const r = run([...prev, ...between, ...cur, ...after]);
  const d = byId(r, 'plan_dynamics');
  check('12 → 16 of 20: «+20 п.п.», neutral, no money claim', d && /16 из 20 \(80%\), до этого 12 из 20 \(60%\): \+20 п\.п\./.test(d.text) && d.type === 'info' && /не рост прибыльности/.test(d.rec), d);
  check('… the 2 unanswered records inside the periods are told', d && /ещё 2 без ответа о плане/.test(d.meta), d && d.meta);
  check('… its trades are the 4 latest «not by plan»', d && d.tradeIds.length === 4, d && d.tradeIds);
  const down = byId(run([...dated(16, { byPlan: true }), ...dated(4, { byPlan: false }), ...dated(12, { byPlan: true }), ...dated(8, { byPlan: false })]), 'plan_dynamics');
  check('16 → 12 of 20: «−20 п.п.», no shaming words', down && /−20 п\.п\./.test(down.text) && !/плохо|стыд|провал/i.test(down.text + down.rec + down.act), down);
  const same = byId(run([...dated(15, { byPlan: true }), ...dated(5, { byPlan: false }), ...dated(15, { byPlan: true }), ...dated(5, { byPlan: false })]), 'plan_dynamics');
  check('15 → 15 of 20: «доля не изменилась»', same && /доля не изменилась/.test(same.text), same);
  const prog = byId(run(dated(25, { byPlan: true })), 'plan_dynamics');
  check('25 answers: progress only, no conclusion', prog && /25 из 40/.test(prog.text) && /мало для вывода/.test(prog.rec), prog);
  const mixed = byId(run([...dated(20, { byPlan: true, strategyId: 'A', strategyRevId: 'a1' }), ...dated(20, { byPlan: false, strategyId: 'B', strategyRevId: 'b1', strategyName: '<b>Мой план</b>' })]), 'plan_dynamics');
  check('20 in strategy A + 20 in strategy B: not glued into one comparison', mixed && /20 из 40/.test(mixed.text) && /в стратегии «<b>Мой план<\/b>»/.test(mixed.text), mixed);
  check('fewer than 20 answers: no card', !byId(run(dated(19, { byPlan: true })), 'plan_dynamics'));
}

// ── 27. data for the review ──
{
  const r = run([...many(3, { byPlan: null, pnl: '' }), ...many(2, { ...CLEAN, commission: '', pnlMode: 'gross' }), ...many(5, CLEAN)]);
  const g = byId(r, 'data_gaps');
  check('gaps in the last records: named per kind, overlap told', g && /без ответа о плане — 3, без P&L — 3, без расходов — 2/.test(g.text) && /могут пересекаться/.test(g.meta), g);
  check('… the step and the trades go to the first gap', g && /Откройте записи без ответа о плане/.test(g.act) && g.tradeIds.length === 3, g);
  check('nothing missing: no card', !byId(run(many(5, CLEAN)), 'data_gaps'));
  const old = byId(run([...many(25, { byPlan: null }), ...many(20, CLEAN)]), 'data_gaps');
  check('only the last 20 records are looked at', !old, old);
}

// ── 18. the drawdown links to its period ──
{
  const r = run([tr({ date: '2026-10-01', pnl: '100' }), tr({ date: '2026-10-02', pnl: '-80', result: 'loss' }), tr({ date: '2026-10-03', pnl: '-70', result: 'loss' }), tr({ date: '2026-10-04', pnl: '200' })], { capital: 1000 });
  const d = byId(r, 'drawdown');
  check('drawdown: its trades are the fall from the peak (2 trades)', d && d.tradeIds.length === 2 && /13\.6%/.test(d.text), d);
}

// ── RU / EN of the new cards: no prescriptions, no broken text ──
{
  const FORBIDDEN = /увелич\S* (объём|размер|риск)|добавля\S* объём|масштабир|0[.,]5\s?%|BOS\/CHOCH|доказан|proven|add size|scale|increase (size|risk)|психолог|psycholog|не торгуйте|skip the session/i;
  const sets = [
    [tr({ byPlan: true, pnl: '-20', result: 'loss' }), ...many(2, CLEAN)],
    [...dated(16, { byPlan: true }), ...dated(4, { byPlan: false }), ...dated(12, { byPlan: true }), ...dated(8, { byPlan: false })],
    [...many(3, { byPlan: null, pnl: '' }), ...many(5, CLEAN)],
    [tr({ setup: 'Range', pnl: '10' }), tr({ setup: 'Range', pnl: '-10', result: 'loss' }), ...many(2, CLEAN)],
    many(30, { rr: '' }),
  ];
  for (const lang of ['ru', 'en']) {
    sets.forEach((list, k) => {
      const r = run(list, { lang });
      const text = r.ins.map(i => [i.text, i.meta, i.rec, i.act].join(' | ')).join('\n');
      const bad = text.match(FORBIDDEN);
      check(`${lang} set ${k}: no prescription or proof claim`, !bad, bad && text.slice(Math.max(0, bad.index - 80), bad.index + 60));
      check(`${lang} set ${k}: no undefined / NaN / null`, !/undefined|NaN|\bnull\b/.test(text), text.slice(0, 200));
      if (lang === 'en') check(`en set ${k}: no Russian words (a user's strategy name aside)`, !/[А-Яа-яЁё]/.test(text), (text.match(/.{0,40}[А-Яа-яЁё].{0,30}/) || [''])[0]);
    });
  }
}

console.table(results);
const failed = results.filter(x => x.result === 'FAIL').length;
console.log(failed ? `${failed} check(s) FAILED` : `All ${results.length} checks passed`);
process.exit(failed ? 1 : 0);
