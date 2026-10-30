const fs=require('fs'),path=require('path'),vm=require('vm'),assert=require('node:assert/strict'),M=require('../insights-learning.js');
const source=fs.readFileSync(path.join(__dirname,'insights-quality.test.cjs'),'utf8'),prefix=source.slice(0,source.indexOf('// ── 1. B/E')).replace('Math, Number, String, Date,','MJLearning, learningPrefs, Math, Number, String, Date,');
const prefs={history:[{effectiveDay:'2026-10-28',timezone:'UTC',maxTrades:3,dailyLoss:100}],tracking:{key:'early_entry',id:'x',sinceDay:'2026-10-01',strategyId:'s',strategyRevId:'r'},action:{id:'a',text:'Check the entry condition',sinceDay:'2026-10-01',strategyId:'s',strategyRevId:'r'}};
const {run,tr,many}=new Function('require','__dirname','MJLearning','learningPrefs',prefix+'\nreturn {run,tr,many};')(require,__dirname,M,()=>prefs);
const rows=Array.from({length:40},(_,i)=>tr({date:'2026-10-28',strategyId:'s',strategyRevId:'r',byPlan:i%3!==0,learning:{trackingId:'x',errorKey:'early_entry',errorPresent:i<6,actionId:'a',actionDone:i%2===0},pnl:i%3===0?'-100':'10'}));
for(const lang of ['ru','en']){
 const r=run(rows,{lang});assert.equal(r.error,null);for(const id of ['mistake_dynamics_x','action_progress_a','trade_limit_2026-10-28','daily_limit_2026-10-28'])assert(r.ins.some(c=>c.id===id),id);
 r.ctx.renderInsights(true);assert(r.nodes.get('insightsWrap').innerHTML.includes('mistake_dynamics_x'));
 const newer=r.ins.filter(c=>/^(mistake_dynamics|action_progress|trade_limit|daily_limit)/.test(c.id));assert(newer.every(c=>c.act&&c.rec&&c.type!=='good'));
 if(lang==='en')assert(newer.every(c=>!/[А-Яа-яЁё]/.test(c.text+c.meta+c.act+c.rec)));
}
const allQuick=run([...many(4,{quickTrade:true})],{quick:false,lang:'en'});assert(allQuick.ins.some(c=>c.id==='trade_limit_2026-10-28'),'account limits must include quick records even if analytics excludes them');
const dayDetail=allQuick.ctx.getInsightDetail(allQuick.ins.find(c=>c.id.startsWith('trade_limit_')));assert(!/quick trades left out/.test(JSON.stringify(dayDetail)),'day-limit detail must not claim quick entries were excluded');
const html=fs.readFileSync(path.join(__dirname,'../index.html'),'utf8'),a=html.indexOf('function calcRR(){'),b=html.indexOf('// ── Checklist',a);
new Function(/<script>([\s\S]*?)<\/script>/.exec(html)[1]);
assert(html.indexOf('src="insights-learning.js"')<html.indexOf('<script>'));
const fields={tEntry:{value:'100'},tSL:{value:'90'},tTP:{value:'120'},rrManualInput:{value:'1:3'}};
const ctx={rrManualMode:true,tForm:{dir:'buy',rrCalc:'1:3'},document:{getElementById:k=>fields[k]},setRRDisplay:v=>ctx.shown=v,fmtRR:String,isNaN};vm.createContext(ctx);vm.runInContext(html.slice(a,b),ctx);ctx.calcRR();assert.equal(ctx.tForm.rrCalc,'1:3');assert.equal(fields.rrManualInput.value,'1:3');assert.equal(ctx.shown,'1:3');
const model=run([...many(15,{result:'win',rr:'1:1'}),...many(15,{result:'loss',rr:'1:5'})]);assert.equal(model.ctx.calcExpectancy([...many(15,{result:'win',rr:'1:1'}),...many(15,{result:'loss',rr:'1:5'})]),0);
const unusual=run(many(3,{setup:'__proto__',mistakes:['constructor']}));assert.equal(unusual.error,null,'dictionary-like setup names must not crash insights');assert(unusual.ins.every(c=>!/undefined/.test(c.text+c.meta)));
const pCard=model.ins.find(c=>c.id.startsWith('plan_dynamics'));
const first=run(rows).ins.find(c=>c.id.startsWith('plan_dynamics'));assert(first);
const other=rows.map(x=>({...x,strategyId:'another'}));const dismissed={[first.id]:{count:40,ts:Date.now(),text:first.text}};
assert(run(other,{storage:{dismissed_insights_v1:dismissed}}).ins.some(c=>c.id.startsWith('plan_dynamics')),'dismissing plan progress for one strategy must not hide another');
console.log('All stage3 generator, quick-limit, RU/EN and manual RR integration checks passed');
