/* Progress and goals count only what is known. The real functions of index.html run in a vm:
   streaks (calendar dates, not clock hours; one date's trades have no order), the drawdown shared
   by the Progress tab and the drawdown goal (none without an initial capital, end-of-day totals),
   goals that show «—» instead of 0 % / 50 %, and a Trader Score that leaves unknown parts out.
   No browser, no HTTP. MJ_INDEX may point at another copy of index.html (to see it fail on older code). */
const fs=require('fs'),vm=require('vm'),path=require('path'),assert=require('node:assert/strict');
const h=fs.readFileSync(process.env.MJ_INDEX||path.join(__dirname,'../index.html'),'utf8');
const cut=(a,b)=>{const i=h.indexOf(a),j=h.indexOf(b,i);assert.ok(i>=0&&j>i,'index.html has '+a);return h.slice(i,j);};
const tryCut=(a,b)=>h.includes(a)?cut(a,b):'';
const fields={'page-progress':{classList:{contains:()=>false}}},el=id=>fields[id]||(fields[id]={value:'',focus(){}});
const ctx={document:{getElementById:el},goals:[],syncSettings(){},closeModal(){},renderHome(){},renderProgress(){},showToast(){},toastWarn(s){ctx.warned=s;},Date,Math,Number,String,JSON,Object,Array,Set,Map,parseFloat,isNaN,isFinite,
 trades:[],baseCapital:0,lang:'ru',T:k=>k,journalToday:()=>'2026-10-27',
 escapeHtml:s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))};
vm.createContext(ctx);
vm.runInContext([cut('function parseRR(rr){','function fmt('),cut('function calcStats(list){','function calcPeriodDelta('),
 cut('function calcDiscipline(){','function getDismissedInsights('),cut('function costNum(v){','const RES_TEXT'),
 cut('function goalHTML(g){','//  HOME CHART'),cut('function calcTraderScore(){','//  DETAIL MODAL'),cut('function saveGoal(){','function deleteGoal('),
 tryCut('// The field opens with the capital already set','// ═══')].join('\n'),ctx);
const set=(list,capital=0)=>{ctx.trades=list;ctx.baseCapital=capital;vm.runInContext('trades=this.trades;baseCapital=this.baseCapital',ctx);};
let n=0;const T=(id,fn)=>{fn();n++;console.log('PASS '+id);};
const tr=(date,o={})=>({id:date+Math.random(),date,pnl:'10',pnlMode:'net',...o});

T('journal streak runs through the end of summer time (Europe/Copenhagen, 25–26 Oct 2026)',()=>{
 process.env.TZ='Europe/Copenhagen';
 set(['2026-10-23','2026-10-24','2026-10-25','2026-10-26','2026-10-27'].map(d=>tr(d)));
 const s=ctx.calcStreaks();assert.equal(s.journal.best,5,'best');assert.equal(s.journal.cur,5,'current');
});
T('journal streak does not depend on the device time zone (UTC+14)',()=>{
 process.env.TZ='Pacific/Kiritimati';
 const s=ctx.calcStreaks();assert.equal(s.journal.cur,5);assert.equal(s.journal.best,5);
 process.env.TZ='Europe/Copenhagen';
});
T('the current journal streak may start yesterday; a gap breaks it',()=>{
 set(['2026-10-20','2026-10-21','2026-10-25','2026-10-26'].map(d=>tr(d)));
 const s=ctx.calcStreaks();assert.equal(s.journal.cur,2);assert.equal(s.journal.best,2);
});
T('one date has no known order: a date with a broken trade breaks the discipline run there',()=>{
 set([tr('2026-10-25',{byPlan:true}),tr('2026-10-25',{byPlan:true}),tr('2026-10-26',{id:'a',byPlan:true}),tr('2026-10-26',{id:'b',byPlan:false})]);
 const s=ctx.calcStreaks();assert.equal(s.discipline.cur,0,'the newest date is mixed');assert.equal(s.discipline.best,2);
});
T('wins: a trade without a known P&L ends the run; mixed date counts as broken',()=>{
 set([tr('2026-10-24'),tr('2026-10-25'),tr('2026-10-25',{pnl:''}),tr('2026-10-26'),tr('2026-10-27')]);
 const s=ctx.calcStreaks();assert.equal(s.wins.cur,2);assert.equal(s.wins.best,2);
});
T('an unanswered impulsive question does not break the discipline run (the label says «not marked»)',()=>{
 set([tr('2026-10-26',{byPlan:true,emotional:null}),tr('2026-10-27',{byPlan:true,emotional:false}),tr('2026-10-27',{byPlan:true})]);
 assert.equal(ctx.calcStreaks().discipline.cur,3);
 set([tr('2026-10-27',{byPlan:true,emotional:true})]);assert.equal(ctx.calcStreaks().discipline.cur,0);
});
T('drawdown: no initial capital gives no percent (was 219 % on the Progress tab)',()=>{
 set([tr('2026-10-01',{pnl:'100'}),tr('2026-10-02',{pnl:'-219'})],0);
 const d=ctx.calcDrawdown(ctx.trades);assert.equal(d.maxPct,null);
});
T('drawdown: end-of-day totals from the initial capital; a trade without P&L is counted apart',()=>{
 set([tr('2026-10-01',{pnl:'100'}),tr('2026-10-02',{pnl:'50'}),tr('2026-10-02',{pnl:'-269'}),tr('2026-10-03',{pnl:''})],1000);
 const d=ctx.calcDrawdown(ctx.trades);assert.equal(d.maxPct.toFixed(2),'19.91');assert.equal(d.unknown,1);
});
T('drawdown goal: no fixed 50 %; a limit is within or over, never «done»',()=>{
 set([tr('2026-10-01',{pnl:'100'}),tr('2026-10-02',{pnl:'-219'})],0);
 let p=ctx.getGoalProgress({type:'drawdown',target:10});assert.notEqual(p.pct,50);assert.equal(p.pct,null);assert.equal(p.state,'unknown');
 set(ctx.trades,1000);
 p=ctx.getGoalProgress({type:'drawdown',target:10});assert.equal(p.state,'over');assert.match(p.label,/19\.9%/);
 p=ctx.getGoalProgress({type:'drawdown',target:25});assert.equal(p.state,'within');assert.equal(Math.round(p.pct),80);
 const html=ctx.goalDeepHTML({type:'drawdown',target:25},0);assert.match(html,/В пределах лимита/);assert.doesNotMatch(html,/Выполнено/);
 const card=ctx.goalHTML({type:'drawdown',target:25});assert.match(card,/80%/);
});
T('goals with unknown data show «—», not 0 %',()=>{
 set([tr('2026-10-01',{pnl:''}),tr('2026-10-02',{pnl:''})],1000);
 for(const type of ['winrate','discipline','rr','pnl']){
  const p=ctx.getGoalProgress({type,target:60});assert.equal(p.pct,null,type);assert.equal(p.state,'unknown',type);
  const html=ctx.goalDeepHTML({type,target:60},0);assert.match(html,/Нет данных/,type);assert.doesNotMatch(html,/Отстаём/,type);
  assert.match(ctx.goalHTML({type,target:60}),/>—</,type);
 }
 assert.equal(ctx.getGoalProgress({type:'trades',target:10}).pct,20,'the record count is known');
});
T('the P&L goal: a loss shows a sign before $, costs not given mark it preliminary',()=>{
 set([tr('2026-10-01',{pnl:'-160'})],1000);assert.match(ctx.getGoalProgress({type:'pnl',target:500}).label,/^−\$160 из \$500$/);
 set([tr('2026-10-01',{pnl:'100',pnlMode:'gross',commission:'',swap:'0'})],1000);assert.match(ctx.getGoalProgress({type:'pnl',target:500}).label,/предв\./);
});
T('Trader Score: three trades without P&L, answers or R:R give no score (was a number)',()=>{
 set([tr('2026-10-01',{pnl:''}),tr('2026-10-02',{pnl:''}),tr('2026-10-03',{pnl:''})]);
 assert.equal(ctx.calcTraderScore(),null);
});
T('Trader Score: an unknown win rate is left out, not scored as 0 %',()=>{
 const base=o=>['2026-10-01','2026-10-02','2026-10-03'].map(d=>tr(d,{byPlan:true,rr:'1:2',...o}));
 set(base({pnl:'-10'}));const losses=ctx.calcTraderScore();
 assert.deepEqual([...losses.parts],['wr','disc','rr']);assert.equal(losses.score,49);   // (0·.30 + 100·.25 + 60·.20)/.75
 set(base({pnl:''}));assert.equal(ctx.calcTraderScore(),null,'without the win rate the parts weigh .45 < .5');
});
T('Trader Score: no mistake marks are not «no mistakes»; a winning broken rule is not clean',()=>{
 const wins=o=>['2026-10-01','2026-10-02','2026-10-03'].map(d=>tr(d,{rr:'1:2',checklistDetail:{a:true,b:true,c:true,d:true,e:true},checklistScore:1,...o}));
 set(wins({byPlan:true}));const clean=ctx.calcTraderScore();
 set(wins({byPlan:true,mistakes:[]}));assert.equal(ctx.calcTraderScore().score,clean.score,'an empty mark list changes nothing');
 set(wins({byPlan:false}));const broken=ctx.calcTraderScore();
 assert.ok(broken.score<clean.score,'profit does not make a broken rule clean');assert.ok(broken.parts.includes('clean'));
 vm.runInContext('lang="en"',ctx);assert.equal(ctx.traderScoreSource(clean),'From: win rate, discipline, R:R, clean trades');vm.runInContext('lang="ru"',ctx);
});
// ── findings of the site check, 30.10 ──
T('N2: no trade with a known P&L gives no drawdown and no «within the limit»',()=>{
 set([tr('2026-10-01',{pnl:''}),tr('2026-10-02',{pnl:''})],10000);
 const d=ctx.calcDrawdown(ctx.trades);assert.equal(d.maxPct,null);assert.equal(d.reason,'no_pnl');assert.equal(d.unknown,2);
 const p=ctx.getGoalProgress({type:'drawdown',target:5});assert.equal(p.state,'unknown');assert.match(p.label,/Нет сделок с известным P&L/);
 assert.match(ctx.goalDeepHTML({type:'drawdown',target:5},0),/просадку не из чего посчитать/);
});
T('N2: some trades without P&L are named in the drawdown goal',()=>{
 set([tr('2026-10-01',{pnl:'-100'}),tr('2026-10-02',{pnl:''})],10000);
 assert.match(ctx.getGoalProgress({type:'drawdown',target:5}).label,/1\.0% при лимите 5%; без P&L: 1$/);
});
T('N4: a balance at or below 0 gives no percent (was 300 %)',()=>{
 set([tr('2026-10-01',{pnl:'-300'})],100);
 const d=ctx.calcDrawdown(ctx.trades);assert.equal(d.maxPct,null);assert.equal(d.reason,'exhausted');assert.equal(d.low,-200);
 const p=ctx.getGoalProgress({type:'drawdown',target:5});assert.equal(p.state,'unknown');assert.match(p.label,/Остаток дошёл до 0/);
});
T('N3: the fall is told by dates, for the insight to link its trades',()=>{
 set([tr('2026-10-01',{pnl:'200'}),tr('2026-10-02',{pnl:'-150'}),tr('2026-10-03',{pnl:'-100'}),tr('2026-10-04',{pnl:'50'})],1000);
 const d=ctx.calcDrawdown(ctx.trades);assert.equal(d.fromDay,'2026-10-01');assert.equal(d.toDay,'2026-10-03');assert.equal(d.peak,1200);assert.equal(d.nowPct.toFixed(2),'16.67');
 set([tr('2026-10-26',{pnl:'2000'}),tr('2026-10-26',{pnl:'-3000'}),tr('2026-10-27',{pnl:'100'})],10000);
 assert.equal(ctx.calcDrawdown(ctx.trades).maxPct.toFixed(1),'10.0','one date is one step: −1000 that day');
});
T('N5: a goal is a number above 0; percents at most 100; the form is emptied after saving',()=>{
 const save=(type,v)=>{ctx.warned=null;el('goalType').value=type;el('goalTarget').value=v;el('goalName').value='x';const before=ctx.goals.length;ctx.saveGoal();return ctx.goals.length>before;};
 vm.runInContext('goals=this.goals',ctx);
 assert.equal(save('pnl','-10'),false);assert.ok(ctx.warned);
 assert.equal(save('winrate','120'),false);assert.equal(save('drawdown','0'),false);
 assert.equal(save('pnl','1500'),true);assert.equal(save('winrate','60'),true);
 assert.equal(ctx.goals.at(-1).days,undefined,'no days are stored');assert.equal(el('goalTarget').value,'');assert.equal(el('goalName').value,'');
});
T('N6: «clean» counts only trades with checklist answers; a broken rule without one does not tip it',()=>{
 const noCl=o=>tr('2026-10-0'+(o.d),{byPlan:true,rr:'1:2',pnl:'10',...o});
 set([noCl({d:1}),noCl({d:2}),noCl({d:3}),noCl({d:4}),noCl({d:5,byPlan:false})]);
 assert.ok(!ctx.calcTraderScore().parts.includes('clean'),'nobody uses the checklist: the part is left out');
});
T('N8, N9: no negative percent on a card; the limit state follows the rounded figure',()=>{
 set([tr('2026-10-01',{pnl:'-80'})],10000);
 assert.match(ctx.goalHTML({type:'pnl',target:500}),/>0%</);
 set([tr('2026-10-01',{pnl:'200'}),tr('2026-10-02',{pnl:'-299.5'})],10000);   // 2.936 % → «2.9%»
 const p=ctx.getGoalProgress({type:'drawdown',target:2.9});assert.match(p.label,/2\.9% при лимите 2\.9%/);assert.equal(p.state,'within');
});
T('N10: a goal without data says what is missing',()=>{
 set([tr('2026-10-01',{pnl:''})],10000);
 assert.match(ctx.goalDeepHTML({type:'discipline',target:80},0),/Ответов о плане, чеклисте и эмоциях ещё нет/);
 assert.match(ctx.goalDeepHTML({type:'rr',target:2},0),/Нет сделок с R:R/);
 assert.match(ctx.goalDeepHTML({type:'winrate',target:60},0),/Нет сделок с известным P&amp;L/);
});
// ── findings of the beta test, 30.10 ──
T('B6: a trade dated in the future (an import) does not start the current streak',()=>{
 set([tr('2026-10-26',{byPlan:true}),tr('2026-10-27',{byPlan:true}),tr('2026-11-05',{byPlan:false,pnl:'-5'})]);
 const s=ctx.calcStreaks();assert.equal(s.discipline.cur,2,'counted from today (27.10) back');assert.equal(s.wins.cur,2);
});
T('B7: a limit on the Home card says in words where it stands',()=>{
 set([tr('2026-10-01',{pnl:'200'}),tr('2026-10-02',{pnl:'-290'})],10000);   // 2.84 %
 assert.match(ctx.goalHTML({type:'drawdown',target:2}),/Лимит превышен/);
 assert.match(ctx.goalHTML({type:'drawdown',target:5}),/В пределах лимита, использовано 57%/);
 assert.doesNotMatch(ctx.goalHTML({type:'winrate',target:60}),/лимит/i);
});
T('B3: the deposit opens with the capital set; empty or negative is not saved, a typed 0 clears it',()=>{
 vm.runInContext('baseCapital=10000',ctx);ctx.openModal=()=>{};
 ctx.openCapModal();assert.equal(el('capInput').value,10000,'the field shows the capital, not a grey hint');
 const save=v=>{ctx.warned=null;el('capInput').value=v;ctx.saveCap();return vm.runInContext('baseCapital',ctx);};
 assert.equal(save(''),10000);assert.ok(ctx.warned);assert.equal(save('-5000'),10000);assert.equal(save('abc'),10000);
 assert.equal(save('12500'),12500);assert.equal(save('0'),0);
});
// ── Codex review 1 Nov, PG1: one date has no known order, so a run is a range unless it is exact ──
const day=(d,win=0,loss=0,none=0)=>[...Array(win)].map(()=>tr(d))
 .concat([...Array(loss)].map(()=>tr(d,{pnl:'-5'})),[...Array(none)].map(()=>tr(d,{pnl:''})));
const wins=()=>{const w=ctx.calcStreaks().wins;return [w.cur,w.curMax,w.best,w.bestMax];};
T('PG1: one date with a win and a loss: the best run is exactly 1, the current one is 0–1 (was best 0)',()=>{
 set(day('2026-10-27',1,1));assert.deepEqual(wins(),[0,1,1,1]);
 set([tr('2026-10-27',{byPlan:true,pnl:'10'}),tr('2026-10-27',{byPlan:false,pnl:'-5'})]);
 const d=ctx.calcStreaks().discipline;assert.deepEqual([d.cur,d.curMax,d.best,d.bestMax],[0,1,1,1]);
});
T('PG1: several mixed dates in a row give a range, not a number',()=>{
 set([...day('2026-10-25',1,1),...day('2026-10-26',1,1)]);assert.deepEqual(wins(),[0,1,1,2]);
 set([...day('2026-10-25',2,1),...day('2026-10-26',3),...day('2026-10-27',1,1)]);assert.deepEqual(wins(),[0,1,3,6]);
});
T('PG1: a trade without a known outcome widens the range; it neither wins nor cancels a known win',()=>{
 set(day('2026-10-27',1,0,1));assert.deepEqual(wins(),[0,2,1,2]);
 set([...day('2026-10-26',2),...day('2026-10-27',0,0,1)]);assert.deepEqual(wins(),[0,3,2,3]);
});
T('PG1: an unanswered «by plan» is unknown, a «no» or an impulsive mark is not; no answers at all give «—»',()=>{
 const disc=()=>{const d=ctx.calcStreaks().discipline;return [d.cur,d.curMax,d.best,d.bestMax];};
 set([tr('2026-10-26',{byPlan:true}),tr('2026-10-27',{})]);assert.deepEqual(disc(),[0,2,1,2]);
 set([tr('2026-10-26',{byPlan:true}),tr('2026-10-27',{emotional:true})]);assert.deepEqual(disc(),[0,0,1,1]);
 set([tr('2026-10-26',{}),tr('2026-10-27',{})]);assert.deepEqual(disc(),[null,null,null,null]);
});
T('PG1: nothing known at all is «unknown», neither 0 nor a range',()=>{
 set(day('2026-10-27',0,0,3));assert.deepEqual(wins(),[null,null,null,null]);
 set([]);assert.deepEqual(wins(),[0,0,0,0],'an empty journal is a real zero');
 assert.deepEqual([ctx.streakText(null,null),ctx.streakText(0,0),ctx.streakText(3,3),ctx.streakText(0,1),ctx.streakText(2,5)],['—','0','3','0–1','2–5']);
});
T('PG1: dates that fit whole are exact, and the journal keeps a plain number',()=>{
 set([...day('2026-10-25',2),...day('2026-10-26',1),...day('2026-10-27',3)]);assert.deepEqual(wins(),[6,6,6,6]);
 set([...day('2026-10-25',2),...day('2026-10-26',0,1),...day('2026-10-27',3)]);assert.deepEqual(wins(),[3,3,3,3]);
 assert.equal(ctx.streakText(ctx.calcStreaks().journal.cur),'3','three days in a row');
});
T('PG1: a future date (an import) does not make the current run; a date-less trade is left out and counted',()=>{
 set([...day('2026-10-27',2),...day('2026-11-05',0,1)]);assert.deepEqual(wins().slice(0,2),[2,2]);
 set([...day('2026-10-27',1,1),...day('2026-11-05',3)]);assert.deepEqual(wins().slice(0,2),[0,1]);
 set([...day('2026-10-27',2),tr('',{pnl:'-5'}),tr(null,{pnl:'-5'})]);assert.deepEqual(wins(),[2,2,2,2]);
 assert.equal(ctx.calcStreaks().undated,2);
});
T('PG1: the dates of a run do not depend on the end of summer time or the device zone',()=>{
 const list=['2026-10-24','2026-10-25','2026-10-26','2026-10-27'].flatMap(d=>day(d,1));
 for(const zone of ['Europe/Copenhagen','Pacific/Kiritimati','America/Los_Angeles']){process.env.TZ=zone;set(list);assert.deepEqual(wins(),[4,4,4,4],zone);}
 process.env.TZ='Europe/Copenhagen';
});
T('PG1: the result does not depend on the order of the records or their ids',()=>{
 const list=[...day('2026-10-26',2,1),...day('2026-10-27',1,1,1)];
 set(list);const a=wins();set([...list].reverse());assert.deepEqual(wins(),a);
 set(list.map((t,i)=>({...t,id:String(100-i)})));assert.deepEqual(wins(),a);
});
T('PG1: the bounds match every possible order and every possible outcome (all small journals)',()=>{
 // A day as letters: P fits, F does not, U unknown. Every order of a day and every outcome of U is tried.
 const orders=(p,f,u)=>{const out=new Set();const go=(s,a,b,c)=>{if(!a&&!b&&!c){out.add(s);return;}if(a)go(s+'P',a-1,b,c);if(b)go(s+'F',a,b-1,c);if(c){go(s+'P',a,b,c-1);go(s+'F',a,b,c-1);}};go('',p,f,u);return [...out];};
 const sizes=(max)=>{const out=[];for(let p=0;p<=max;p++)for(let f=0;f<=max-p;f++)for(let u=0;u<=max-p-f;u++)if(p+f+u)out.push([p,f,u]);return out;};
 const measure=s=>{let best=0,run=0;for(const c of s){run=c==='P'?run+1:0;if(run>best)best=run;}return [run,best];};
 const check=days=>{
  if(!days.some(([p,f])=>p+f))return 0;   // nothing known: the separate «unknown» case
  let min=[Infinity,Infinity],max=[-1,-1];
  const walk=(i,s)=>{if(i===days.length){const m=measure(s);min=[Math.min(min[0],m[0]),Math.min(min[1],m[1])];max=[Math.max(max[0],m[0]),Math.max(max[1],m[1])];return;}for(const o of orders(...days[i]))walk(i+1,s+o);};
  walk(0,'');
  const list=days.flatMap(([p,f,u],i)=>{const date='2026-10-'+(10+i);return [...Array(p).fill(true),...Array(f).fill(false),...Array(u).fill(null)].map(v=>({date,v}));});
  const r=ctx.tradeRun(list,t=>t.v,'2026-10-27');
  assert.deepEqual([r.cur,r.curMax,r.best,r.bestMax],[min[0],max[0],min[1],max[1]],JSON.stringify(days));
  return 1;
 };
 let n=0;const s3=sizes(3),s4=sizes(4);
 for(const a of s4){n+=check([a]);for(const b of s4)n+=check([a,b]);}
 for(const a of s3)for(const b of s3)for(const c of s3)n+=check([a,b,c]);
 assert.ok(n>5000,'journals tried: '+n);
});
// ── Codex review 1 Nov, PG2: a goal is not confirmed while a result of the journal is missing ──
const inLang=(l,fn)=>{vm.runInContext('lang="'+l+'"',ctx);try{return fn();}finally{vm.runInContext('lang="ru"',ctx);}};
T('PG2: +100 net and a record without P&L keep the known sum and do not confirm a $50 goal',()=>{
 set([tr('2026-10-01',{pnl:'100',pnlMode:'net',commission:'1',swap:'0'}),tr('2026-10-02',{pnl:''})]);
 const g={type:'pnl',target:50},p=ctx.getGoalProgress(g);
 assert.equal(p.state,'partial');assert.equal(p.cur,100,'the known sum stays');
 assert.equal(p.label,'$100 из $50; без P&L: 1');
 const deep=ctx.goalDeepHTML(g,0),card=ctx.goalHTML(g);
 assert.match(deep,/Предварительно/);assert.doesNotMatch(deep,/Выполнено|выполнена/);assert.match(deep,/пока не подтверждена/);
 assert.match(card,/без P&L: 1\. Пока не подтверждена/);assert.doesNotMatch(card,/var\(--positive\)/);
 inLang('en',()=>{
  assert.equal(ctx.getGoalProgress(g).label,'$100 of $50; no P&L: 1');
  const d=ctx.goalDeepHTML(g,0);assert.match(d,/Preliminary/);assert.doesNotMatch(d,/Done|goal reached/);assert.match(d,/not confirmed yet/);
  assert.match(ctx.goalHTML(g),/\. Not confirmed yet/);
 });
});
T('PG2: a total below the goal with a record missing is not «behind» either',()=>{
 set([tr('2026-10-01',{pnl:'-160'}),tr('2026-10-02',{pnl:''})]);
 const g={type:'pnl',target:500},p=ctx.getGoalProgress(g);assert.equal(p.state,'partial');assert.equal(p.label,'−$160 из $500; без P&L: 1');
 const deep=ctx.goalDeepHTML(g,0);assert.match(deep,/Предварительно/);assert.doesNotMatch(deep,/Отстаём/);
});
T('PG2: costs not given leave the total open as well',()=>{
 set([tr('2026-10-01',{pnl:'100',pnlMode:'gross',commission:'',swap:'0'})]);
 const p=ctx.getGoalProgress({type:'pnl',target:50});assert.equal(p.state,'partial');assert.equal(p.label,'$100 из $50 (предв.)');
});
T('PG2: all results known confirm the goal; an explicit 0 stays a known zero; an empty journal is no loss',()=>{
 set([tr('2026-10-01',{pnl:'100'}),tr('2026-10-02',{pnl:'-20'})]);
 let p=ctx.getGoalProgress({type:'pnl',target:50});assert.equal(p.state,'done');assert.equal(p.label,'$80 из $50');assert.match(ctx.goalDeepHTML({type:'pnl',target:50},0),/Выполнено/);
 set([tr('2026-10-01',{pnl:'0'})]);
 p=ctx.getGoalProgress({type:'pnl',target:50});assert.equal(p.state,'progress');assert.equal(p.cur,0);assert.equal(p.label,'$0 из $50');
 set([]);
 p=ctx.getGoalProgress({type:'pnl',target:50});assert.equal(p.state,'progress');assert.equal(p.cur,0);assert.equal(p.label,'$0 из $50');
});
T('PG2: the win-rate goal counts known P&L too, so it says what is missing',()=>{
 set([tr('2026-10-01',{pnl:'100'}),tr('2026-10-02',{pnl:''})]);
 const g={type:'winrate',target:60},p=ctx.getGoalProgress(g);assert.equal(p.state,'partial');assert.equal(p.label,'Сейчас 100.0% / цель 60%; без P&L: 1');
 const deep=ctx.goalDeepHTML(g,0);assert.match(deep,/Предварительно/);assert.doesNotMatch(deep,/Выполнено|Цель достигнута/);
 set([tr('2026-10-01',{pnl:'100'}),tr('2026-10-02',{pnl:'-5'})]);
 assert.equal(ctx.getGoalProgress({type:'winrate',target:40}).state,'done','all known: the goal is confirmed');
});
// ── Codex review 2 Nov, PG4: the note under the streaks names the real reason of a range ──
const note=()=>ctx.streakRangeNote(ctx.calcStreaks());
T('PG4: everything filled in: the note names the order only, nothing is said to be missing',()=>{
 const answers={emotional:false,pnlMode:'net',commission:'0',swap:'0'};
 set([tr('2026-10-27',{...answers,byPlan:true,pnl:'10'}),tr('2026-10-27',{...answers,byPlan:false,pnl:'-5'})]);
 assert.equal(note(),'str_range_note str_range_order');
});
T('PG4: an unknown result on its own date: the note names the P&L, the order changes nothing',()=>{
 set([tr('2026-10-26',{byPlan:true}),tr('2026-10-27',{byPlan:true,pnl:''})]);
 const s=ctx.calcStreaks();assert.equal(s.wins.order,false);assert.equal(s.wins.missing,true);
 assert.equal(note(),'str_range_note str_range_pnl');
});
T('PG4: an unanswered plan question on its own date: the note names the answer, not the P&L',()=>{
 set([tr('2026-10-26',{byPlan:true}),tr('2026-10-27',{})]);
 assert.equal(note(),'str_range_note str_range_plan');
});
T('PG4: both reasons at once are both named',()=>{
 set([...day('2026-10-25',1,1),tr('2026-10-26',{pnl:''})]);
 const w=ctx.calcStreaks().wins;assert.equal(w.order,true);assert.equal(w.missing,true);
 assert.match(note(),/str_range_order/);assert.match(note(),/str_range_pnl/);
 set(day('2026-10-27',1,0,1));const u=ctx.calcStreaks().wins;assert.equal(u.order,true,'if it was a loss, the order matters');assert.equal(u.missing,true);
});
T('PG4: a mixed date that cannot change the numbers is not named as a reason',()=>{
 set([...day('2026-10-20',1,1),...day('2026-10-21',0,1),...day('2026-10-22',3),...day('2026-10-23',0,0,1)]);
 const w=ctx.calcStreaks().wins;assert.deepEqual([w.cur,w.curMax,w.best,w.bestMax],[0,4,3,4]);
 assert.equal(w.order,false);assert.equal(w.missing,true);
});
T('PG4: exact numbers, «—» and an empty journal give no note',()=>{
 set(['2026-10-26','2026-10-27'].map(d=>tr(d,{byPlan:true})));assert.equal(note(),'');
 set(day('2026-10-27',0,0,3));assert.equal(note(),'','nothing known: «—» needs no note');
 set([]);assert.equal(note(),'');
});
T('PG4: every range has a named reason, an exact number has none (all small journals)',()=>{
 const sizes=[];for(let p=0;p<=3;p++)for(let f=0;f<=3-p;f++)for(let u=0;u<=3-p-f;u++)if(p+f+u)sizes.push([p,f,u]);
 let n=0;
 for(const a of sizes)for(const b of sizes)for(const c of sizes){
  const days=[a,b,c];if(!days.some(([p,f])=>p+f))continue;
  const list=days.flatMap(([p,f,u],i)=>{const date='2026-10-'+(10+i);return [...Array(p).fill(true),...Array(f).fill(false),...Array(u).fill(null)].map(v=>({date,v}));});
  const r=ctx.tradeRunWhy(list,t=>t.v,'2026-10-27'),exact=r.cur===r.curMax&&r.best===r.bestMax,id=JSON.stringify(days);
  assert.equal(r.order||r.missing,!exact,id);
  if(days.every(([,,u])=>!u))assert.equal(r.missing,false,'nothing unknown: '+id);
  if(days.every(([p,f,u])=>p+f+u===1||p===p+f+u||f===p+f+u))assert.equal(r.order,false,'no date can be ordered: '+id);
  n++;
 }
 assert.ok(n>5000,'journals tried: '+n);
});
T('PG4: both languages have the reasons; the old sentence that always blamed missing data is gone',()=>{
 for(const key of ['str_range_note','str_range_order','str_range_pnl','str_range_plan'])
  assert.equal((h.match(new RegExp(key+":'",'g'))||[]).length,2,key);
 assert.doesNotMatch(h,/а у некоторых сделок нет P&L или ответа/);assert.doesNotMatch(h,/and some trades have no P&L or no/);
});
// ── The drawdown goal with incomplete money data: the known part is shown, nothing final is claimed ──
const ddGoal=target=>({type:'drawdown',target});
const lossAndUnknown=()=>[tr('2026-10-01',{pnl:'-100'}),tr('2026-10-02',{pnl:''})];   // −100 of 10 000 is 1.0 %
T('DD: a record without P&L, the known part within the limit: preliminary, compliance not confirmed',()=>{
 set(lossAndUnknown(),10000);
 const g=ddGoal(5),p=ctx.getGoalProgress(g);
 assert.equal(p.state,'prelim_within');assert.equal(p.reason,'pnl');
 assert.equal(p.cur.toFixed(1),'1.0','the known part of the end-of-day model stays');assert.equal(Math.round(p.pct),20);
 assert.equal(p.label,'Макс. просадка 1.0% при лимите 5%; без P&L: 1');
 const card=ctx.goalHTML(g),deep=ctx.goalDeepHTML(g,0);
 assert.match(card,/Предварительно: по известным данным в пределах лимита, использовано 20%/);
 assert.doesNotMatch(card,/1\. В пределах лимита/);
 assert.match(deep,/>Предварительно</);assert.doesNotMatch(deep,/>В пределах лимита</);
 assert.match(deep,/использовано 20% лимита по известным данным/);
 assert.match(deep,/соблюдение лимита пока не подтверждено/);assert.match(deep,/без P&amp;L/);
 inLang('en',()=>{
  assert.equal(ctx.getGoalProgress(g).label,'Max drawdown 1.0% against a 5% limit; no P&L: 1');
  assert.match(ctx.goalHTML(g),/Preliminary: within the limit on known data, 20% used/);
  const d=ctx.goalDeepHTML(g,0);assert.match(d,/>Preliminary</);assert.doesNotMatch(d,/>Within the limit</);
  assert.match(d,/20% of the limit used on known data/);assert.match(d,/compliance with the limit is not confirmed yet/);
 });
});
T('DD: a record without P&L, the known part over the limit: preliminary too, the known overrun is plain',()=>{
 set(lossAndUnknown(),10000);
 const g=ddGoal(0.5),p=ctx.getGoalProgress(g);
 assert.equal(p.state,'prelim_over');assert.equal(p.pct,200);
 const card=ctx.goalHTML(g),deep=ctx.goalDeepHTML(g,0);
 assert.match(card,/Предварительно: по известным данным лимит превышен/);assert.match(card,/var\(--negative\)/);
 assert.doesNotMatch(card,/1\. Лимит превышен/);
 assert.match(deep,/>Предварительно, выше лимита</);assert.doesNotMatch(deep,/>Лимит превышен</);
 assert.match(deep,/по известным данным лимит превышен/);
 const tip=ctx.getGoalTip(g,p.pct,p.cur,p.reason,p.state);
 assert.match(tip,/итоговая просадка может измениться/i);assert.match(tip,/решает ваша стратегия/);assert.doesNotMatch(tip,/соблюдение лимита/);
 inLang('en',()=>{
  assert.match(ctx.goalHTML(g),/Preliminary: the limit is exceeded on known data/);
  const d=ctx.goalDeepHTML(g,0);assert.match(d,/>Preliminary, over the limit</);assert.match(d,/the final drawdown may change/i);
 });
});
T('DD: the limit state still follows the rounded figure when the data is incomplete',()=>{
 set([tr('2026-10-01',{pnl:'200'}),tr('2026-10-02',{pnl:'-299.5'}),tr('2026-10-03',{pnl:''})],10000);   // 2.936 % → «2.9%»
 assert.equal(ctx.getGoalProgress(ddGoal(2.9)).state,'prelim_within');assert.equal(ctx.getGoalProgress(ddGoal(2.8)).state,'prelim_over');
});
T('DD: costs not given make it preliminary, and only the costs are named as the reason',()=>{
 set([tr('2026-10-01',{pnl:'-100',pnlMode:'gross',commission:'',swap:'0'})],10000);
 const g=ddGoal(5),p=ctx.getGoalProgress(g);
 assert.equal(p.state,'prelim_within');assert.equal(p.reason,'costs');assert.equal(p.label,'Макс. просадка 1.0% при лимите 5%','the status says «preliminary», the label does not repeat it');
 assert.match(ctx.goalHTML(g),/5%. Предварительно: по известным данным/);
 const deep=ctx.goalDeepHTML(g,0);assert.match(deep,/не заполнены расходы/);assert.doesNotMatch(deep,/без P&amp;L/);
 inLang('en',()=>assert.match(ctx.goalDeepHTML(g,0),/costs are not filled in/));
});
T('DD: both gaps at once are both named; a record with only a P&L gap does not mention costs',()=>{
 set([tr('2026-10-01',{pnl:'-100',pnlMode:'gross',commission:'',swap:'0'}),tr('2026-10-02',{pnl:''})],10000);
 const g=ddGoal(5);assert.equal(ctx.getGoalProgress(g).reason,'both');
 const both=ctx.goalDeepHTML(g,0);assert.match(both,/без P&amp;L/);assert.match(both,/расходы/);
 set(lossAndUnknown(),10000);assert.doesNotMatch(ctx.goalDeepHTML(g,0),/расходы/);
});
T('DD: the note promises no direction: neither a minimum nor a maximum of the final drawdown',()=>{
 for(const [list,target] of [[lossAndUnknown(),5],[lossAndUnknown(),0.5],[[tr('2026-10-01',{pnl:'-100',pnlMode:'gross',commission:'',swap:'0'})],5]]){
  set(list,10000);const g=ddGoal(target),{pct,cur,reason,state}=ctx.getGoalProgress(g);
  for(const l of ['ru','en'])inLang(l,()=>{
   const words=ctx.getGoalTip(g,pct,cur,reason,state)+ctx.goalLimitWords(state,pct);
   assert.doesNotMatch(words,/минимум|максимум|не меньше|не больше|как минимум|больше|меньше|minimum|maximum|at least|at most|or more|or less|higher|lower/i,words);
  });
 }
});
T('DD: the note of the money goal is not used for the drawdown, and the money goals keep theirs',()=>{
 set(lossAndUnknown(),10000);
 const deep=ctx.goalDeepHTML(ddGoal(5),0);assert.doesNotMatch(deep,/сумма только известных|Доля побед|цель пока не подтверждена/);
 assert.doesNotMatch(ctx.goalHTML(ddGoal(5)),/Пока не подтверждена/);
 const money=ctx.getGoalProgress({type:'pnl',target:50});assert.equal(money.state,'partial');
 assert.match(ctx.goalDeepHTML({type:'pnl',target:50},0),/сумма только известных/);
 assert.match(ctx.goalHTML({type:'pnl',target:50}),/Пока не подтверждена/);
});
T('DD: an explicit net 0 is known: an ordinary status; with a gap next to it the status is preliminary',()=>{
 set([tr('2026-10-01',{pnl:'0'})],10000);
 let p=ctx.getGoalProgress(ddGoal(5));assert.equal(p.state,'within');assert.equal(p.cur,0);assert.equal(p.reason,undefined);
 assert.match(ctx.goalDeepHTML(ddGoal(5),0),/>В пределах лимита</);
 set([tr('2026-10-01',{pnl:'0'}),tr('2026-10-02',{pnl:''})],10000);
 p=ctx.getGoalProgress(ddGoal(5));assert.equal(p.state,'prelim_within');assert.equal(p.cur,0);
});
T('DD: nothing to count from stays «no data»: empty journal, every result unknown, no capital, balance gone',()=>{
 const none=(list,capital,why)=>{set(list,capital);const g=ddGoal(5),p=ctx.getGoalProgress(g);
  assert.equal(p.state,'unknown',why);assert.equal(p.pct,null,why);assert.equal(p.reason,why);
  assert.match(ctx.goalDeepHTML(g,0),/Нет данных/,why);assert.doesNotMatch(ctx.goalDeepHTML(g,0),/Предварительно/,why);};
 none([],10000,'no_pnl');
 none([tr('2026-10-01',{pnl:''}),tr('2026-10-02',{pnl:''})],10000,'no_pnl');
 none(lossAndUnknown(),0,'capital');
 none([tr('2026-10-01',{pnl:'-300'}),tr('2026-10-02',{pnl:''})],100,'exhausted');
});
T('DD: complete data keeps the ordinary statuses and notes',()=>{
 set([tr('2026-10-01',{pnl:'200'}),tr('2026-10-02',{pnl:'-290'})],10000);   // 2.84 %, costs known
 const within=ctx.getGoalProgress(ddGoal(5)),over=ctx.getGoalProgress(ddGoal(2));
 assert.equal(within.state,'within');assert.equal(over.state,'over');assert.equal(within.reason,undefined);
 assert.equal(within.label,'Макс. просадка 2.8% при лимите 5%');
 assert.match(ctx.goalHTML(ddGoal(5)),/В пределах лимита, использовано 57%/);assert.doesNotMatch(ctx.goalHTML(ddGoal(5)),/Предварительно/);
 assert.match(ctx.goalHTML(ddGoal(2)),/\. Лимит превышен/);
 const deep=ctx.goalDeepHTML(ddGoal(5),0);assert.match(deep,/>В пределах лимита</);assert.match(deep,/Просадка считается по итогам дней/);
 assert.match(ctx.goalDeepHTML(ddGoal(2),0),/>Лимит превышен</);
});
T('DD: the trades, the drawdown model and the streaks are left as they were',()=>{
 const list=lossAndUnknown(),before=JSON.stringify(list);set(list,10000);
 const d=ctx.calcDrawdown(list);ctx.goalDeepHTML(ddGoal(5),0);ctx.goalHTML(ddGoal(0.5));
 assert.equal(JSON.stringify(list),before);assert.equal(d.maxPct.toFixed(1),'1.0');assert.equal(d.unknown,1);assert.equal(d.reason,null);
});
console.log(`Progress and goals: ${n}/${n} passed`);
