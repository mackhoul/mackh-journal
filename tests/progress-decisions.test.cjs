/* Andrey's decisions of 2 Nov: the Journal Index has no titles and marks a small sample, Progress says
   what its streaks and goals count, and the record button stays on every screen. The real functions of
   index.html run in a vm. No browser, no HTTP. MJ_INDEX may point at another copy of index.html. */
const fs=require('fs'),vm=require('vm'),path=require('path'),assert=require('node:assert/strict');
const h=fs.readFileSync(process.env.MJ_INDEX||path.join(__dirname,'../index.html'),'utf8');
const cut=(a,b)=>{const i=h.indexOf(a),j=h.indexOf(b,i);assert.ok(i>=0&&j>i,'index.html has '+a);return h.slice(i,j);};
const scoreBlock=cut('function calcTraderScore(){','//  DETAIL MODAL');
const fields={},el=id=>fields[id]||(fields[id]={id,value:'',textContent:'',hidden:false,style:{}});
const ctx={document:{getElementById:el},Date,Math,Number,String,JSON,Object,Array,Set,Map,parseFloat,isNaN,isFinite,
 trades:[],baseCapital:10000,lang:'ru',T:k=>'['+k+']',journalToday:()=>'2026-10-27',appSettings:{quickInAnalytics:false}};
vm.createContext(ctx);
vm.runInContext([cut('function parseRR(rr){','function fmt('),cut('function calcStats(list){','function calcPeriodDelta('),
 cut('function calcDiscipline(){','function getDismissedInsights('),cut('function costNum(v){','const RES_TEXT'),scoreBlock,
 cut('function getGoalProgress(g){','//  HOME CHART')].join('\n'),ctx);
const set=list=>{ctx.trades=list;vm.runInContext('trades=this.trades',ctx);};
const inLang=(l,fn)=>{vm.runInContext('lang="'+l+'"',ctx);try{return fn();}finally{vm.runInContext('lang="ru"',ctx);}};
let n=0;const T=(id,fn)=>{fn();n++;console.log('PASS '+id);};
const tr=(i,o={})=>({id:'t'+i,date:'2026-10-'+String(1+i%27).padStart(2,'0'),pnl:'10',pnlMode:'net',byPlan:true,rr:'1:2',...o});
const many=(count,o)=>[...Array(count)].map((_,i)=>tr(i,o));

T('the index gives a number and its parts, no title and no colour of judgement',()=>{
 set(many(3,{pnl:'100'}));
 const ts=ctx.calcTraderScore();
 assert.equal(typeof ts.score,'number');assert.deepEqual([...ts.parts],['wr','disc','rr']);
 assert.equal(ts.label,undefined);assert.equal(ts.col,undefined);
});
T('the titles are gone from the code, in both languages',()=>{
 for(const word of ['Отличный трейдер','Expert Trader','Хороший прогресс','Good Progress','Средний уровень','Developing','Требует работы','Needs Work','Высокий риск','High Risk'])
  assert.ok(!scoreBlock.includes(word),word);
 assert.match(h,/score_name:'Индекс записей'/);assert.match(h,/score_name:'Journal Index'/);
 assert.doesNotMatch(h,/>Trader Score</,'the name on the screen comes from the dictionary');
});
T('below 30 trades the index says there is little data; from 30 it does not',()=>{
 set(many(3));assert.equal(ctx.journalIndexFew(ctx.calcTraderScore()),'Мало данных: 3 из 30 сделок');
 inLang('en',()=>assert.equal(ctx.journalIndexFew(ctx.calcTraderScore()),'Little data: 3 of 30 trades'));
 set(many(29));assert.equal(ctx.journalIndexFew(ctx.calcTraderScore()),'Мало данных: 29 из 30 сделок');
 set(many(30));assert.equal(ctx.journalIndexFew(ctx.calcTraderScore()),'');
});
T('the tile shows the name, the number, the parts and the mark, in neutral colours',()=>{
 for(const id of ['traderScoreWrap','traderScoreNum','traderScoreLbl','traderScoreHint','traderScoreFew','traderScoreArc'])fields[id]={id,textContent:'',hidden:false,style:{}};
 set(many(3,{pnl:'100'}));ctx.renderTraderScore();
 assert.equal(el('traderScoreWrap').style.display,'flex');
 assert.equal(el('traderScoreLbl').textContent,'[score_name]');
 assert.match(el('traderScoreHint').textContent,/^Из: винрейт, дисциплина, R:R$/);
 assert.equal(el('traderScoreFew').textContent,'Мало данных: 3 из 30 сделок');assert.equal(el('traderScoreFew').hidden,false);
 for(const id of ['traderScoreNum','traderScoreLbl','traderScoreArc'])assert.ok(!/positive|negative|warning/.test(JSON.stringify(el(id).style)),id);
 assert.ok(el('traderScoreArc').style.strokeDasharray,'the arc still shows the number');
 set(many(30,{pnl:'100'}));ctx.renderTraderScore();assert.equal(el('traderScoreFew').hidden,true);
 set(many(2));ctx.renderTraderScore();assert.equal(el('traderScoreWrap').style.display,'none','under 3 trades there is no index, as before');
});
T('the arc in the markup has no colour of judgement either',()=>{
 assert.doesNotMatch(cut('id="traderScoreWrap"','id="traderScoreNum"'),/var\(--positive\)/);
 assert.match(h,/id="traderScoreFew"[^>]*hidden/);
});
T('Progress says what its streaks and goals count, in both languages',()=>{
 assert.match(h,/id="progScope"/);assert.match(h,/_setT\('progScope', *'prog_scope'\)/);
 assert.match(h,/prog_scope:'Серии и цели считаются по всем сделкам, включая быстрые\.'/);
 assert.match(h,/prog_scope:'Streaks and goals count all trades, quick ones included\.'/);
});
T('…and it is true: with quick trades off in the analytics they still count in streaks and goals',()=>{
 assert.equal(ctx.appSettings.quickInAnalytics,false);
 set([tr(1,{quickTrade:true}),tr(2,{quickTrade:true}),tr(3)]);
 assert.equal(ctx.calcStreaks().wins.cur,3);
 assert.equal(ctx.getGoalProgress({type:'trades',target:10}).cur,3);
 assert.equal(ctx.getGoalProgress({type:'pnl',target:100}).cur,30);
});
T('the record button stays on every screen, so the side menu does not jump',()=>{
 const page=()=>({classList:{add(){},remove(){},contains:()=>false}});
 const pages={},fab={style:{}};
 const nav={document:{getElementById:id=>id==='fabBtn'?fab:(pages[id]=pages[id]||page()),querySelectorAll:()=>[]},
  stratCanLeave:()=>true,renderHome(){},renderTrades(){},renderAnalytics(){},renderProgress(){},stratRender(){}};
 vm.createContext(nav);vm.runInContext(cut('function goPage(id, btn){','// Market tabs'),nav);
 for(const id of ['analytics','progress','home','trades','strategies']){nav.goPage(id);assert.notEqual(fab.style.display,'none',id);}
});
T('a quick trade saved on Analytics or Progress shows there at once, as a full trade does',()=>{
 const body=cut('function saveQuickTrade(){','\n}\n');
 assert.match(body,/page-analytics[^\n]*renderAnalytics\(\)/);assert.match(body,/page-progress[^\n]*renderProgress\(\)/);
});
T('neither Buy nor Sell is lit in the markup of the form',()=>{
 assert.match(h,/<button class="tbtn" id="btnBuy"/);assert.match(h,/<button class="tbtn" id="btnSell"/);
});
console.log(`Progress decisions: ${n}/${n} passed`);
