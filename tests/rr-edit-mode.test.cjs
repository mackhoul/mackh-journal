/* A manual R:R survives an edit of the trade. The real form code of index.html (openAddTrade,
   openEditTrade, stepNext, syncFormToState/syncStateToForm, setRRMode/calcRR, saveTrade) runs on a
   small fake DOM: save → JSON → open «Edit» → change only the notes → all steps → «Update».
   The levels 1.085 / 1.082 / 1.091 give 1:2, the trader wrote 1:3. No browser, no HTTP.
   MJ_INDEX may point at another copy of index.html (to see the test fail on older code). */
const fs=require('fs'),vm=require('vm'),path=require('path'),assert=require('node:assert/strict');
const h=fs.readFileSync(process.env.MJ_INDEX||path.join(__dirname,'../index.html'),'utf8');
const cut=(a,b)=>{const i=h.indexOf(a),j=h.indexOf(b,i);assert.ok(i>=0&&j>i,'index.html has '+a);return h.slice(i,j);};
const byId=new Map();
const el=id=>{if(!byId.has(id)){const cls=new Set();byId.set(id,{id,value:'',checked:false,textContent:'',style:{},dataset:{},
 classList:{contains:c=>cls.has(c),toggle(c,on){on?cls.add(c):cls.delete(c);},add:c=>cls.add(c),remove:c=>cls.delete(c)},focus(){}});}return byId.get(id);};
const ctx={Date,Math,Number,String,JSON,Object,Array,Set,parseFloat,isNaN,
 document:{getElementById:el,querySelectorAll:()=>[]},
 trades:[],editingId:null,tForm:{},currentTags:[],currentMistakes:[],currentImg:null,checklistState:{},checklist:[],currentStep:0,
 T:x=>x,_setT(){},openModal(){},closeModal(){},showToast(){},toastWarn(s){throw Error(s);},resultError(){},costError(){},
 renderChecklist(){},updateCLScore(){},stratFillSelect(){},updateCostTotal(){},renderLearningTrade(){},renderTags(){},
 setTrade(k,v){ctx.tForm[k]=v;if(k==='dir'){el('btnBuy').classList.toggle('sel-buy',v==='buy');el('btnSell').classList.toggle('sel-sell',v==='sell');}
  if(k==='result')el('btnLoss').classList.toggle('sel-loss',v==='loss');},
 journalToday:()=>'2026-10-30',defaultPnlMode:()=>'gross',tFormCostMode:()=>'gross',tFormCostsChanged:()=>false,readCosts:()=>({commission:'',swap:''}),
 stratTradeLink:()=>({}),readLearningTrade:()=>null,readLearningRisk:(prev)=>prev?.riskSnapshot||null,learningDayPolicy:()=>null,learningTimezone:()=>'Europe/Copenhagen',
 tombIds:()=>new Set(),syncTrade(t){ctx.sent=JSON.parse(JSON.stringify(t));},renderHome(){},renderTrades(){},lsSet(){}};
el('page-analytics');el('page-progress');
vm.createContext(ctx);
vm.runInContext([cut('function parseRR(rr){','function fmt('),cut('function fmtRR(raw){','// WR color'),
 cut('function rrColor(n){','// ── Checklist'),cut('function syncFormToState(){','// ── Add choice'),
 cut('function openAddTrade(){','function saveTrade(){'),cut('function saveTrade(){','// ═')].join('\n'),ctx);
const run=s=>vm.runInContext(s,ctx);
const typeLevels=(e,sl,tp)=>{el('tEntry').value=e;el('tSL').value=sl;el('tTP').value=tp;run('calcRR()');};
const throughSteps=()=>{run('stepNext(1)');run('stepNext(2)');run('stepNext(3)');};
const edit=(trade,fn)=>{ctx.trades=[JSON.parse(JSON.stringify(trade))];run(`openEditTrade(${JSON.stringify(trade.id)})`);fn&&fn();throughSteps();run('saveTrade()');return ctx.sent;};
let checks=0;const test=(name,fn)=>{fn();checks++;console.log('PASS '+name);};

let manual;
test('a new full trade saves the R:R typed by hand, not the one of the levels',()=>{
 run('openAddTrade()');el('tPair').value='EURUSD';el('tMarket').value='forex';run('setTrade("result","loss")');el('tPnl').value='-20';
 typeLevels('1.085','1.082','1.091');assert.equal(run('tForm.rrCalc'),'1:2');
 run('setRRMode(true)');el('rrManualInput').value='1:3';run('onRRManualInput()');
 throughSteps();run('saveTrade()');manual=ctx.sent;
 assert.equal(manual.rr,'1:3');assert.equal(manual.rrMode,'manual');assert.equal(manual.entry,1.085);
});
test('editing only the notes keeps the manual 1:3 (Codex R1)',()=>{
 const s=edit(manual,()=>{
  assert.equal(run('rrManualMode'),true,'the edit opens in manual mode');
  assert.equal(el('rrManualInput').value,'1:3');assert.equal(el('rrManualDisplay').textContent,'1:3');
  el('tNotes').value='Only the notes changed';
 });
 assert.equal(s.rr,'1:3');assert.equal(s.rrMode,'manual');assert.equal(s.notes,'Only the notes changed');
 const again=edit(s);assert.equal(again.rr,'1:3','a second edit keeps it too');
});
test('in manual mode a level change does not rewrite the typed R:R',()=>{
 const s=edit(manual,()=>{typeLevels('1.085','1.082','1.097');});
 assert.equal(s.rr,'1:3');assert.equal(s.tp,1.097);
});
test('the trader can still switch back to auto: the levels decide and the trade remembers auto',()=>{
 const s=edit(manual,()=>{run('setRRMode(false)');});
 assert.equal(s.rr,'1:2');assert.equal(s.rrMode,'auto');
 const t=edit(s,()=>{assert.equal(run('rrManualMode'),false);typeLevels('1.085','1.082','1.094');});
 assert.equal(t.rr,'1:3','auto follows the new target');
});
test('an older trade without a mode: a saved R:R that differs from the levels is never replaced',()=>{
 const legacy={id:'old1',pair:'EURUSD',dir:'buy',entry:1.085,sl:1.082,tp:1.091,rr:'1:3',result:'loss',pnl:'-20',date:'2026-10-01'};
 const s=edit(legacy,()=>{assert.equal(run('rrManualMode'),true);el('tNotes').value='x';});
 assert.equal(s.rr,'1:3');assert.equal(s.rrMode,'manual');
});
test('an older trade whose R:R matches its levels opens in auto and stays the same',()=>{
 const legacy={id:'old2',pair:'EURUSD',dir:'buy',entry:1.085,sl:1.082,tp:1.091,rr:'1:2',result:'win',pnl:'20',date:'2026-10-01'};
 const s=edit(legacy,()=>{assert.equal(run('rrManualMode'),false);});
 assert.equal(s.rr,'1:2');assert.equal(s.rrMode,'auto');
});
test('an older trade with levels on the wrong side keeps its saved R:R',()=>{
 const legacy={id:'old3',pair:'EURUSD',dir:'sell',entry:1.085,sl:1.082,tp:1.091,rr:'1:2.5',result:'loss',pnl:'-5',date:'2026-10-01'};
 assert.equal(edit(legacy).rr,'1:2.5');
});
test('a quick record (no levels) keeps its R:R and its type',()=>{
 const quick={id:'q1',pair:'GBPUSD',quickTrade:true,dir:null,entry:null,sl:null,tp:null,rr:'1:4',result:'win',pnl:'40',date:'2026-10-01'};
 const s=edit(quick);assert.equal(s.rr,'1:4');assert.equal(s.quickTrade,true);
});
test('a trade without any R:R opens in auto, as before',()=>{
 const none={id:'n1',pair:'EURUSD',dir:'buy',entry:null,sl:null,tp:null,rr:null,result:'be',pnl:'0',date:'2026-10-01'};
 const s=edit(none,()=>{assert.equal(run('rrManualMode'),false);});
 assert.equal(s.rr,null);
});
console.log(`R:R edit mode: ${checks}/${checks} passed`);
