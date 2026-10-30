/* The full trade form keeps what was typed in «Learning from my mistakes» and «Confirm the planned
   size used» while the trader moves between its steps (stepNext → syncStateToForm → renderLearningTrade),
   starts clean for every newly opened form, and a strategy change in a later form re-renders the
   questions with that form's trade, not the first one ever opened. Small fake DOM, no browser, no HTTP. */
const fs=require('fs'),vm=require('vm'),path=require('path'),assert=require('node:assert/strict'),M=require('../insights-learning.js');
const byId=new Map();
class Element{
 constructor(id=''){this._id='';this.value='';this.dataset={};this.checked=false;this.textContent='';this.style={};this.listeners={};if(id)this.id=id;}
 set id(v){this._id=v;if(v)byId.set(v,this);} get id(){return this._id;}
 set innerHTML(h){this._html=h;
  // a fresh render makes fresh fields, as the browser does
  for(const m of h.matchAll(/<(input|textarea|select|p|button)\b([^>]*\bid="([^"]+)"[^>]*)>/g)){
   const e=new Element(m[3]),v=/\bvalue="([^"]*)"/.exec(m[2]);e.value=v?v[1]:'';e.checked=/\bchecked\b/.test(m[2]);
   if(m[1]==='select'){const sel=/<option value="(yes|no)" selected>/.exec(h.slice(m.index,h.indexOf('</select>',m.index)));e.value=sel?sel[1]:'';}
  }
 }
 get innerHTML(){return this._html||'';}
 addEventListener(t,f){(this.listeners[t]=this.listeners[t]||[]).push(f);} fire(t){(this.listeners[t]||[]).forEach(f=>f());}
 after(){} closest(){return this;}
}
const today=M.day(Date.now(),'Europe/Copenhagen');
const ctx={MJLearning:M,Intl,Date,JSON,Number,Math,Object,Array,Set,String,Error,lang:'ru',dataOwner:'a',baseCapital:10000,editingId:null,tForm:{dir:'buy'},trades:[],
 sdocs:{pref:{id:'pref',kind:'note',data:{}}},
 document:{getElementById:id=>byId.get(id)||null,createElement:()=>new Element(),querySelector:()=>null},
 escapeHtml:s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),
 MISTAKES_LABELS:{early_entry:{ru:'Ранний вход',en:'Early entry'}},mLabel:()=>'Ранний вход',
 sdocAll:()=>[],stratEnsureRevision:()=>'r1',stratCurrentRevision:()=>'r1',sdocUid:p=>p+'-1',sdocPut:()=>({}),computeCapital:()=>10000,calcPosition(){},renderHome(){},toastWarn(){},closeModal(){},openSettings(){}};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname,'../insights-learning-ui.js'),'utf8'),ctx);
// the trader's saved choices: watch «early entry» and one action in strategy s1, max risk 1 %
const prefs={history:[],risk:{s1:[{effectiveDay:today,maxPct:1,savedAt:'x'}]},
 tracking:{id:'track1',key:'early_entry',strategyId:'s1',strategyRevId:'r1',sinceDay:today},
 action:{id:'act1',text:'Дождаться закрытия свечи',strategyId:'s1',strategyRevId:'r1',sinceDay:today}};
ctx.learningPrefs=()=>prefs;
new Element('tNotes');new Element('qNotes');const strat=new Element('tStrategy');strat.value='s1';
new Element('tEntry').value='1.0850';new Element('tSL').value='1.0820';new Element('tDate').value=today;
const link={strategyId:'s1',strategyRevId:'r1'};
{
 const current=ctx.stratCurrentRevision;
 ctx.stratCurrentRevision=()=> 'r2';
 const html=ctx.learningFieldHTML('t',null);
 assert.ok(!html.includes('id="tLearnError"'),'a mismatched revision must not offer an answer that saving discards');
 assert.match(html,/Начните новое наблюдение/);
 const edited=ctx.learningFieldHTML('t',{strategyId:'s1',strategyRevId:'r1'});
 assert.ok(edited.includes('id="tLearnError"'),'editing retains the trade’s original revision');
 ctx.stratCurrentRevision=current;
}
let checks=0;const test=(name,fn)=>{fn();checks++;console.log('PASS '+name);};
const typeRisk=()=>{for(const [k,v] of Object.entries({Size:'0.4',Multiplier:'100000',Step:'0.01',Minimum:'0.01',FeeIn:'0',FeeOut:'0'}))byId.get('lr'+k).value=v;
 byId.get('lrConfirm').checked=true;byId.get('tLearningRisk').dataset.dirty='1';};

test('new full form: answers and the confirmed size survive moving to the next steps',()=>{
 ctx.tForm={dir:'buy'};vm.runInContext('tForm=this.tForm',ctx);
 ctx.renderLearningTrade('t',null);                       // the form opens
 byId.get('tLearnError').value='no';byId.get('tLearnAction').value='yes';typeRisk();
 ctx.renderLearningTrade('t',null);                       // «Далее: чеклист» → syncStateToForm
 ctx.renderLearningTrade('t',null);                       // «Далее: дисциплина»
 const l=ctx.readLearningTrade('t',null,link,today);
 assert.equal(l.errorPresent,false);assert.equal(l.actionDone,true);
 const r=ctx.readLearningRisk(null,link,today);
 assert.ok(r&&r.confirmed);assert.equal(Math.round(r.riskUsd),120);assert.equal(r.maxPct,1);
});
test('a newly opened form starts clean, it does not keep the previous form’s answers',()=>{
 ctx.tForm={dir:'buy'};vm.runInContext('tForm=this.tForm',ctx);
 ctx.renderLearningTrade('t',null);
 assert.equal(byId.get('tLearnError').value,'');assert.equal(byId.get('lrConfirm').checked,false);
 const l=ctx.readLearningTrade('t',null,link,today);assert.equal(l.errorPresent,null);assert.equal(l.actionDone,null);
});
test('editing: changed answers survive the steps; the trade’s own answers show at open',()=>{
 const old={id:'e1',learning:{trackingId:'track1',errorKey:'early_entry',errorPresent:true,actionId:'act1',actionDone:false}};
 ctx.tForm={dir:'buy'};vm.runInContext('tForm=this.tForm',ctx);
 ctx.renderLearningTrade('t',old);
 assert.equal(byId.get('tLearnError').value,'yes');assert.equal(byId.get('tLearnAction').value,'no');
 byId.get('tLearnAction').value='yes';
 ctx.renderLearningTrade('t',old);ctx.renderLearningTrade('t',old);
 const l=ctx.readLearningTrade('t',old,link,today);assert.equal(l.errorPresent,true);assert.equal(l.actionDone,true);
});
test('a strategy change in a later form re-renders with that form’s trade, not the first one',()=>{
 const later={id:'e2',learning:{trackingId:'track1',errorKey:'early_entry',errorPresent:false}};
 ctx.tForm={dir:'buy'};vm.runInContext('tForm=this.tForm',ctx);
 ctx.renderLearningTrade('t',later);
 strat.fire('change');
 assert.equal(byId.get('tLearnError').value,'no');
});
// The trade-limit card declines the record count: «3 записи», «5 записей», «21 запись»
{
 const source=fs.readFileSync(path.join(__dirname,'insights-quality.test.cjs'),'utf8'),prefix=source.slice(0,source.indexOf('// ── 1. B/E')).replace('Math, Number, String, Date,','MJLearning, learningPrefs, Math, Number, String, Date,');
 const limit={history:[{effectiveDay:'2026-10-28',timezone:'UTC',maxTrades:1,dailyLoss:null}]};
 const {run,many}=new Function('require','__dirname','MJLearning','learningPrefs',prefix+'\nreturn {run,many};')(require,__dirname,M,()=>limit);
 for(const [n,word] of [[3,'3 записи'],[5,'5 записей'],[21,'21 запись']]){
  test(`trade-limit card: «${word}»`,()=>{
   const c=run(many(n,{date:'2026-10-28'})).ins.find(i=>i.id==='trade_limit_2026-10-28');
   assert.ok(c,'card');assert.ok(c.text.includes(word+' при личном лимите 1'),c.text);
  });
 }
}
console.log('All '+checks+' learning form-step checks passed');
