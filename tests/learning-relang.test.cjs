/* A language switch (applyLang → relangLearning) draws the open learning blocks again in the new
   language and keeps what was typed but not saved: settings fields, the answers of the full and the
   quick form, the confirmed-size fields with their «changed» mark. And the questions are offered by
   the same day rule as saving (readLearningTrade): a record dated before the start of tracking gets
   a note instead of a question whose answer would be dropped. Small fake DOM, no browser, no HTTP. */
const fs=require('fs'),vm=require('vm'),path=require('path'),assert=require('node:assert/strict'),M=require('../insights-learning.js');
const byId=new Map();
class Element{
 constructor(id=''){this._id='';this.value='';this.type='';this.dataset={};this.checked=false;this.textContent='';this.style={};this.listeners={};if(id)this.id=id;}
 set id(v){this._id=v;if(v)byId.set(v,this);} get id(){return this._id;}
 set innerHTML(h){this._html=h;
  // a fresh render makes fresh fields, as the browser does, and the old ones leave the document
  (this.owned||[]).forEach(id=>byId.delete(id));this.owned=[];
  for(const m of h.matchAll(/<(input|textarea|select|p|button)\b([^>]*\bid="([^"]+)"[^>]*)>/g)){
   const e=new Element(m[3]),v=/\bvalue="([^"]*)"/.exec(m[2]),t=/\btype="([^"]*)"/.exec(m[2]),f=/\bdata-learn-for="([^"]*)"/.exec(m[2]);this.owned.push(m[3]);
   e.value=v?v[1]:'';e.type=t?t[1]:'';e.checked=/\bchecked\b/.test(m[2]);if(f)e.dataset.learnFor=f[1];
   if(m[1]==='select'){const sel=/<option value="([^"]*)" selected>/.exec(h.slice(m.index,h.indexOf('</select>',m.index)));e.value=sel?sel[1]:'';}
  }
 }
 get innerHTML(){return this._html||'';}
 addEventListener(t,f){(this.listeners[t]=this.listeners[t]||[]).push(f);} fire(t){(this.listeners[t]||[]).forEach(f=>f());}
 after(){} closest(){return this;} prepend(){}
}
const ctx={MJLearning:M,Intl,Date,JSON,Number,Math,Object,Array,Set,String,Error,lang:'ru',dataOwner:'a',baseCapital:10000,editingId:null,tForm:{dir:'buy'},trades:[],
 sdocs:{},
 document:{getElementById:id=>byId.get(id)||null,createElement:()=>new Element(),querySelector:()=>new Element()},
 escapeHtml:s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),
 MISTAKES_LABELS:{early_entry:{ru:'Ранний вход',en:'Early entry'}},mLabel:()=>'Ранний вход',
 sdocAll:()=>[{id:'s1',data:{name:'Demo'}}],stratEnsureRevision(){ctx.ensured++;return 'r1';},stratCurrentRevision:()=>'r1',ensured:0,sdocUid:p=>p+'-1',sdocPut:()=>({}),computeCapital:()=>10000,calcPosition(){},renderHome(){},toastWarn(){},closeModal(){},openSettings(){}};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(__dirname,'../insights-learning-ui.js'),'utf8'),ctx);
const today=ctx.journalToday(),before=M.day(Date.parse(today+'T12:00:00Z')-86400000,'UTC');
const prefs={history:[{effectiveDay:today,timezone:'Europe/Copenhagen',maxTrades:2,dailyLoss:null,savedAt:'x'}],risk:{s1:[{effectiveDay:today,maxPct:1,savedAt:'x'}]},
 tracking:{id:'track1',key:'early_entry',strategyId:'s1',strategyRevId:'r1',sinceDay:today},
 action:{id:'act1',text:'Дождаться закрытия свечи',strategyId:'s1',strategyRevId:'r1',sinceDay:today}};
ctx.learningPrefs=()=>prefs;
new Element('tNotes');new Element('qNotes');new Element('tStrategy').value='s1';new Element('qStrategy').value='s1';
new Element('tEntry').value='1.0850';new Element('tSL').value='1.0820';const tDate=new Element('tDate');tDate.value=today;new Element('qDate').value=today;
const link={strategyId:'s1',strategyRevId:'r1'},$=id=>byId.get(id);
const setLang=l=>{ctx.lang=l;ctx.relangLearning();};
let checks=0;const test=(name,fn)=>{fn();checks++;console.log('PASS '+name);};

test('full form: RU → EN keeps the answers and the confirmed size, and the risk stays «changed»',()=>{
 ctx.lang='ru';ctx.tForm={dir:'buy'};vm.runInContext('tForm=this.tForm',ctx);ctx.renderLearningTrade('t',null);
 $('tLearnError').value='no';$('tLearnAction').value='yes';
 for(const [k,v] of Object.entries({Size:'0.4',Multiplier:'100000',Step:'0.01',Minimum:'0.01',FeeIn:'0',FeeOut:'0'}))$('lr'+k).value=v;
 $('lrConfirm').checked=true;$('tLearningRisk').dataset.dirty='1';
 setLang('en');
 assert.match($('tLearning').innerHTML,/Learning from my mistakes/);assert.doesNotMatch($('tLearning').innerHTML,/Моя работа над ошибками/);
 assert.match($('tLearningRisk').innerHTML,/Confirm the planned size used/);
 assert.equal($('tLearnError').value,'no');assert.equal($('tLearnAction').value,'yes');
 assert.equal($('lrSize').value,'0.4');assert.equal($('lrConfirm').checked,true);assert.equal($('tLearningRisk').dataset.dirty,'1');
 const l=ctx.readLearningTrade('t',null,link,today);assert.equal(l.errorPresent,false);assert.equal(l.actionDone,true);
 const r=ctx.readLearningRisk(null,link,today);assert.equal(r.confirmed,true);assert.equal(Math.round(r.riskUsd),120);
 assert.match($('lrPreview').textContent,/^Planned risk \$120\.00/);
 setLang('ru');assert.match($('tLearning').innerHTML,/Моя работа над ошибками/);assert.equal($('tLearnError').value,'no');
});
test('an untouched saved size stays untouched after a language switch',()=>{
 const t={id:'e1',strategyId:'s1',strategyRevId:'r1',learning:null,riskSnapshot:{confirmed:true,capital:10000,size:0.2,multiplier:100000,step:0.01,minimum:0.01,feeEntry:0,feeExit:0,riskUsd:60,maxPct:1}};
 ctx.tForm={dir:'buy'};vm.runInContext('tForm=this.tForm',ctx);ctx.renderLearningTrade('t',t);
 setLang('en');assert.equal($('tLearningRisk').dataset.dirty,'');assert.equal($('lrSize').value,'0.2');
 assert.equal(ctx.readLearningRisk(t,link,today),t.riskSnapshot,'the stored snapshot is kept as it was');
 ctx.lang='ru';
});
test('quick form: the answers survive the switch',()=>{
 ctx.lang='ru';ctx.renderLearningTrade('q',null);$('qLearnError').value='yes';
 setLang('en');assert.match($('qLearning').innerHTML,/It will remain a quick-entry record/);assert.equal($('qLearnError').value,'yes');assert.equal($('qLearnAction').value,'');
 assert.equal(ctx.readLearningTrade('q',null,link,today).actionDone,null,'an empty answer stays unknown');
 ctx.lang='ru';
});
test('settings: the section changes language and keeps what was typed but not saved',()=>{
 ctx.lang='ru';ctx.openLearningSettings();assert.match($('learningSettings').innerHTML,/Обучение и личные лимиты/);
 assert.equal($('lpStrategy').value,'s1');assert.equal($('lpMax').value,1);
 $('lpCount').value='3';$('lpMax').value='0.7';$('lpAction').value='Проверить уровень';$('lpTimezone').value='Europe/Kyiv';
 setLang('en');
 assert.match($('learningSettings').innerHTML,/Learning and personal limits/);assert.doesNotMatch($('learningSettings').innerHTML,/Обучение и личные лимиты/);
 assert.equal($('lpCount').value,'3');assert.equal($('lpMax').value,'0.7');assert.equal($('lpAction').value,'Проверить уровень');assert.equal($('lpTimezone').value,'Europe/Kyiv');
 assert.equal($('lpStrategy').value,'s1');assert.match($('lpRiskHistory').textContent,/1%/);
 ctx.lang='ru';
});
test('a record dated before the start of tracking gets a note, not a question that saving drops',()=>{
 ctx.lang='ru';tDate.value=before;ctx.tForm={dir:'buy'};vm.runInContext('tForm=this.tForm',ctx);ctx.renderLearningTrade('t',null);
 assert.ok(!$('tLearning').innerHTML.includes('id="tLearnError"'));assert.ok(!$('tLearning').innerHTML.includes('id="tLearnAction"'));
 assert.match($('tLearning').innerHTML,new RegExp('Наблюдение действует с '+today));
 assert.equal(ctx.readLearningTrade('t',null,link,before),null,'saving agrees: nothing is kept for that date');
 tDate.value=today;tDate.fire('change');
 assert.ok($('tLearning').innerHTML.includes('id="tLearnError"'),'a later date brings the questions back');
 $('tLearnError').value='no';tDate.fire('change');assert.equal($('tLearnError').value,'no','a redraw for the date keeps the answer');
 const old={id:'o1',date:before,strategyId:'s1',strategyRevId:'r1',learning:null};tDate.value=before;
 ctx.tForm={dir:'buy'};vm.runInContext('tForm=this.tForm',ctx);ctx.renderLearningTrade('t',old);
 assert.ok(!$('tLearning').innerHTML.includes('id="tLearnError"'),'an edit of an older record offers no question either');
 tDate.value=today;
});
const qDate=$('qDate');
test('full form: a date before the tracking and back keeps the typed answers (Codex F1)',()=>{
 ctx.lang='ru';tDate.value=today;ctx.tForm={dir:'buy'};vm.runInContext('tForm=this.tForm',ctx);ctx.renderLearningTrade('t',null);
 $('tLearnError').value='no';$('tLearnAction').value='yes';
 tDate.value=before;tDate.fire('change');
 assert.equal($('tLearnError'),undefined,'the hidden questions are gone from the document');
 assert.equal(ctx.readLearningTrade('t',null,link,before),null,'a hidden answer is not saved');
 tDate.value=today;tDate.fire('change');
 assert.equal($('tLearnError').value,'no');assert.equal($('tLearnAction').value,'yes');
 const l=ctx.readLearningTrade('t',null,link,today);assert.equal(l.errorPresent,false);assert.equal(l.actionDone,true);
});
test('quick form: the same round trip keeps the answers, an untouched one stays unknown',()=>{
 ctx.lang='ru';qDate.value=today;ctx.renderLearningTrade('q',null);$('qLearnError').value='no';
 qDate.value=before;qDate.fire('change');assert.equal($('qLearnError'),undefined);
 qDate.value=today;qDate.fire('change');
 assert.equal($('qLearnError').value,'no');assert.equal($('qLearnAction').value,'');
 const l=ctx.readLearningTrade('q',null,link,today);assert.equal(l.errorPresent,false);assert.equal(l.actionDone,null);
});
test('a typed answer never moves to another tracking',()=>{
 ctx.tForm={dir:'buy'};vm.runInContext('tForm=this.tForm',ctx);ctx.renderLearningTrade('t',null);
 $('tLearnError').value='yes';$('tLearnAction').value='no';
 tDate.value=before;tDate.fire('change');
 const was=prefs.tracking;prefs.tracking={...was,id:'track2'};               // the trader started new tracking meanwhile
 tDate.value=today;tDate.fire('change');
 assert.equal($('tLearnError').value,'','the new tracking starts unanswered');assert.equal($('tLearnAction').value,'no','the same action keeps its answer');
 prefs.tracking=was;
});
test('an edit: the changed answer survives the round trip, not the stored one',()=>{
 const t={id:'e2',date:today,strategyId:'s1',strategyRevId:'r1',learning:{trackingId:'track1',errorKey:'early_entry',errorPresent:true,actionId:'act1',actionDone:true}};
 ctx.tForm={dir:'buy'};vm.runInContext('tForm=this.tForm',ctx);ctx.renderLearningTrade('t',t);
 assert.equal($('tLearnError').value,'yes');$('tLearnError').value='no';
 tDate.value=before;tDate.fire('change');tDate.value=today;tDate.fire('change');
 assert.equal($('tLearnError').value,'no');assert.equal(ctx.readLearningTrade('t',t,link,today).errorPresent,false);
});
test('drawing the forms creates no strategy revision (Codex F2)',()=>{
 assert.equal(ctx.ensured,0,'only saving may create a revision');
});
console.log(`Learning blocks on a language switch and the day rule: ${checks}/${checks} passed`);
