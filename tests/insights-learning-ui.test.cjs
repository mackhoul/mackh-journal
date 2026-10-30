/* DOM-free unit tests for form state, account isolation and JSON persistence.
   This is not a browser/layout test. No HTTP requests are made. */
const fs=require('fs'),vm=require('vm'),path=require('path'),assert=require('node:assert/strict'),M=require('../insights-learning.js');
const fields=new Map();
class Element{
 constructor(id=''){this.id=id;this.value='';this.dataset={};this.checked=false;this.textContent='';this.style={};this.children=[];fields.set(id,this);}
 set innerHTML(h){this._html=h;const re=/<(input|textarea|select|p|button)\b([^>]*\bid="([^"]+)"[^>]*)>([\s\S]*?)(?:<\/\1>|(?=<))/g;let m;
  // Parse only test fields/values, not HTML layout or scripts.
  for(const match of h.matchAll(/<(input|textarea|select|p|button)\b([^>]*\bid="([^"]+)"[^>]*)>/g)){
   const e=new Element(match[3]),value=/\bvalue="([^"]*)"/.exec(match[2]);e.value=value?value[1]:'';e.checked=/\bchecked\b/.test(match[2]);
  }
 }
 get innerHTML(){return this._html||'';}
 appendChild(x){this.children.push(x);}prepend(x){this.children.unshift(x);}after(){}closest(){return this;}
}
const settingsBody=new Element('settingsBody');
const ctx={MJLearning:M,Intl,Date,JSON,Number,Math,Object,Array,Set,String,lang:'en',sdocs:{s:{id:'s',kind:'strategy',data:{name:'My strategy'}}},dataOwner:'a',baseCapital:10000,editingId:null,tForm:{dir:'buy'},trades:[],window:{_currentInsights:[]},
 document:{getElementById:id=>fields.get(id)||null,createElement:()=>new Element(),querySelector:()=>settingsBody},
 escapeHtml:s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),MISTAKES_LABELS:{early_entry:{ru:'Ранний вход',en:'Early entry'}},mLabel:()=> 'Early entry',
 renderHome(){},toastWarn(s){ctx.warning=s;},sdocAll:kind=>Object.values(ctx.sdocs).filter(d=>d.kind===kind),stratEnsureRevision:()=> 'r',stratCurrentRevision:()=> 'r',sdocUid:p=>p+'-new',computeCapital:()=>10000,tradeCostsPending:t=>!!t.pending,tradeNet:t=>t.pnl===''?NaN:Number(t.pnl),
 sdocPut(kind,data,id){if(ctx.refuse)return null;const d={id,kind,data:JSON.parse(JSON.stringify(data)),v:1};ctx.sdocs[id]=d;return d;},closeModal(){},openSettings(){ctx.openLearningSettings();}
};
vm.createContext(ctx);vm.runInContext(fs.readFileSync(path.join(__dirname,'../insights-learning-ui.js'),'utf8'),ctx);
let checks=0;const test=(name,fn)=>{fn();checks++;console.log('PASS '+name);};
const value=(id,v)=>{assert(fields.has(id),id);fields.get(id).value=v;};
test('settings save per-strategy risk, account timezone and no invented count limit',()=>{
 ctx.openLearningSettings();value('lpStrategy','s');value('lpTimezone','America/New_York');value('lpMax','0.5');value('lpCount','');value('lpLoss','');value('lpMistake','early_entry');value('lpAction','Check my condition');fields.get('lpSave').onclick();
 const p=ctx.learningPrefs();assert.equal(p.risk.s[0].maxPct,.5);assert.equal(p.history[0].timezone,'America/New_York');assert.equal(p.history[0].maxTrades,null);assert.equal(p.tracking.strategyRevId,'r');assert.equal(p.action.text,'Check my condition');
});
test('second save preserves risk history and ending action does not restore stale preferences',()=>{
 value('lpStrategy','s');fields.get('lpStrategy').onchange();value('lpMax','1');value('lpCount','3');fields.get('lpSave').onclick();assert.equal(ctx.learningPrefs().risk.s.length,2);fields.get('lpClearAction').onclick();assert.equal(ctx.learningPrefs().risk.s.length,2);assert.equal(ctx.learningPrefs().history.at(-1).maxTrades,3);assert.equal(ctx.learningPrefs().action,null);
});
test('invalid limits do not overwrite saved preferences',()=>{
 const before=JSON.stringify(ctx.learningPrefs());value('lpCount','0');fields.get('lpSave').onclick();assert.equal(JSON.stringify(ctx.learningPrefs()),before);assert.match(fields.get('lpStatus').textContent,/positive/);
});
test('reload of serialised docs preserves preferences; another account has no access',()=>{
 const saved=JSON.stringify(ctx.sdocs);ctx.sdocs=JSON.parse(saved);assert.equal(ctx.learningPrefs().history.at(-1).maxTrades,3);ctx.sdocs={};ctx.dataOwner='b';assert.equal(Object.keys(ctx.learningPrefs()).length,0);ctx.sdocs=JSON.parse(saved);ctx.dataOwner='a';
});
test('explicit selected-error absence survives JSON, missing answer remains null',()=>{
 new Element('qLearnError').value='no';const date=ctx.journalToday(),link={strategyId:'s',strategyRevId:'r'};const result=ctx.readLearningTrade('q',null,link,date);assert.equal(JSON.parse(JSON.stringify(result)).errorPresent,false);fields.get('qLearnError').value='';assert.equal(ctx.readLearningTrade('q',null,link,date).errorPresent,null);
});
test('different strategy cannot receive an assessment for another strategy',()=>{
 fields.get('qLearnError').value='yes';assert.equal(ctx.readLearningTrade('q',null,{strategyId:'other',strategyRevId:'r'},ctx.journalToday()),null);
});
test('editing notes does not erase an answer from a previous tracking session',()=>{
 fields.get('qLearnError').value='';const before={learning:{trackingId:'old-track',errorKey:'early_entry',errorPresent:true}};
 const after=ctx.readLearningTrade('q',before,{strategyId:'s',strategyRevId:'r'},ctx.journalToday());assert.equal(after.trackingId,'old-track');assert.equal(after.errorPresent,true);
 fields.get('qLearnError').value='no';const newer=ctx.readLearningTrade('q',before,{strategyId:'s',strategyRevId:'r'},ctx.journalToday());assert.equal(newer.errorPresent,false);assert.equal(newer.history[0].trackingId,'old-track');
});
test('risk snapshot needs known fees, contract and actual size; no invented 1% maximum',()=>{
 const box=new Element('tLearningRisk');box.dataset.dirty='1';new Element('lrConfirm').checked=true;
 for(const [k,v]of Object.entries({Capital:'10000',Size:'10',Multiplier:'1',Step:'1',Minimum:'1',FeeIn:'',FeeOut:'0'}))new Element('lr'+k).value=v;
 new Element('tEntry').value='100';new Element('tSL').value='90';assert.throws(()=>ctx.readLearningRisk(null,{strategyId:'unknown'},ctx.journalToday()));fields.get('lrFeeIn').value='0';const r=ctx.readLearningRisk(null,{strategyId:'unknown'},ctx.journalToday());assert.equal(r.riskUsd,100);assert.equal(r.maxPct,null);assert.equal(JSON.parse(JSON.stringify(r)).confirmed,true);
});
test('editing notes preserves the original confirmed risk snapshot',()=>{fields.get('tLearningRisk').dataset.dirty='';const old={riskSnapshot:{confirmed:true,capital:5000,riskUsd:25,maxPct:.5}};assert.equal(ctx.readLearningRisk(old,{},ctx.journalToday()),old.riskSnapshot);});
test('failed local storage is not reported as a saved setting',()=>{ctx.refuse=true;assert.equal(ctx.learningSavePrefs({history:[]}),false);assert.match(ctx.warning,/Could not save/);ctx.refuse=false;});
test('realised R is separate and unavailable with missing costs or original risk',()=>{
 const t={pnl:'100',riskSnapshot:{confirmed:true,riskUsd:50}};assert.equal(ctx.learningRealisedR(t),2);assert.equal(ctx.learningRealisedR({...t,pending:true}),null);assert.equal(ctx.learningRealisedR({pnl:'100'}),null);assert(ctx.learningRiskDetails(t).includes('2.00R'));
});
console.log('All '+checks+' UI-state checks passed');
