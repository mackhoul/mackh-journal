const fs=require('fs'),vm=require('vm'),path=require('path'),assert=require('node:assert/strict');
const h=fs.readFileSync(path.join(__dirname,'../index.html'),'utf8'),cut=(a,b)=>h.slice(h.indexOf(a),h.indexOf(b,h.indexOf(a)));
const fields={};const get=id=>fields[id]||(fields[id]={value:'',checked:false,classList:{contains:()=>false},focus(){}});
const learning={trackingId:'track',errorKey:'early_entry',errorPresent:false,actionId:'action',actionDone:true},risk={confirmed:true,riskUsd:50,capital:10000,maxPct:.5};
const ctx={Date,Math,Number,String,JSON,parseFloat,isNaN,parseRR:require('../insights-learning.js').parseRR,document:{getElementById:get},trades:[],editingId:null,rrManualMode:false,tForm:{pair:'EURUSD',result:'win',byPlan:true,pnl:'10',date:'2026-10-28'},currentTags:[],currentMistakes:[],currentImg:null,qCurrentImg:null,qForm:{result:'win',byPlan:false},
 syncFormToState(){},tFormCostMode:()=> 'gross',tFormCostsChanged:()=>false,readCosts:()=>({commission:'0',swap:'0'}),stratTradeLink:()=>({strategyId:'s',strategyRevId:'r'}),readLearningTrade:()=>learning,readLearningRisk:()=>risk,
 journalToday:()=> '2026-10-28',learningTimezone:()=> 'Europe/Copenhagen',learningDayPolicy:()=>({ruleSavedAt:'2026-10-28T10:00:00Z',maxTrades:3}),tombIds:()=>new Set(),
 syncTrade(t){ctx.sent=JSON.parse(JSON.stringify(t));},showToast(){},T:x=>x,lsSet(){},closeModal(){},renderHome(){},renderTrades(){},renderAnalytics(){},renderProgress(){},fmtRR:String,resultError(){},stepNext(){},costError(){},toastWarn(s){throw Error(s);}
};vm.createContext(ctx);
const start=h.indexOf('function saveTrade(){'),end=h.indexOf('// ═',start);vm.runInContext(h.slice(start,end),ctx);
vm.runInContext(cut('function saveQuickTrade(){','// ═'),ctx);
ctx.saveTrade();assert.equal(ctx.sent.learning.errorPresent,false);assert.equal(ctx.sent.learning.actionDone,true);assert.equal(ctx.sent.riskSnapshot.maxPct,.5);assert.equal(ctx.sent.tradingTimezone,'Europe/Copenhagen');assert.equal(ctx.sent.dayPolicy.maxTrades,3);
const full=ctx.sent;ctx.trades=[{...full,quickTrade:true}];ctx.editingId=full.id;ctx.tForm={...ctx.tForm,notes:'Edited notes',costsWere:{commission:'0',swap:'0'}};ctx.saveTrade();assert.equal(ctx.sent.quickTrade,true,'editing a quick record must preserve its type');assert.equal(ctx.sent.recordedAt,full.recordedAt);assert.equal(ctx.sent.dayPolicy.ruleSavedAt,full.dayPolicy.ruleSavedAt);
for(const[k,v]of Object.entries({qPair:'EURUSD',qCommission:'0',qSwap:'0',qRR:'1:2',qDate:'2026-10-28',qSession:'London',qPnl:'10',qNotes:'Fictional'}))get(k).value=v;
ctx.saveQuickTrade();assert.equal(ctx.sent.quickTrade,true);assert.equal(ctx.sent.learning.errorPresent,false);assert.equal(ctx.sent.riskSnapshot,null);assert.equal(ctx.sent.byPlan,false);assert.equal(ctx.sent.dayPolicy.maxTrades,3);
const validate=cut('function validateTradeImport(data){','function importJSON(input){');vm.runInContext(validate,ctx);const roundTrip=JSON.parse(JSON.stringify({trades:[full,ctx.sent],baseCapital:10000,goals:[]}));assert.equal(ctx.validateTradeImport(roundTrip),roundTrip);assert.equal(roundTrip.trades[0].riskSnapshot.riskUsd,50);
const before=ctx.trades;assert.throws(()=>ctx.validateTradeImport({trades:[null]}));assert.equal(ctx.trades,before);assert.throws(()=>ctx.validateTradeImport({trades:[{id:'same'},{id:'same'}]}));
console.log('Trade payload, edit, quick-entry and JSON round-trip checks passed');
