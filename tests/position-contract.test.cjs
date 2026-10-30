const fs=require('fs'),path=require('path'),vm=require('vm'),assert=require('node:assert/strict'),M=require('../insights-learning.js');
const h=fs.readFileSync(path.join(__dirname,'../index.html'),'utf8'),a=h.indexOf('function calcPosition(){'),b=h.indexOf('function initPositionCalc(){',a);
const fields={},get=id=>fields[id]||(fields[id]={value:'',checked:false,dataset:{}});
const out={children:[],_html:'',_text:'',set innerHTML(v){this._html=v;this._text='';this.children=[];},get innerHTML(){return this._html;},set textContent(v){this._text=v;this._html='';this.children=[];},get textContent(){return this._text;},appendChild(x){this.children.push(x);}};fields.pcOut=out;
const chips=[.5,1,2].map(r=>({dataset:{r:String(r)},classList:{toggle(){}},disabled:false}));
for(const[k,v]of Object.entries({tStrategy:'s',tDate:'2026-10-28',tEntry:'1.1',tSL:'1.09',tMarket:'forex',tPair:'EURUSD',lrMultiplier:'100000',lrStep:'.01',lrMinimum:'.01',lrFeeIn:'0',lrFeeOut:'0'}))get(k).value=v;
const ctx={MJLearning:M,Number,String,Math,parseFloat,baseCapital:10000,tForm:{dir:'buy'},risk:1,max:1,getRiskPct:()=>ctx.risk,learningText:(ru,en)=>en,learningMax:()=>ctx.max,journalToday:()=> '2026-10-28',computeCapital:()=>10000,pairInfo:()=>({p:'EURUSD',base:'EUR',quote:'USD'}),escapeHtml:s=>String(s),learningRiskPreview(){ctx.previewed=true;},
 document:{getElementById:get,querySelectorAll:()=>chips,createElement:()=>({})}};
vm.createContext(ctx);vm.runInContext(h.slice(a,b),ctx);ctx.calcPosition();assert(out.innerHTML.includes('0.1 lots'));assert.equal(chips[2].disabled,true);assert.equal(chips[1].disabled,false);assert.equal(out.children.length,1);out.children[0].onclick();assert.equal(get('lrConfirm').checked,false);assert.equal(get('lrSize').value,.1);assert(ctx.previewed);
ctx.risk=1.2;ctx.calcPosition();assert.match(out.textContent,/exceeds your personal maximum/);assert.equal(out.children.length,0);
ctx.max=.5;ctx.risk=1;ctx.calcPosition();assert.equal(chips[1].disabled,true);assert.match(out.textContent,/exceeds/);
ctx.risk=.5;ctx.baseCapital=0;ctx.calcPosition();assert.match(out.textContent,/Set starting capital/);
ctx.baseCapital=10000;ctx.max=1;get('tSL').value='1.2';ctx.calcPosition();assert.match(out.textContent,/valid stop/);
console.log('Position-calculator contract, maximum, copying and unknown-capital checks passed');
