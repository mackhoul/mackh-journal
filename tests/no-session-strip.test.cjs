/* Andrey's decision of 2 Nov: the thin coloured 24h line on top of every screen is gone. It had no labels and
   read as a stray line. The sessions stay in the «Сейчас» tile on the home screen: the real renderKillzones of
   index.html runs in a vm and still draws them there. No browser. MJ_INDEX may point at another copy. */
const fs=require('fs'),vm=require('vm'),path=require('path'),assert=require('node:assert/strict');
const h=fs.readFileSync(process.env.MJ_INDEX||path.join(__dirname,'../index.html'),'utf8');
const cut=(a,b)=>{const i=h.indexOf(a),j=h.indexOf(b,i);assert.ok(i>=0&&j>i,'index.html has '+a);return h.slice(i,j);};

let n=0,failed=0;
const T=(id,fn)=>{try{fn();n++;console.log('PASS '+id);}catch(e){failed++;console.log('FAIL '+id+' :: '+String(e.message).split('\n')[0].slice(0,120));}};

for(const [why,re] of [
 ['the markup',/id="sStrip"|class="sstrip"/],
 ['the styles',/\.sstrip\b/],
 ['the marks on it',/\.ss-seg\b|\.ss-now\b|class="ss-seg|class="ss-now/],
 ['its animation',/ssPulse/],
 ['the code that drew it',/getElementById\('sStrip'\)/],
])T('the line is gone: '+why,()=>assert.doesNotMatch(h,re));

T('other session styles that share the prefix stay',()=>{
 assert.match(h,/\.ss-table\{/);assert.match(h,/\.ss-best\{/);
});

const SEED=new Date('2026-11-02T14:30:00Z');
const code=[
 cut('const SESSIONS = [','function getSession(time){'),
 cut('const KZ_TIMEZONES = [','function setKzTimezone(id){'),
 cut('function populateKzTzSelect(){','// Session boundaries in UTC'),
 cut('const SESSION_ORDER = [','function sessLabel(name){'),
].join('\n');
const run=()=>{
 const el={};const calls=[];
 const get=id=>el[id]||(el[id]={id,innerHTML:'',textContent:'',title:'',dataset:{}});
 class D extends Date{constructor(...a){a.length?super(...a):super(SEED.getTime());}}
 const ctx={document:{getElementById:id=>{calls.push(id);return id==='sStrip'?null:get(id);}},localStorage:{getItem:()=>null,setItem(){}},
  Intl,Date:D,String,Math,RegExp,parseInt,console,lang:'ru',
  T:k=>k,fmtDur:m=>m+' мин',sessLabel:s=>s,renderPhrase(){},renderDayMap(){}};
 vm.createContext(ctx);vm.runInContext(code+'\nthis.renderKillzones=renderKillzones;',ctx);
 ctx.renderKillzones();
 return {el,calls};
};
T('the sessions are still drawn in the «Сейчас» tile, with the mark of the current time',()=>{
 const {el}=run();
 assert.match(el.kzTrack.innerHTML,/class="kz-seg/);assert.match(el.kzTrack.innerHTML,/class="kz-marker"/);
 for(const s of ['Asia','London','New York','Overlap'])assert.match(el.kzTrack.innerHTML,new RegExp('title="'+s+'"'));
 assert.match(el.kzNowPill.textContent,/^\d\d:\d\d$/);
});
T('drawing the sessions no longer looks for the line',()=>{
 assert.equal(run().calls.includes('sStrip'),false);
});

if(failed){console.error(failed+' failed, '+n+' passed');process.exit(1);}
console.log('All '+n+' session line checks passed');
