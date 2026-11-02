/* Andrey's decision of 2 Nov: an import adds. New trades from a backup join the journal and reach the server
   through the save queue, nothing is removed, a trade the server has keeps the journal's version, one deleted
   here stays deleted. Capital and goals come from the file only where the account has none. The real import,
   queue and delivery code of index.html runs in a vm against a stub server. No browser, no HTTP.
   MJ_INDEX may point at another copy of index.html. */
const fs=require('fs'),vm=require('vm'),path=require('path'),assert=require('node:assert/strict');
const h=fs.readFileSync(process.env.MJ_INDEX||path.join(__dirname,'../index.html'),'utf8');
const cut=(a,b)=>{const i=h.indexOf(a),j=h.indexOf(b,i);assert.ok(i>=0&&j>i,'index.html has '+a);return h.slice(i,j);};
// one whole top-level function, up to its closing brace at the start of a line
const fn=a=>{const i=h.indexOf(a),j=h.indexOf('\n}\n',i);assert.ok(i>=0&&j>i,'index.html has '+a);return h.slice(i,j+3);};
const code=[
 cut('function jwtSub(token){','function setDataOwner(owner){').replace(/function currentIdentityOwner[^\n]*\n/,''),
 fn('function setDataOwner(owner){'),
 fn('function safeLocalStorageSet(key, value'),
 fn('function addToPendingQueue(trade, owner=dataOwner, opts={}){'),
 cut('function removeFromPendingQueue(id','// Writes a server-assigned image URL'),
 cut("const TOMB_KEY = 'deleted_trades_v1';",'// Deletes a trade on this device right away'),
 cut('function syncPendingQueue(opts={}){','// The server refused a save because the trade is deleted'),
 fn('function applySaveResult(owner, id, payload, result){'),
 cut('async function syncSettings(){','function showLoader(show){'),
 fn('async function loadData('),
 fn('function syncLabelHTML(id){'),
 fn('function plural(n, one, few, many){'),
 fn('function setSyncStatus(state){'),
 fn('function updateBackupStatus(){'),
 cut('function validateTradeImport(data){','//  UNDO DELETE').replace(/\/\/ ═+\s*$/,''),
].join('\n');

const OWNER='web:u1';
function setup({server=[],capital=0,goals=[],local,settingsKnown=true,serverKnown=true,answer=true,quotaOn=null}={}){
 const store=new Map();const posts=[],paths=[],settingsPosts=[],settingsPaths=[],toasts=[],warns=[],confirms=[],notes=[];const rendered=[];
 const net={down:false,tradesDown:!serverKnown,settingsDown:!settingsKnown,settingsWriteDown:false,oldServer:false};
 const copy=x=>JSON.parse(JSON.stringify(x));
 const srv=new Map(server.map(t=>[String(t.id),{...t}]));
 const srvS={base_capital:capital,goals:copy(goals)};   // what the account holds on the server, another device may change it
 const srvDeleted=new Set();
 const hooks={onConfirm:null,onPost:null,beforeAnswer:null,holdSave:null};
 const calls=[];
 const ls={getItem:k=>store.has(k)?store.get(k):null,removeItem:k=>store.delete(k),
  setItem(k,v){if(quotaOn&&k.endsWith(quotaOn)){const e=new Error('full');e.name='QuotaExceededError';throw e;}store.set(k,String(v));}};
 const el={};const get=id=>el[id]||(el[id]={id,style:{},textContent:'',innerHTML:'',title:'',setAttribute(){}});
 const ctx={localStorage:ls,console:{log(){},warn(){},error(){}},JSON,Math,Date,String,Number,Object,Array,Set,Map,parseFloat,isNaN,isFinite,Promise,setTimeout:()=>0,clearTimeout(){},
  document:{getElementById:get},
  confirm:m=>{confirms.push(m);if(hooks.onConfirm)hooks.onConfirm();return answer;},
  showToast:m=>toasts.push(m),toastWarn:m=>warns.push(m),showSyncStatus:m=>notes.push(m),showLoader(){},renderHome:()=>rendered.push('home'),renderTrades:()=>rendered.push('trades'),closeModal(){},warnEditOfDeletedTrade(){},dropDeletedTrade(){},applyServerDeleted(){},carryImgUrlToQueue(){},
  accountLabel:()=>'a@example.invalid',stratReset(){},renderSubscription(){},resetFormsForAccountSwitch(){},
  FileReader:class{readAsText(f){ctx.__imported=this.onload({target:{result:f}});}},
  api:async(method,p,body)=>{
   ctx.api._lastStatus=net.down?0:200;
   if(net.down)return null;
   // the same rules as server.js: add_only never replaces a row, fill_empty writes only what is empty
   if(method==='POST'&&(p==='/trades'||p==='/trades?add_only=1')){
    const t=copy(body);posts.push(t);paths.push(p);if(hooks.onPost)hooks.onPost(t);
    if(srvDeleted.has(String(t.id)))return {ok:true,skipped:'deleted'};
    if(p!=='/trades'&&srv.has(String(t.id)))return {ok:true,skipped:'exists',trade:copy(srv.get(String(t.id)))};
    srv.set(String(t.id),t);return {ok:true};
   }
   if(method==='POST'&&p==='/settings'){settingsPosts.push(copy(body));settingsPaths.push(p);if(net.settingsWriteDown)return null;if(hooks.holdSave)await hooks.holdSave;srvS.base_capital=body.base_capital;srvS.goals=copy(body.goals);return {ok:true};}
   if(method==='POST'&&p==='/settings?fill_empty=1'){
    settingsPosts.push(copy(body));settingsPaths.push(p);if(net.settingsWriteDown)return null;if(hooks.holdSave)await hooks.holdSave;
    if(net.oldServer){srvS.base_capital=body.base_capital;srvS.goals=copy(body.goals);return {ok:true};}
    if(!(srvS.base_capital>0)&&body.base_capital>0)srvS.base_capital=body.base_capital;
    if(!srvS.goals.length&&body.goals.length)srvS.goals=copy(body.goals);
    return {ok:true,...copy(srvS)};
   }
   if(method==='GET'&&p==='/trades')return net.tradesDown?null:[...srv.values()].map(copy);
   if(method==='GET'&&p==='/settings')return net.settingsDown?null:copy(srvS);
   if(method==='DELETE')return {ok:true};
   return null;
  }};
 // the server has answered, the answer is still on its way to the page
 const direct=ctx.api;
 ctx.api=async(method,p,body)=>{calls.push(method+' '+p);const answer=await direct(method,p,body);if(hooks.beforeAnswer)await hooks.beforeAnswer(method,p);return answer;};
 vm.createContext(ctx);
 vm.runInContext(`const PENDING_KEY='pending_trades_v3';let ideas=[],subState=null,dataOwner=${JSON.stringify(OWNER)},ownerEpoch=1,lang='ru',trades=[],baseCapital=0,goals=[],syncStatus='';\n`+code,ctx);
 ctx.__set=(name,value)=>{ctx.__v=value;vm.runInContext(name+'=this.__v',ctx);};
 ctx.__get=name=>JSON.parse(JSON.stringify(vm.runInContext(name,ctx)));   // a copy in this realm, so deepEqual compares values
 ctx.__set('trades',JSON.parse(JSON.stringify(local||server)));
 ctx.safeLocalStorageSet('trades_v3',JSON.parse(JSON.stringify(local||server)),OWNER);
 ctx.__set('baseCapital',capital);ctx.__set('goals',goals);
 if(serverKnown)ctx.__set('_serverIds',new Set(server.map(t=>String(t.id))));
 const settle=async()=>{for(let i=0;i<60;i++)await Promise.resolve();};
 const run=async(file)=>{ctx.importJSON({files:[typeof file==='string'?file:JSON.stringify(file)],value:''});await ctx.__imported;await settle();await ctx.syncPendingQueue();await settle();};
 return {ctx,run,settle,calls,posts,paths,settingsPosts,settingsPaths,toasts,warns,confirms,notes,srv,srvS,srvDeleted,net,hooks,store,get,rendered,
  journal:()=>ctx.__get('trades').map(t=>t.id),queue:()=>JSON.parse(JSON.stringify(ctx.getQueue(OWNER))).map(t=>t.id)};
}
const tr=(id,o={})=>({id,pair:'EURUSD',date:'2026-10-20',result:'win',pnl:'10',...o});
const rejected=async(file,why)=>{
 const s=setup({server:[tr('own')],capital:100});await s.run(file);
 assert.equal(s.confirms.length,0,why+': no question');assert.deepEqual(s.journal(),['own'],why+': journal unchanged');
 assert.equal(s.posts.length,0,why+': nothing sent');assert.equal(s.warns.length,1,why+': a warning');
};
let n=0,failed=0;const T=async(id,fn)=>{try{await fn();n++;console.log('PASS '+id);}catch(e){failed++;console.log('FAIL '+id+' :: '+String(e.message).split('\n')[0].slice(0,120));}};

(async()=>{
 await T('new trades join the journal and reach the server; what the account had stays',async()=>{
  const s=setup({server:[tr('own',{notes:'мои'})]});
  await s.run({trades:[tr('n1'),tr('n2')]});
  assert.deepEqual(s.journal(),['own','n1','n2']);
  assert.deepEqual([...s.srv.keys()].sort(),['n1','n2','own']);
  assert.equal(s.srv.get('own').notes,'мои');
  assert.deepEqual(s.queue(),[],'everything was delivered');
  assert.deepEqual(s.rendered.slice(0,2),['home','trades']);
 });
 await T('a trade the server already has keeps the journal version, the old copy is not sent',async()=>{
  const s=setup({server:[tr('same',{pnl:'99'})]});
  await s.run({trades:[tr('same',{pnl:'1'}),tr('n1')]});
  assert.deepEqual(s.posts.map(t=>t.id),['n1']);
  assert.equal(s.srv.get('same').pnl,'99');assert.equal(s.ctx.__get('trades')[0].pnl,'99');
 });
 await T('the same file twice adds nothing the second time and asks nothing',async()=>{
  const s=setup({server:[]});const file={trades:[tr('n1')]};
  await s.run(file);assert.equal(s.confirms.length,1);assert.equal(s.posts.length,1);
  await s.run(file);assert.equal(s.confirms.length,1,'no question');assert.equal(s.posts.length,1,'nothing sent again');
  assert.deepEqual(s.journal(),['n1']);assert.equal(s.toasts.at(-1),'Новых сделок в файле нет');
 });
 await T('the question says what will happen: how many are added, how many stay, nothing is deleted',async()=>{
  const s=setup({server:[tr('same')]});
  await s.run({trades:[tr('same'),tr('n1'),tr('n2')]});
  const q=s.confirms[0];
  assert.match(q,/a@example\.invalid/);assert.match(q,/будет добавлено: 2/);assert.match(q,/Уже есть в журнале: 1/);assert.match(q,/Ничего не удаляется/);
  assert.doesNotMatch(q,/замен/i,'the old promise is gone');
 });
 await T('the answer after the import says it was added, with the right word for one trade',async()=>{
  const s=setup({server:[]});await s.run({trades:[tr('n1')]});
  assert.equal(s.toasts.at(-1),'Добавлена 1 сделка, отправляем на сервер');
  const m=setup({server:[]});await m.run({trades:[tr('n1'),tr('n2'),tr('n3')]});
  assert.equal(m.toasts.at(-1),'Добавлено 3 сделки, отправляем на сервер');
 });
 await T('«no» to the question changes nothing',async()=>{
  const s=setup({server:[tr('own')],answer:false});
  await s.run({trades:[tr('n1')],baseCapital:500,goals:[{id:'g1',type:'trades',target:5}]});
  assert.deepEqual(s.journal(),['own']);assert.equal(s.posts.length,0);assert.equal(s.settingsPosts.length,0);assert.deepEqual(s.queue(),[]);assert.equal(s.ctx.__get('baseCapital'),0);
 });
 await T('a trade deleted on this device does not come back',async()=>{
  const s=setup({server:[]});
  s.ctx.setTombs([{id:'gone',at:1,done:true}],OWNER);
  await s.run({trades:[tr('gone'),tr('n1')]});
  assert.deepEqual(s.journal(),['n1']);assert.deepEqual(s.posts.map(t=>t.id),['n1']);
  assert.match(s.confirms[0],/Удалены раньше и не вернутся: 1/);
 });
 await T('a trade deleted on the server is refused there and is not counted as saved',async()=>{
  const s=setup({server:[]});s.srvDeleted.add('n1');
  await s.run({trades:[tr('n1')]});
  assert.deepEqual([...s.srv.keys()],[],'the server did not take it');assert.deepEqual(s.queue(),[],'no endless retry');
 });
 await T('a trade only on this device is sent in its local version, not the file version',async()=>{
  const s=setup({server:[],local:[tr('here',{pnl:'55'})]});
  await s.run({trades:[tr('here',{pnl:'1'})]});
  assert.equal(s.srv.get('here').pnl,'55');assert.deepEqual(s.journal(),['here']);
 });
 await T('ids compare as text: 77 in the file is 77 in the journal',async()=>{
  const s=setup({server:[tr('77')]});
  await s.run({trades:[tr(77)]});
  assert.equal(s.posts.length,0);assert.deepEqual(s.journal(),['77']);
 });
 await T('service fields of a file never reach the server',async()=>{
  const s=setup({server:[]});
  await s.run({trades:[tr('n1',{__restore:5,__qv:'x'})]});
  assert.equal('__restore' in s.posts[0],false);assert.equal('__qv' in s.posts[0],false);
 });
 await T('without the server list the import waits: it must not overwrite newer edits',async()=>{
  const s=setup({server:[],serverKnown:false});
  await s.run({trades:[tr('n1')]});
  assert.equal(s.confirms.length,0);assert.deepEqual(s.journal(),[]);assert.equal(s.posts.length,0);assert.match(s.warns[0],/Нет связи с сервером/);
 });
 await T('when the server goes down the trades wait in the queue and are delivered later',async()=>{
  const s=setup({server:[]});s.hooks.onConfirm=()=>{s.net.down=true;};
  await s.run({trades:[tr('n1'),tr('n2')]});
  assert.deepEqual(s.queue(),['n1','n2']);assert.equal(s.ctx.__get('syncStatus'),'pending');
  s.net.down=false;await s.ctx.syncPendingQueue();
  assert.deepEqual(s.queue(),[]);assert.deepEqual([...s.srv.keys()],['n1','n2']);assert.equal(s.ctx.__get('syncStatus'),'synced');
 });
 await T('no room on the device: nothing changes and the person is told',async()=>{
  const s=setup({server:[tr('own')],quotaOn:'pending_trades_v3'});
  await s.run({trades:[tr('n1')]});
  assert.deepEqual(s.journal(),['own']);assert.equal(s.posts.length,0);assert.equal(s.toasts.filter(m=>/Добавлен/.test(m)).length,0,'no «added»');assert.match(s.warns[0],/памяти|места/i);
 });
 await T('capital and goals: an empty account takes them from the file, and the server gets them',async()=>{
  const s=setup({server:[]});
  const g=[{id:'g1',type:'trades',target:5,name:'Цель'}];
  await s.run({trades:[tr('n1')],baseCapital:7000,goals:g});
  assert.equal(s.ctx.__get('baseCapital'),7000);assert.deepEqual(s.ctx.__get('goals').map(x=>x.id),['g1']);
  assert.equal(s.settingsPosts.length,1);assert.equal(s.settingsPosts[0].base_capital,7000);assert.deepEqual(s.settingsPosts[0].goals.map(x=>x.id),['g1']);
  assert.match(s.confirms[0],/Депозит и цели из файла/);
 });
 await T('capital and goals: the account\'s own values are never overwritten',async()=>{
  const s=setup({server:[],capital:5000,goals:[{id:'mine',type:'pnl',target:1}]});
  await s.run({trades:[tr('n1')],baseCapital:7000,goals:[{id:'g1',type:'trades',target:5}]});
  assert.equal(s.ctx.__get('baseCapital'),5000);assert.deepEqual(s.ctx.__get('goals').map(x=>x.id),['mine']);
  assert.equal(s.settingsPosts.length,0);assert.doesNotMatch(s.confirms[0],/Депозит/);
 });
 await T('capital and goals: each is filled on its own',async()=>{
  const s=setup({server:[],capital:5000});
  await s.run({trades:[],baseCapital:7000,goals:[{id:'g1',type:'trades',target:5}]});
  assert.equal(s.ctx.__get('baseCapital'),5000);assert.deepEqual(s.ctx.__get('goals').map(x=>x.id),['g1']);
  assert.equal(s.settingsPosts[0].base_capital,5000);
  assert.match(s.confirms[0],/Цели из файла/);assert.doesNotMatch(s.confirms[0],/Депозит/);
 });
 await T('capital and goals: if the server settings are unknown they are left alone',async()=>{
  const s=setup({server:[],settingsKnown:false});
  await s.run({trades:[tr('n1')],baseCapital:7000,goals:[{id:'g1',type:'trades',target:5}]});
  assert.equal(s.ctx.__get('baseCapital'),0);assert.equal(s.settingsPosts.length,0);assert.deepEqual(s.posts.map(t=>t.id),['n1']);
 });
 for(const [why,file] of [
  ['not json','это не json'],
  ['date in another format',{trades:[tr('x',{date:'02.11.2026'})]}],
  ['a date that does not exist',{trades:[tr('x',{date:'2026-13-45'})]}],
  ['a day past the end of the month',{trades:[tr('x',{date:'2026-02-30'})]}],
  ['a date that is not text',{trades:[tr('x',{date:20261102})]}],
  ['P&L that is not a number',{trades:[tr('x',{pnl:'abc'})]}],
  ['entry that is not a number',{trades:[tr('x',{entry:'abc'})]}],
  ['commission that is not a number',{trades:[tr('x',{commission:'x'})]}],
  ['swap that is not a number',{trades:[tr('x',{swap:'y'})]}],
  ['id zero',{trades:[tr(0)]}],
  ['a goal of an unknown type',{trades:[tr('x')],goals:[{id:'g',type:'nope',target:5}]}],
  ['a goal without a number',{trades:[tr('x')],goals:[{id:'g',type:'trades',target:'abc'}]}],
  ['a goal below zero',{trades:[tr('x')],goals:[{id:'g',type:'trades',target:-1}]}],
 ])await T('refused before anything changes: '+why,()=>rejected(file,why));
 for(const [why,t] of [
  ['no date',{date:undefined}],['an empty date',{date:''}],['empty P&L',{pnl:''}],['P&L as a number',{pnl:12.5}],['a signed P&L',{pnl:'+50'}],['empty costs',{commission:'',swap:null}],['a decimal comma in a cost',{commission:'1,5'}],
 ])await T('still accepted: '+why,async()=>{
  const s=setup({server:[]});await s.run({trades:[tr('ok',t)]});assert.deepEqual(s.journal(),['ok']);
 });
 await T('the status: trades on their way are counted with the right word',async()=>{
  const s=setup({server:[]});s.hooks.onConfirm=()=>{s.net.down=true;};await s.run({trades:[tr('n1'),tr('n2')]});s.ctx.updateBackupStatus();
  assert.equal(s.get('backupStatusText').textContent,'2 сделки ждут сервера');
 });
 for(const l of ['ru','en'])await T('every import message fits the one-line toast of a phone: '+l,async()=>{
  const said=[];
  const collect=async(opts,file)=>{const s=setup(opts);s.ctx.__set('lang',l);await s.run(file);said.push(...s.toasts,...s.warns);};
  await collect({server:[]},'это не json');
  await collect({server:[],serverKnown:false},{trades:[tr('n1')]});
  await collect({server:[],quotaOn:'pending_trades_v3'},{trades:[tr('n1')]});
  await collect({server:[tr('n1')]},{trades:[tr('n1')]});
  await collect({server:[]},{trades:Array.from({length:128},(_,i)=>tr('n'+i))});
  await collect({server:[]},{trades:[],goals:[{id:'g1',type:'trades',target:5}]});
  assert.ok(said.length>=6,'each case said something');
  for(const m of said)assert.ok(m.length<=46,'too long for a phone: '+m);
 });
 await T('the status: nothing pending and all on the server',async()=>{
  const s=setup({server:[tr('a')]});s.ctx.updateBackupStatus();
  assert.equal(s.get('backupStatusText').textContent,'Все данные в безопасности');
 });
 await T('the status: trades only on this device are not called safe',async()=>{
  const s=setup({server:[tr('a')],local:[tr('a'),tr('here1'),tr('here2')]});s.ctx.updateBackupStatus();
  assert.equal(s.get('backupStatusText').textContent,'2 сделки есть только на этом устройстве');
  assert.equal(s.get('pendingWarning').style.display,'block');
 });
 await T('the status: without the server the data is not called safe',async()=>{
  const s=setup({server:[],serverKnown:false});s.ctx.updateBackupStatus();
  assert.equal(s.get('backupStatusText').textContent,'Нет связи с сервером');
 });
 await T('the dot: trades only on this device keep it from saying «synced»',async()=>{
  const s=setup({server:[tr('a')],local:[tr('a'),tr('here')]});await s.ctx.syncPendingQueue();
  assert.equal(s.ctx.__get('syncStatus'),'pending');
 });
 // R1: «an import adds» has to hold when the account changed after this page loaded
 const NEWER={pnl:'999',notes:'newer from another device'};
 await T('R1: a trade added elsewhere after the page loaded is seen before the question, the file does not touch it',async()=>{
  const s=setup({server:[]});s.srv.set('x',tr('x',NEWER));
  await s.run({trades:[tr('x',{pnl:'7'})]});
  assert.equal(s.srv.get('x').pnl,'999');assert.equal(s.posts.length,0,'nothing sent');
  assert.equal(s.confirms.length,0,'nothing to ask');assert.equal(s.ctx.__get('trades')[0].pnl,'999','the journal shows the account version');
 });
 await T('R1: the question counts such a trade as already there',async()=>{
  const s=setup({server:[]});s.srv.set('x',tr('x',NEWER));
  await s.run({trades:[tr('x',{pnl:'7'}),tr('n1')]});
  assert.match(s.confirms[0],/будет добавлено: 1/);assert.match(s.confirms[0],/Уже есть в журнале: 1/);
 });
 await T('R1: a trade that appears while the question is open keeps the account version, here too',async()=>{
  const s=setup({server:[]});s.hooks.onConfirm=()=>s.srv.set('x',tr('x',NEWER));
  await s.run({trades:[tr('x',{pnl:'7'}),tr('n1')]});
  assert.equal(s.srv.get('x').pnl,'999','the server keeps it');assert.equal(s.srv.get('x').notes,NEWER.notes);
  const here=s.ctx.__get('trades');assert.equal(here.find(t=>t.id==='x').pnl,'999','the journal shows it');
  assert.ok(s.srv.has('n1'),'the new one still arrives');assert.deepEqual(s.queue(),[]);
  assert.match(s.notes.at(-1),/Уже есть в аккаунте: 1/,'the person is told');
  s.ctx.updateBackupStatus();assert.equal(s.get('backupStatusText').textContent,'Все данные в безопасности');
 });
 await T('R1: a trade waiting without a connection does not overwrite what appears meanwhile',async()=>{
  const s=setup({server:[]});s.hooks.onConfirm=()=>{s.net.down=true;};
  await s.run({trades:[tr('x',{pnl:'7'})]});
  assert.deepEqual(s.queue(),['x']);
  s.srv.set('x',tr('x',NEWER));s.net.down=false;await s.ctx.syncPendingQueue();await s.settle();
  assert.equal(s.srv.get('x').pnl,'999');assert.equal(s.ctx.__get('trades')[0].pnl,'999');assert.deepEqual(s.queue(),[]);
 });
 await T('R1: every imported trade goes as add-only, an ordinary save does not',async()=>{
  const s=setup({server:[tr('own')]});
  await s.run({trades:[tr('n1'),tr('n2')]});
  assert.deepEqual(s.paths,['/trades?add_only=1','/trades?add_only=1']);
  s.ctx.addToPendingQueue(tr('own',{notes:'моя правка'}),OWNER);await s.ctx.syncPendingQueue();
  assert.equal(s.paths.at(-1),'/trades','an edit is an ordinary save');assert.equal(s.srv.get('own').notes,'моя правка');
 });
 await T('R1: an edit made while the imported trade waits is the person\'s own save, not add-only',async()=>{
  const s=setup({server:[]});s.hooks.onConfirm=()=>{s.net.down=true;};
  await s.run({trades:[tr('x',{pnl:'7'})]});
  s.ctx.addToPendingQueue(tr('x',{pnl:'8'}),OWNER);s.net.down=false;await s.ctx.syncPendingQueue();
  assert.deepEqual(s.paths.at(-1),'/trades');assert.equal(s.srv.get('x').pnl,'8');
 });
 await T('R1: when the server keeps its version but a newer edit is queued, the edit still goes and shows',async()=>{
  const s=setup({server:[]});let once=false;
  s.hooks.onPost=t=>{if(once)return;once=true;s.srv.set('x',tr('x',NEWER));s.ctx.__set('trades',[tr('x',{pnl:'8'})]);s.ctx.addToPendingQueue(tr('x',{pnl:'8'}),OWNER);};
  await s.run({trades:[tr('x',{pnl:'7'})]});
  assert.equal(s.srv.get('x').pnl,'8');assert.equal(s.ctx.__get('trades')[0].pnl,'8');assert.deepEqual(s.queue(),[]);
 });
 await T('R1: the add-only mark reaches neither the journal nor the data, even when a file carries it',async()=>{
  const s=setup({server:[]});
  await s.run({trades:[tr('n1',{__addOnly:true})]});
  assert.equal('__addOnly' in s.posts[0],false);assert.equal('__addOnly' in s.ctx.__get('trades')[0],false);
 });
 await T('R1: a local-only trade goes as add-only too, a version the account got elsewhere wins',async()=>{
  const s=setup({server:[],local:[tr('here',{pnl:'55'})]});s.hooks.onConfirm=()=>s.srv.set('here',tr('here',NEWER));
  await s.run({trades:[tr('here',{pnl:'1'})]});
  assert.equal(s.srv.get('here').pnl,'999');assert.equal(s.ctx.__get('trades')[0].pnl,'999');
 });
 await T('R1: without a fresh answer the import stops, an older list of the server is not enough',async()=>{
  const s=setup({server:[]});s.net.tradesDown=true;
  await s.run({trades:[tr('n1')]});
  assert.equal(s.confirms.length,0);assert.equal(s.posts.length,0);assert.deepEqual(s.journal(),[]);assert.match(s.warns[0],/Нет связи с сервером/);
 });
 await T('R1: the fresh read keeps what only this page holds',async()=>{
  const s=setup({server:[]});s.ctx.__set('trades',[tr('only-in-memory')]);
  await s.ctx.loadData({refresh:true});
  assert.deepEqual(s.journal(),['only-in-memory']);
 });
 await T('R1: the person sees that the journal is being checked, the first request can take a while',async()=>{
  const s=setup({server:[]});await s.run({trades:[tr('n1')]});
  assert.equal(s.toasts[0],'Сверяем журнал с сервером...');
 });
 // R2: «only where the account has none» is about the account now, not this page
 const G=id=>({id,type:'trades',target:5});
 await T('R2: capital and goals set elsewhere after the page loaded stay, nothing is asked or sent about them',async()=>{
  const s=setup({server:[]});s.srvS.base_capital=9000;s.srvS.goals=[G('remote')];
  await s.run({trades:[tr('n1')],baseCapital:700,goals:[G('file')]});
  assert.equal(s.settingsPosts.length,0);assert.equal(s.srvS.base_capital,9000);assert.deepEqual(s.srvS.goals.map(g=>g.id),['remote']);
  assert.doesNotMatch(s.confirms[0],/Депозит|Цели/);
  assert.equal(s.ctx.__get('baseCapital'),9000);assert.deepEqual(s.ctx.__get('goals').map(g=>g.id),['remote']);
 });
 await T('R2: set while the question is open: the server keeps them and this device shows them',async()=>{
  const s=setup({server:[]});s.hooks.onConfirm=()=>{s.srvS.base_capital=9000;s.srvS.goals=[G('remote')];};
  await s.run({trades:[tr('n1')],baseCapital:700,goals:[G('file')]});
  assert.equal(s.srvS.base_capital,9000);assert.deepEqual(s.srvS.goals.map(g=>g.id),['remote']);
  assert.equal(s.ctx.__get('baseCapital'),9000);assert.deepEqual(s.ctx.__get('goals').map(g=>g.id),['remote']);
  assert.equal(s.ctx.lsGet('baseCapital_v3',OWNER),'9000','the stored copy too');
  assert.match(s.warns.at(-1),/уже заданы/,'the person is told');assert.ok(s.warns.at(-1).length<=46,'fits a phone');
 });
 await T('R2: the same note in English fits a phone too',async()=>{
  const s=setup({server:[]});s.ctx.__set('lang','en');s.hooks.onConfirm=()=>{s.srvS.base_capital=9000;};
  await s.run({trades:[],baseCapital:700});
  assert.match(s.warns.at(-1),/already in the account/);assert.ok(s.warns.at(-1).length<=46,s.warns.at(-1));
 });
 await T('R2: capital and goals are checked one by one against the server',async()=>{
  const s=setup({server:[]});s.hooks.onConfirm=()=>{s.srvS.base_capital=9000;};
  await s.run({trades:[],baseCapital:700,goals:[G('file')]});
  assert.equal(s.srvS.base_capital,9000);assert.deepEqual(s.srvS.goals.map(g=>g.id),['file']);
  assert.equal(s.ctx.__get('baseCapital'),9000);assert.deepEqual(s.ctx.__get('goals').map(g=>g.id),['file']);
 });
 await T('R2: the file fills through the fill-only request and always names both values',async()=>{
  const s=setup({server:[],capital:5000});
  await s.run({trades:[],goals:[G('file')]});
  assert.deepEqual(s.settingsPaths,['/settings?fill_empty=1']);
  assert.equal(s.settingsPosts[0].base_capital,5000,'an older server writes both, so neither may be missing');
  assert.deepEqual(s.settingsPosts[0].goals.map(g=>g.id),['file']);
 });
 await T('R2: an older server answers without values: what was filled stays on screen',async()=>{
  const s=setup({server:[]});s.net.oldServer=true;
  await s.run({trades:[],baseCapital:700,goals:[G('file')]});
  assert.equal(s.ctx.__get('baseCapital'),700);assert.deepEqual(s.ctx.__get('goals').map(g=>g.id),['file']);assert.equal(s.notes.length,0);
 });
 await T('R2: when the write fails the person is told',async()=>{
  const s=setup({server:[]});s.net.settingsWriteDown=true;
  await s.run({trades:[],baseCapital:700});
  assert.match(s.warns.at(-1),/не дошли до сервера/);
 });
 await T('R2: a failed read of the settings leaves them alone even if an earlier one worked',async()=>{
  const s=setup({server:[]});s.net.settingsDown=true;
  await s.run({trades:[tr('n1')],baseCapital:700,goals:[G('file')]});
  assert.equal(s.settingsPosts.length,0);assert.equal(s.ctx.__get('baseCapital'),0);assert.deepEqual(s.posts.map(t=>t.id),['n1']);
  assert.doesNotMatch(s.confirms[0],/Депозит|Цели/);
 });
 // R3: 77 and '77' are one trade everywhere
 await T('R3: the status counts 77 here and \'77\' on the server as one trade',async()=>{
  const s=setup({server:[tr('77')],local:[tr(77)]});
  assert.equal(s.ctx.localOnlyCount(),0);
  s.ctx.updateBackupStatus();assert.equal(s.get('backupStatusText').textContent,'Все данные в безопасности');
  await s.ctx.syncPendingQueue();assert.equal(s.ctx.__get('syncStatus'),'synced');
 });
 await T('R3: the same after a real load, and the other way round',async()=>{
  const s=setup({server:[tr(77)],local:[tr('77')]});
  await s.ctx.loadData({refresh:true});
  assert.equal(s.ctx.localOnlyCount(),0);
 });
 await T('R3: a queued 77 and a queued \'77\' are not counted as only here',async()=>{
  const s=setup({server:[],local:[tr('5')]});s.net.down=true;s.ctx.addToPendingQueue(tr(5),OWNER);
  assert.equal(s.ctx.localOnlyCount(),0);
 });
 await T('R3: the note next to a trade agrees with the status',async()=>{
  const s=setup({server:[tr('77')],local:[tr(77)]});
  assert.equal(s.ctx.syncLabelHTML(77),'');assert.match(s.ctx.syncLabelHTML(78),/Нет на сервере/);
 });
 await T('R3: a delivered save and a delivered deletion update the server list with any id type',async()=>{
  const s=setup({server:[]});await s.run({trades:[tr(5)]});
  assert.equal(s.ctx.localOnlyCount(),0);assert.equal(s.ctx.syncLabelHTML(5),'');
  s.ctx.setTombs([{id:5,at:1}],OWNER);await s.ctx.syncPendingQueue();
  assert.equal(vm.runInContext('_serverIds.has("5")',s.ctx),false);
 });
 // N1: an answer that was on its way while the settings changed must not undo that change
 const once=(s,method,path,fn)=>{let done=false;s.hooks.beforeAnswer=async(m,p)=>{if(done||m!==method||p!==path)return;done=true;await fn();};};
 const manual=s=>{s.ctx.__set('baseCapital',9000);s.ctx.__set('goals',[G('manual')]);return s.ctx.syncSettings();};
 const keptManual=(s,why)=>{
  assert.equal(s.ctx.__get('baseCapital'),9000,why+': the page');assert.deepEqual(s.ctx.__get('goals').map(g=>g.id),['manual'],why+': the page');
  assert.equal(s.ctx.lsGet('baseCapital_v3',OWNER),'9000',why+': the stored copy');assert.match(s.ctx.lsGet('goals_v1',OWNER),/manual/,why+': the stored copy');
  assert.equal(s.srvS.base_capital,9000,why+': the server');assert.deepEqual(s.srvS.goals.map(g=>g.id),['manual'],why+': the server');
 };
 await T('N1: a manual change made while the answer of the fill was on its way stays, and the next save does not undo it',async()=>{
  const s=setup({server:[]});once(s,'POST','/settings?fill_empty=1',()=>manual(s));
  await s.run({trades:[],baseCapital:700,goals:[G('file')]});
  keptManual(s,'after the late answer');
  assert.equal(s.warns.filter(m=>/уже заданы/.test(m)).length,0,'no note about values the person has just set');
  await s.ctx.syncSettings();keptManual(s,'after the next ordinary save');
 });
 await T('N1: a manual change made while the fresh read was on its way stays, and the file does not touch it',async()=>{
  const s=setup({server:[]});once(s,'GET','/settings',()=>manual(s));
  await s.run({trades:[tr('n1')],baseCapital:700,goals:[G('file')]});
  keptManual(s,'after the late read');
  assert.doesNotMatch(s.confirms[0],/Депозит|Цели/);assert.equal(s.settingsPaths.filter(p=>p.includes('fill_empty')).length,0);
  await s.ctx.syncSettings();keptManual(s,'after the next ordinary save');
 });
 await T('N1: the same for an ordinary load when the app starts',async()=>{
  const s=setup({server:[]});once(s,'GET','/settings',()=>manual(s));
  await s.ctx.loadData();
  keptManual(s,'after the late read');
 });
 await T('N1: a change saved by another tab while the answer of the fill was on its way stays in the stored copy',async()=>{
  const s=setup({server:[]});once(s,'POST','/settings?fill_empty=1',()=>{s.ctx.lsSet('baseCapital_v3','9000',OWNER);s.srvS.base_capital=9000;});
  await s.run({trades:[],baseCapital:700});
  assert.equal(s.ctx.lsGet('baseCapital_v3',OWNER),'9000');
 });
 await T('N1: a change saved by another tab while the read was on its way stays in the stored copy',async()=>{
  const s=setup({server:[]});once(s,'GET','/settings',()=>{s.ctx.lsSet('baseCapital_v3','9000',OWNER);s.srvS.base_capital=9000;});
  await s.ctx.loadData({refresh:true});
  assert.equal(s.ctx.lsGet('baseCapital_v3',OWNER),'9000');
 });
 await T('N1: a read waits for an ordinary save on its way, so it cannot bring the older values back',async()=>{
  const s=setup({server:[]});let release;s.hooks.holdSave=new Promise(r=>{release=r;});
  s.ctx.__set('baseCapital',9000);const saving=s.ctx.syncSettings();
  const load=s.ctx.loadData({refresh:true});await s.settle();
  assert.equal(s.calls.includes('GET /settings'),false,'no read while the save is out');
  release();await saving;await load;
  assert.ok(s.calls.includes('GET /settings'));assert.equal(s.ctx.__get('baseCapital'),9000);assert.equal(s.srvS.base_capital,9000);
 });
 await T('N1: the fill waits for an ordinary save on its way, so it comes after it',async()=>{
  const s=setup({server:[]});let release,saving;
  s.hooks.onConfirm=()=>{s.hooks.holdSave=new Promise(r=>{release=r;});s.ctx.__set('goals',[G('manual')]);saving=s.ctx.syncSettings();};
  await s.run({trades:[],baseCapital:700});
  assert.ok(s.calls.includes('POST /settings'),'the save is out');
  assert.equal(s.calls.includes('POST /settings?fill_empty=1'),false,'no fill while the save is out');
  release();await saving;await s.settle();
  assert.ok(s.calls.indexOf('POST /settings')<s.calls.indexOf('POST /settings?fill_empty=1'));
  assert.equal(s.srvS.base_capital,700);assert.deepEqual(s.srvS.goals.map(g=>g.id),['manual']);
 });
 await T('N1: a read waits for a fill on its way too, so a second import cannot undo the first',async()=>{
  const s=setup({server:[]});let release;
  s.hooks.onConfirm=()=>{s.hooks.holdSave=new Promise(r=>{release=r;});};
  await s.run({trades:[],baseCapital:700});
  assert.equal(s.calls.filter(c=>c==='GET /settings').length,1,'the read before the question');
  const second=s.ctx.loadData({refresh:true});await s.settle();
  assert.equal(s.calls.filter(c=>c==='GET /settings').length,1,'no new read while the fill is out');
  release();await second;await s.settle();
  assert.equal(s.srvS.base_capital,700);assert.equal(s.ctx.__get('baseCapital'),700);assert.equal(s.ctx.lsGet('baseCapital_v3',OWNER),'700');
 });
 await T('N1: a change on this page that could not reach the stored copy is respected too',async()=>{
  const s=setup({server:[]});once(s,'GET','/settings',()=>{s.ctx.__set('baseCapital',9000);});
  await s.ctx.loadData({refresh:true});
  assert.equal(s.ctx.__get('baseCapital'),9000);
 });
 await T('N1: another account does not wait for the save of the previous one',async()=>{
  const s=setup({server:[]});s.hooks.holdSave=new Promise(()=>{});
  s.ctx.__set('baseCapital',9000);s.ctx.syncSettings();
  s.ctx.setDataOwner('web:u2');
  const load=s.ctx.loadData();await s.settle();
  assert.ok(s.calls.includes('GET /settings'),'the read went out');await load;
 });
 // N2: a kept version replaces the file's copy, never an edit that arrived meanwhile
 const TAB_B={pnl:'1234',notes:'saved in tab B'};
 await T('N2: an edit another tab delivered while the answer was on its way stays, in the stored copy and on this page',async()=>{
  const s=setup({server:[]});s.hooks.onConfirm=()=>s.srv.set('x',tr('x',NEWER));
  once(s,'POST','/trades?add_only=1',()=>{const b=tr('x',TAB_B);s.srv.set('x',b);s.ctx.safeLocalStorageSet('trades_v3',[b],OWNER);});
  await s.run({trades:[tr('x',{pnl:'7'})]});
  assert.equal(s.srv.get('x').pnl,'1234');assert.deepEqual(s.queue(),[]);
  const stored=s.ctx.lsJSON('trades_v3',[],OWNER)[0];assert.equal(stored.pnl,'1234');assert.equal(stored.notes,TAB_B.notes);
  const here=s.ctx.__get('trades')[0];assert.equal(here.pnl,'1234');assert.equal(here.notes,TAB_B.notes);
 });
 await T('N2: without such an edit the account version replaces the file copy, also when the file has a picture',async()=>{
  const s=setup({server:[]});s.hooks.onConfirm=()=>s.srv.set('x',tr('x',NEWER));
  await s.run({trades:[tr('x',{pnl:'7',img:'data:image/png;base64,AAAA'})]});
  assert.equal(s.ctx.lsJSON('trades_v3',[],OWNER)[0].pnl,'999');assert.equal(s.ctx.__get('trades')[0].pnl,'999');
 });
 await T('N2: when another account is on screen by then, only the stored copy of the first one changes',async()=>{
  const s=setup({server:[]});s.hooks.onConfirm=()=>s.srv.set('x',tr('x',NEWER));
  once(s,'POST','/trades?add_only=1',()=>{s.ctx.setDataOwner('web:u2');});
  await s.run({trades:[tr('x',{pnl:'7'})]});
  assert.equal(s.ctx.lsJSON('trades_v3',[],OWNER)[0].pnl,'999');assert.deepEqual(s.ctx.__get('trades'),[]);
 });
 await T('N2: an edit from another tab is respected for the other account too',async()=>{
  const s=setup({server:[]});s.hooks.onConfirm=()=>s.srv.set('x',tr('x',NEWER));
  once(s,'POST','/trades?add_only=1',()=>{s.ctx.safeLocalStorageSet('trades_v3',[tr('x',TAB_B)],OWNER);s.ctx.setDataOwner('web:u2');});
  await s.run({trades:[tr('x',{pnl:'7'})]});
  assert.equal(s.ctx.lsJSON('trades_v3',[],OWNER)[0].pnl,'1234');
 });
 if(failed){console.error(failed+' failed, '+n+' passed');process.exit(1);}
 console.log('All '+n+' trade import checks passed');
})().catch(e=>{console.error(e);process.exit(1);});
