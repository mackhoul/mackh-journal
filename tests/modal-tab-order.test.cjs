/* Tab inside a window never sticks. A closed <details> keeps its fields in the page and, in Chromium, they
   still report a size, but the browser refuses to focus them. The real keyboard handler of index.html
   runs in a vm against a small page that behaves the same way. No browser. MJ_INDEX may point at another
   copy of index.html. */
const fs=require('fs'),vm=require('vm'),path=require('path'),assert=require('node:assert/strict');
const h=fs.readFileSync(process.env.MJ_INDEX||path.join(__dirname,'../index.html'),'utf8');
const cut=(a,b)=>{const i=h.indexOf(a),j=h.indexOf(b,i);assert.ok(i>=0&&j>i,'index.html has '+a);return h.slice(i,j);};
const code=cut('const V4_LAYERS =','// Things that open or switch on a click');

function page(tree){
 const doc={activeElement:null,asked:[]};
 const all=[];
 function make(n,parent){
  const [tag,id,o={},kids=[]]=n;
  const e={tagName:tag.toUpperCase(),id,parentElement:parent,children:[],disabled:false,tabIndex:0,open:!!o.open,isConnected:true,dataset:{},
   classList:{contains:c=>(o.cls||'').split(' ').includes(c)},
   getClientRects:()=>o.gone?[]:[{}],                                     // a closed fold still reports a size, as in Chromium
   hasAttribute:()=>o.tabindex!==undefined,setAttribute(){},
   matches(sel){return sel.split(',').some(p=>{p=p.trim();
    if(p==='a[href]')return tag==='a';if(p==='[tabindex]')return o.tabindex!==undefined;return p===tag;});},
   contains(x){for(let c=x;c;c=c.parentElement)if(c===e)return true;return false;},
   closest(){return null;},
   querySelector(sel){return sel==='.modal'?walk(e).find(x=>x.classList.contains('modal')):sel==='summary'?walk(e).find(x=>x.tagName==='SUMMARY')||null:null;},
   querySelectorAll(sel){return walk(e).filter(x=>x!==e&&x.matches(sel));},
   compareDocumentPosition(x){return all.indexOf(x)>all.indexOf(e)?4:2;},
   focus(){
    doc.asked.push(id);
    if(e.refuses)return;
    for(let p=e.parentElement,c=e;p;c=p,p=p.parentElement)
     if(p.tagName==='DETAILS'&&!p.open&&!(c.tagName==='SUMMARY'&&walk(p).find(x=>x.tagName==='SUMMARY')===c))return;   // the browser refuses a hidden field
    doc.activeElement=e;
   }};
  if(o.tabindex!==undefined)e.tabIndex=o.tabindex;
  if(o.refuses)e.refuses=true;
  all.push(e);
  e.children=kids.map(k=>make(k,e));
  return e;
 }
 const walk=e=>[e,...e.children.flatMap(walk)];
 const layer=make(tree,null);
 let handler=null;
 const ctx={Node:{DOCUMENT_POSITION_FOLLOWING:4},parseInt,Map,CSS:{escape:x=>x},
  getComputedStyle:()=>({zIndex:'300',visibility:'visible'}),
  MutationObserver:class{observe(){}},
  closeFullscreen(){},closeModal(){},
  document:{get activeElement(){return doc.activeElement;},
   querySelectorAll:sel=>sel==='.overlay, #fullscreen'?[]:sel==='.overlay.open, #fullscreen.open'?[layer]:[],
   querySelector:()=>null,getElementById:()=>null,
   addEventListener:(type,fn)=>{if(type==='keydown')handler=fn;}}};
 vm.createContext(ctx);
 vm.runInContext(code+';v4ModalFocus();',ctx);
 const byId=id=>all.find(x=>x.id===id);
 const press=(shift)=>handler({key:'Tab',shiftKey:!!shift,preventDefault(){}});
 const walkFrom=(id,count,shift)=>{byId(id).focus();const seen=[];for(let i=0;i<count;i++){press(shift);seen.push(doc.activeElement&&doc.activeElement.id);}return seen;};
 return {byId,press,walkFrom,doc};
}
const modal=kids=>['div','layer',{},[['div','box',{cls:'modal',tabindex:-1},kids]]];
// the quick entry window as it is in index.html: a closed fold in the middle of the form
const quick=(open=false)=>modal([['button','close'],['button','win'],['input','pnl'],['input','rr'],
 ['details','fold',{open},[['summary','foldHead'],['input','commission'],['input','swap'],['input','net']]],
 ['input','pair'],['textarea','notes'],['button','save']]);
// the Setup step of the full form: two closed folds one after another
const setupStep=()=>modal([['button','close'],['input','tags'],['textarea','notes'],
 ['details','learn',{},[['summary','learnHead'],['input','learnA']]],
 ['details','risk',{},[['summary','riskHead'],['input','riskA'],['input','riskB']]],
 ['button','back'],['button','next']]);

let n=0;const T=(id,fn)=>{fn();n++;console.log('PASS '+id);};
T('quick entry: Tab goes past a closed fold to the end of the form and back to the start',()=>{
 assert.deepEqual(page(quick()).walkFrom('close',9),['win','pnl','rr','foldHead','pair','notes','save','close','win']);
});
T('a hidden field of a closed fold is not even tried',()=>{
 const p=page(quick());p.walkFrom('close',9);
 assert.ok(!p.doc.asked.includes('commission'),'Tab asked a field the page hides');
});
T('quick entry: Shift+Tab goes back through the same stops',()=>{
 assert.deepEqual(page(quick()).walkFrom('save',8,true),['notes','pair','foldHead','rr','pnl','win','close','save']);
});
T('an opened fold lets Tab walk through its fields',()=>{
 assert.deepEqual(page(quick(true)).walkFrom('rr',6),['foldHead','commission','swap','net','pair','notes']);
});
T('two closed folds in a row: only their headings are stops',()=>{
 assert.deepEqual(page(setupStep()).walkFrom('notes',5),['learnHead','riskHead','back','next','close']);
 assert.deepEqual(page(setupStep()).walkFrom('back',4,true),['riskHead','learnHead','notes','tags']);
});
T('a field inside a fold inside a closed fold is not a stop',()=>{
 const p=page(modal([['button','a'],['details','outer',{},[['summary','outerHead'],
  ['details','inner',{open:true},[['summary','innerHead'],['input','deep']]]]],['button','b']]));
 assert.deepEqual(p.walkFrom('a',2),['outerHead','b']);
});
T('a control the browser refuses for any other reason is skipped, not a dead end',()=>{
 const p=page(modal([['button','a'],['button','stubborn',{refuses:true}],['button','b']]));
 assert.deepEqual(p.walkFrom('a',2),['b','a']);
 assert.deepEqual(p.walkFrom('b',1,true),['a']);
});
T('when nothing can take the focus Tab stops quietly and does not hang',()=>{
 const p=page(modal([['button','only'],['button','x',{refuses:true}],['button','y',{refuses:true}]]));
 assert.deepEqual(p.walkFrom('only',2),['only','only']);
});
console.log('All '+n+' window Tab order checks passed');
