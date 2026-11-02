/* The sign-in form tells a person what happened: every answer of the server stays on the screen until
   the next attempt or a switch of the tab. The real doAuth runs in a vm. No browser, no HTTP.
   MJ_INDEX may point at another copy of index.html. */
const fs=require('fs'),vm=require('vm'),path=require('path'),assert=require('node:assert/strict');
const h=fs.readFileSync(process.env.MJ_INDEX||path.join(__dirname,'../index.html'),'utf8');
const cut=(a,b)=>{const i=h.indexOf(a),j=h.indexOf(b,i);assert.ok(i>=0&&j>i,'index.html has '+a);return h.slice(i,j);};
const block=cut('function setAuthMode(mode','// Exchanges the refresh token');

const body={tagName:'BODY'};
function setup({login}={}){
 const doc={activeElement:body,elements:{}};
 const el=id=>doc.elements[id]||(doc.elements[id]=(()=>{
  let off=false;
  const classes=new Set();
  return {id,value:'',textContent:'',className:'',autocomplete:'',
   // a browser drops the focus of a button that becomes disabled
   get disabled(){return off;},set disabled(v){off=v;if(v&&doc.activeElement===this)doc.activeElement=body;},
   focus(){if(!off)doc.activeElement=this;},
   classList:{toggle(c,on){on?classes.add(c):classes.delete(c);},add(c){classes.add(c);},remove(c){classes.delete(c);},contains:c=>classes.has(c)}};
 })());
 doc.getElementById=el;
 const sessions=[];
 const ctx={document:doc,JSON,String,lang:'ru',
  fetchSupaConfig:async()=>login==='no-config'?null:{web_auth_ready:true,supabase_url:'https://stub.test',supabase_anon_key:'k'},
  fetch:async()=>{
   if(login==='network')throw new TypeError('Failed to fetch');
   const answers={
    wrong:[400,{error_description:'Invalid login credentials'}],
    taken:[422,{msg:'User already registered'}],
    limit:[429,{msg:'Rate limit exceeded'}],
    confirm:[200,{user:{id:'u1'}}],
    ok:[200,{access_token:'a.b.c',refresh_token:'r',user:{id:'u1',email:'a@example.invalid'}}],
   }[login];
   return {ok:answers[0]<400,json:async()=>answers[1]};
  },
  saveWebSession:s=>sessions.push(s),jwtSub:()=>null,startApp:async()=>{}};
 vm.createContext(ctx);
 vm.runInContext('let authMode="in";'+block,ctx);
 el('authEmail').value='a@example.invalid';el('authPass').value='fictional-pass';
 return {ctx,doc,el,sessions};
}
const shown=s=>/(^|\s)show(\s|$)/.test(s.el('authMsg').className);
let n=0;const T=async(id,fn)=>{await fn();n++;console.log('PASS '+id);};

(async()=>{
 for(const [id,login,mode,text,kind] of [
  ['wrong password','wrong','in','Неверный email или пароль','err'],
  ['account already exists','taken','up','Такой аккаунт уже есть — войдите','err'],
  ['too many attempts','limit','in','Слишком много попыток, подождите немного','err'],
  ['server unavailable','no-config','in','Сервер недоступен. Попробуйте ещё раз через минуту.','err'],
  ['no connection','network','in','Нет связи с сервером','err'],
  ['account created, confirm the email','confirm','up','Аккаунт создан. Подтвердите email и войдите.','ok'],
 ])await T('the message stays on the screen: '+id,async()=>{
  const s=setup({login});
  if(mode==='up')s.ctx.setAuthMode('up');
  await s.ctx.doAuth();
  assert.equal(s.el('authMsg').textContent,text);
  assert.ok(shown(s),'the message is visible');
  assert.match(s.el('authMsg').className,new RegExp('(^|\\s)'+kind+'(\\s|$)'));
 });
 await T('after a failed attempt the button works again and has its own text',async()=>{
  const s=setup({login:'wrong'});await s.ctx.doAuth();
  assert.equal(s.el('authBtn').disabled,false);assert.equal(s.el('authBtn').textContent,'Войти');
 });
 await T('a keyboard user stays on the button after a failed attempt',async()=>{
  const s=setup({login:'wrong'});s.el('authBtn').focus();await s.ctx.doAuth();
  assert.equal(s.doc.activeElement,s.el('authBtn'));
 });
 await T('a mouse user who is typing elsewhere keeps their focus',async()=>{
  const s=setup({login:'wrong'});s.el('authPass').focus();await s.ctx.doAuth();
  assert.equal(s.doc.activeElement,s.el('authPass'));
 });
 await T('after «account created» the form is on the sign-in tab',async()=>{
  const s=setup({login:'confirm'});s.ctx.setAuthMode('up');await s.ctx.doAuth();
  assert.equal(s.el('authBtn').textContent,'Войти');assert.ok(s.el('authTabIn').classList.contains('active'));
 });
 await T('switching the tab clears an old message',async()=>{
  const s=setup({login:'wrong'});await s.ctx.doAuth();assert.ok(shown(s));
  s.ctx.setAuthMode('up');assert.ok(!shown(s));
 });
 await T('a new attempt clears the old message first',async()=>{
  const s=setup({login:'wrong'});await s.ctx.doAuth();
  s.el('authPass').value='';await s.ctx.doAuth();
  assert.equal(s.el('authMsg').textContent,'Заполните email и пароль');assert.ok(shown(s));
 });
 await T('a successful sign-in shows no message and saves the session',async()=>{
  const s=setup({login:'ok'});await s.ctx.doAuth();
  assert.ok(!shown(s));assert.equal(s.sessions.length,1);assert.equal(s.sessions[0].access_token,'a.b.c');
 });
 console.log('All '+n+' sign-in message checks passed');
})().catch(e=>{console.error(e);process.exit(1);});
