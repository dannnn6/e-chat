'use strict';
const $ = id => document.getElementById(id);
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const uuid = () => crypto.randomUUID();
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
const unb64 = text => Uint8Array.from(atob(text.replaceAll('-','+').replaceAll('_','/') + '='.repeat((4-text.length%4)%4)), c => c.charCodeAt(0));
const hex = buffer => [...new Uint8Array(buffer)].map(x => x.toString(16).padStart(2,'0')).join('');
const sha = async data => hex(await crypto.subtle.digest('SHA-256', data));
const ECDSA = {name:'ECDSA', namedCurve:'P-256'};
const SIGN = {name:'ECDSA', hash:'SHA-256'};
let authMode = 'register', credentials = null, globalDb, db, running = false, refreshPromise;
let currentId = null, visible = new Map(), conversations = [], replyTo = null, editing = null, chosenFiles = [];
let moreHistory = true, loadingHistory = false, edge = localStorage.getItem('echat-edge') !== 'false';
let historyWindow = false;
let payloadBytes = 0, readTimer, toastTimer, draftTimer, fatalAuth = false, sending = false;
const lastRead = new Map();

function element(tag, cls, value) { const e = document.createElement(tag); if(cls) e.className=cls; if(value!==undefined) e.textContent=value; return e; }
function button(label, fn, cls='') { const b=element('button',cls,label); b.type='button'; b.onclick=()=>Promise.resolve().then(fn).catch(showError); return b; }
function toast(message) { $('toast').textContent=message; $('toast').hidden=false; clearTimeout(toastTimer); toastTimer=setTimeout(()=>$('toast').hidden=true,6000); }
function showError(error) { console.error(error.name || 'Error', error.status || ''); toast(error.message || 'Ошибка. Повторите действие.'); }
function dialog(title) { const body=$('dialog-body'); body.replaceChildren(element('h2','',title)); if(!$('dialog').open) $('dialog').showModal(); return body; }
function closeDialog() { $('dialog').close(); }
function codeBlock(text) { return element('div','code',text); }
function bytes(value) { return value<1024 ? value+' Б' : value<1048576 ? (value/1024).toFixed(1)+' КБ' : (value/1048576).toFixed(1)+' МБ'; }
function connection(label) { $('network-state').textContent=label; }
function current() { return conversations.find(c=>c.id===currentId); }
function nearBottom() { const n=$('message-list'); return n.scrollHeight-n.scrollTop-n.clientHeight<90; }

function openDb(name, version, upgrade) { return new Promise((resolve,reject)=>{ const r=indexedDB.open(name,version); r.onupgradeneeded=()=>upgrade(r.result); r.onsuccess=()=>resolve(r.result); r.onerror=()=>reject(r.error); }); }
function requestResult(r) { return new Promise((resolve,reject)=>{r.onsuccess=()=>resolve(r.result); r.onerror=()=>reject(r.error);}); }
function transactionDone(t) { return new Promise((resolve,reject)=>{t.oncomplete=()=>resolve();t.onerror=()=>reject(t.error);t.onabort=()=>reject(t.error||new Error('Локальное сохранение отменено'));}); }
async function get(store,key,database=db) { return requestResult(database.transaction(store).objectStore(store).get(key)); }
async function all(store,database=db) { return requestResult(database.transaction(store).objectStore(store).getAll()); }
async function put(store,value,key,database=db) { const t=database.transaction(store,'readwrite'); const done=transactionDone(t); if(key===undefined)t.objectStore(store).put(value);else t.objectStore(store).put(value,key);await done; }
async function remove(store,key,database=db) {const t=database.transaction(store,'readwrite');const done=transactionDone(t);t.objectStore(store).delete(key);await done;}
async function cachedMessages(cid,limit=200) { return new Promise((resolve,reject)=>{const items=[];const t=db.transaction('messages');const r=t.objectStore('messages').index('history').openCursor(IDBKeyRange.bound([cid,0],[cid,Number.MAX_SAFE_INTEGER]),'prev');r.onsuccess=()=>{const c=r.result;if(!c||items.length>=limit){resolve(items.reverse());return;}items.push(c.value);c.continue();};r.onerror=()=>reject(r.error);}); }
async function applyBatch(batch, ack=null, fromSync=false) {
  const t=db.transaction(['convs','messages','meta','outbox'],'readwrite'), done=transactionDone(t);
  const cs=t.objectStore('convs'), ms=t.objectStore('messages'), os=t.objectStore('outbox'), meta=t.objectStore('meta');
  const previous=meta.get('cursor');
  previous.onsuccess=()=>{
    if(fromSync&&!batch.reset&&previous.result!==undefined&&batch.cursor<previous.result)return;
    if(fromSync&&batch.reset){cs.clear();ms.clear();visible.clear();}
    for(const c of batch.conversations||[]){
      if(c.removed){cs.delete(c.id);const r=ms.index('cid').openCursor(c.id);r.onsuccess=()=>{const cur=r.result;if(cur){cur.delete();cur.continue();}};if(c.id===currentId){visible.clear();currentId=null;}}
      else if(fromSync)cs.put(c);
      else {const r=cs.get(c.id);r.onsuccess=()=>{if(!r.result)cs.put(c);};}
    }
    for(const m of batch.messages||[]){const r=ms.get(m.id);r.onsuccess=()=>{if(!r.result||r.result.version<=m.version)ms.put(m);};if(m.senderId===credentials.user.id)os.delete(m.clientId);}
    if(fromSync&&batch.cursor!==undefined)meta.put(batch.cursor,'cursor');
    if(ack)os.delete(ack);
  };
  await done;
  for(const m of batch.messages||[]){const old=visible.get(m.id);if(old&&m.version>=old.version)visible.set(m.id,m);}
}
function contiguous(rows){const sorted=rows.sort((a,b)=>a.seq-b.seq);let start=0;for(let i=1;i<sorted.length;i++)if(sorted[i].seq!==sorted[i-1].seq+1)start=i;return sorted.slice(start);}
async function readyText(){return (await all('outbox')).some(q=>q.status!=='failed'&&q.nextAt<=Date.now()&&!q.files?.length);}
const yieldUpload=Symbol('yield-upload');
async function enqueue(record){
  const t=db.transaction('outbox','readwrite'),done=transactionDone(t),store=t.objectStore('outbox'),r=store.getAll();let reason='';
  r.onsuccess=()=>{const items=r.result;const size=q=>(q.files||[]).reduce((n,f)=>n+f.blob.size,0);if(items.length>=200)reason='Очередь заполнена: сначала отправьте или удалите старые сообщения';else if(items.reduce((n,q)=>n+size(q),size(record))>100*1024*1024)reason='В очереди уже 100 МБ файлов';if(reason)t.abort();else store.put(record);};
  try{await done;}catch(error){throw new Error(reason||error.message||'Не удалось сохранить очередь');}
}
async function trimCache(cid) { const t=db.transaction('messages','readwrite'),done=transactionDone(t);let count=0;const r=t.objectStore('messages').index('history').openCursor(IDBKeyRange.bound([cid,0],[cid,Number.MAX_SAFE_INTEGER]),'prev');r.onsuccess=()=>{const c=r.result;if(c){if(++count>1000)c.delete();c.continue();}};await done; }

async function rawRequest(path, data, options={}) {
  const controller=new AbortController(), timer=setTimeout(()=>controller.abort(),90000);
  const headers={...(options.headers||{})}; if(options.auth!==false&&credentials)headers.Authorization='Bearer '+credentials.token;
  let body=data; if(data!==undefined && !(data instanceof Blob) && !(data instanceof ArrayBuffer) && !ArrayBuffer.isView(data)){body=JSON.stringify(data);headers['Content-Type']='application/json';payloadBytes+=encoder.encode(body).length;}
  else if(body!==undefined)payloadBytes+=body.size??body.byteLength??0;
  try {
    const response=await fetch(path,{method:options.method||(data===undefined?'GET':'POST'),headers,body,signal:controller.signal,cache:'no-store',credentials:'omit'});
    if(options.blob&&response.ok){const blob=await response.blob();payloadBytes+=blob.size;return blob;}
    const text=await response.text();payloadBytes+=encoder.encode(text).length;let value;try{value=JSON.parse(text);}catch{value={error:'Некорректный ответ сервера'};}
    if(!response.ok){const error=new Error(value.error||'HTTP '+response.status);error.status=response.status;throw error;}
    return value;
  } catch(error) { if(error.name==='AbortError')throw new Error('Сеть отвечает слишком долго. Сообщение осталось в очереди.');throw error; }
  finally {clearTimeout(timer);}
}
async function validateChallenge(challenge, expected) {
  const p=challenge.payload, lines=String(challenge.transcript||'').split('\n');
  if(!p || lines.length!==5 || lines[0]!=='ECHAT-AUTH-1' || lines[1]!==location.origin || lines[2]!==challenge.challengeId || !/^[a-f0-9]{32}$/.test(lines[2]) || !/^[A-Za-z0-9_-]{40,64}$/.test(lines[3]))throw new Error('Сервер вернул запрос подписи для другого контекста');
  for(const [key,value] of Object.entries(expected))if(p[key]!==value)throw new Error('Параметры регистрации изменены сервером: '+key);
  if(challenge.accountId!==p.accountId || 'e_'+(await sha(unb64(p.rootPublicKey))).slice(0,40)!==p.accountId || await sha(unb64(p.devicePublicKey))!==p.deviceId)throw new Error('Идентификатор не соответствует публичному ключу');
  const canonical=JSON.stringify(Object.fromEntries(Object.keys(p).sort().map(k=>[k,p[k]]))).replace(/[\u007f-\uffff]/g,c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0'));
  if(await sha(encoder.encode(canonical))!==lines[4] || challenge.expiresAt<=Date.now() || challenge.expiresAt>Date.now()+180000)throw new Error('Повреждённый или просроченный запрос подписи');
}
async function updateQueued(record) {
  const t=db.transaction('outbox','readwrite'), done=transactionDone(t), s=t.objectStore('outbox'), q=s.get(record.clientId);
  q.onsuccess=()=>{if(q.result)s.put(record);};await done;
}
async function deviceLogin() {
  if(refreshPromise)return refreshPromise;
  refreshPromise=(async()=>{const challenge=await rawRequest('/api/auth/challenge',{mode:'login',accountId:credentials.user.id,devicePublicKey:credentials.devicePublicKey},{auth:false});await validateChallenge(challenge,{mode:'login',accountId:credentials.user.id,devicePublicKey:credentials.devicePublicKey});const signature=b64(await crypto.subtle.sign(SIGN,credentials.privateKey,encoder.encode(challenge.transcript)));const session=await rawRequest('/api/auth/complete',{challengeId:challenge.challengeId,signature},{auth:false});credentials={...credentials,...session};await put('meta',credentials,'credentials',globalDb);})();
  try{await refreshPromise;}finally{refreshPromise=null;}
}
async function api(path,data,options={}) {
  try{return await rawRequest(path,data,options);}catch(error){if(error.status===401 && options.auth!==false && credentials){try{await deviceLogin();}catch(loginError){if(loginError.status===401||loginError.status===403){fatalAuth=true;connection('Нужен повторный вход');toast('Доступ устройства отозван. Откройте настройки и восстановите аккаунт по ключу.');}throw loginError;}return rawRequest(path,data,options);}throw error;}
}
const rpc=(action,data={})=>api('/api/rpc?action='+encodeURIComponent(action),data);

function setAuthMode(mode) {authMode=mode;$('tab-register').classList.toggle('selected',mode==='register');$('tab-recover').classList.toggle('selected',mode==='recover');for(const id of ['name-field','invite-field'])$(id).hidden=mode!=='register';for(const id of ['recovery-field','revoke-field'])$(id).hidden=mode!=='recover';$('display-name').required=mode==='register';$('registration-invite').required=mode==='register';$('auth-submit').textContent=mode==='register'?'Создать ключ':'Восстановить аккаунт';}
async function recoveryKeys(code) {
  const parts=code.trim().split('.'); if(parts.length!==4||parts[0]!=='ECHAT1')throw new Error('Некорректный формат ключа ECHAT1');
  if((await sha(encoder.encode(parts.slice(0,3).join('.')))).slice(0,12)!==parts[3])throw new Error('Ключ повреждён: контрольная сумма не совпадает');
  const privateKey=await crypto.subtle.importKey('pkcs8',unb64(parts[1]),ECDSA,true,['sign']);
  const publicKey=await crypto.subtle.importKey('spki',unb64(parts[2]),ECDSA,true,['verify']);
  const a=await crypto.subtle.exportKey('jwk',privateKey),b=await crypto.subtle.exportKey('jwk',publicKey);
  if(a.x!==b.x||a.y!==b.y)throw new Error('Части ключа не соответствуют друг другу');
  return {privateKey,publicKey};
}
async function enrol(root,mode) {
  const device=await crypto.subtle.generateKey(ECDSA,false,['sign','verify']);
  const devicePublicKey=b64(await crypto.subtle.exportKey('spki',device.publicKey));
  const rootPublicKey=b64(await crypto.subtle.exportKey('spki',root.publicKey));
  const challenge=await rawRequest('/api/auth/challenge',{mode,rootPublicKey,devicePublicKey,name:$('display-name').value||'E-chat',deviceName:$('device-name').value,invite:$('registration-invite').value,revokeOthers:$('revoke-others').checked},{auth:false});
  await validateChallenge(challenge,{mode,rootPublicKey,devicePublicKey,name:($('display-name').value||'E-chat').trim(),deviceName:$('device-name').value.trim(),revokeOthers:$('revoke-others').checked});
  const signature=b64(await crypto.subtle.sign(SIGN,root.privateKey,encoder.encode(challenge.transcript)));
  const session=await rawRequest('/api/auth/complete',{challengeId:challenge.challengeId,signature},{auth:false});
  credentials={...session,privateKey:device.privateKey,devicePublicKey};
  await put('meta',credentials,'credentials',globalDb);
  $('recovery-input').value='';$('registration-invite').value='';closeDialog();await start();
}
function downloadBlob(blob,name) {const url=URL.createObjectURL(blob),a=element('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),60000);}
$('auth-form').onsubmit=async event=>{event.preventDefault();$('auth-submit').disabled=true;try{
  if(!crypto.subtle)throw new Error('Откройте E-chat по HTTPS. Криптография недоступна на обычном HTTP.');
  if(authMode==='recover'){await enrol(await recoveryKeys($('recovery-input').value),'recover');return;}
  const root=await crypto.subtle.generateKey(ECDSA,true,['sign','verify']);
  const base='ECHAT1.'+b64(await crypto.subtle.exportKey('pkcs8',root.privateKey))+'.'+b64(await crypto.subtle.exportKey('spki',root.publicKey));
  const code=base+'.'+(await sha(encoder.encode(base))).slice(0,12),body=dialog('Сохраните ключ восстановления');
  body.append(element('p','','Без него нельзя восстановить аккаунт после потери устройства. Не отправляйте ключ собеседникам: он даёт полный доступ к аккаунту.'));
  const area=element('textarea');area.value=code;area.readOnly=true;area.rows=6;area.spellcheck=false;body.append(area);
  body.append(button('Сохранить ключ в файл',()=>downloadBlob(new Blob(['E-chat recovery key\n\n'+code+'\n\nServer: '+location.origin+'\n'],{type:'text/plain'}),'echat-recovery.txt')));
  const label=element('label','check'),check=element('input');check.type='checkbox';label.append(check,document.createTextNode('Я сохранил ключ в надёжном месте'));body.append(label);
  const confirm=button('Ключ сохранён, зарегистрироваться',async()=>{confirm.disabled=true;try{await enrol(root,'register');}finally{confirm.disabled=!check.checked;}},'primary');confirm.disabled=true;check.onchange=()=>confirm.disabled=!check.checked;body.append(confirm);
}catch(error){showError(error);}finally{$('auth-submit').disabled=false;}};
$('tab-register').onclick=()=>setAuthMode('register');$('tab-recover').onclick=()=>setAuthMode('recover');

async function start() {
  db=await openDb('echat-v1-'+credentials.user.id,1,d=>{d.createObjectStore('meta');d.createObjectStore('convs',{keyPath:'id'});const m=d.createObjectStore('messages',{keyPath:'id'});m.createIndex('cid','cid');m.createIndex('history',['cid','seq']);d.createObjectStore('outbox',{keyPath:'clientId'});});
  $('auth').hidden=true;$('main').hidden=false;running=true;fatalAuth=false;updateEdge();await render();
  syncLoop().catch(showError);
  if(navigator.locks)navigator.locks.request('echat-outbox-'+credentials.user.id,()=>outboxLoop()).catch(showError);else outboxLoop().catch(showError);
  navigator.storage?.persist?.().catch(()=>{});
}
function updateEdge(){ $('edge-toggle').classList.toggle('active',edge);$('edge-toggle').textContent=edge?'E-режим включён':'Обычный режим';localStorage.setItem('echat-edge',String(edge)); }
$('edge-toggle').onclick=()=>{edge=!edge;updateEdge();toast(edge?'Малые пакеты синхронизации и загрузки файлов. Текст отправляется первым.':'Обычный размер пакетов. Файлы по-прежнему не скачиваются автоматически.');};
async function syncLoop(){let failure=0;while(running){if(fatalAuth){await sleep(5000);continue;}if(!navigator.onLine){connection('Нет сети · очередь сохранена');await sleep(2000);continue;}if(document.hidden){await sleep(3000);continue;}try{
  const cursor=await get('meta','cursor');const result=await rpc('sync',{cursor:cursor===undefined?null:cursor,limit:edge?8:50,wait:25});
  await applyBatch(result,null,true);await render();failure=0;connection('На связи');if(result.reset&&currentId)await loadHistory(false);if(result.more)continue;
}catch(error){failure++;connection(error.status===401||error.status===403?'Нужен повторный вход':'Соединяемся · очередь сохранена');await sleep(Math.min(30000,1000*2**Math.min(failure,5))*(.75+Math.random()/2));}}
}
async function render(){
  conversations=(await all('convs')).sort((a,b)=>b.updatedAt-a.updatedAt||a.id.localeCompare(b.id));renderConversations();
  const conv=current();if(!conv){$('empty-state').hidden=false;$('chat-content').hidden=true;return;}
  $('empty-state').hidden=true;$('chat-content').hidden=false;$('chat-title').textContent=conv.title;
  $('chat-subtitle').textContent=conv.kind==='channel'?'Канал · '+conv.memberCount+' участников':conv.kind==='group'?'Группа · '+conv.memberCount+' участников':conv.kind==='saved'?'Личные заметки и файлы':'Личный диалог';
  $('compose').hidden=!conv.canSend;$('readonly').hidden=conv.canSend;$('readonly').textContent=conv.kind==='channel'?'В этом канале публикуют только администраторы.':'Отправка собеседнику недоступна. Проверьте блокировку в меню.';
  const cached=await cachedMessages(currentId);
  for(const m of cached){const old=visible.get(m.id);if((!historyWindow||old)&&(!old||m.version>=old.version))visible.set(m.id,m);}
  if(!historyWindow){const keep=contiguous([...visible.values()]).slice(-1000);visible=new Map(keep.map(m=>[m.id,m]));}
  await renderMessages();
}
function renderConversations(){
  const fragment=document.createDocumentFragment(),filter=$('chat-filter').value.toLocaleLowerCase();
  for(const c of conversations){if(filter&&!c.title.toLocaleLowerCase().includes(filter))continue;const row=button('',()=>openConversation(c.id),'conv-row'+(c.id===currentId?' current':''));row.setAttribute('role','listitem');row.dataset.cid=c.id;
    const icon=c.kind==='saved'?'☆':c.kind==='channel'?'◉':c.kind==='group'?'#':c.title.slice(0,1).toLocaleUpperCase();
    row.append(element('span','avatar',icon));const info=element('div','conv-text');info.append(element('strong','',c.title),element('small','',c.lastText||'Нет сообщений'));row.append(info);if(c.unread)row.append(element('span','badge',c.unread>99?'99+':String(c.unread)));fragment.append(row);
  }$('conversation-list').replaceChildren(fragment);
}
$('chat-filter').oninput=renderConversations;
async function openConversation(cid){
  if(currentId)await saveDraft();currentId=cid;visible.clear();historyWindow=false;replyTo=null;editing=null;chosenFiles=[];updateContext();renderFiles();$('main').classList.add('chat-open');
  $('message-input').value=(await get('meta','draft:'+cid))||'';for(const m of contiguous(await cachedMessages(cid)))visible.set(m.id,m);
  moreHistory=true;await render();scrollBottom();await loadHistory(false);scrollBottom();
}
async function loadHistory(older){if(!currentId||loadingHistory)return;loadingHistory=true;const cid=currentId;try{const request={cid,limit:edge?20:50};if(older){const seqs=[...visible.values()].filter(m=>m.cid===cid).map(m=>m.seq);if(seqs.length)request.beforeSeq=Math.min(...seqs);}
 const result=await rpc('history',request);await applyBatch({conversations:[result.conversation],messages:result.messages});if(cid===currentId){moreHistory=result.more;if(!older){visible.clear();historyWindow=false;}for(const m of result.messages)visible.set(m.id,m);let rows=[...visible.values()].sort((a,b)=>a.seq-b.seq);if(rows.length>1000){rows=older?rows.slice(0,1000):rows.slice(-1000);historyWindow=older;visible=new Map(rows.map(m=>[m.id,m]));}await renderMessages();}await trimCache(cid);
}catch(error){if(error.status===403||error.status===404)showError(error);else connection('Показан локальный кэш');}finally{loadingHistory=false;}}
$('older').onclick=()=>loadHistory(true);$('back').onclick=()=>{$('main').classList.remove('chat-open');saveDraft().catch(showError);};
function scrollBottom(){const list=$('message-list');list.scrollTop=list.scrollHeight;$('jump-bottom').hidden=true;markReadSoon();}
$('jump-bottom').onclick=async()=>{if(historyWindow){historyWindow=false;visible.clear();await loadHistory(false);await render();}scrollBottom();};
$('message-list').onscroll=()=>{$('jump-bottom').hidden=nearBottom()&&!historyWindow;if(nearBottom())markReadSoon();};
async function renderMessages(){
 const cid=currentId;if(!cid)return;const list=$('message-list'),atBottom=nearBottom(),oldHeight=list.scrollHeight,oldTop=list.scrollTop;
 const first=[...$('messages').children].find(node=>node.getBoundingClientRect().bottom>list.getBoundingClientRect().top),anchor=first?.dataset.mid,anchorOffset=first?first.getBoundingClientRect().top-list.getBoundingClientRect().top:0;
 const actual=[...visible.values()].filter(m=>m.cid===cid).sort((a,b)=>a.seq-b.seq),queued=(await all('outbox')).filter(m=>m.cid===cid).sort((a,b)=>a.createdAt-b.createdAt);
 const nodes=document.createDocumentFragment();for(const m of actual)nodes.append(messageNode(m,false));for(const q of queued)if(!actual.some(m=>m.clientId===q.clientId&&m.senderId===credentials.user.id))nodes.append(messageNode({...q,id:'pending:'+q.clientId,senderId:credentials.user.id,senderName:credentials.user.name,attachments:[]},true));
 if(cid!==currentId)return;$('messages').replaceChildren(nodes);$('older').hidden=!moreHistory;
 if(atBottom)list.scrollTop=list.scrollHeight;else{const n=anchor?[...$('messages').children].find(node=>node.dataset.mid===anchor):null;if(n)list.scrollTop+=n.getBoundingClientRect().top-list.getBoundingClientRect().top-anchorOffset;else list.scrollTop=oldTop+(list.scrollHeight-oldHeight);}
 $('jump-bottom').hidden=nearBottom()&&!historyWindow;markReadSoon();
}
function messageNode(m,pending){
 const own=m.senderId===credentials.user.id,row=element('article','msg'+(own?' own':'')+(pending?' pending':'')+(m.deleted?' deleted':''));row.dataset.mid=m.id;
 const bubble=element('div','bubble');if(!own)bubble.append(element('div','sender',m.senderName));
 if(m.replyTo){const replied=visible.get(m.replyTo);bubble.append(element('div','reply',replied?(replied.deleted?'Сообщение удалено':replied.body||'[Файл]'):'Ответ на сообщение'));}
 bubble.append(element('div','msg-body',m.deleted?'Сообщение удалено':m.body||''));
 for(const file of m.attachments||[])bubble.append(button('↓ '+file.name+' · '+bytes(file.size),async()=>{const blob=await api('/api/files/'+file.id,undefined,{blob:true});if(await sha(await blob.arrayBuffer())!==file.sha256)throw new Error('Контрольная сумма файла не совпадает');downloadBlob(blob,file.name);},'attachment'));
 if(pending&&m.files?.length)bubble.append(element('div','small','Файлы в очереди: '+m.files.length));
 const meta=element('div','msg-meta'),time=new Date(m.createdAt).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'});meta.append(element('span','',time+(m.edited?' · изм.':'')));
 if(own){let status=pending?(m.status==='failed'?'Ошибка · нажмите ⋮':'В очереди'):(current()?.peerReadSeq>=m.seq?'✓✓':'✓');meta.append(element('span',m.status==='failed'?'failed':'',status));}
 meta.append(button('⋮',()=>messageMenu(m,pending),'msg-action'));bubble.append(meta);row.append(bubble);return row;
}
function markReadSoon(){clearTimeout(readTimer);if(document.hidden||!currentId||!nearBottom())return;const cid=currentId;const max=Math.max(0,...[...visible.values()].filter(m=>m.cid===cid).map(m=>m.seq));if(!max||max<=(lastRead.get(cid)||current()?.readSeq||0))return;readTimer=setTimeout(async()=>{if(document.hidden||currentId!==cid||!nearBottom())return;try{await rpc('read',{cid,seq:max});lastRead.set(cid,max);}catch{/* Retry only after visibility/next sync; no misleading read receipt. */}},600);}
function messageMenu(m,pending){const body=dialog(pending?'Очередь отправки':'Сообщение');if(pending){body.append(element('p','',m.error||'Сообщение хранится на этом устройстве и будет отправлено после восстановления связи.'));body.append(button('Повторить',async()=>{const q=await get('outbox',m.clientId);if(q){q.status='queued';q.nextAt=0;q.error='';await put('outbox',q);}closeDialog();await renderMessages();},'block-button'));body.append(button('Удалить из очереди',async()=>{if(sending)throw new Error('Дождитесь окончания текущей попытки отправки');await remove('outbox',m.clientId);closeDialog();await renderMessages();},'block-button'));return;}
 if(!m.deleted){body.append(button('Ответить',()=>{replyTo=m.id;editing=null;updateContext();closeDialog();$('message-input').focus();},'block-button'));body.append(button('Копировать текст',async()=>{await navigator.clipboard.writeText(m.body);toast('Скопировано');closeDialog();},'block-button'));}
 if(m.senderId===credentials.user.id&&!m.deleted)body.append(button('Редактировать',()=>{editing=m.id;replyTo=null;$('message-input').value=m.body;updateContext();closeDialog();$('message-input').focus();},'block-button'));
 if(!m.deleted&&(m.senderId===credentials.user.id||['owner','admin'].includes(current()?.role)))body.append(button('Удалить для всех',async()=>{if(!confirm('Удалить сообщение у всех участников?'))return;await rpc('delete',{cid:m.cid,messageId:m.id});closeDialog();},'block-button'));
}
function updateContext(){$('compose-context').hidden=!replyTo&&!editing;$('context-text').textContent=editing?'Редактирование сообщения':replyTo?'Ответ: '+(visible.get(replyTo)?.body||'[Файл]'):'';}
$('cancel-context').onclick=()=>{replyTo=null;editing=null;updateContext();};
async function saveDraft(){if(currentId&&!editing)await put('meta',$('message-input').value,'draft:'+currentId);}
$('message-input').oninput=()=>{clearTimeout(draftTimer);draftTimer=setTimeout(()=>saveDraft().catch(showError),250);};
$('message-input').onkeydown=e=>{if(e.key==='Enter'&&!e.shiftKey&&!e.isComposing){e.preventDefault();$('compose').requestSubmit();}};
function renderFiles(){const n=$('file-preview');n.replaceChildren();n.hidden=!chosenFiles.length;chosenFiles.forEach((file,i)=>n.append(button(file.name+' · '+bytes(file.size)+' ×',()=>{chosenFiles.splice(i,1);renderFiles();})));}
$('attach').onclick=()=>$('files').click();$('files').onchange=()=>{const files=[...$('files').files];$('files').value='';if(files.some(f=>f.size>10*1024*1024||!f.size)||files.length+chosenFiles.length>4){toast('До 4 файлов, каждый от 1 байта до 10 МБ.');return;}chosenFiles.push(...files);renderFiles();};
$('compose').onsubmit=async event=>{event.preventDefault();if(!currentId||!current()?.canSend)return;const body=$('message-input').value.trim();if(!body&&!chosenFiles.length)return;$('send').disabled=true;try{
 if(editing){await rpc('edit',{cid:currentId,messageId:editing,body});editing=null;}else{
  const record={clientId:uuid(),cid:currentId,body,replyTo,createdAt:Date.now(),status:'queued',attempt:0,nextAt:0,files:chosenFiles.map(f=>({blob:f,name:f.name,mime:f.type||'application/octet-stream',clientId:uuid()}))};
  await enqueue(record); // Durable commit BEFORE clearing input or showing it as accepted.
 }
 $('message-input').value='';replyTo=null;chosenFiles=[];updateContext();renderFiles();await saveDraft();await renderMessages();scrollBottom();
}catch(error){showError(error);}finally{$('send').disabled=false;}};
async function uploadFile(record,file){
 if(!file.sha256){file.sha256=await sha(await file.blob.arrayBuffer());await updateQueued(record);}
 if(!file.uploadId){const info=await api('/api/uploads',{cid:record.cid,clientId:file.clientId,name:file.name,mime:file.mime,total:file.blob.size,sha256:file.sha256});file.uploadId=info.id;await updateQueued(record);}
 let info=await api('/api/uploads/'+file.uploadId);while(!info.ready){const chunk=file.blob.slice(info.offset,Math.min(file.blob.size,info.offset+(edge?32768:262144)));info=await api('/api/uploads/'+file.uploadId+'?offset='+info.offset,chunk,{method:'PUT',headers:{'Content-Type':'application/octet-stream'}});file.offset=info.offset;await updateQueued(record);if(await readyText())throw yieldUpload;}
 return file.uploadId;
}
async function outboxLoop(){while(running){if(!navigator.onLine||fatalAuth){await sleep(1500);continue;}const records=(await all('outbox')).filter(q=>q.status!=='failed'&&q.nextAt<=Date.now()).sort((a,b)=>(a.files?.length?1:0)-(b.files?.length?1:0)||a.createdAt-b.createdAt);const q=records[0];if(!q){await sleep(600);continue;}sending=true;try{
 const attachmentIds=[];for(const file of q.files||[])attachmentIds.push(await uploadFile(q,file));
 const result=await rpc('send',{cid:q.cid,clientId:q.clientId,body:q.body,replyTo:q.replyTo,attachmentIds});await applyBatch({messages:[result.message]},q.clientId);await render();
}catch(error){if(error===yieldUpload)continue;q.attempt=(q.attempt||0)+1;q.error=error.message;q.status=[400,403,404,413,422].includes(error.status)?'failed':'queued';q.nextAt=Date.now()+Math.min(60000,1000*2**Math.min(q.attempt,6))*(.75+Math.random()/2);await updateQueued(q);if(q.status==='failed')toast('Сообщение не отправлено: '+error.message);await renderMessages();}finally{sending=false;}await sleep(100);}}

function inputDialog(title,label,submit,initial=''){const body=dialog(title),input=element('input');input.value=initial;input.placeholder=label;input.setAttribute('aria-label',label);body.append(input);const send=button('Продолжить',async()=>{send.disabled=true;try{await submit(input.value.trim());}finally{send.disabled=false;}},'primary');body.append(element('div','row')).append(send);setTimeout(()=>input.focus(),50);return body;}
$('new-direct').onclick=()=>inputDialog('Новый личный чат','ID собеседника: e_…',async peerId=>{const result=await rpc('create',{kind:'direct',clientId:uuid(),peerId});await applyBatch({conversations:[result.conversation]});closeDialog();await render();await openConversation(result.conversation.id);});
$('new-space').onclick=()=>{const body=dialog('Создать или присоединиться');for(const [kind,label]of[['group','Создать группу'],['channel','Создать канал']])body.append(button(label,()=>inputDialog(label,'Название',async title=>{const result=await rpc('create',{kind,title,clientId:uuid()});await applyBatch({conversations:[result.conversation]});closeDialog();await render();await openConversation(result.conversation.id);}), 'block-button'));body.append(button('Войти по приглашению',()=>inputDialog('Приглашение','Вставьте код приглашения',async invite=>{const result=await rpc('join',{invite});await applyBatch({conversations:[result.conversation]});closeDialog();await render();await openConversation(result.conversation.id);}), 'block-button'));};
$('settings').onclick=()=>{const body=dialog('Аккаунт E-chat');body.append(element('p','',credentials.user.name),codeBlock(credentials.user.id));body.append(button('Копировать ID',async()=>{await navigator.clipboard.writeText(credentials.user.id);toast('ID скопирован');},'block-button'));body.append(button('Мои устройства',devicesDialog,'block-button'));body.append(element('p','','За эту вкладку обработано '+bytes(payloadBytes)+' полезных данных. Это не счётчик оператора: TLS, заголовки и ресурсы приложения не включены.'));body.append(element('p','','Файлы не загружаются автоматически. Локальная очередь хранится в этом браузере. Не очищайте данные сайта до отправки. Фоновые push-уведомления в этом пилоте не реализованы.'));
 body.append(button('Выйти на этом браузере / восстановить ключ',async()=>{if(!confirm('Ключ восстановления сохранён? После выхода он потребуется для повторного входа. Локальные сообщения и очередь останутся в браузере. Это локальный выход: для отзыва доступа на сервере используйте «Мои устройства».'))return;running=false;await remove('meta','credentials',globalDb);location.reload();},'block-button'));
};
async function devicesDialog(){const result=await api('/api/auth/devices');const body=dialog('Мои устройства');for(const d of result.devices){const row=element('div','member');row.append(element('strong','',d.name+(d.current?' · это устройство':'')),element('small','',d.revoked?'Доступ отозван':new Date(d.createdAt).toLocaleString('ru-RU')));if(!d.revoked)row.append(button('Отозвать доступ',async()=>{if(!confirm('Отозвать сессии этого устройства?'))return;await api('/api/auth/revoke',{deviceId:d.id});if(d.current){running=false;await remove('meta','credentials',globalDb);location.reload();}else await devicesDialog();}));body.append(row);} }
$('chat-menu').onclick=()=>{const c=current();if(!c)return;const body=dialog(c.title);body.append(button(c.muted?'Включить уведомления':'Выключить уведомления',async()=>{await rpc('mute',{cid:c.id,muted:!c.muted});closeDialog();},'block-button'));body.append(element('p','','В этом пилоте режим уведомлений сохраняется для будущего push-клиента; системных фоновых уведомлений пока нет.'));
 if(c.kind==='direct'){body.append(codeBlock(c.peerId));body.append(button('Заблокировать собеседника',async()=>{await rpc('block',{peerId:c.peerId,blocked:true});closeDialog();},'block-button'));body.append(button('Разблокировать собеседника',async()=>{await rpc('block',{peerId:c.peerId,blocked:false});closeDialog();},'block-button'));}
 if(['group','channel'].includes(c.kind)){body.append(button('Участники и права',()=>membersDialog(c),'block-button'));if(['owner','admin'].includes(c.role)){body.append(button('Добавить участника по ID',()=>inputDialog('Добавить участника','e_…',async userId=>{await rpc('member',{cid:c.id,userId,op:'add'});closeDialog();}),'block-button'));body.append(button('Новое приглашение',async()=>{const invite=await rpc('invite',{cid:c.id});const b=dialog('Приглашение на 24 часа');b.append(element('p','','До 100 вступлений. Предыдущий код приглашения отозван.'),codeBlock(invite.invite),button('Копировать',async()=>{await navigator.clipboard.writeText(invite.invite);toast('Скопировано');}));},'block-button'));}body.append(button('Покинуть диалог',async()=>{if(!confirm('Покинуть диалог? Владелец сначала должен передать права.'))return;await rpc('member',{cid:c.id,userId:credentials.user.id,op:'remove'});closeDialog();},'block-button'));}
};
async function membersDialog(c){const result=await rpc('members',{cid:c.id}),body=dialog('Участники');for(const m of result.members){const row=element('div','member');row.append(element('strong','',m.name+' · '+m.role),element('small','',m.id));if(m.id!==credentials.user.id&&m.role!=='owner'&&['owner','admin'].includes(c.role)){row.append(button('Удалить',async()=>{if(!confirm('Удалить участника?'))return;await rpc('member',{cid:c.id,userId:m.id,op:'remove'});await membersDialog(c);}));if(c.role==='owner'){row.append(button(m.role==='admin'?'Снять администратора':'Назначить администратором',async()=>{await rpc('member',{cid:c.id,userId:m.id,op:m.role==='admin'?'demote':'promote'});await membersDialog(c);}));row.append(button('Передать владение',async()=>{if(!confirm('Вы потеряете права владельца. Продолжить?'))return;await rpc('member',{cid:c.id,userId:m.id,op:'transfer'});closeDialog();}));}}body.append(row);}}
$('search').onclick=()=>{const cid=currentId;if(!cid)return;inputDialog('Поиск в диалоге','Текст сообщения',async query=>{let before;const body=dialog('Результаты поиска'),results=element('div');body.append(results);const next=button('Искать дальше',async()=>{next.disabled=true;try{const data={cid,query};if(before)data.beforeSeq=before;const result=await rpc('search',data);for(const m of result.messages)results.append(button(m.senderName+': '+m.body,async()=>{visible.set(m.id,m);closeDialog();await renderMessages();const n=[...$('messages').children].find(e=>e.dataset.mid===m.id);n?.scrollIntoView({block:'center'});},'block-button'));before=result.nextBefore;next.hidden=!result.more;if(!result.messages.length)results.append(element('p','','В просмотренном блоке совпадений нет.'));}finally{next.disabled=false;}});body.append(next);next.click();});};
window.addEventListener('online',()=>connection('Восстанавливаем связь…'));
window.addEventListener('offline',()=>connection('Нет сети · очередь сохранена'));
document.addEventListener('visibilitychange',()=>{if(!document.hidden)markReadSoon();else saveDraft().catch(()=>{});});
(async()=>{try{globalDb=await openDb('echat-identity-v1',1,d=>d.createObjectStore('meta'));credentials=await get('meta','credentials',globalDb);if('serviceWorker'in navigator)navigator.serviceWorker.register('/sw.js').catch(()=>{});if(credentials)await start();}catch(error){showError(error);}})();