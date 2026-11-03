'use strict';
// Compact authenticated-shell notifications. The API remains authoritative for
// permission filtering, unread counts and per-user revision state.
window.NotificationShell=(()=>{
 const POLL_MS=30000, severityRank={info:0,low:1,medium:2,high:3,critical:4};
 let generation=0,requestRevision=0,timer=0,items=[],open=false,started=false;
 const centerContext={offset:0,unreadOnly:false,includeDismissed:false,severity:'',source:'',hostId:''};
 const node=id=>document.getElementById(id);
 const button=()=>node('notification-button'),panel=()=>node('notification-panel');
 const status=message=>{const target=node('notification-status');if(target.textContent!==message)target.textContent=message;};
 function safeLink(value){
  if(typeof value!=='string'||!value||value.includes('\\')||(!value.startsWith('/')&&!value.startsWith('#'))||value.startsWith('//'))return '';
  try{const parsed=new URL(value,location.href);return parsed.origin===location.origin?parsed.pathname+parsed.search+parsed.hash:'';}catch{return '';}
 }
 function countLabel(unread,severity){
  if(!Number.isInteger(unread)||unread<0)return 'Notifications, unread count unavailable';
  const count=unread===1?'1 unread':`${unread} unread`;
  return `Notifications, ${count}${severity?`, highest severity ${severity}`:''}`;
 }
 function setCount(unread,currentItems=items){
  const badge=node('notification-badge'),control=button();
  if(!Number.isInteger(unread)||unread<0){badge.hidden=true;badge.textContent='0';delete control.dataset.severity;control.setAttribute('aria-label',countLabel(null));return;}
  const severity=currentItems.filter(item=>!item.read&&!item.dismissed).map(item=>item.severity).filter(level=>level in severityRank).sort((a,b)=>severityRank[b]-severityRank[a])[0]||'';
  badge.hidden=unread===0;badge.textContent=unread>99?'99+':String(unread);
  if(severity)control.dataset.severity=severity;else delete control.dataset.severity;
  control.setAttribute('aria-label',countLabel(unread,severity));
 }
 function element(tag,className,text){const result=document.createElement(tag);if(className)result.className=className;if(text!==undefined)result.textContent=String(text);return result;}
 function readableSource(value){return String(value||'notification').replace(/[._-]+/g,' ');}
 function render(){
  const list=node('notification-list');list.replaceChildren();
  if(!items.length){const empty=element('div','notification-empty');empty.append(element('strong','', 'All caught up.'),element('p','help','No current notifications are available for your account.'));list.append(empty);return;}
  for(const item of items){
   const article=element('article','notification-item'+(item.read?' is-read':''));article.dataset.severity=item.severity||'info';
   const meta=element('div','notification-meta');meta.append(element('span','notification-severity',item.severity||'info'),element('span','',readableSource(item.source)));
   if(item.host_id)meta.append(element('span','','server '+item.host_id));
   if(item.lifecycle==='resolved')meta.append(element('span','notification-resolved','resolved'));
   const stamp=element('time','',Number.isFinite(item.created)?new Date(item.created*1000).toLocaleString():'Time unavailable');if(Number.isFinite(item.created))stamp.dateTime=new Date(item.created*1000).toISOString();meta.append(stamp);
   const reason=element('p','notification-reason',item.reason||'Reason unavailable');
   const actions=element('div','notification-actions'),link=safeLink(item.deep_link);
   if(link){const anchor=element('a','button','Open');anchor.href=link;anchor.addEventListener('click',()=>close());actions.append(anchor);}
   if(!item.read){const read=element('button','quiet','Mark read');read.type='button';read.addEventListener('click',()=>mutate(item,'read',read));actions.append(read);}
   const dismiss=element('button','quiet','Dismiss');dismiss.type='button';dismiss.addEventListener('click',()=>mutate(item,'dismiss',dismiss));actions.append(dismiss);
   article.append(meta,reason,actions);list.append(article);
  }
 }
 function schedule(run=generation){clearTimeout(timer);if(!started||document.hidden)return;timer=setTimeout(()=>{if(run===generation)refresh();},POLL_MS);}
 async function refresh(){
  if(!started||document.hidden)return;
  const run=generation,request=++requestRevision;
  try{
   const [count,page]=await Promise.all([api('/notifications/unread-count'),api('/notifications?limit=8')]);
   if(run!==generation||request!==requestRevision)return;
   items=Array.isArray(page.items)?page.items.slice(0,8):[];setCount(count.unread,items);render();
   status(page.more?'Showing the 8 most recent notifications. More remain available through the API.':`${page.total||0} recent notification${page.total===1?'':'s'}.`);
  }catch(error){
   if(run!==generation||request!==requestRevision)return;
   setCount(null);status('Notification updates are temporarily delayed. '+error.message);
  }finally{if(run===generation)schedule(run);}
 }
 async function mutate(item,action,control){
  const run=generation;
  requestRevision++;
  control.disabled=true;
  try{
   await api(`/notifications/${encodeURIComponent(item.id)}/${action}`,'POST',{revision:item.revision});
   if(run!==generation||!started)return;
   if(action==='dismiss')items=items.filter(candidate=>candidate!==item);else item.read=true;
   render();
   status(action==='dismiss'?'Notification dismissed for your account.':'Notification marked read for your account.');
   const count=await api('/notifications/unread-count');
   if(run!==generation||!started)return;
   setCount(count.unread,items);
   if(location.hash==='#notifications')await center(renderRevision);
  }catch(error){if(run===generation&&started){status(error.message);if(control.isConnected)control.disabled=false;}}
 }
 function close({focus=false}={}){open=false;panel().hidden=true;button().setAttribute('aria-expanded','false');if(focus)button().focus();}
 function toggle(){
  if(open){close();return;}
  open=true;panel().hidden=false;button().setAttribute('aria-expanded','true');refresh();
 }
 function reset(){
  generation++;requestRevision++;started=false;clearTimeout(timer);timer=0;items=[];open=false;
  panel().hidden=true;button().setAttribute('aria-expanded','false');setCount(null,[]);
  status('');node('notification-list').replaceChildren();Object.assign(centerContext,{offset:0,unreadOnly:false,includeDismissed:false,severity:'',source:'',hostId:''});
 }
 function start(){generation++;requestRevision++;started=true;clearTimeout(timer);refresh();}
 button().addEventListener('click',toggle);node('notification-close').addEventListener('click',()=>close({focus:true}));node('notification-panel').querySelector('.notification-center-link').addEventListener('click',()=>close());
 document.addEventListener('click',event=>{if(open&&!event.target.closest('.notification-shell'))close();});
 document.addEventListener('keydown',event=>{if(open&&event.key==='Escape'){close({focus:true});event.preventDefault();}});
 document.addEventListener('visibilitychange',()=>{if(document.hidden)clearTimeout(timer);else if(started)refresh();});
 function query(){
  const params=new URLSearchParams({limit:'25',offset:String(centerContext.offset)});
  if(centerContext.unreadOnly)params.set('unread_only','true');
  if(centerContext.includeDismissed)params.set('include_dismissed','true');
  for(const [key,value] of [['severity',centerContext.severity],['source',centerContext.source],['host_id',centerContext.hostId]])if(value)params.set(key,value);
  return params;
 }
 function centerItem(item){
  const article=element('article','card notification-center-item'+(item.read?' is-read':''));article.dataset.severity=item.severity||'info';
  const meta=element('div','notification-meta');meta.append(element('span','notification-severity',item.severity||'info'),element('span','',readableSource(item.source)));
  if(item.host_id)meta.append(element('span','',hostName(item.host_id)));
  if(item.lifecycle==='resolved')meta.append(element('span','notification-resolved','resolved'));
  const stamp=element('time','',Number.isFinite(item.created)?new Date(item.created*1000).toLocaleString():'Time unavailable');if(Number.isFinite(item.created))stamp.dateTime=new Date(item.created*1000).toISOString();meta.append(stamp);
  const reason=element('p','notification-reason',item.reason||'Reason unavailable'),actions=element('div','notification-actions'),link=safeLink(item.deep_link);
  if(link){const anchor=element('a','button','Open subject');anchor.href=link;actions.append(anchor);}
  if(!item.read&&!item.dismissed){const read=element('button','quiet','Mark read');read.type='button';read.addEventListener('click',()=>centerMutate(item,'read',read));actions.append(read);}
  if(!item.dismissed){const dismiss=element('button','quiet','Dismiss');dismiss.type='button';dismiss.addEventListener('click',()=>centerMutate(item,'dismiss',dismiss));actions.append(dismiss);}
  article.append(meta,reason,actions);return article;
 }
 async function centerMutate(item,action,control){
  control.disabled=true;
  try{await api(`/notifications/${encodeURIComponent(item.id)}/${action}`,'POST',{revision:item.revision});await refresh();if(location.hash==='#notifications')await center(renderRevision);}
  catch(error){if(control.isConnected)control.disabled=false;toast(error.message);}
 }
 async function center(revision=renderRevision){
  const root=node('content'),page=await api('/notifications?'+query());
  if(!currentView(revision,'notifications')||!root.isConnected)return;
  const hostOptions=hosts.map(host=>`<option value="${esc(host.id)}" ${centerContext.hostId===host.id?'selected':''}>${esc(host.name)}</option>`).join('');
  root.innerHTML=PatchyUI.heading('Your notification history.','Permission-filtered attention and recovery notes, kept separate from operational acknowledgement.')+`<section class="card notification-center-controls"><form id="notification-filters"><div class="form-grid"><label>Severity<select name="severity"><option value="">All severities</option>${['critical','high','medium','low','info'].map(value=>`<option value="${value}" ${centerContext.severity===value?'selected':''}>${value}</option>`).join('')}</select></label><label>Source<input name="source" value="${esc(centerContext.source)}" maxlength="40" pattern="[a-z0-9][a-z0-9_.-]*" placeholder="All sources"></label><label>Server<select name="host_id"><option value="">All servers</option>${hostOptions}</select></label></div><div class="actions"><label class="check"><input name="unread_only" type="checkbox" ${centerContext.unreadOnly?'checked':''}>Unread only</label><label class="check"><input name="include_dismissed" type="checkbox" ${centerContext.includeDismissed?'checked':''}>Include dismissed</label><button type="submit">Apply filters</button><button type="button" class="quiet" id="notification-filters-clear">Clear</button></div></form><p class="help">Read and dismiss affect only your account. They never acknowledge an alert, resolve an incident, approve AI work or run remediation.</p></section><section id="notification-center-list" aria-label="Notification history"></section><div class="actions notification-center-pages"><button id="notification-center-prev" ${page.offset?'':'disabled'}>Previous</button><span class="help">${page.total?`${page.offset+1}–${Math.min(page.offset+page.items.length,page.total)} of ${page.total}`:'0 notifications'}</span><button id="notification-center-next" ${page.more?'':'disabled'}>Next</button></div><p class="help notification-center-coverage">This view catches up through the current polling fallback. Authenticated server push/replay, live toasts and cross-tab/cross-controller delivery remain planned.</p>`;
  const list=node('notification-center-list');
  if(page.items.length)for(const item of page.items)list.append(centerItem(item));else{const empty=element('div','card notification-empty');empty.append(element('strong','','No matching notifications.'),element('p','help','Adjust the filters or wait for a new event visible to your account.'));list.append(empty);}
  node('notification-filters').onsubmit=event=>{event.preventDefault();const form=new FormData(event.currentTarget);Object.assign(centerContext,{offset:0,severity:String(form.get('severity')||''),source:String(form.get('source')||'').trim(),hostId:String(form.get('host_id')||''),unreadOnly:form.has('unread_only'),includeDismissed:form.has('include_dismissed')});center(revision).catch(error=>toast(error.message));};
  node('notification-filters-clear').onclick=()=>{Object.assign(centerContext,{offset:0,unreadOnly:false,includeDismissed:false,severity:'',source:'',hostId:''});center(revision).catch(error=>toast(error.message));};
  node('notification-center-prev').onclick=()=>{centerContext.offset=Math.max(0,centerContext.offset-25);center(revision).catch(error=>toast(error.message));};
  node('notification-center-next').onclick=()=>{centerContext.offset+=25;center(revision).catch(error=>toast(error.message));};
 }
 return {start,reset,refresh,center};
})();
window.notificationCenter=(revision)=>window.NotificationShell.center(revision);
