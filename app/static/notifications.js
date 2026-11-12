'use strict';
// Compact authenticated-shell notifications. The API remains authoritative for
// permission filtering, unread counts and per-user revision state.
window.NotificationShell=(()=>{
 const POLL_MS=30000, severityRank={info:0,low:1,medium:2,high:3,critical:4};
 let generation=0,requestRevision=0,centerRequestRevision=0,timer=0,items=[],open=false,started=false,stream=null;
 // Delivery-path state only: a live stream says nothing about collector, agent or AI health.
 let liveState='',lastSync=0,syncDelayed=false,streamRetryAt=0,streamRetryDelay=0;
 const STREAM_RETRY_MIN_MS=POLL_MS,STREAM_RETRY_MAX_MS=600000;
 const liveLabels={connecting:'Connecting',live:'Live',reconnecting:'Reconnecting',unavailable:'Unavailable, polling only',polling:'Polling only'};
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
 function syncNode(){
  let target=node('notification-sync');if(target)return target;
  const anchor=panel().querySelector('.notification-coverage');if(!anchor)return null;
  target=element('p','notification-sync help');target.id='notification-sync';
  target.append(element('span','notification-sync-state'),element('span','notification-sync-time'),element('span','notification-sync-note','Shows notification delivery only, not collector, agent or AI health.'));
  anchor.before(target);return target;
 }
 function renderSync(){
  const target=syncNode();if(!target)return;
  const state=syncDelayed?'delayed':(liveState||'');
  target.dataset.state=state||'idle';
  const label=syncDelayed?`Delayed${liveState?` (${(liveLabels[liveState]||liveState).toLowerCase()})`:''}`:(liveLabels[liveState]||'Not started');
  const [stateText,timeText]=target.children;
  stateText.textContent=`Live updates: ${label}. `;
  if(lastSync){const when=new Date(lastSync);timeText.textContent=`Last synchronized ${when.toLocaleTimeString()}. `;timeText.title=when.toISOString();}
  else{timeText.textContent='Not yet synchronized. ';timeText.removeAttribute('title');}
 }
 function setLive(state){if(liveState!==state){liveState=state;renderSync();}}
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
 function connect(run){
  if(typeof EventSource!=='function'){setLive('polling');return;}
  setLive('connecting');
  if(stream)stream.close();
  const current=new EventSource('/api/notifications/stream');stream=current;
  current.onopen=()=>{if(stream===current&&run===generation&&started){streamRetryDelay=0;streamRetryAt=0;setLive('live');}};
  current.addEventListener('notifications',()=>{if(stream===current&&run===generation&&started){setLive('live');refresh();}});
  current.addEventListener('close',()=>{if(stream!==current||run!==generation)return;current.close();stream=null;if(typeof showLogin==='function')showLogin();else reset();});
  current.onerror=()=>{
   if(stream!==current||run!==generation||!started)return;
   // A non-200 stream response (for example 429 at stream capacity, or a proxy 502/503) fails the
   // EventSource permanently: the browser will not reconnect, so do not claim it is reconnecting.
   if(current.readyState===2){
    current.close();stream=null;
    streamRetryDelay=Math.min(STREAM_RETRY_MAX_MS,Math.max(STREAM_RETRY_MIN_MS,streamRetryDelay*2));streamRetryAt=Date.now()+streamRetryDelay;
    setLive('unavailable');if(open)status('Live updates are unavailable. The 30-second catch-up remains active.');return;
   }
   setLive('reconnecting');if(open)status('Live updates are reconnecting. The 30-second catch-up remains active.');
  };
 }
 async function refresh(){
  if(!started||document.hidden)return;
  const run=generation,request=++requestRevision;
  try{
   const [count,page]=await Promise.all([api('/notifications/unread-count'),api('/notifications?limit=8')]);
   if(run!==generation||request!==requestRevision)return;
   items=Array.isArray(page.items)?page.items.slice(0,8):[];setCount(count.unread,items);render();
   lastSync=Date.now();syncDelayed=false;renderSync();
   // Bounded retry of a refused stream, only after an authoritative refresh succeeds.
   if(!stream&&liveState==='unavailable'&&Date.now()>=streamRetryAt)connect(run);
   status(page.more?'Showing the 8 most recent notifications. More remain available through the API.':`${page.total||0} recent notification${page.total===1?'':'s'}.`);
   if(location.hash==='#notifications')await refreshCenterList(renderRevision);
  }catch(error){
   if(run!==generation||request!==requestRevision)return;
   setCount(null);syncDelayed=true;renderSync();status('Notification updates are temporarily delayed. '+error.message);
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
   if(location.hash==='#notifications')await refreshCenterList(renderRevision);
  }catch(error){if(run===generation&&started){status(error.message);if(control.isConnected)control.disabled=false;}}
 }
 function close({focus=false}={}){open=false;panel().hidden=true;button().setAttribute('aria-expanded','false');if(focus)button().focus();}
 function toggle(){
  if(open){close();return;}
  open=true;panel().hidden=false;button().setAttribute('aria-expanded','true');refresh();
 }
 function reset(){
  generation++;requestRevision++;centerRequestRevision++;started=false;clearTimeout(timer);timer=0;items=[];open=false;
  if(stream){stream.close();stream=null;}
  panel().hidden=true;button().setAttribute('aria-expanded','false');setCount(null,[]);
  liveState='';lastSync=0;syncDelayed=false;streamRetryAt=0;streamRetryDelay=0;renderSync();
  status('');node('notification-list').replaceChildren();Object.assign(centerContext,{offset:0,unreadOnly:false,includeDismissed:false,severity:'',source:'',hostId:''});
 }
 function start(){generation++;requestRevision++;started=true;clearTimeout(timer);connect(generation);refresh();}
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
  article.dataset.eventId=item.id;
  const meta=element('div','notification-meta');meta.append(element('span','notification-severity',item.severity||'info'),element('span','',readableSource(item.source)));
  if(item.host_id)meta.append(element('span','',hostName(item.host_id)));
  if(item.lifecycle==='resolved')meta.append(element('span','notification-resolved','resolved'));
  const stamp=element('time','',Number.isFinite(item.created)?new Date(item.created*1000).toLocaleString():'Time unavailable');if(Number.isFinite(item.created))stamp.dateTime=new Date(item.created*1000).toISOString();meta.append(stamp);
  const reason=element('p','notification-reason',item.reason||'Reason unavailable'),actions=element('div','notification-actions'),link=safeLink(item.deep_link);
  if(link){const anchor=element('a','button','Open subject');anchor.href=link;anchor.dataset.notificationAction='open';actions.append(anchor);}
  if(!item.read&&!item.dismissed){const read=element('button','quiet','Mark read');read.type='button';read.dataset.notificationAction='read';read.addEventListener('click',()=>centerMutate(item,'read',read));actions.append(read);}
  if(!item.dismissed){const dismiss=element('button','quiet','Dismiss');dismiss.type='button';dismiss.dataset.notificationAction='dismiss';dismiss.addEventListener('click',()=>centerMutate(item,'dismiss',dismiss));actions.append(dismiss);}
  article.append(meta,reason,actions);return article;
 }
 async function centerMutate(item,action,control){
  control.disabled=true;
  try{await api(`/notifications/${encodeURIComponent(item.id)}/${action}`,'POST',{revision:item.revision});await refresh();}
  catch(error){if(control.isConnected)control.disabled=false;toast(error.message);}
 }
 function applyCenterPage(page,preserveFocus=true){
  const list=node('notification-center-list');if(!list)return;
  const active=document.activeElement,activeCard=active?.closest?.('[data-event-id]');
  const focus=preserveFocus&&activeCard&&list.contains(active)?{id:activeCard.dataset.eventId,action:active.dataset.notificationAction||''}:null;
  list.replaceChildren();
  if(page.items.length)for(const item of page.items)list.append(centerItem(item));else{const empty=element('div','card notification-empty');empty.append(element('strong','','No matching notifications.'),element('p','help','Adjust the filters or wait for a new event visible to your account.'));list.append(empty);}
  const range=node('notification-center-range'),previous=node('notification-center-prev'),next=node('notification-center-next');
  if(range)range.textContent=page.total?`${page.offset+1}–${Math.min(page.offset+page.items.length,page.total)} of ${page.total}`:'0 notifications';
  if(previous)previous.disabled=!page.offset;if(next)next.disabled=!page.more;
  if(focus){const card=[...list.querySelectorAll('[data-event-id]')].find(candidate=>candidate.dataset.eventId===focus.id);const target=card&&[...card.querySelectorAll('[data-notification-action]')].find(candidate=>candidate.dataset.notificationAction===focus.action);if(target)target.focus();}
 }
 async function refreshCenterList(revision=renderRevision){
  const request=++centerRequestRevision,page=await api('/notifications?'+query());
  if(request!==centerRequestRevision||!currentView(revision,'notifications'))return;
  applyCenterPage(page);
 }
 async function center(revision=renderRevision){
  const request=++centerRequestRevision,root=node('content'),page=await api('/notifications?'+query());
  if(request!==centerRequestRevision||!currentView(revision,'notifications')||!root.isConnected)return;
  const hostOptions=hosts.map(host=>`<option value="${esc(host.id)}" ${centerContext.hostId===host.id?'selected':''}>${esc(host.name)}</option>`).join('');
  root.innerHTML=PatchyUI.heading('notifications','Your notification history.','Permission-filtered attention and recovery notes, kept separate from operational acknowledgement.')+`<section class="card notification-center-controls"><form id="notification-filters"><div class="form-grid"><label>Severity<select name="severity"><option value="">All severities</option>${['critical','high','medium','low','info'].map(value=>`<option value="${value}" ${centerContext.severity===value?'selected':''}>${value}</option>`).join('')}</select></label><label>Source<input name="source" value="${esc(centerContext.source)}" maxlength="40" pattern="[a-z0-9][a-z0-9_.-]*" placeholder="All sources"></label><label>Server<select name="host_id"><option value="">All servers</option>${hostOptions}</select></label></div><div class="actions"><label class="check"><input name="unread_only" type="checkbox" ${centerContext.unreadOnly?'checked':''}>Unread only</label><label class="check"><input name="include_dismissed" type="checkbox" ${centerContext.includeDismissed?'checked':''}>Include dismissed</label><button type="submit">Apply filters</button><button type="button" class="quiet" id="notification-filters-clear">Clear</button></div></form><p class="help">Read and dismiss affect only your account. They never acknowledge an alert, resolve an incident, approve AI work or run remediation.</p></section><section id="notification-center-list" aria-label="Notification history"></section><div class="actions notification-center-pages"><button id="notification-center-prev">Previous</button><span class="help" id="notification-center-range"></span><button id="notification-center-next">Next</button></div><p class="help notification-center-coverage">Authenticated server push refreshes this page from durable, permission-filtered history. A 30-second polling fallback remains active; live toasts and complete failover acceptance remain planned.</p>`;
  applyCenterPage(page,false);
  node('notification-filters').onsubmit=event=>{event.preventDefault();const form=new FormData(event.currentTarget);Object.assign(centerContext,{offset:0,severity:String(form.get('severity')||''),source:String(form.get('source')||'').trim(),hostId:String(form.get('host_id')||''),unreadOnly:form.has('unread_only'),includeDismissed:form.has('include_dismissed')});center(revision).catch(error=>toast(error.message));};
  node('notification-filters-clear').onclick=()=>{Object.assign(centerContext,{offset:0,unreadOnly:false,includeDismissed:false,severity:'',source:'',hostId:''});center(revision).catch(error=>toast(error.message));};
  node('notification-center-prev').onclick=()=>{centerContext.offset=Math.max(0,centerContext.offset-25);center(revision).catch(error=>toast(error.message));};
  node('notification-center-next').onclick=()=>{centerContext.offset+=25;center(revision).catch(error=>toast(error.message));};
 }
 return {start,reset,refresh,center};
})();
