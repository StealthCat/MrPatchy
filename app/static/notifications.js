'use strict';
// Compact authenticated-shell notifications. The API remains authoritative for
// permission filtering, unread counts and per-user revision state.
window.NotificationShell=(()=>{
 const POLL_MS=30000, severityRank={info:0,low:1,medium:2,high:3,critical:4};
 // Live toasts: only new or higher-revision unread high/critical events seen after
 // the first successful refresh. Hiding a toast is local to this tab and never
 // marks the notification read, dismisses it or acknowledges its subject.
 const TOAST_LIMIT=3,TOAST_MS=10000,TOAST_SEEN_LIMIT=500,toastSeverities=new Set(['high','critical']);
 let generation=0,requestRevision=0,centerRequestRevision=0,timer=0,items=[],open=false,started=false,stream=null,toastSeen=null;
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
 function toastStack(){
  let stack=node('notification-toasts');
  if(!stack){
   stack=element('div','notification-toasts');stack.id='notification-toasts';
   stack.setAttribute('role','status');stack.setAttribute('aria-live','polite');stack.setAttribute('aria-label','New notifications');
   if(typeof stack.showPopover==='function')stack.popover='manual';
  }
  // A modal dialog makes everything outside it inert, so mount inside the open
  // dialog. The top-layer popover keeps the stack above the dialog without
  // moving focus.
  const dialog=node('modal'),host=dialog?.open?dialog:document.body;
  if(stack.parentNode!==host)host.append(stack);
  return stack;
 }
 function showStack(stack){
  if(!stack.children.length){if(stack.popover&&stack.matches(':popover-open'))stack.hidePopover();stack.hidden=true;return;}
  stack.hidden=false;
  if(stack.popover){try{if(stack.matches(':popover-open'))stack.hidePopover();stack.showPopover();}catch{}}
 }
 function removeToast(card){clearTimeout(card._timer);card.remove();const stack=node('notification-toasts');if(stack)showStack(stack);}
 function armToast(card){
  const arm=()=>{clearTimeout(card._timer);card._timer=setTimeout(()=>removeToast(card),TOAST_MS);};
  card.addEventListener('mouseenter',()=>clearTimeout(card._timer));card.addEventListener('mouseleave',()=>{if(!card.contains(document.activeElement))arm();});
  card.addEventListener('focusin',()=>clearTimeout(card._timer));card.addEventListener('focusout',event=>{if(!card.contains(event.relatedTarget)&&!card.matches(':hover'))arm();});
  arm();
 }
 function toastCard({severity,title,reason,link,linkLabel,eventId}){
  const card=element('article','notification-toast');card.dataset.severity=severity;if(eventId)card.dataset.eventId=eventId;
  const head=element('div','notification-meta');head.append(element('span','notification-severity',severity),element('span','',title));
  const actions=element('div','notification-actions');
  if(link){const anchor=element('a','button',linkLabel);anchor.href=link;anchor.addEventListener('click',()=>removeToast(card));actions.append(anchor);}
  const hide=element('button','quiet','Hide');hide.type='button';hide.setAttribute('aria-label','Hide this toast. The notification stays unread.');hide.addEventListener('click',()=>removeToast(card));actions.append(hide);
  card.append(head,element('p','notification-reason',reason),actions);return card;
 }
 function clearToasts(){const stack=node('notification-toasts');if(!stack)return;for(const card of [...stack.children])clearTimeout(card._timer);stack.replaceChildren();showStack(stack);}
 // Toast admission reads the durable arrival cursor (GET /notifications/arrivals),
 // not the bell's recent list or any bounded unread window. The first successful
 // refresh takes a baseline cursor, so events present at sign-in, reload or
 // reconnect never toast. Later refreshes receive, in commit order, each visible
 // current revision committed after the cursor, independent of producer
 // timestamps and of how many older unread events exist. Items are filtered by
 // the server to the caller's current role.
 const TOAST_ARRIVAL_PAGE=100,TOAST_ARRIVAL_PAGES=5;
 async function toastArrivals(){
  const from=toastSeen?toastSeen.cursor:null;
  if(from===null){const page=await api('/notifications/arrivals');return {from,cursor:arrivalCursor(page),items:[],baseline:true};}
  let cursor=from;const found=[];
  // Bounded catch-up per refresh; anything beyond it is picked up on the next one.
  for(let pageNo=0;pageNo<TOAST_ARRIVAL_PAGES;pageNo++){
   const page=await api(`/notifications/arrivals?after=${cursor}&limit=${TOAST_ARRIVAL_PAGE}`);
   // A cursor beyond the retained sequence is reset to a fresh baseline.
   if(page.reset)return {from,cursor:arrivalCursor(page),items:[],baseline:true};
   found.push(...(Array.isArray(page.items)?page.items:[]));cursor=arrivalCursor(page);
   if(!page.more)break;
  }
  return {from,cursor,items:found,baseline:false};
 }
 function arrivalCursor(page){if(!Number.isInteger(page?.cursor)||page.cursor<0)throw new Error('Notification arrival cursor unavailable');return page.cursor;}
 // Cross-tab deduplication: every tab keeps its own arrival cursor, so tabs of the
 // same account claim each (event, revision) in shared same-origin storage before
 // showing it. Web Locks make the check-and-claim atomic; without them a
 // best-effort read-modify-write still dedupes non-concurrent tabs. Claims hold
 // only event IDs and revisions, are bounded, belong to one account and are
 // cleared on reset. Unusable storage fails open to this tab's own toasts.
 const TOAST_CLAIM_KEY='mrpatchy-notification-toasts',TOAST_CLAIM_LIMIT=500,TOAST_CLAIM_MS=86400000;
 function toastAccount(){return typeof currentUser!=='undefined'&&currentUser&&typeof currentUser.username==='string'?currentUser.username:'';}
 function claimStored(account,candidates){
  const now=Date.now(),raw=localStorage.getItem(TOAST_CLAIM_KEY);
  let stored=null;try{stored=JSON.parse(raw||'null');}catch{stored=null;}
  let entries=stored&&stored.v===1&&stored.account===account&&Array.isArray(stored.entries)?stored.entries.filter(entry=>Array.isArray(entry)&&typeof entry[0]==='string'&&Number.isFinite(entry[1])&&Number.isFinite(entry[2])&&now-entry[2]<TOAST_CLAIM_MS&&entry[2]<=now+60000):[];
  const claimed=new Map(entries.map(entry=>[entry[0],entry[1]])),mine=[];
  for(const item of candidates){
   const revision=Number(item.revision)||0,known=claimed.get(item.id);
   if(known!==undefined&&known>=revision)continue;
   claimed.set(item.id,revision);mine.push(item);
   entries=entries.filter(entry=>entry[0]!==item.id);entries.push([item.id,revision,now]);
  }
  if(mine.length)localStorage.setItem(TOAST_CLAIM_KEY,JSON.stringify({v:1,account,entries:entries.slice(-TOAST_CLAIM_LIMIT)}));
  return mine;
 }
 async function claimToasts(candidates){
  const account=toastAccount();
  if(!candidates.length||!account)return candidates;
  const attempt=()=>{try{return claimStored(account,candidates);}catch{return candidates;}};
  try{if(navigator.locks&&typeof navigator.locks.request==='function')return await navigator.locks.request(TOAST_CLAIM_KEY,attempt);}catch{return candidates;}
  return attempt();
 }
 function clearToastClaims(){try{localStorage.removeItem(TOAST_CLAIM_KEY);}catch{}}
 async function noteToasts(current,arrivals,run=generation){
  // Without a fresh arrival result the bell still updates; existing toasts are
  // pruned but nothing new is admitted and the cursor is kept for a retry.
  const fresh=[];
  if(arrivals&&(toastSeen?toastSeen.cursor:null)===arrivals.from){
   const first=toastSeen===null;
   toastSeen={cursor:arrivals.cursor,revisions:toastSeen?.revisions||new Map()};
   if(!first&&!arrivals.baseline)for(const item of arrivals.items){
    // Arrivals are delivered once per revision; the bounded memory only guards
    // against duplicate items inside one catch-up.
    const revision=Number(item.revision)||0,known=toastSeen.revisions.get(item.id);
    if(known!==undefined&&known>=revision)continue;
    toastSeen.revisions.delete(item.id);toastSeen.revisions.set(item.id,revision);
    if(!item.read&&!item.dismissed&&item.lifecycle!=='resolved'&&toastSeverities.has(item.severity))fresh.push(item);
   }
   while(toastSeen.revisions.size>TOAST_SEEN_LIMIT)toastSeen.revisions.delete(toastSeen.revisions.keys().next().value);
  }
  if(!toastSeen)return;
  let stack=toastStack();
  for(const card of [...stack.querySelectorAll('[data-event-id]')]){const item=current.find(candidate=>candidate.id===card.dataset.eventId);if(item&&(item.read||item.dismissed))removeToast(card);}
  if(!fresh.length){showStack(stack);return;}
  // Another open tab of this account may already have shown these revisions.
  const claimed=await claimToasts(fresh);
  if(run!==generation||!started)return;
  fresh.splice(0,fresh.length,...claimed);
  stack=toastStack();
  if(!fresh.length){showStack(stack);return;}
  fresh.sort((a,b)=>(Number(b.created)||0)-(Number(a.created)||0)||(String(a.id)<String(b.id)?-1:1));
  if(fresh.length>TOAST_LIMIT){
   clearToasts();
   const severity=fresh.some(item=>item.severity==='critical')?'critical':'high';
   const card=toastCard({severity,title:'notifications',reason:`${fresh.length} new ${severity==='critical'?'critical or high':'high'}-severity notifications need attention.`,link:'#notifications',linkLabel:'Open notification center'});
   stack.append(card);armToast(card);showStack(stack);return;
  }
  for(const item of fresh.reverse()){
   for(const old of [...stack.querySelectorAll('[data-event-id]')])if(old.dataset.eventId===item.id)removeToast(old);
   const card=toastCard({severity:item.severity,title:readableSource(item.source)+(item.host_id?' · '+(typeof hostName==='function'?hostName(item.host_id):'server '+item.host_id):''),reason:item.reason||'Reason unavailable',link:safeLink(item.deep_link),linkLabel:'Open',eventId:item.id});
   stack.append(card);armToast(card);
  }
  while(stack.children.length>TOAST_LIMIT)removeToast(stack.firstElementChild);
  showStack(stack);
 }
 node('modal')?.addEventListener('close',()=>{const stack=node('notification-toasts');if(stack&&stack.parentNode!==document.body){document.body.append(stack);showStack(stack);}});
 function schedule(run=generation){clearTimeout(timer);if(!started||document.hidden)return;timer=setTimeout(()=>{if(run===generation)refresh();},POLL_MS);}
 function connect(run){
  if(typeof EventSource!=='function')return;
  if(stream)stream.close();
  const current=new EventSource('/api/notifications/stream');stream=current;
  current.addEventListener('notifications',()=>{if(stream===current&&run===generation&&started)refresh();});
  current.addEventListener('close',()=>{if(stream!==current||run!==generation)return;current.close();stream=null;if(typeof showLogin==='function')showLogin();else reset();});
  current.onerror=()=>{if(stream===current&&run===generation&&started&&open)status('Live updates are reconnecting. The 30-second catch-up remains active.');};
 }
 async function refresh(){
  if(!started||document.hidden)return;
  const run=generation,request=++requestRevision;
  try{
   const [count,page,arrivals]=await Promise.all([api('/notifications/unread-count'),api('/notifications?limit=8'),toastArrivals().catch(()=>null)]);
   if(run!==generation||request!==requestRevision)return;
   items=Array.isArray(page.items)?page.items.slice(0,8):[];setCount(count.unread,items);render();await noteToasts(items,arrivals,run);if(run!==generation)return;
   status(page.more?'Showing the 8 most recent notifications. More remain available through the API.':`${page.total||0} recent notification${page.total===1?'':'s'}.`);
   if(location.hash==='#notifications')await refreshCenterList(renderRevision);
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
   if(location.hash==='#notifications')await refreshCenterList(renderRevision);
  }catch(error){if(run===generation&&started){status(error.message);if(control.isConnected)control.disabled=false;}}
 }
 function close({focus=false}={}){open=false;panel().hidden=true;button().setAttribute('aria-expanded','false');if(focus)button().focus();}
 function toggle(){
  if(open){close();return;}
  open=true;panel().hidden=false;button().setAttribute('aria-expanded','true');refresh();
 }
 function reset(){
  generation++;requestRevision++;centerRequestRevision++;started=false;clearTimeout(timer);timer=0;items=[];open=false;toastSeen=null;clearToasts();clearToastClaims();
  if(stream){stream.close();stream=null;}
  panel().hidden=true;button().setAttribute('aria-expanded','false');setCount(null,[]);
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
  root.innerHTML=PatchyUI.heading('notifications','Your notification history.','Permission-filtered attention and recovery notes, kept separate from operational acknowledgement.')+`<section class="card notification-center-controls"><form id="notification-filters"><div class="form-grid"><label>Severity<select name="severity"><option value="">All severities</option>${['critical','high','medium','low','info'].map(value=>`<option value="${value}" ${centerContext.severity===value?'selected':''}>${value}</option>`).join('')}</select></label><label>Source<input name="source" value="${esc(centerContext.source)}" maxlength="40" pattern="[a-z0-9][a-z0-9_.-]*" placeholder="All sources"></label><label>Server<select name="host_id"><option value="">All servers</option>${hostOptions}</select></label></div><div class="actions"><label class="check"><input name="unread_only" type="checkbox" ${centerContext.unreadOnly?'checked':''}>Unread only</label><label class="check"><input name="include_dismissed" type="checkbox" ${centerContext.includeDismissed?'checked':''}>Include dismissed</label><button type="submit">Apply filters</button><button type="button" class="quiet" id="notification-filters-clear">Clear</button></div></form><p class="help">Read and dismiss affect only your account. They never acknowledge an alert, resolve an incident, approve AI work or run remediation.</p></section><section id="notification-center-list" aria-label="Notification history"></section><div class="actions notification-center-pages"><button id="notification-center-prev">Previous</button><span class="help" id="notification-center-range"></span><button id="notification-center-next">Next</button></div><p class="help notification-center-coverage">Authenticated server push refreshes this page from durable, permission-filtered history. A 30-second polling fallback remains active. New high and critical notifications also appear briefly as toasts; hiding a toast leaves the notification unread. Complete failover acceptance remains planned.</p>`;
  applyCenterPage(page,false);
  node('notification-filters').onsubmit=event=>{event.preventDefault();const form=new FormData(event.currentTarget);Object.assign(centerContext,{offset:0,severity:String(form.get('severity')||''),source:String(form.get('source')||'').trim(),hostId:String(form.get('host_id')||''),unreadOnly:form.has('unread_only'),includeDismissed:form.has('include_dismissed')});center(revision).catch(error=>toast(error.message));};
  node('notification-filters-clear').onclick=()=>{Object.assign(centerContext,{offset:0,unreadOnly:false,includeDismissed:false,severity:'',source:'',hostId:''});center(revision).catch(error=>toast(error.message));};
  node('notification-center-prev').onclick=()=>{centerContext.offset=Math.max(0,centerContext.offset-25);center(revision).catch(error=>toast(error.message));};
  node('notification-center-next').onclick=()=>{centerContext.offset+=25;center(revision).catch(error=>toast(error.message));};
 }
 return {start,reset,refresh,center};
})();
