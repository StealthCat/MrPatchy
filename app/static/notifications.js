'use strict';
// Compact authenticated-shell notifications. The API remains authoritative for
// permission filtering, unread counts and per-user revision state.
window.NotificationShell=(()=>{
 const POLL_MS=30000, severityRank={info:0,low:1,medium:2,high:3,critical:4};
 let generation=0,requestRevision=0,centerRequestRevision=0,timer=0,items=[],open=false,started=false,stream=null,seen=null;
 // Live toasts: the first authoritative page after start() is a silent baseline, so
 // reloads, sign-in and cursor catch-up never replay existing events as toasts.
 const TOAST_LIMIT=3,TOAST_VISIBLE=4,TOAST_MS=8000,SEEN_LIMIT=1000,STICKY={high:true,critical:true};
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
 function toastRegion(){return node('notification-toasts');}
 function removeToast(toastNode){clearTimeout(toastNode._timer);toastNode.remove();}
 function removeToastsFor(id){const region=toastRegion();if(region)for(const toastNode of [...region.children])if(toastNode.dataset.eventId===id)removeToast(toastNode);}
 function armToast(toastNode,sticky){
  if(sticky)return;
  const arm=()=>{clearTimeout(toastNode._timer);toastNode._timer=setTimeout(()=>removeToast(toastNode),TOAST_MS);};
  const hold=()=>clearTimeout(toastNode._timer);
  toastNode.addEventListener('mouseenter',hold);toastNode.addEventListener('focusin',hold);
  toastNode.addEventListener('mouseleave',()=>{if(!toastNode.contains(document.activeElement))arm();});
  toastNode.addEventListener('focusout',event=>{if(!toastNode.contains(event.relatedTarget))arm();});
  arm();
 }
 function pushToast(toastNode,sticky){
  const region=toastRegion();if(!region)return;
  const close=element('button','quiet notification-toast-close','×');close.type='button';close.setAttribute('aria-label','Close notification toast');
  close.addEventListener('click',()=>removeToast(toastNode));toastNode.prepend(close);
  region.append(toastNode);
  // Bound the visible stack; the bell and center retain every event.
  while(region.children.length>TOAST_VISIBLE)removeToast(region.firstElementChild);
  armToast(toastNode,sticky);
 }
 function itemToast(item){
  const severity=item.severity in severityRank?item.severity:'info';
  const toastNode=element('article','notification-toast');toastNode.dataset.severity=severity;toastNode.dataset.eventId=item.id;
  const meta=element('div','notification-meta');meta.append(element('span','notification-severity',severity),element('span','',readableSource(item.source)));
  if(item.host_id)meta.append(element('span','',typeof hostName==='function'?hostName(item.host_id):'server '+item.host_id));
  const reason=element('p','notification-reason',item.reason||'Reason unavailable'),link=safeLink(item.deep_link);
  toastNode.append(meta,reason);
  if(link){const actions=element('div','notification-actions'),anchor=element('a','button','Open');anchor.href=link;anchor.addEventListener('click',()=>removeToast(toastNode));actions.append(anchor);toastNode.append(actions);}
  pushToast(toastNode,!!STICKY[severity]);
 }
 function summaryToast(extra){
  const toastNode=element('article','notification-toast');toastNode.dataset.severity='info';
  const actions=element('div','notification-actions'),anchor=element('a','button','View notification center');anchor.href='#notifications';anchor.addEventListener('click',()=>removeToast(toastNode));actions.append(anchor);
  toastNode.append(element('p','notification-reason',`${extra} more new notification${extra===1?'':'s'} arrived.`),actions);
  pushToast(toastNode,false);
 }
 function announce(current){
  const keys=current.map(item=>`${item.id}:${item.revision}`);
  if(seen===null||seen.size>SEEN_LIMIT){const baseline=seen===null;seen=new Set(keys);if(baseline)return;}
  const fresh=[];
  current.forEach((item,index)=>{if(seen.has(keys[index]))return;seen.add(keys[index]);if(!item.read&&!item.dismissed)fresh.push(item);});
  // Closing or expiring a toast is page-local: it never reads, dismisses, acknowledges or remediates.
  for(const item of current)if(item.read||item.dismissed)removeToastsFor(item.id);
  fresh.slice(0,TOAST_LIMIT).forEach(itemToast);
  if(fresh.length>TOAST_LIMIT)summaryToast(fresh.length-TOAST_LIMIT);
 }
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
   const [count,page]=await Promise.all([api('/notifications/unread-count'),api('/notifications?limit=8')]);
   if(run!==generation||request!==requestRevision)return;
   items=Array.isArray(page.items)?page.items.slice(0,8):[];setCount(count.unread,items);render();announce(items);
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
   render();removeToastsFor(item.id);
   status(action==='dismiss'?'Notification dismissed for your account.':'Notification marked read for your account.');
   const count=await api('/notifications/unread-count');
   if(run!==generation||!started)return;
   setCount(count.unread,items);
   if(location.hash==='#notifications')await refreshCenterList(renderRevision);
  }catch(error){if(run===generation&&started){status(error.message);if(control.isConnected)control.disabled=false;}}
 }
 // The open panel already lists every recent event, so the toast stack steps aside.
 function toastsBehindPanel(value){const region=toastRegion();if(region)region.classList.toggle('is-behind-panel',value);}
 function close({focus=false}={}){open=false;panel().hidden=true;toastsBehindPanel(false);button().setAttribute('aria-expanded','false');if(focus)button().focus();}
 function toggle(){
  if(open){close();return;}
  open=true;panel().hidden=false;toastsBehindPanel(true);button().setAttribute('aria-expanded','true');refresh();
 }
 function reset(){
  generation++;requestRevision++;centerRequestRevision++;started=false;clearTimeout(timer);timer=0;items=[];open=false;
  if(stream){stream.close();stream=null;}
  panel().hidden=true;toastsBehindPanel(false);button().setAttribute('aria-expanded','false');setCount(null,[]);
  status('');node('notification-list').replaceChildren();seen=null;
  const region=toastRegion();if(region)for(const toastNode of [...region.children])removeToast(toastNode);Object.assign(centerContext,{offset:0,unreadOnly:false,includeDismissed:false,severity:'',source:'',hostId:''});
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
  try{await api(`/notifications/${encodeURIComponent(item.id)}/${action}`,'POST',{revision:item.revision});removeToastsFor(item.id);await refresh();}
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
  root.innerHTML=PatchyUI.heading('notifications','Your notification history.','Permission-filtered attention and recovery notes, kept separate from operational acknowledgement.')+`<section class="card notification-center-controls"><form id="notification-filters"><div class="form-grid"><label>Severity<select name="severity"><option value="">All severities</option>${['critical','high','medium','low','info'].map(value=>`<option value="${value}" ${centerContext.severity===value?'selected':''}>${value}</option>`).join('')}</select></label><label>Source<input name="source" value="${esc(centerContext.source)}" maxlength="40" pattern="[a-z0-9][a-z0-9_.-]*" placeholder="All sources"></label><label>Server<select name="host_id"><option value="">All servers</option>${hostOptions}</select></label></div><div class="actions"><label class="check"><input name="unread_only" type="checkbox" ${centerContext.unreadOnly?'checked':''}>Unread only</label><label class="check"><input name="include_dismissed" type="checkbox" ${centerContext.includeDismissed?'checked':''}>Include dismissed</label><button type="submit">Apply filters</button><button type="button" class="quiet" id="notification-filters-clear">Clear</button></div></form><p class="help">Read and dismiss affect only your account. They never acknowledge an alert, resolve an incident, approve AI work or run remediation.</p></section><section id="notification-center-list" aria-label="Notification history"></section><div class="actions notification-center-pages"><button id="notification-center-prev">Previous</button><span class="help" id="notification-center-range"></span><button id="notification-center-next">Next</button></div><p class="help notification-center-coverage">Authenticated server push refreshes this page from durable, permission-filtered history. New events also appear as brief toasts on any page; closing a toast never marks it read. A 30-second polling fallback remains active; complete failover acceptance remains planned.</p>`;
  applyCenterPage(page,false);
  node('notification-filters').onsubmit=event=>{event.preventDefault();const form=new FormData(event.currentTarget);Object.assign(centerContext,{offset:0,severity:String(form.get('severity')||''),source:String(form.get('source')||'').trim(),hostId:String(form.get('host_id')||''),unreadOnly:form.has('unread_only'),includeDismissed:form.has('include_dismissed')});center(revision).catch(error=>toast(error.message));};
  node('notification-filters-clear').onclick=()=>{Object.assign(centerContext,{offset:0,unreadOnly:false,includeDismissed:false,severity:'',source:'',hostId:''});center(revision).catch(error=>toast(error.message));};
  node('notification-center-prev').onclick=()=>{centerContext.offset=Math.max(0,centerContext.offset-25);center(revision).catch(error=>toast(error.message));};
  node('notification-center-next').onclick=()=>{centerContext.offset+=25;center(revision).catch(error=>toast(error.message));};
 }
 return {start,reset,refresh,center};
})();
