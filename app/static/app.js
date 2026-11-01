'use strict';
const $=s=>document.querySelector(s), esc=PatchyUI.esc;
const packageViewContext=new Map();
const aiListContext=new Map();
const startupViewContext=new Map();
const historyViewContext=new Map();
const activityViewContext=new Map();const investigationViewContext=new Map();
const fleetReviewContext={q:'',filter:'attention',offset:0};
const serverListContext={q:"",state:"all",offset:0};
let csrf='',hosts=[],selected='',page='overview',toastTimer,modalRevision=0,releaseRequest=0,renderRevision=0,sessionRevision=0,currentUser=null;
const date=t=>t?new Date(t*1000).toLocaleString():'Not yet';
const badge=s=>`<span class="badge ${esc(s)}">${esc(s)}</span>`;
async function api(path,method='GET',body){const session=sessionRevision;const r=await fetch('/api'+path,{method,headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:body===undefined?undefined:JSON.stringify(body)});let data=await r.json();if(session!==sessionRevision&&path!=='/sso')throw Error('Session changed; previous response discarded');if(!r.ok){if(r.status===401)showLogin();throw Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.detail));}return data;}
function toast(message,global=false){
 const target=global?$('#toast'):$('#modal').open?$('#modal-message'):$('#toast');
 target.textContent=message;target.classList.remove('hidden');target.style.display='block';
 clearTimeout(toastTimer);toastTimer=setTimeout(()=>{target.style.display='none';},6000);
}
// Success feedback for a navigation is shown once the matching hashchange render has finished.
let pendingNavToast=null;
async function navigateWithToast(hash,message){
 pendingNavToast={hash,message,session:sessionRevision};
 if(location.hash===hash){await render();return;}
 location.hash=hash;
}
function flushNavToast(revision){
 const pending=pendingNavToast;if(!pending||revision!==renderRevision)return;
 pendingNavToast=null;
 if(pending.session===sessionRevision&&location.hash===pending.hash&&!$('#shell').classList.contains('hidden'))toast(pending.message);
}
function showLogin(){
 pendingNavToast=null;sessionRevision++;renderRevision++;modalRevision++;releaseRequest++;
 packageViewContext.clear();aiListContext.clear();assessmentOffsets.clear();startupViewContext.clear();historyViewContext.clear();activityViewContext.clear();investigationViewContext.clear();Object.assign(fleetReviewContext,{q:'',filter:'attention',offset:0});Object.assign(serverListContext,{q:'',state:'all',offset:0});csrf='';hosts=[];selected='';currentUser=null;document.body.dataset.role='viewer';document.title='Sign in · Mr Patchy';
 $('#modal').close();$('#modal-body').replaceChildren();$('#content').replaceChildren();
 $('#toast').style.display='none';clearTimeout(toastTimer);
 $('#login').classList.remove('hidden');$('#shell').classList.add('hidden');
}
function isAdmin(){return currentUser?.role==='admin';}
function currentView(revision,name){return revision===renderRevision&&page===name&&!$('#shell').classList.contains('hidden');}
function showShell(){$('#login').classList.add('hidden');$('#shell').classList.remove('hidden');}
function heading(title,sub,button=''){return PatchyUI.heading(page,title,sub,button);}
function empty(title,text,action=''){return PatchyUI.empty(title,text,action);}
function serverSelect(){return `<select id="server-select" aria-label="Select server">${hosts.map(h=>`<option value="${h.id}" ${h.id===selected?'selected':''}>${esc(h.name)}</option>`).join('')}</select>`;}
function hostName(id){return hosts.find(h=>h.id===id)?.name||id;}
function bindSelect(fn){$('#server-select')?.addEventListener('change',e=>{selected=e.target.value;fn().catch(error=>toast(error.message));});}
function modal(title,html){modalRevision++;$('#modal-message').classList.add('hidden');$('#modal-message').textContent='';$('#modal-title').textContent=title;$('#modal-body').innerHTML=html;$('#modal').showModal();}
function modalRequest(){
 const revision=modalRevision,session=sessionRevision;
 const active=()=>revision===modalRevision&&session===sessionRevision;
 const sameSession=()=>session===sessionRevision;
 return {active,sameSession,close(message){if(!sameSession())return false;if(active())$('#modal').close();toast(message,true);return true;},error(error){if(!sameSession())return false;toast(error.message,!active());return true;}};
}
async function render(){
 const revision=++renderRevision;
 let requested=location.hash.slice(1)||'overview';
 if(requested.startsWith('overview/'))requested='overview';
 if(requested.startsWith('ai-logs/'))requested='ai-logs';
 if(requested.startsWith('investigations/'))requested='investigations';
 if(requested.startsWith('activity/'))requested='activity';
 if(requested.startsWith('settings/'))requested='settings';
 if(requested.startsWith('servers/'))requested='servers';
 if(!['security','overview','servers','packages','repositories','investigations','activity','schedules','settings','history','users','ai-logs'].includes(requested))requested='overview';
 try{
  const [me,list]=await Promise.all([api('/identity'),api('/hosts')]);
  if(revision!==renderRevision)return;
  currentUser=me;document.body.dataset.role=me.role;hosts=list;
  $('#application-version').textContent=me.version?'v'+me.version:'SELF-HOSTED';
  if(!isAdmin()&&['security','settings','repositories','schedules','users','ai-logs'].includes(requested)){
   requested='overview';history.replaceState(null,'','#overview');
  }
  page=requested;
  document.querySelectorAll('[data-nav]').forEach(a=>{a.classList.toggle('active',a.dataset.nav===page);if(a.dataset.nav===page)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');});
  $('#breadcrumb').textContent='Workspace / '+PatchyUI.pages[page][0];
  document.title=PatchyUI.pages[page][0]+' · Mr Patchy';
  if(!hosts.some(h=>h.id===selected))selected=hosts[0]?.id||'';
  $('#content').innerHTML=PatchyUI.loading();
  await ({security:fleetSecurityCoverage,overview,servers,packages,repositories,investigations,activity,schedules,settings,history:packageHistory,users,'ai-logs':aiDiagnostics}[page])(revision);
  flushNavToast(revision);
 }catch(error){if(revision===renderRevision)pendingNavToast=null;if(revision===renderRevision&&!$('#shell').classList.contains('hidden')){$('#content').innerHTML=heading('Unable to load this view.','Your workspace could not be refreshed.')+empty('Let’s try that again.',esc(error.message),'<button id="retry-view" class="primary">Retry loading</button>');$('#retry-view').onclick=render;}}
}
// Fleet contact is an observation, never a component readiness or protection claim.
function fleetObservation(host,now){
 if(host.enabled===false)return {kind:'disabled',label:'Management disabled',reason:'Automatic management is paused; retained observations may be old.'};
 const seen=host.last_seen,age=now-seen;
 if(typeof seen!=='number'||!Number.isFinite(seen)||seen<=0)return {kind:'unknown',label:'No contact recorded',reason:'Enrollment or collection has not produced a usable contact timestamp.'};
 if(age<0)return {kind:'unknown',label:'Future contact timestamp',reason:'Clock disagreement prevents a freshness assessment.'};
 if(age>=120)return {kind:'stale',label:'Contact expired',reason:'No contact in the last two minutes. Current outcomes are unknown.'};
 if((host.integrity||[]).length||host.error||host.state!=='online')return {kind:'attention',label:'Review stored findings',reason:host.error||'Recent contact includes findings or a reported state that needs review.'};
 return {kind:'recent',label:'Recent contact',reason:'Contact within two minutes and no stored integrity findings. Individual collectors may still be stale.'};
}
async function overview(revision=renderRevision){
 const snapshot=[...hosts],d=await api('/dashboard');if(!currentView(revision,'overview'))return;
 const root=$('#content'),now=Date.now()/1000,observations=snapshot.map(host=>({host,...fleetObservation(host,now)}));
 const requested=location.hash.slice(1)||'overview';
 const section=requested==='overview/attention'?'attention':requested==='overview/monitoring'?'monitoring':'summary';
 if(!['overview','overview/attention','overview/monitoring'].includes(requested))history.replaceState(null,'','#overview');
 const entries=[['summary','Summary'],['attention','Server attention'],['monitoring','Monitoring']];
 const labels=Object.fromEntries(entries),link=key=>key==='summary'?'#overview':'#overview/'+key;
 $('#breadcrumb').textContent='Workspace / Overview / '+labels[section];document.title=labels[section]+' · Fleet Overview · Mr Patchy';
 const navigation='<nav class="overview-sections" aria-label="Fleet overview pages">'+PatchyUI.sectionNavigation(entries,section,link,entries.map(item=>item[0]),[])+'</nav>';
 const recent=observations.filter(row=>row.kind==='recent').length,attention=observations.filter(row=>!['recent','disabled'].includes(row.kind)).length;
 const stat=(label,value,detail,icon,style='')=>`<div class="stat ${style}">${PatchyUI.icon(icon)}<label>${label}</label><strong>${esc(value)}</strong><small>${detail}</small></div>`;
 const intro=heading(section==='summary'?'A healthier fleet starts here.':section==='attention'?'A closer look at your servers.':'Know what each signal means.',section==='summary'?'Stored signals, clear next steps, and room to investigate.':section==='attention'?'Review contact gaps and stored findings before deciding what to do.':'Expected timing does not prove that a check succeeded.','<button class="primary" data-admin data-action="add">+ Add server</button>');
 const notice='<p class="help fleet-snapshot-note">This page combines stored snapshots, not a live health probe. Disabled servers are excluded from package totals. Contact freshness does not verify individual collectors, Docker readiness or malware protection.</p>';
 const tile=row=>`<article class="fleet-observation"><div class="fleet-observation-title">${PatchyUI.icon('servers')}<h3><a href="${serverLink(row.host.id)}">${esc(row.host.name)}</a></h3>${badge(row.kind)}</div><p class="help">${esc(row.host.address)} · ${esc(row.host.architecture||'Architecture not reported')}</p><strong>${esc(row.label)}</strong><p>${esc(row.reason)}</p><p class="help">Last contact: ${date(row.host.last_seen)}</p><a class="button" href="${serverLink(row.host.id)}">Open server →</a></article>`;
 let content='';
 if(section==='summary'){
  content=`<div class="stats">${stat('Recent contact',recent,'No stored integrity findings; not readiness','servers','accent')}${stat('Servers to review',attention,'Contact gaps or stored findings','investigations',attention?'warn':'')}${stat('Updates available',d.updates,esc(d.packages.toLocaleString())+' installed package records','packages')}${stat('Past patch deadline',d.overdue,'Based on configured priority deadlines','schedules',d.overdue?'warn':'')}</div>
   <div class="quick-links" aria-label="Fleet shortcuts"><a href="#overview/attention">${PatchyUI.icon('servers')} Review server attention ${PatchyUI.icon('arrow')}</a><a href="#packages">${PatchyUI.icon('packages')} Review updates</a><a href="#investigations">${PatchyUI.icon('investigations')} Investigate behaviors</a><a href="#schedules" data-admin>${PatchyUI.icon('schedules')} Plan patching</a></div>
   <div class="fleet-summary-grid"><section class="card fleet-reading"><div class="card-head"><h2>Review queue</h2><a class="mint" href="#overview/attention">Review servers →</a></div><dl class="fleet-review-facts"><div><dt>Stored integrity findings</dt><dd>${esc(d.integrity_alerts)}</dd></div><div><dt>Behaviors awaiting trust</dt><dd>${esc(d.investigations)}</dd></div><div><dt>Disabled servers</dt><dd>${observations.filter(row=>row.kind==='disabled').length}</dd></div></dl><p class="help">Counts are observations, not confirmed attacks. A vulnerable version or AI opinion alone does not authorize containment.</p><a href="#overview/monitoring" class="mint">Understand collection & coverage →</a></section>
   <section class="hero fleet-guide"><div><div class="eyebrow">MR PATCHY'S NEXT STEP</div><h2>${attention?'Start with the gaps.':'Keep a curious eye.'}</h2><p>${attention?'Open Server attention to review expired contact, unknown timestamps and stored findings.':'A quiet summary is useful, but it cannot certify every collector or endpoint. Review coverage before drawing conclusions.'}</p></div>${PatchyUI.mascot('welcome')}</section></div>
   <section class="card fleet-reading"><div class="card-head"><h2>Your servers</h2><a class="mint" href="#servers">View all ${snapshot.length} →</a></div>${snapshot.length?`<div class="fleet-observation-grid">${observations.slice(0,3).map(tile).join('')}</div>`:empty('Make room for your first server','Enroll a supported Linux machine, verify installation, then review its collection results.','<button data-admin data-action="add">Enroll a server →</button>')}</section>`;
 }else if(section==='attention'){
  content=`<section class="card fleet-reading"><div class="toolbar" id="fleet-review-controls"><label>Find a server<input type="search" id="fleet-review-search" value="${esc(fleetReviewContext.q)}" placeholder="Name or address"></label><label>Review group<select id="fleet-review-filter"><option value="attention">Needs review</option><option value="all">All servers</option><option value="stale">Expired contact</option><option value="unknown">Unknown freshness</option><option value="disabled">Management disabled</option><option value="recent">Recent contact</option></select></label><button id="fleet-review-reset">Reset filters</button></div><p class="help" id="fleet-review-count" role="status"></p><div id="fleet-review-cards"></div><div class="actions"><button id="fleet-review-prev">Previous</button><span class="help" id="fleet-review-page"></span><button id="fleet-review-next">Next</button></div></section>`;
 }else{
  content=`<div class="fleet-summary-grid"><section class="card fleet-reading"><h2>Collection & timing</h2><dl class="fleet-coverage-list"><div><dt>Repository checks</dt><dd>Configured every ${esc(d.repo_minutes)} minutes; package candidates come from central signed metadata.</dd></div><div><dt>Process observations</dt><dd>Normally sampled every 30 seconds. Short-lived activity can be missed.</dd></div><div><dt>Integrity observations</dt><dd>Managed files are normally checked every five minutes. This is bounded coverage, not a full filesystem scan.</dd></div><div><dt>Contact freshness</dt><dd>This view uses a two-minute window. Missing, expired or future timestamps cannot certify availability. Check each server's System & collector page for independent collection times.</dd></div></dl></section><section class="hero fleet-guide"><div><div class="eyebrow">A CURIOUS LITTLE CARETAKER</div><h2>Follow the evidence.</h2><p>AI triage is optional. Per-server pause and global policy govern provider calls; deterministic collection continues. Historical findings remain available.</p><a class="button" href="#servers">Choose a server →</a></div>${PatchyUI.mascot('working')}</section></div>
   <section class="card fleet-reading"><h2>Coverage has boundaries</h2><p>Recent contact is not proof that patching succeeded, a reboot took effect, an endpoint is clean, or every collector is current. Package totals describe retained inventory for enabled servers; held packages may still have candidates.</p><p>Review target errors, individual collection timestamps and operation outcomes. The deployment-health dashboard, remote readiness and expanded automatic protection remain unfinished.</p><div class="quick-links"><a href="#activity">${PatchyUI.icon('activity')} Review operation outcomes</a><a href="#servers">${PatchyUI.icon('servers')} Open server details</a>${isAdmin()?'<a href="#security">'+PatchyUI.icon('shield')+' Review security coverage</a><a href="#activity/workers">'+PatchyUI.icon('activity')+' Inspect worker reports</a>':''}</div></section>`;
 }
 root.innerHTML=intro+navigation+notice+`<div data-fleet-section="${section}">${content}</div>`;
 if(section!=='attention')return;
 const state=fleetReviewContext,search=$('#fleet-review-search'),filter=$('#fleet-review-filter');filter.value=state.filter;
 const draw=()=>{
  const q=state.q.toLocaleLowerCase(),rows=observations.filter(row=>(state.filter==='all'||(state.filter==='attention'?!['recent','disabled'].includes(row.kind):row.kind===state.filter))&&[row.host.name,row.host.address].some(value=>String(value||'').toLocaleLowerCase().includes(q)));
  const visible=pagedRows(state,rows,12,'#fleet-review');
  $('#fleet-review-count').textContent=rows.length+' matching of '+snapshot.length+' servers. Reasons describe stored observations at page load.';
  $('#fleet-review-cards').innerHTML=rows.length?'<div class="fleet-observation-grid">'+visible.map(tile).join('')+'</div>':empty(snapshot.length?'No servers in this view':'No servers enrolled yet',snapshot.length?'Change the filters to inspect other groups. No matches does not certify full protection.':'Add and verify a server to begin collecting observations.');
 };
 search.oninput=()=>{state.q=search.value;state.offset=0;draw();};filter.onchange=()=>{state.filter=filter.value;state.offset=0;draw();};
 $('#fleet-review-reset').onclick=()=>{Object.assign(state,{q:'',filter:'attention',offset:0});search.value='';filter.value='attention';draw();search.focus();};
 bindPager(state,12,'#fleet-review',draw);
 draw();
}
function pagedRows(state,rows,size,prefix){
 state.offset=Math.min(state.offset,Math.max(0,Math.ceil(rows.length/size)-1)*size);
 $(prefix+'-page').textContent=rows.length?'Page '+(state.offset/size+1)+' of '+Math.ceil(rows.length/size):'No results';
 $(prefix+'-prev').disabled=state.offset===0;$(prefix+'-next').disabled=state.offset+size>=rows.length;
 return rows.slice(state.offset,state.offset+size);
}
function bindPager(state,size,prefix,draw){
 for(const [suffix,step] of [['prev',-size],['next',size]])$(prefix+'-'+suffix).onclick=()=>{state.offset+=step;draw();$(prefix+'-count').scrollIntoView({block:'nearest'});};
}
async function servers(revision=renderRevision){
 if(location.hash==='#servers/deleted')return deletedServers(revision);
 if(location.hash.startsWith('#servers/'))return serverWorkspace(revision);
 const root=$('#content'),state=serverListContext;
 root.innerHTML=heading('Your Linux fleet.','Find a server, review its signals, and open a focused workspace.','<button class="primary" data-admin data-action="add">+ Add server</button>'+(isAdmin()?'<a class="button" href="#servers/deleted">Deleted servers</a>':''))+`
 <section class="card server-directory" aria-label="Managed servers"><div class="toolbar" id="server-list-controls"><label>Find a server<input id="server-list-search" type="search" placeholder="Name, address or architecture" value="${esc(state.q)}"></label><label>Management<select id="server-list-state"><option value="all">All servers</option><option value="enabled">Enabled</option><option value="disabled">Disabled</option></select></label><button id="server-list-clear">Reset filters</button></div><p class="help" id="server-list-count" role="status"></p><div id="server-list-cards"></div><div class="actions server-list-pagination"><button id="server-list-prev">Previous</button><span id="server-list-page" class="help"></span><button id="server-list-next">Next</button></div></section>`;
 const search=$('#server-list-search'),filter=$('#server-list-state');filter.value=state.state;
 const draw=()=>{
  const q=state.q.toLocaleLowerCase(),rows=hosts.filter(h=>(state.state==='all'||(state.state==='enabled'?h.enabled!==false:h.enabled===false))&&[h.name,h.address,h.architecture,h.package_manager].some(value=>String(value||'').toLocaleLowerCase().includes(q)));
  const visible=pagedRows(state,rows,24,'#server-list');
  $('#server-list-count').textContent=rows.length+' matching of '+hosts.length+' managed servers. Status is the latest stored observation.';
  $('#server-list-cards').innerHTML=rows.length?`<div class="server-directory-grid">${visible.map(serverDirectoryCard).join('')}</div>`:empty(hosts.length?'No matching servers':'No servers enrolled yet',hosts.length?'Change or reset the filters to see your fleet.':'Add a server, prepare its target and verify installation before monitoring begins.');
  $('#server-list-clear').disabled=!state.q&&state.state==='all'&&state.offset===0;
 };
 search.oninput=()=>{state.q=search.value;state.offset=0;draw();};filter.onchange=()=>{state.state=filter.value;state.offset=0;draw();};
 $('#server-list-clear').onclick=()=>{Object.assign(state,{q:'',state:'all',offset:0});search.value='';filter.value='all';draw();search.focus();};
 bindPager(state,24,'#server-list',draw);
 draw();
}
function serverDirectoryCard(h){
 const link=serverLink(h.id),id=esc(h.id);
 return `<article class="server-directory-card"><div class="server-card-title">${PatchyUI.icon('servers')}<div><a class="server-name" href="${link}"><strong>${esc(h.name)}</strong></a><small>${esc(PatchyUI.endpoint(h.address,h.port))}</small></div>${badge(h.enabled===false?'disabled':h.state)}</div><dl class="server-card-facts"><div><dt>Architecture</dt><dd>${esc(h.architecture||'Awaiting enrollment')}</dd></div><div><dt>Last contact</dt><dd>${date(h.last_seen)}</dd></div></dl>${h.error?`<p class="notice server-card-error">${esc(h.error)}</p>`:''}<div class="actions"><a class="button primary" href="${link}">Open server →</a><button data-action="inspect" data-id="${id}" ${h.enabled===false?'disabled':''}>${isAdmin()?'Manage':'Inspect'} ↗</button></div>${isAdmin()?`<div class="actions server-card-management"><button class="quiet" data-host-lifecycle="${id}">${h.enabled===false?'Enable':'Disable'} server</button><button class="quiet" data-host-delete="${id}">Delete server</button></div>`:''}</article>`;
}
async function addServer(){
 modal('Enroll server · Step 1 of 3',`${PatchyUI.enrollment(1)}<p class="help">Enter the endpoint Mr Patchy will reach over SSH.</p><form id="host-form"><div class="form-grid"><label>Display name<input name="name" placeholder="Living-room Pi" required maxlength="120"></label><label>IP address or hostname<input name="address" placeholder="192.168.1.50" required></label><label>SSH port<input type="number" name="port" value="22" min="1" max="65535"></label></div><button class="primary">Continue to preparation →</button></form>`);
 $('#host-form').onsubmit=async e=>{e.preventDefault();const button=e.target.querySelector('button');if(button.disabled)return;button.disabled=true;try{const b=Object.fromEntries(new FormData(e.target));b.port=+b.port;const r=await api('/hosts','POST',b);hosts=await api('/hosts');await prepareServer(r.id);}catch(e){toast(e.message+' Close this dialog and review Servers before trying again; the server may already have been created.');}};
}
async function prepareServer(id){
 const h=hosts.find(x=>x.id===id);
 modal('Prepare '+h.name+' · Step 2 of 3',`${PatchyUI.enrollment(2)}<p class="help">Run the script as root on <strong>${esc(h.address)}</strong>. Python 3, OpenSSH server, sudo and OpenSSL must already be installed. RPM targets also need python3-dnf and python3-rpm; SELinux systems need policycoreutils-python-utils. It creates /opt/drpatch, the drpatch user, a dedicated SSH public key and restricted sudo permissions. No network access is needed by the bootstrap.</p><label>Installation mode<select id="install-mode"><option value="curl">1 · Fetch from Mr Patchy with curl</option><option value="download">2 · Download and run on the target</option><option value="offline" selected>3 · Offline preparation, then finish over SSH</option></select></label><div id="install-delivery"><a href="/api/hosts/${id}/installer" download><button>↓ Download Bash installer</button></a><pre>sudo bash mrpatchy-enroll.sh</pre></div><p class="help">Keep the ED25519 SHA256 host fingerprint printed by the script. You will verify it in the next step.</p><button class="primary" id="prepare-next">I ran the script · Proceed to step 3 →</button>`);
 const delivery=$('#install-delivery'),mode=$('#install-mode'),revision=modalRevision;
 let requestNumber=0,selectedEndpoint='default';
 const current=number=>number===requestNumber&&revision===modalRevision&&delivery.isConnected&&mode.value==='curl';
 mode.onchange=async()=>{
  const number=++requestNumber;
  if(mode.value!=='curl'){
   delivery.innerHTML=`<a href="/api/hosts/${id}/installer" download><button>↓ Download Bash installer</button></a><pre>sudo bash mrpatchy-enroll.sh</pre>`;
   return;
  }
  delivery.innerHTML='<p class="help" role="status">Loading HTTPS endpoints…</p>';
  try{
   const {endpoints}=await api(`/hosts/${id}/enrollment-endpoints`);
   if(!current(number))return;
   delivery.innerHTML=`<label>Fetch from HTTPS endpoint<select id="install-endpoint">${endpoints.map(item=>`<option value="${esc(item.id)}">${esc(item.label)} · ${esc(item.url)}</option>`).join('')}</select></label><p class="help">Choose an address reachable from the target. Configure internal and external profiles in Settings → HTTPS.</p><div id="install-command"></div><p class="help">Link expires in one hour. If the target does not trust this endpoint's certificate, add --cacert /path/to/ca.pem to curl using a trusted CA bundle. The ACME directory URL is for certificate issuance, not installer downloads.</p>`;
   const endpoint=$('#install-endpoint'),command=$('#install-command');
   endpoint.value=endpoints.some(item=>item.id===selectedEndpoint)?selectedEndpoint:'default';
   endpoint.onchange=async()=>{
    const number=++requestNumber;
    selectedEndpoint=endpoint.value;
    command.innerHTML='<p class="help" role="status">Generating download link…</p>';
    try{
     const result=await api(`/hosts/${id}/enrollment-link`,'POST',{endpoint:selectedEndpoint});
     if(current(number)&&command.isConnected)command.innerHTML=`<pre>${esc(result.command)}</pre>`;
    }catch(error){if(current(number)){command.textContent='Unable to generate a link. Select an endpoint to retry.';toast(error.message);}}
   };
   await endpoint.onchange();
  }catch(error){if(current(number)){delivery.textContent='Unable to load HTTPS endpoints. Select the curl mode again to retry.';toast(error.message);}}
 };
 $('#prepare-next').onclick=()=>finishServer(id);
}
function resumeEnrollment(){
 if(!isAdmin())return;
 const saved=enrollmentProgress();
 if(saved&&hosts.some(h=>h.id===saved.hostId))finishServer(saved.hostId);
}
// Tab-local progress contains only host/job IDs; never credentials or target output.
function enrollmentProgress(value){
 const key='mrpatchy-enrollment:'+currentUser.username;
 if(value===undefined){try{return JSON.parse(sessionStorage.getItem(key)||'null');}catch{return null;}}
 if(value===null)sessionStorage.removeItem(key);else sessionStorage.setItem(key,JSON.stringify(value));
}
function finishServer(id){
 const h=hosts.find(x=>x.id===id);if(!h||!isAdmin())return;
 const saved=enrollmentProgress();
 if(saved&&saved.hostId!==id){toast('Finish the pending installation from Activity before starting another.');return;}
 modal('Connect and verify · Step 3 of 3',`${PatchyUI.enrollment(3)}<p>Mr Patchy will connect to <strong>${esc(PatchyUI.endpoint(h.address,h.port))}</strong>, install its collector and service, then verify SHA-256 hashes, ownership, permissions and service state.</p><form id="finish-form"><label>ED25519 host fingerprint printed on the target<input name="fingerprint" value="${esc(h.fingerprint)}" placeholder="SHA256:…" required pattern="SHA256:[A-Za-z0-9+/]{43}"></label><p class="help">Verify this against the target console. SSH identity verification is required before connecting.</p><button class="primary">Finish and verify installation</button></form><div id="enrollment-result" class="notice" role="status" aria-live="polite">${saved?'Restoring installation status…':'After verification, your server Overview will open automatically.'}</div><div class="actions"><button id="enrollment-check" hidden>Check installation status</button><button id="enrollment-stop" hidden>Stop tracking (job continues)</button><a href="#activity" class="button">Review Activity</a></div><p class="help">Closing this dialog does not cancel installation. Reopen Finish / verify installation to resume. Reloading this tab restores saved progress.</p>`);
 const revision=modalRevision,session=sessionRevision,result=$('#enrollment-result'),form=$('#finish-form'),button=form.querySelector('button'),check=$('#enrollment-check');
 const current=()=>revision===modalRevision&&session===sessionRevision&&result.isConnected&&$('#modal').open;
 let progress=saved,busy=false;
 const stopTracking=$('#enrollment-stop');stopTracking.hidden=!saved;
 stopTracking.onclick=()=>{enrollmentProgress(null);modalRevision++;$('#modal').close();toast('Tracking stopped. Installation was not cancelled; review Activity before starting more work.');};
 const observe=async()=>{
  if(busy||!current())return;busy=true;button.disabled=true;check.hidden=true;
  try{
   if(!progress.jobId){
    const rows=await api('/jobs?host_id='+encodeURIComponent(id)+'&limit=100');if(!current())return;
    const matches=rows.filter(j=>j.host_id===id&&j.action==='deploy'&&!progress.previous.includes(j.id));
    if(matches.length!==1)throw Error('Installation submission is unconfirmed. Review Activity before retrying; no installation has been replayed.');
    progress.jobId=matches[0].id;enrollmentProgress(progress);
   }
   while(current()){
    const state=await api('/jobs/'+encodeURIComponent(progress.jobId));if(!current())return;
    if(state.host_id!==id||state.action!=='deploy')throw Error('Operation identity does not match this installation. Review Activity.');
    result.textContent='Installation '+state.state+(state.output?' · '+state.output:'');
    if(state.state==='complete'){
     const list=await api('/hosts');if(!current())return;
     const host=list.find(item=>item.id===id);if(!host||host.enabled===false||host.deleted_at)throw Error('Server is unavailable or management is disabled. Review Activity.');
     hosts=list;selected=id;enrollmentProgress(null);
     // Keep the verified confirmation on the destination, including after refresh.
     sessionStorage.setItem('mrpatchy-enrollment-success:'+currentUser.username,id);
     modalRevision++;$('#modal').close();await navigateWithToast(serverLink(id),'Installation verified for '+host.name+'. Monitoring data will arrive shortly.');return;
    }
    if(['failed','interrupted','cancelled'].includes(state.state)){
     stopTracking.hidden=true;enrollmentProgress(null);progress=null;button.disabled=false;button.textContent='Retry installation after reviewing Activity';
     result.textContent+=' · Review the error and recovery status before explicitly retrying.';return;
    }
    if(!['queued','running'].includes(state.state))throw Error('Unrecognized installation state. Review Activity.');
    await new Promise(resolve=>setTimeout(resolve,2000));
   }
  }catch(error){if(current()){result.textContent=error.message;check.hidden=false;}}
  finally{busy=false;}
 };
 check.onclick=observe;
 form.onsubmit=async e=>{
  e.preventDefault();if(busy||progress||!current())return;busy=true;button.disabled=true;
  try{
   const rows=await api('/jobs?host_id='+encodeURIComponent(id)+'&limit=100');if(!current())return;
   const active=rows.filter(j=>j.action==='deploy'&&['queued','running'].includes(j.state));
   if(active.length>1)throw Error('Multiple active installations. Review Activity before proceeding.');
   if(!active.length){await api(`/hosts/${id}/fingerprint`,'PUT',{fingerprint:new FormData(form).get('fingerprint')});if(!current())return;}
   progress={hostId:id,jobId:active[0]?.id||'',previous:rows.map(j=>j.id),requestId:crypto.randomUUID()};
   // Persist before the POST: a lost response must never cause a blind replay.
   enrollmentProgress(progress);stopTracking.hidden=false;
   sessionStorage.removeItem('mrpatchy-enrollment-success:'+currentUser.username);
   if(!progress.jobId){const job=await api(`/hosts/${id}/actions/deploy`,'POST');if(enrollmentProgress()?.requestId!==progress.requestId)return;progress.jobId=job.job_id;enrollmentProgress(progress);}
   if(!current())return;
   result.textContent='Installation queued. Waiting for backend verification…';
  }catch(error){if(current()){result.textContent=error.message;if(progress)check.hidden=false;else button.disabled=false;}}
  finally{busy=false;}
  if(progress&&current())observe();
 };
 if(saved){button.disabled=true;observe();}
}
async function inspect(id){
 selected=id;const h=hosts.find(x=>x.id===id);
 modal(h.name,`<div class="toolbar">${badge(h.state)}<span class="muted">${esc(PatchyUI.endpoint(h.address,h.port))}</span></div>${h.error?`<div class="notice">${esc(h.error)}</div>`:''}<div data-admin><h3>Installation &amp; recovery</h3><p class="help">The personalized bootstrap is always available. Re-running it restores this server’s assigned public key and restricted helper.</p><div class="actions"><a href="/api/hosts/${id}/installer" download><button>↓ Download Bash installer</button></a><button id="resume-enrollment">Prepare / re-enroll</button><button id="finish-enrollment">Finish / verify installation</button></div></div><h3>Monitoring &amp; maintenance</h3><div class="actions"><button data-operator data-action="refresh" data-id="${id}">Check repositories</button><button data-admin id="host-history">Observation &amp; inventory history</button><button data-admin id="repair-packages">Repair broken package state</button><button data-admin id="release-upgrade" ${h.package_manager==='rpm'?'disabled title="RPM distribution upgrades are not supported yet"':''}>Plan distribution upgrade</button></div>${h.integrity.length?`<h3>Integrity findings</h3><pre>${esc(JSON.stringify(h.integrity,null,2))}</pre>`:''}${serverManagementPanel(h)}`);
 $('#resume-enrollment').onclick=()=>prepareServer(id);$('#finish-enrollment').onclick=()=>finishServer(id);
 $('#host-history').onclick=()=>historyModal(id);
 $('#release-upgrade').onclick=()=>releasePanel(id);
 $('#repair-packages').onclick=()=>{modal('Review package recovery',`<p>${h.package_manager==='rpm'?'Rebuild and verify the RPM database':'Run dpkg configuration and APT dependency repair'} on <strong>${esc(h.name)}</strong>?</p><p class="help">${h.package_manager==='rpm'?'This verifies database structure only. Review dependency problems separately; no packages will be installed or removed.':'This can install dependencies and run maintainer scripts that restart services. Package removal is prohibited.'} Review the result in Activity before retrying a failed repair.</p><button class="primary" id="confirm-repair">Run recovery</button>`);$('#confirm-repair').onclick=async()=>{try{await api(`/hosts/${id}/actions/repair`,'POST');$('#modal').close();toast('Package recovery queued');}catch(e){toast(e.message);}};};
}
function recoverySummary(policy){return `<div class="notice"><strong>Approved recovery policy</strong><p>Automatic reboot: <strong>${policy.reboot?'enabled — services may be interrupted':'disabled'}</strong><br>Snapshot rollback: <strong>${policy.rollback?'enabled after a failed patch or post-reboot health check':'disabled'}</strong></p><small>Changing this policy before execution requires a new patch approval.</small></div>`;}
function historyModal(id,kind='inventory'){
 modalRevision++;$('#modal').close();const link=serverLink(id,'history/'+kind);
 if(location.hash===link)render();else location.hash=link;
}

async function packages(revision=renderRevision,context=null){const root=context?.root||$('#content'),hostId=context?.hostId||selected;if(!selected){root.innerHTML=heading('Packages, accounted for.','Installed versions and centrally discovered updates.')+empty('Enroll a server first','Package inventory appears after the collector is installed.');return;}root.innerHTML=(context?'':heading('Packages, accounted for.','Candidates come from central APT / DNF repository checks. Held and version-locked packages stay protected.'))+`<div class="toolbar">${context?'':serverSelect()}<input id="package-search" aria-label="Find a package" placeholder="Find a package…"><label class="check"><input id="updates-only" type="checkbox"> Updates only</label><button class="primary" data-operator id="patch-selected">Install selected updates</button></div><div class="selection-bar"><div class="actions" data-operator><button id="select-all-updates">Select all eligible updates</button><button id="clear-updates">Clear selection</button></div><span id="selection-summary" role="status">0 selected</span><a href="${context?serverLink(hostId,'history'):'#history'}" class="mint">Package history →</a></div><p class="help">Select all applies to the current filter, up to 500 updates per reviewed batch. Held, broken and already queued packages are excluded. Expected installation shows an estimated start, separate from the policy deadline.</p><div class="card" id="package-table"></div>`;if(!context)bindSelect(packages);const contextKey=(context?'server:':'fleet:')+hostId,savedFilters=packageViewContext.get(contextKey);if(savedFilters){$('#package-search').value=savedFilters.search;$('#updates-only').checked=savedFilters.updates;}const rememberFilters=()=>packageViewContext.set(contextKey,{search:$('#package-search').value,updates:$('#updates-only').checked});let timer,requestNumber=0;const table=$('#package-table');const updateSelection=()=>{if(!table.isConnected)return;const eligible=table.querySelectorAll('.pkg-check:not(:disabled)').length;$('#selection-summary').textContent=table.querySelectorAll('.pkg-check:checked').length+' selected · '+eligible+' eligible in this view';};$('#select-all-updates').onclick=()=>{const boxes=[...table.querySelectorAll('.pkg-check:not(:disabled)')];boxes.forEach((box,i)=>box.checked=i<500);updateSelection();if(boxes.length>500)toast('Selected the first 500 eligible updates. Install in reviewed batches.');};$('#clear-updates').onclick=()=>{table.querySelectorAll('.pkg-check').forEach(box=>box.checked=false);updateSelection();};const load=async()=>{if(selected!==hostId||!table.isConnected)return;const request=++requestNumber;const rows=await api(`/hosts/${hostId}/packages?q=${encodeURIComponent($('#package-search').value)}&updates=${$('#updates-only').checked}`);if(request!==requestNumber||selected!==hostId||!table.isConnected)return;table.innerHTML=rows.length?`<div class="table-wrap"><table class="package-table"><thead><tr><th></th><th>Package</th><th>Installed / state</th><th>Candidate</th><th>Priority</th><th>Policy deadline</th><th>AI importance</th><th>Expected installation</th></tr></thead><tbody>${rows.map(p=>`<tr><td><input type="checkbox" class="pkg-check" aria-label="Select ${esc(p.name)}" data-version="${esc(p.candidate)}" value="${esc(p.name)}" ${currentUser?.role==='viewer'||!p.candidate||p.held||p.installation?.job_id||['queued','installing'].includes(p.installation?.state)||(p.dpkg_state&&!p.dpkg_state.endsWith(' installed'))?'disabled':''}></td><td>${esc(p.name)}${p.held?'<small>Held by target policy</small>':''}</td><td>${esc((p.installed_versions||[p.installed]).join(', '))}<small>${esc(p.dpkg_state||'install ok installed')}</small></td><td>${esc(p.candidate||'—')}</td><td>${p.candidate?`<select ${isAdmin()?'':'disabled'} class="priority-select" data-name="${esc(p.name)}" aria-label="Patch priority">${['auto','critical','high','normal','low'].map(v=>`<option value="${v}" ${v===(p.priority_manual?p.priority:'auto')?'selected':''}>${v==='auto'?'Auto ('+p.priority+')':v}</option>`).join('')}</select>`:'—'}</td><td>${p.due?date(p.due):'—'}</td><td>${assessmentCell(p.assessment)}${p.installed_assessment?assessmentCell(p.installed_assessment):''}</td><td class="installation-cell">${installationCell(p.installation)}</td></tr>`).join('')}</tbody></table></div>`:empty('No matching packages','Finish enrollment and check repositories to populate the inventory.');updateSelection();};$('#package-table').addEventListener('change',async e=>{if(e.target.matches('.pkg-check')){if(table.querySelectorAll('.pkg-check:checked').length>500){e.target.checked=false;toast('A reviewed batch may include at most 500 updates.');}updateSelection();return;}if(!e.target.matches('.priority-select'))return;try{await api(`/hosts/${hostId}/priority`,'PUT',{name:e.target.dataset.name,priority:e.target.value});toast('Patch priority saved');await load();}catch(error){toast(error.message);}});$('#package-search').oninput=()=>{rememberFilters();clearTimeout(timer);timer=setTimeout(()=>load().catch(e=>toast(e.message)),250);};$('#updates-only').onchange=()=>{rememberFilters();load().catch(e=>toast(e.message));};$('#patch-selected').onclick=async()=>{const chosen=[...table.querySelectorAll('.pkg-check:checked')];const names=chosen.map(x=>x.value);const expected_versions=Object.fromEntries(chosen.map(x=>[x.value,x.dataset.version]));if(!names.length)return toast('Select at least one available update');if(names.length>500)return toast('Select at most 500 updates per reviewed batch');let policy;try{policy=await api(`/hosts/${hostId}/patch-policy`);}catch(error){return toast(error.message);}if(selected!==hostId||!table.isConnected)return;modal('Review patch installation',`<p>Install the selected updates on <strong>${esc(hostName(hostId))}</strong>?</p><p class="help">Package scripts may restart services. Package removal and held-package upgrades are prohibited.</p>${recoverySummary(policy)}<pre>${esc(names.join('\n'))}</pre><button class="primary" id="confirm-patch">Install ${names.length} selected updates</button>`);$('#confirm-patch').onclick=async event=>{const button=event.target;button.disabled=true;try{await api(`/hosts/${hostId}/patch`,'POST',{packages:names,expected_versions,expected_recovery_policy:policy});$('#modal').close();toast('Installation queued. Follow progress in Activity.');if(table.isConnected)await load();}catch(e){toast(e.message);button.disabled=false;}};};await load();}
async function repositories(revision=renderRevision,context=null){const root=context?.root||$('#content'),hostId=context?.hostId||selected;if(!selected){root.innerHTML=heading('Repositories, in view.','Every configured source, with its original format preserved.')+empty('No repository inventory yet','Enroll a server to view and manage its sources.');return;}const r=await api(`/hosts/${hostId}/repositories`),rpm=r.package_manager==='rpm',editable=path=>r.editable_paths?r.editable_paths.includes(path):!path.includes('preferences');if(selected!==hostId||!currentView(revision,context?'servers':'repositories')||!root.isConnected)return;root.innerHTML=(context?'':heading('Repositories, in view.','Edit sources, repair URLs, manage suites and signing keys.'))+`<div class="toolbar">${context?'':serverSelect()}<div class="actions"><button data-operator data-action="refresh" data-id="${hostId}">↻ Check now</button><button id="new-source">+ Add source</button><button id="upload-key">Upload signing key</button><button id="repository-access">Repository access</button><button id="restore-backup">Restore backup</button></div></div><div class="card"><div class="card-head"><h2>Source configuration</h2><small>Last successful check: ${date(r.last_checked)}</small></div>${r.error?`<div class="notice">${esc(r.error)}</div>`:''}<p class="help">Changes are backed up on the target. Disable a Deb822 stanza with Enabled: no, a .repo section with enabled=0, comment a .list line, or save an empty file to remove its repositories. A failed refresh never marks stale metadata as current.</p><div class="toolbar">${(r.health||[]).map(x=>`<span title="${esc(x.detail)}">${esc(x.path.split('/').pop())} ${badge(x.state)}</span>`).join('')}</div><div id="source-files">${Object.entries(r.files).map(([path,content])=>`<details class="source"><summary>${esc(path)}</summary><textarea data-path="${esc(path)}" ${!editable(path)?'readonly':''}>${esc(content)}</textarea>${editable(path)?'<button class="save-source">Review &amp; save</button>':'<p class="help">Package-manager policy is mirrored centrally. Edit this policy on the target.</p>'}</details>`).join('')||'<p class="muted">Awaiting inventory.</p>'}</div></div><div class="card"><h2>Discovered signing keys</h2><pre>${esc(r.keys.join('\n')||'No keys discovered')}</pre><p class="help">${rpm?'RPM keys are imported into the target RPM trust database. Set gpgkey=file:///etc/pki/rpm-gpg/your-key.asc in the .repo file.':'For rotated keys, upload a replacement and point the repository’s Signed-By setting at /etc/apt/keyrings/your-key.asc.'}</p></div>`;if(!context)bindSelect(repositories);$('#repository-access').onclick=()=>repositoryAccessModal(hostId);$('#restore-backup').onclick=()=>backupModal(hostId);document.querySelectorAll('.save-source').forEach(btn=>btn.onclick=()=>{const ta=btn.previousElementSibling;saveSource(ta.dataset.path,ta.value,hostId);});$('#new-source').onclick=()=>{modal('Add repository source',`<form id="new-source-form"><label>Path<input name="path" value="${rpm?'/etc/yum.repos.d/custom.repo':'/etc/apt/sources.list.d/custom.sources'}" required></label><label>Source configuration<textarea name="content" placeholder="${rpm?'[vendor]&#10;name=Vendor&#10;baseurl=https://example.org/rpm/$releasever/$basearch&#10;enabled=1&#10;gpgcheck=1&#10;gpgkey=file:///etc/pki/rpm-gpg/vendor.asc':'Types: deb&#10;URIs: https://example.org/debian&#10;Suites: stable&#10;Components: main&#10;Signed-By: /etc/apt/keyrings/vendor.asc'}" required></textarea></label><button class="primary">Review source</button></form>`);$('#new-source-form').onsubmit=e=>{e.preventDefault();const b=Object.fromEntries(new FormData(e.target));$('#modal').close();saveSource(b.path,b.content,hostId);};};$('#upload-key').onclick=()=>{modal('Upload repository signing key',`<p class="help">Verify the key fingerprint with the repository publisher before uploading. ${rpm?'RPM keys are imported into the system RPM trust database and can validate packages from any configured RPM repository.':'It will only be trusted by repositories referencing it through Signed-By.'}</p><form id="key-form"><label>Key file (.asc or .gpg)<input name="key" type="file" accept=".asc,.gpg" required></label><button class="primary">Upload key to target</button></form>`);const request=modalRequest();$('#key-form').onsubmit=async e=>{e.preventDefault();const button=e.target.querySelector('button');if(button.disabled)return;button.disabled=true;try{const f=e.target.key.files[0];const bytes=new Uint8Array(await f.arrayBuffer());let raw='';for(const b of bytes)raw+=String.fromCharCode(b);await api(`/hosts/${hostId}/keys`,'PUT',{name:f.name,data:btoa(raw)});request.close('Key upload queued');}catch(error){request.error(error);if(request.active())button.disabled=false;}};};}
function saveSource(path,content,hostId){modal('Review repository change',`<p class="help">Write this configuration to ${esc(hostName(hostId))}. Existing content is backed up under /opt/drpatch/backups.</p><h3>${esc(path)}</h3><pre>${esc(content||'(empty file — repositories disabled)')}</pre><button class="primary" id="confirm-source">Save to target</button>`);const request=modalRequest();$('#confirm-source').onclick=async event=>{const button=event.currentTarget;if(button.disabled)return;button.disabled=true;try{await api(`/hosts/${hostId}/repositories`,'PUT',{path,content});request.close('Repository change queued');}catch(error){request.error(error);if(request.active())button.disabled=false;}};}
async function investigations(revision=renderRevision,context=null,offset=null){const key=context?.hostId||'fleet';offset=offset??investigationViewContext.get(key)??0;const root=context?.root||$('#content');const base=context?serverLink(context.hostId,'investigations'):'#investigations';const canChange=!context||(context.host.enabled!==false&&!context.host.deleted_at);if(location.hash.startsWith(base+'/item/'))return investigationAssessmentPage(revision,context,base);const [rows,status]=await Promise.all([api('/investigations?'+(context?'host_id='+encodeURIComponent(context.hostId)+'&':'')+'offset='+offset+'&limit=50'),context?Promise.resolve(null):api('/investigation-status')]);if(!currentView(revision,context?'servers':'investigations')||!root.isConnected)return;investigationViewContext.set(key,offset);root.innerHTML=(context?'<p class="help">Investigations for this server only. Approvals apply to the exact executable identity and behavior; AI assessments remain advisory.</p>':heading('A second look at the unfamiliar.','Host-specific executable hashes, identities, and connection patterns.')+(isAdmin()?triageStatus(status):'')+`<div class="notice">Queue: ${status.pending} pending${isAdmin()?' · '+status.hourly_limit+'/hour':''} · ${status.enabled?'enabled':'disabled'}. Oldest pending: ${date(status.oldest)}. AI assessments are advisory. A known-good approval applies only to this exact executable hash, user, and connection pattern on this host. Changed behavior creates a new investigation.</div>`)+(rows.length?rows.map(r=>`<div class="card investigation"><div><div class="eyebrow">${esc(hostName(r.host_id))}</div><h3><code>${esc(r.evidence.executable)}</code></h3><p class="help">UID ${esc(r.evidence.uid)} · Last seen ${date(r.last_seen)}</p>${badge(r.approved?'approved':r.verdict)}</div>${canChange?`<button data-admin data-action="trust" data-id="${r.id}" data-approved="${r.approved}">${r.approved?'Revoke approval':'Review & approve'}</button>`:''}<div class="description">${esc(r.analysis)}</div><div class="actions" data-admin><a class="button" href="${base}/item/${encodeURIComponent(r.id)}/history">Assessment history</a>${canChange&&['low','medium','high','unknown'].includes(r.verdict)?`<button data-action="retriage-investigation" data-id="${esc(r.id)}">Re-triage</button>`:''}</div>${r.retry?`<p class="help">Retry: ${esc(r.retry.state.replaceAll('_',' '))} · ${r.retry.attempts} attempt${r.retry.attempts===1?'':'s'}${r.retry.next_at?' · Eligibility: '+date(r.retry.next_at):''}${r.retry.reason?'<br>'+esc(r.retry.reason):''}</p>`:''}${canChange&&!r.approved&&['error','pending'].includes(r.verdict)?`<button data-admin data-action="retry-investigation" data-id="${r.id}">Retry investigation</button>`:''}<details><summary>Evidence &amp; SHA-256</summary><pre>${esc(JSON.stringify(r.evidence,null,2))}</pre></details></div>`).join(''):empty('Nothing to investigate yet','New executable hashes and connection patterns appear here after a server starts reporting.'));serverPagination(root,offset,rows.length===50,n=>investigations(revision,context,n),50);}
async function activity(revision=renderRevision,context=null,offset=null){
 if(!context&&location.hash==='#activity/workers')return workerRegistrations(revision);
 if(!context&&location.hash.startsWith('#activity/audit'))return auditWorkspace(revision);
 if(!context&&location.hash.startsWith('#activity/jobs/'))return operationDetail(revision,null,location.hash.slice('#activity/jobs/'.length));
 const key=context?.hostId||'fleet';offset=offset??activityViewContext.get(key)??0;
 const root=context?.root||$('#content');
 const jobs=await api('/jobs?'+(context?'host_id='+encodeURIComponent(context.hostId)+'&':'')+'offset='+offset+'&limit=50');
 if(!currentView(revision,context?'servers':'activity')||!root.isConnected)return;
 activityViewContext.set(key,offset);
 root.innerHTML=(context?'':heading('A record of the work.','Queued operations, results, and recovery decisions.')+activityNavigation('operations'))+`<div class="card"><h2>Operations</h2>${jobs.length?jobs.map(j=>`<details class="source"><summary>${badge(j.state)} ${esc(j.action)} · ${esc(hostName(j.host_id))} · ${date(j.created)}</summary>${j.ai_deferred?`<p class="help">${j.next_at?'Next AI eligibility: '+date(j.next_at):'Waiting for server and global AI resume.'}</p>`:''}<pre>${esc(j.output||'Awaiting execution')}</pre><a class="button" href="${context?serverLink(context.hostId,'patching/jobs/'+encodeURIComponent(j.id)):'#activity/jobs/'+encodeURIComponent(j.id)}">Open operation detail →</a>${isAdmin()&&j.state==='queued'?`<button class="cancel-job" data-id="${j.id}">Cancel queued operation</button>`:''}${isAdmin()&&['running','recovery_required'].includes(j.state)?`<button class="reconcile-job" data-id="${j.id}" data-action="${esc(j.action)}">Review interrupted operation</button>`:''}</details>`).join(''):empty('No operations yet','Enrollment, repository checks, and patch runs will appear here.')}</div>`;
 document.querySelectorAll('.cancel-job').forEach(button=>button.onclick=()=>{modal('Cancel queued operation',`<p>Cancel this operation before it starts? A linked release plan will also be cancelled and require a new plan.</p><button class="primary" id="confirm-cancel-job">Cancel operation</button>`);$('#confirm-cancel-job').onclick=async event=>{event.target.disabled=true;try{await api('/operations/jobs/'+button.dataset.id+'/cancel','POST');$('#modal').close();if(root.isConnected)await activity(revision,context,offset);toast('Operation cancelled');}catch(error){toast(error.message);event.target.disabled=false;}};});
 document.querySelectorAll('.reconcile-job').forEach(button=>button.onclick=()=>{
  const advisory=['security-plan','startup-plan'].includes(button.dataset.action);
  modal('Reconcile interrupted operation',advisory?`<p>Review the retained AI run, per-call usage receipt, and spend reservation first. A transmitted call without a receipt may still have incurred a charge. This releases the server queue; it does not retry the advisory request.</p><form id="reconcile-form"><label class="check"><input type="checkbox" required>I reviewed the retained AI and spend records and want to release queued work</label><button class="primary">Reconcile and release queue</button></form>`:`<p>Verify package state, services, reboot status and any snapshot rollback on the target through a trusted console first. Check for a pending reboot timer. This releases the host’s queue; it does not retry the interrupted operation.</p><p class="help">Mr Patchy also requires both the central worker lock and target mutation lock to be idle.</p><form id="reconcile-form"><label class="check"><input type="checkbox" required>I verified the target state and it is safe to resume queued work</label><button class="primary">Reconcile and release queue</button></form>`);
  $('#reconcile-form').onsubmit=async e=>{e.preventDefault();try{await api('/operations/jobs/'+button.dataset.id+'/reconcile','POST',advisory?{verified_ai_receipts:true}:{verified_target_state:true});$('#modal').close();if(root.isConnected)await activity(revision,context,offset);}catch(error){toast(error.message);}};
 });
 serverPagination(root,offset,jobs.length===50,n=>activity(revision,context,n),50);
}
async function operationDetail(revision,context,rawId){
 const root=context?.root||$('#content'),scope=context?.hostId,back=scope?serverLink(scope,'patching'):'#activity';
 const current=()=>currentView(revision,scope?'servers':'activity')&&root.isConnected;
 if(!scope)root.innerHTML=heading('Follow an operation.','Stored output and outcome, without replaying work.')+activityNavigation('operations')+PatchyUI.loading();
 let id;try{id=decodeURIComponent(rawId);}catch{id='';}
 try{
  if(!id)throw Error('Invalid operation link');
  const data=await api('/jobs/'+encodeURIComponent(id)+(scope?'?host_id='+encodeURIComponent(scope):''));if(!current())return;
  if(data.id!==id||(scope&&data.host_id!==scope))throw Error('Operation identity differs; reopen the operation list.');
  if(!scope){$('#breadcrumb').textContent='Workspace / Activity / Operation';document.title='Operation '+data.id+' · Mr Patchy';}
  const fact=(name,value)=>'<div><dt>'+name+'</dt><dd>'+esc(value??'Not reported')+'</dd></div>';
  root.innerHTML=(scope?'':heading('Follow an operation.','Stored output and outcome, without replaying work.')+activityNavigation('operations'))+'<a class="button" href="'+back+'">← Back to operations</a><section class="card activity-detail"><div class="history-detail-heading">'+PatchyUI.portrait()+'<h2>Operation detail</h2></div>'+badge(data.state)+'<dl class="server-facts">'+fact('Operation ID',data.id)+fact('Server ID',data.host_id)+fact('Action',data.action)+fact('Created',date(data.created))+(data.ai_deferred?fact('AI eligibility',data.next_at?date(data.next_at):'Waiting for server and global AI resume'):'')+'</dl><p class="help">This is a stored observation, not a live target verification. Missing output is not proof of success. Cancellation and interrupted-operation review remain on the operation list with their existing confirmations.</p><h3>Recorded output</h3><pre tabindex="0" aria-label="Recorded operation output">'+esc(data.output||'No output recorded yet.')+'</pre></section>';
 }catch(error){if(current())root.innerHTML=(scope?'':heading('Unable to load operation.','The record may be unavailable.')+activityNavigation('operations'))+empty('Operation unavailable',esc(error.message),'<a class="button" href="'+back+'">Back to operations</a><button id="operation-detail-retry">Retry operation</button>');const retry=root.querySelector('#operation-detail-retry');if(retry)retry.onclick=render;}
}
async function auditWorkspace(revision){
 const root=$('#content');if(!isAdmin()){root.innerHTML=heading('Audit trail.','Administrator review only.')+empty('Administrator access required','Return to operations for records available to your role.','<a class="button" href="#activity">Operations</a>');return;}
 let id;try{id=decodeURIComponent(location.hash.slice('#activity/audit'.length).replace(/^\//,''));}catch{id='invalid';}
 const current=()=>currentView(revision,'activity')&&root.isConnected;
 root.innerHTML=heading('Every decision leaves a trail.','Historical audit records, separate from execution output.')+activityNavigation('audit')+'<div id="audit-workspace">'+PatchyUI.loading()+'</div>';
 $('#breadcrumb').textContent='Workspace / Activity / Audit trail';document.title='Audit trail · Mr Patchy';
 const panel=root.querySelector('#audit-workspace'),note='<p class="help">Audit entries record reported decisions and events; they do not certify target state. Retention can remove entries. Offset pages may shift as new entries arrive.</p>';
 if(id){try{const data=await api('/audit/entries/'+encodeURIComponent(id));if(!current()||!panel.isConnected)return;if(String(data.id)!==id)throw Error('Audit entry identity differs; reopen the list.');panel.innerHTML='<a class="button" href="#activity/audit">← Back to audit trail</a><section class="card activity-detail"><div class="history-detail-heading">'+PatchyUI.portrait()+'<h2>Audit entry</h2></div>'+note+'<p>'+date(data.created)+' · Record '+esc(data.id)+'</p><h3>'+esc(data.action)+'</h3><pre tabindex="0" aria-label="Audit entry detail">'+esc(data.detail)+'</pre></section>';}catch(error){if(current()&&panel.isConnected){panel.innerHTML=empty('Audit entry unavailable',esc(error.message),'<a class="button" href="#activity/audit">Back to audit trail</a><button id="audit-retry">Retry entry</button>');panel.querySelector('button').onclick=render;}}return;}
 let ticket=0;const load=async(offset)=>{const turn=++ticket;panel.innerHTML=PatchyUI.loading();try{const rows=await api('/audit?offset='+offset+'&limit=50');if(!current()||!panel.isConnected||turn!==ticket)return;activityViewContext.set('audit',offset);panel.innerHTML='<section class="card activity-detail"><h2>Audit trail</h2>'+note+(rows.length?'<div class="table-wrap"><table><thead><tr><th>When</th><th>Action</th><th>Record</th></tr></thead><tbody>'+rows.map(row=>'<tr><td>'+date(row.created)+'</td><td>'+esc(row.action)+'</td><td><a class="button" href="#activity/audit/'+encodeURIComponent(row.id)+'">Open entry '+esc(row.id)+'</a></td></tr>').join('')+'</tbody></table></div>':empty('No audit entries on this page','Try Previous or review the retention settings.'))+'</section>';serverPagination(panel,offset,rows.length===50,load,50);}catch(error){if(current()&&panel.isConnected&&turn===ticket){panel.innerHTML=empty('Audit trail unavailable',esc(error.message),'<button>Retry audit trail</button>');panel.querySelector('button').onclick=()=>load(offset);}}};
 await load(activityViewContext.get('audit')||0);
}
function activityNavigation(current){
 return isAdmin()?`<nav class="overview-sections" aria-label="Activity pages"><a href="#activity" ${current==='operations'?'class="active" aria-current="page"':''}>Operations</a><a href="#activity/audit" ${current==='audit'?'class="active" aria-current="page"':''}>Audit trail</a><a href="#activity/workers" ${current==='workers'?'class="active" aria-current="page"':''}>Workers</a></nav>`:'';
}
async function workerRegistrations(revision,offset=0){
 const root=$('#content');
 if(!isAdmin()){root.innerHTML=heading('Worker registrations.','Runtime details require administrator access.')+empty('Administrator access required','Return to operations to review work available to your role.','<a class="button" href="#activity">Operations</a>');return;}
 const data=await api('/operations/workers?offset='+offset);
 if(!currentView(revision,'activity')||!root.isConnected)return;
 $('#breadcrumb').textContent='Workspace / Activity / Workers';document.title='Workers · Mr Patchy';
 const field=value=>esc(value===null||value===undefined?'Not reported':value);
 root.innerHTML=heading('Worker registrations.','Reported scheduler loops, with explicit freshness and readiness limits.')+activityNavigation('workers')+`<section class="card"><h2>Coverage & readiness</h2><ul class="help">${data.gaps.map(gap=>`<li>${esc(gap)}</li>`).join('')}</ul><p class="help">A heartbeat expires after ${field(data.fresh_seconds)} seconds. Runtime type is reported configuration. A fresh report does not verify Docker-container health or successful target access.</p><p class="help">Startup schema structure checks required tables, columns and primary keys. Types and other constraints remain unassessed; this point-in-time check is not general readiness.</p></section><section class="card" id="expected-workers"><h2>Expected workers</h2><p class="help">Controller-configured identities, independent of the registration page. Missing is not a verified stopped process. Readiness is not assessed.</p>${data.expectation_error?`<p role="alert">${esc(data.expectation_error)}</p>`:(data.expected||[]).length?`<div class="expected-worker-grid">${data.expected.map(row=>`<article class="expected-worker"><h3>${esc(row.id)}</h3>${badge(row.state)}<p>${esc(row.reason)}</p><p class="help">Registration: ${row.registered?'available':'missing'} · Last report: ${row.age_seconds===null?'unavailable':esc(Math.floor(row.age_seconds))+' seconds ago'}</p></article>`).join('')}</div>`:empty('Worker expectations not configured','Configure MRPATCHY_EXPECTED_WORKER_IDS on the controller to track missing workers. Registered history below remains available.')}</section><section class="card"><h2>Registered runtimes</h2><p class="help">On narrow screens, scroll the table horizontally for version, workload and timestamp details.</p>${data.items.length?`<div class="table-wrap"><table class="worker-registry-table"><thead><tr><th>Identity / runtime</th><th>Liveness</th><th>Version / coordinator</th><th>Capacity & active work</th><th>Last report</th></tr></thead><tbody>${data.items.map((row,index)=>`<tr><td><strong>${field(row.id)}</strong><small>${field(row.role)} · ${field(row.deployment_type)}<br>Boot ${field(row.boot_id)}</small><small>Controller/key startup check: ${row.controller_state==='verified'?'verified at startup':row.controller_state==='not_checked'?'not enabled':'not reported'}. Does not verify shared files or target access.</small><small>Schema structure / receipt protocol: ${row.schema_structure==='verified'?'verified at startup':row.schema_structure==='not_checked'?'not enabled':'not reported'}.</small><strong>${row.control?.action==='drain'?'Drain requested':row.control?.action==='resume'?(row.control.revision?'Resume requested':'No drain requested'):'Control unavailable'}</strong><small>Requested revision ${field(row.control?.revision)} · observed ${field(row.control_revision)}<br>Requests apply only to this boot. Refresh to observe progress.</small>${row.controllable?`<button class="worker-control" data-index="${index}">${row.control.action==='drain'?'Resume admission':'Drain worker'}</button>`:'<small>Refresh or inspect this runtime before controlling it.</small>'}</td><td>${badge(row.state)}<small>${field(row.reason)}</small><small>Readiness: not assessed</small></td><td>${field(row.version)}<small>Coordinator at report: ${row.coordinator===true?'yes':row.coordinator===false?'no':'unknown'}</small></td><td>${field(row.active_jobs?.length)} assigned jobs / ${field(row.job_capacity)} capacity<small>${field(row.active_polls)} running polls / ${field(row.poll_capacity)} capacity<br>${field(row.pending_polls)} queued polls · notification: ${row.notification_active===true?'assigned':row.notification_active===false?'idle':'unknown'}<br>AI tasks: ${row.active_ai_tasks===null||row.active_ai_tasks===undefined?'count unavailable':field(row.active_ai_tasks)} / ${field(row.ai_capacity)} capacity</small>${row.active_jobs?.length?`<details><summary>Reported job IDs</summary><ul>${row.active_jobs.map(id=>`<li>${esc(id)}</li>`).join('')}</ul></details>`:''}</td><td>${row.heartbeat?date(row.heartbeat):'Not reported'}<small>Reported uptime: ${row.uptime_seconds===null||row.uptime_seconds===undefined?'unavailable':field(Math.floor(row.uptime_seconds))+' seconds'}</small></td></tr>`).join('')}</tbody></table></div>`:empty('No workers registered yet','Rebuild and restart worker runtimes to begin reporting. Older workers do not register; absence here is not proof that no worker is running.')}<div class="actions"><button id="worker-prev" ${offset?'':'disabled'}>Previous</button><span class="help">Page ${offset/50+1}</span><button id="worker-next" ${data.more?'':'disabled'}>Next</button></div></section>`;
 root.querySelectorAll('.worker-control').forEach(button=>button.onclick=()=>{
  const row=data.items[Number(button.dataset.index)],action=row.control.action==='drain'?'resume':'drain';
  modal(action==='drain'?'Drain worker':'Resume worker admission',`<p><strong>${esc(row.id)}</strong><br>Boot <code>${esc(row.boot_id)}</code></p><p>${action==='drain'?'Stop new assignments after the worker observes this request. Assigned operations, queued polls, AI and notification work finish normally; they are not cancelled. The coordinator role is released.':'Allow this boot to accept work again under existing scheduler, global AI and per-server policies.'}</p><p class="help">This is a cooperative request, not a process shutdown, readiness check or recovery approval. Refresh Workers to see the observed revision and draining/drained state. Restarting creates a new boot and clears this boot-specific request.</p><form id="worker-control-form"><label>Reason<textarea name="reason" minlength="10" maxlength="1000" required></textarea></label><button class="primary">${action==='drain'?'Request drain':'Request resume'}</button></form>`);
  const form=$('#worker-control-form'),dialog=modalRevision;
  form.onsubmit=async event=>{event.preventDefault();const submit=form.querySelector('button');if(submit.disabled)return;submit.disabled=true;
   try{await api('/operations/workers/control','POST',{worker_id:row.id,boot_id:row.boot_id,revision:row.control.revision,action,reason:form.elements.reason.value.trim()});if(dialog!==modalRevision)return;$('#modal').close();toast('Worker '+action+' requested; refresh to observe acknowledgement');if(currentView(revision,'activity')&&location.hash==='#activity/workers')await workerRegistrations(revision,offset);}
   catch(error){if(dialog===modalRevision){toast(error.message);submit.disabled=false;}}
  };
 });
 for(const [selector,next] of [['#worker-prev',Math.max(0,offset-50)],['#worker-next',offset+50]])$(selector).onclick=async()=>{const buttons=[$('#worker-prev'),$('#worker-next')];buttons.forEach(button=>button.disabled=true);try{await workerRegistrations(revision,next);}catch(error){if(currentView(revision,'activity')){toast(error.message);buttons[0].disabled=!offset;buttons[1].disabled=!data.more;}}};
}
async function tlsModal(){
 const revision=modalRevision;let state;
 try{state=await api('/tls');}catch(error){toast(error.message);return;}
 if(revision!==modalRevision)return;
 modal('Internal & external HTTPS',`<p class="help">Two independent certificate profiles share the published HTTPS listener. Use different hostnames; certificate selection follows the hostname requested by your browser. Internal is a certificate profile, not a network access restriction.</p><label>Profile<select id="tls-profile"><option value="internal">Internal</option><option value="external">External / public</option></select></label><div id="tls-profile-editor"></div>`);
 const editor=$('#tls-profile-editor');
 const draw=()=>{
  const profile=$('#tls-profile').value,item=state.profiles[profile];
  editor.innerHTML=`<form id="tls-form"><label class="check"><input name="enabled" type="checkbox" ${item.enabled?'checked':''}>Enable this HTTPS profile</label><label>Domain or IP address<input name="domain" value="${esc(item.domain)}" placeholder="${profile==='internal'?'patchy.home.example.com':'patchy.example.com'}"></label><label>Additional hostnames (one per line)<textarea name="aliases">${esc((item.aliases||[]).join('\n'))}</textarea></label><div class="form-grid"><label>Browser-facing HTTPS port<input name="https_port" type="number" min="1" max="65535" value="${item.https_port||''}" placeholder="Effective browser port (${item.effective_https_port})"></label><label class="check"><input name="redirect_http" type="checkbox" ${item.redirect_http?'checked':''}>Redirect HTTP to this profile's HTTPS address</label></div><label>Certificate mode<select name="mode"><option value="internal">Built-in local CA</option><option value="acme">ACME (Let's Encrypt or custom CA)</option><option value="uploaded">Upload certificate &amp; private key</option></select></label><div id="tls-acme"><label>ACME directory URL<input name="acme_url" type="url" value="${esc(item.acme_url)}" placeholder="https://acme-v02.api.letsencrypt.org/directory"></label><label>ACME account email<input name="email" type="email" value="${esc(item.email)}"></label><label>Challenge method<select name="challenge"><option value="auto">Automatic (HTTP-01 / TLS-ALPN-01)</option><option value="http">HTTP-01 only</option><option value="tlsalpn">TLS-ALPN-01 only</option></select></label><label>ACME server CA bundle ${item.ca_configured?'· configured':''}<input type="file" name="ca" accept=".pem,.crt"></label><label class="check"><input name="clear_ca" type="checkbox">Clear saved CA bundle (use system trust)</label><label>EAB key ID (optional)<input name="eab_id" value="${esc(item.eab_id)}"></label><label>EAB HMAC key ${item.eab_configured?'· configured':''}<input name="eab_key" type="password" autocomplete="new-password" placeholder="Leave blank to keep the saved secret"></label><label class="check"><input name="clear_eab" type="checkbox">Clear saved EAB credentials</label></div><div id="tls-upload"><p class="help">${item.certificate_configured?'A certificate and key are saved. Leave uploads empty to keep them.':'Upload a certificate chain and its matching unencrypted private key.'} The SAN must cover every hostname in this profile.</p><div class="form-grid"><label>Certificate chain PEM<input type="file" name="certificate" accept=".pem,.crt"></label><label>Private key PEM<input type="file" name="private_key" accept=".pem,.key"></label></div></div><p class="help">Public ACME still needs external TCP 80 and/or 443 forwarded to the published Docker ports. An explicit browser port takes priority; otherwise a matching PUBLIC_URL supplies the external port, then HTTPS_PORT is the fallback. Forward that browser port to the Docker-published HTTPS port; the container continues listening on 443. Keep PUBLIC_URL aligned with your default enrollment/SSO address. Curl enrollment also lets you select either enabled HTTPS profile. Changing addresses may require signing in again.</p><button class="primary">Validate &amp; apply this profile</button></form>`;
  const form=$('#tls-form'),selector=$('#tls-profile');
  form.elements.mode.value=item.mode;form.elements.challenge.value=item.challenge;
  const modeChanged=()=>{$('#tls-acme').classList.toggle('hidden',form.elements.mode.value!=='acme');$('#tls-upload').classList.toggle('hidden',form.elements.mode.value!=='uploaded');};
  form.elements.mode.onchange=modeChanged;modeChanged();
  form.onsubmit=async event=>{
   event.preventDefault();const f=new FormData(form),button=form.querySelector('button');button.disabled=true;selector.disabled=true;
   const body={enabled:f.has('enabled'),domain:f.get('domain').trim(),aliases:f.get('aliases').split(/\s+/).filter(Boolean),mode:f.get('mode'),acme_url:f.get('acme_url'),email:f.get('email'),https_port:f.get('https_port')?+f.get('https_port'):null,redirect_http:f.has('redirect_http'),challenge:f.get('challenge'),eab_id:f.get('eab_id'),eab_key:f.get('eab_key'),clear_ca:f.has('clear_ca'),clear_eab:f.has('clear_eab')};
   try{
    for(const key of ['ca','certificate','private_key']){const file=f.get(key);if(file.size>100000)throw Error('Each PEM upload must be at most 100 KB');body[key]=file.size?await file.text():'';}
    const saved=await api('/tls/'+profile,'PUT',body);if(!form.isConnected)return;
    state=saved;draw();toast('HTTPS profile applied. Certificate issuance may continue in the background.');
   }catch(error){if(form.isConnected)toast(error.message);}finally{if(button.isConnected)button.disabled=false;if(selector.isConnected)selector.disabled=false;}
  };
  $('#modal').scrollTop=0;
 };
 $('#tls-profile').onchange=draw;draw();
}
document.addEventListener('click',async e=>{const b=e.target.closest('[data-action]');if(!b)return;const {action,id}=b.dataset,revision=renderRevision;try{if(action==='retry-investigation'){b.disabled=true;try{const result=await api('/investigations/'+id+'/retry','POST');toast(result.detail);if(revision===renderRevision)await render();}finally{if(b.isConnected)b.disabled=false;}return;}if(action==='retriage-investigation')return requestInvestigationRetriage(id);if(action==='revoke-known-good')return requestKnownGoodRevocation(b.dataset.fingerprint,b.dataset.version,b.dataset.linked);if(action==='add')return addServer();if(action==='inspect')return inspect(id);if(action==='refresh'){await api(`/hosts/${id}/actions/refresh`,'POST');toast('Operation queued. See Activity for progress.');return;}if(action==='trust'){const approved=b.dataset.approved!=='true';modal(approved?'Approve known-good behavior':'Revoke behavior approval',`<p>${approved?'Record this exact behavior as reviewed and trusted? Its AI assessment alone is not proof of safety.':'This behavior will no longer be marked as trusted.'}</p><button class="primary" id="confirm-trust">${approved?'Approve behavior':'Revoke approval'}</button>`);const request=modalRequest();$('#confirm-trust').onclick=async event=>{const button=event.currentTarget;if(button.disabled)return;button.disabled=true;try{await api('/investigations/'+id,'PUT',{approved});request.close(approved?'Behavior approval saved':'Behavior approval revoked');if(request.sameSession()&&revision===renderRevision)await render();}catch(error){request.error(error);if(request.active())button.disabled=false;}};}}catch(e){toast(e.message);}});
$('#close-modal').onclick=()=>{modalRevision++;releaseRequest++;$('#modal').close();};$('#modal').addEventListener('cancel',()=>{modalRevision++;releaseRequest++;});$('#refresh-page').onclick=render;$('#logout').onclick=async()=>{try{await api('/logout','POST');showLogin();}catch(e){toast(e.message);}};$('#login-form').onsubmit=async e=>{e.preventDefault();try{const d=await api('/login','POST',{password:new FormData(e.target).get('password'),username:new FormData(e.target).get('username')||'admin',otp:new FormData(e.target).get('otp')||''});csrf=d.csrf;e.target.reset();showShell();await render();resumeEnrollment();}catch(e){$('#login-error').textContent=e.message;}};window.addEventListener('hashchange',()=>{modalRevision++;releaseRequest++;$('#modal').close();window.scrollTo(0,0);render();});(async()=>{try{csrf=(await api('/session')).csrf;showShell();await render();resumeEnrollment();}catch{showLogin();}})();

setInterval(()=>{if(!$('#shell').classList.contains('hidden')&&!$('#modal').open&&!document.activeElement?.closest('#server-list-controls,#fleet-review-controls')&&document.visibilityState==='visible'&&(page==='overview'||(page==='servers'&&(!location.hash.startsWith('#servers/')||location.hash.endsWith('/overview')))))render();},30000);

async function repositoryAccessModal(hostId){
 const revision=modalRevision;try{
 const access=await api(`/hosts/${hostId}/repository-access`);if(revision!==modalRevision)return;
 modal('Central repository access',`<p class="help">Configure how Mr Patchy reaches this server’s repositories. Credentials stay encrypted in the database and are passed privately to the central package backend. Target package-manager hooks and plugins are never imported.</p><form id="access-form"><label>APT default release (leave blank for RPM)<input name="default_release" value="${esc(access.default_release||'')}" placeholder="bookworm"></label><label>HTTP(S) proxy (optional, no embedded credentials)<input name="proxy" value="${esc(access.proxy||'')}"></label><label>Private repository CA bundle (PEM)<textarea name="ca">${esc(access.ca||'')}</textarea></label><label>Mirror mappings · JSON object<textarea name="mirrors" placeholder='{"file:/srv/repository": "https://mirror.example.com/repository"}'>${esc(JSON.stringify(access.mirrors||{},null,2))}</textarea></label><p class="help">Map an exact file:, cdrom: or HTTP(S) source URI to a centrally reachable HTTP(S) mirror with the same layout and signed metadata. Original target files are preserved.</p><p class="help">Configured credential scopes: ${esc((access.credential_scopes||[]).join(', ')||'none')}</p><label class="check"><input name="replace_credentials" type="checkbox">Replace saved credentials (empty list clears them)</label><label>New credentials · JSON array<textarea name="credentials" placeholder='[{"machine":"https://repo.example.com/private","login":"user","password":"token"}]'>[]</textarea></label><button class="primary">Save repository access</button></form>`);
 const request=modalRequest();$('#access-form').onsubmit=async e=>{e.preventDefault();const button=e.target.querySelector('button');if(button.disabled)return;button.disabled=true;try{const f=new FormData(e.target);await api(`/hosts/${hostId}/repository-access`,'PUT',{default_release:f.get('default_release'),proxy:f.get('proxy'),ca:f.get('ca'),mirrors:JSON.parse(f.get('mirrors')),replace_credentials:f.has('replace_credentials'),credentials:JSON.parse(f.get('credentials'))});request.close('Repository access saved. Run Check now to refresh candidates.');}catch(error){request.error(error);if(request.active())button.disabled=false;}};
 }catch(e){toast(e.message);}
}
async function backupModal(hostId){
 const revision=modalRevision;try{const result=await api(`/hosts/${hostId}/backups`);if(revision!==modalRevision)return;modal('Restore a repository backup',`<p class="help">Review a saved configuration before restoring it. The current file is backed up again when the restore runs.</p>${result.backups.map((b,i)=>`<div class="card"><h3>${esc(b.path)}</h3><small>Backup ${esc(b.id)}</small><pre>${esc(b.content)}</pre><button class="restore-source" data-index="${i}">Review restoration</button></div>`).join('')||'<p>No restorable backups yet. Backups made by older releases remain on the target for manual recovery.</p>'}`);document.querySelectorAll('.restore-source').forEach(button=>button.onclick=()=>{const b=result.backups[+button.dataset.index];saveSource(b.path,b.content,hostId);});}catch(e){toast(e.message);}
}

// Account controls are available to every role; authorization is enforced by the API.
const usernameLabel=document.createElement('label');usernameLabel.textContent='Username';
const usernameInput=document.createElement('input');usernameInput.name='username';usernameInput.value='admin';usernameInput.autocomplete='username';usernameLabel.append(usernameInput);
usernameInput.required=true;usernameInput.maxLength=64;$('#login-form [name=password]').closest('label').before(usernameLabel);
const otpLabel=document.createElement('label');otpLabel.textContent='Authenticator code (if enabled)';
const otpInput=document.createElement('input');otpInput.name='otp';otpInput.autocomplete='one-time-code';otpInput.inputMode='numeric';otpInput.maxLength=6;otpLabel.append(otpInput);
$('#login-form button').before(otpLabel);
const accountButton=document.createElement('button');accountButton.textContent='Account';$('#logout').before(accountButton);
$('#header-actions').append(accountButton,$('#logout'));
accountButton.onclick=async()=>{const revision=modalRevision;try{const me=await api('/identity');if(revision!==modalRevision)return;modal('Account · '+me.username,`<p>Role: ${esc(me.role)} · MFA: ${me.mfa?'enabled':'not enabled'}</p><form id="account-form"><label>Current password<input name="password" type="password" required autocomplete="current-password"></label><label>Current authenticator code<input name="otp" maxlength="6"></label><h3>Choose your own password</h3><p class="help">Use at least 12 characters. Changing your password signs out all your sessions and preserves MFA.</p><label>New password (only for password change)<input name="new_password" type="password" minlength="12" autocomplete="new-password"></label><label>Confirm new password<input name="confirm_password" type="password" autocomplete="new-password"></label><div class="actions"><button type="button" id="mfa-setup">Set up authenticator MFA</button><button type="button" id="change-password">Change password</button><button type="button" id="revoke-sessions">Revoke all sessions</button></div></form>${me.role==='admin'?'<button id="manage-users">Manage users</button><button id="operations-panel">Operations</button>':''}`);
const body=()=>Object.fromEntries(new FormData($('#account-form')));
$('#mfa-setup').onclick=async event=>{const revision=modalRevision,button=event.target;button.disabled=true;try{const result=await api('/identity/mfa','POST',body());if(revision!==modalRevision)return;modal('Confirm authenticator',`<p>Add this secret to your authenticator app, then enter its six-digit code. Confirmation revokes existing sessions.</p><pre>${esc(result.secret)}</pre><form id="otp-confirm"><label>Code<input name="otp" required maxlength="6"></label><button class="primary">Enable MFA</button></form>`);$('#otp-confirm').onsubmit=async e=>{e.preventDefault();try{await api('/identity/mfa/confirm','POST',Object.fromEntries(new FormData(e.target)));$('#modal').close();showLogin();}catch(error){toast(error.message);}};}catch(error){toast(error.message);}finally{if(button.isConnected)button.disabled=false;}};
for(const [id,path,method] of [['change-password','password','PUT'],['revoke-sessions','sessions','DELETE']])$('#'+id).onclick=async()=>{if(id==='change-password'&&$('#account-form [name=new_password]').value!==$('#account-form [name=confirm_password]').value)return toast('New passwords do not match');try{await api('/identity/'+path,method,body());$('#modal').close();showLogin();}catch(error){toast(error.message);}};
if(me.role==='admin'){$('#manage-users').onclick=()=>{$('#modal').close();location.hash='users';};$('#operations-panel').onclick=operationsPanel;}
}catch(error){toast(error.message);}};

async function operationsPanel(){
 const revision=modalRevision;
 try{
  const [alerts,notification]=await Promise.all([api('/operations/alerts'),api('/operations/notifications')]);
  if(revision!==modalRevision)return;
  const webhook=notification.channel==='webhook'?notification:{};
  modal('Operations',`<div class="operations-links"><button id="advanced-controls">SSO, SMTP &amp; target policies</button><button id="expert-workflows">Staged rollout &amp; advisory matching</button></div><p class="help">${notification.channel==='smtp'?'SMTP is currently configured. Saving this webhook form switches delivery to webhook.':'Webhook delivery is opt-in and uses HTTPS.'}</p><form id="notification-form"><label>Webhook URL<input name="url" type="url" value="${esc(webhook.url||'')}"></label><label>Bearer token ${webhook.token_configured?'· configured':''}<input name="token" type="password" autocomplete="new-password" placeholder="Leave blank to keep the existing token"></label><label class="check"><input name="clear_token" type="checkbox">Clear saved token</label><label class="check"><input name="enabled" type="checkbox" ${webhook.enabled?'checked':''}>Enable delivery</label><button>Save webhook configuration</button></form><h3>Maintenance window</h3><form id="window-form"><label>Server<select name="host">${hosts.map(h=>`<option value="${h.id}" ${h.id===selected?'selected':''}>${esc(h.name)}</option>`).join('')}</select></label><label>Windows JSON (UTC minutes, Monday=0; [] means unrestricted)<textarea name="windows" disabled></textarea></label><p class="help" id="window-status" role="status">Loading saved policy…</p><button disabled>Save window</button></form><p><a href="/api/audit/export" download>Download audit JSONL</a> · <a href="/api/metrics" target="_blank" rel="noopener">Metrics</a></p><h3>Alerts</h3>${alerts.map(a=>`<div class="card"><strong>${esc(hostName(a.host_id))} · ${esc(a.kind)}</strong> ${badge(a.state)}<p>${esc(a.message)}</p><button class="ack-alert" data-id="${a.id}" ${a.state!=='open'?'disabled':''}>Acknowledge</button></div>`).join('')||'<p>No alerts recorded.</p>'}`);
  $('#advanced-controls').onclick=advancedControls;
  $('#notification-form').onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{await api('/operations/notifications','PUT',{url:f.get('url'),token:f.get('token'),clear_token:f.has('clear_token'),enabled:f.has('enabled')});toast('Notification configuration saved');}catch(error){toast(error.message);}};
  const form=$('#window-form'),status=$('#window-status'),save=form.querySelector('button');let request=0;
  const loadWindow=async()=>{
   const ticket=++request,id=form.elements.host.value;save.disabled=true;form.elements.windows.disabled=true;form.elements.windows.value='';
   status.textContent=id?'Loading saved policy…':'Enroll a server to configure its maintenance window.';
   if(!id)return;
   try{const policy=await api('/operations/'+id+'/window');if(ticket!==request||!form.isConnected)return;
    form.elements.windows.value=JSON.stringify(policy.windows,null,2);form.elements.windows.disabled=false;save.disabled=false;
    status.textContent=policy.windows.length?'Saved policy loaded. Times are UTC.':'No restrictions are saved for this server.';
   }catch(error){if(form.isConnected&&ticket===request)status.textContent=error.message;}
  };
  form.elements.host.onchange=loadWindow;
  form.onsubmit=async e=>{e.preventDefault();const f=new FormData(form),ticket=request;save.disabled=true;try{await api('/operations/'+f.get('host')+'/window','PUT',{windows:JSON.parse(f.get('windows'))});toast('Maintenance window saved');}catch(error){toast(error.message);}finally{if(form.isConnected&&ticket===request)save.disabled=false;}};
  document.querySelectorAll('.ack-alert').forEach(b=>b.onclick=async()=>{try{await api('/operations/alerts/'+b.dataset.id+'/ack','POST');if(b.isConnected)await operationsPanel();}catch(error){toast(error.message);}});
  await loadWindow();
 }catch(error){toast(error.message);}
}

// API-backed expert workflows remain explicit and reviewed.
document.addEventListener('click',async event=>{
 const button=event.target.closest('#expert-workflows');if(!button)return;
 modal('Reviewed fleet workflows',`<form id="rollout-form"><label>Server IDs in rollout order (first is canary, one per line)<textarea name="hosts">${esc(hosts.map(h=>h.id).join('\n'))}</textarea></label><p class="help">${hosts.map(h=>esc(h.id+' = '+h.name)).join('<br>')}</p><label>Package names including architecture (one per line)<textarea name="packages" placeholder="openssl:amd64"></textarea></label><p class="help">Each server uses its current reviewed candidate. Later servers wait for successful patching and service-health checks on the preceding server. Maintenance windows apply. Review each server’s current reboot and rollback policy before submitting.</p><button class="primary">Queue staged rollout</button></form><h3>Advisory matching</h3><form id="advisory-form"><label>Server<select name="host">${hosts.map(h=>`<option value="${h.id}">${esc(h.name)}</option>`).join('')}</select></label><label>Installed package names (up to 100, one per line)<textarea name="packages"></textarea></label><p class="help">This sends selected source package names/versions and distro release to OSV. Unsupported derivatives are reported rather than assumed safe.</p><button>Query advisory IDs</button></form><pre id="advisory-result"></pre>`);
 const lines=value=>value.split('\n').map(x=>x.trim()).filter(Boolean);
 $('#rollout-form').onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target),hostIds=lines(f.get('hosts')),packageNames=lines(f.get('packages'));try{
 const policies=Object.fromEntries(await Promise.all(hostIds.map(async id=>[id,await api('/hosts/'+id+'/patch-policy')])));
 modal('Review staged rollout',`<p>Servers run in this order, with the first acting as canary. A failed or unreconciled server blocks later stages.</p>${hostIds.map(id=>`<h3>${esc(hostName(id))}</h3>${recoverySummary(policies[id])}`).join('')}<pre>${esc(packageNames.join('\n'))}</pre><button class="primary" id="confirm-rollout">Approve staged rollout</button>`);
 $('#confirm-rollout').onclick=async()=>{const confirmButton=$('#confirm-rollout');confirmButton.disabled=true;try{const result=await api('/operations/rollouts','POST',{hosts:hostIds,packages:packageNames,expected_recovery_policies:policies});$('#modal').close();toast('Rollout queued: '+result.jobs.length+' servers');}catch(error){confirmButton.disabled=false;toast(error.message);}};
 }catch(error){toast(error.message);}};
 $('#advisory-form').onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{const result=await api('/operations/'+f.get('host')+'/advisories','POST',{packages:lines(f.get('packages'))});$('#advisory-result').textContent=JSON.stringify(result,null,2);}catch(error){toast(error.message);}};
});
(async()=>{try{if((await api('/sso')).enabled){const link=document.createElement('a');link.href='/auth/sso';link.textContent='Sign in with your organization';$('#login-form').append(link);}}catch{}})();
async function advancedControls(){
 const revision=modalRevision;let notification;try{notification=await api('/operations/notifications');}catch(error){toast(error.message);return;}if(revision!==modalRevision)return;
 modal('Enterprise and recovery controls',`<h3>SSO account binding</h3><p class="help">Configure OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET in the deployment first. Bind the immutable provider subject to a pre-created account; email matching never grants access.</p><form id="sso-binding"><label>Provider subject<input name="subject" required></label><label>Existing username<input name="username" required></label><button>Bind identity</button></form><h3>SMTP alerts</h3><form id="smtp-form"><label>Mail server<input name="host" required></label><div class="form-grid"><label>Port<input name="port" type="number" value="587"></label><label>Encryption<select name="mode"><option value="starttls">STARTTLS</option><option value="tls">TLS</option></select></label></div><label>Sender<input name="sender" type="email" required></label><label>Recipients (comma separated)<input name="recipients" required></label><label>Username<input name="username"></label><label>Password<input name="password" type="password" autocomplete="new-password" placeholder="Leave blank to keep the existing password"></label><label class="check"><input name="clear_password" type="checkbox">Clear saved SMTP password</label><p class="help" id="smtp-secret-status"></p><label>Private CA PEM (optional)<textarea name="ca"></textarea></label><label class="check"><input name="enabled" type="checkbox">Enable SMTP delivery (replaces webhook delivery)</label><button>Save SMTP configuration</button></form><h3>Target controls</h3><label>Server<select id="advanced-host">${hosts.map(h=>`<option value="${h.id}">${esc(h.name)}</option>`).join('')}</select></label><div class="actions"><button id="rotate-key">Rotate SSH identity</button><button id="enable-ebpf">Enable eBPF</button><button id="disable-ebpf">Disable eBPF</button></div><p class="help">eBPF requires bpftrace/kernel support and relaxes the collector service sandbox to permit kernel tracing. Script/library hashes are sampled without exporting command-line arguments.</p><form id="recovery-policy"><label class="check"><input name="reboot" type="checkbox">Automatically reboot when required after approved patches</label><label class="check"><input name="rollback" type="checkbox">Automatically roll back failed patches using the validated root-owned adapter</label><p class="help">Rollback requires /etc/mrpatchy/rollback on the target and a tested bootable snapshot layout. Enabling reboot can interrupt services. Reboots must be observed and health verified before advancing a rollout.</p><button>Save recovery policy</button></form>`);
 const smtpForm=$('#smtp-form');
 if(notification.channel==='smtp'){for(const key of ['host','port','mode','sender','username','ca'])smtpForm.elements[key].value=notification[key]??'';smtpForm.elements.recipients.value=(notification.recipients||[]).join(', ');smtpForm.elements.enabled.checked=!!notification.enabled;$('#smtp-secret-status').textContent=notification.password_configured?'A password is configured. It is never returned to the browser.':'No SMTP password is configured.';}
 $('#sso-binding').onsubmit=async e=>{e.preventDefault();try{await api('/operations/sso-binding','PUT',Object.fromEntries(new FormData(e.target)));toast('SSO identity bound');}catch(error){toast(error.message);}};
 $('#smtp-form').onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{await api('/operations/smtp','PUT',{host:f.get('host'),port:+f.get('port'),mode:f.get('mode'),sender:f.get('sender'),recipients:f.get('recipients').split(',').map(x=>x.trim()),username:f.get('username'),password:f.get('password'),clear_password:f.has('clear_password'),ca:f.get('ca'),enabled:f.has('enabled')});toast('SMTP settings saved');}catch(error){toast(error.message);}};
 $('#rotate-key').onclick=async()=>{const id=$('#advanced-host').value;try{await api('/hosts/'+id+'/actions/rotate-key','POST');toast('Rotation queued. Follow Activity for verification.');}catch(error){toast(error.message);}};
 for(const [name,enabled] of [['enable-ebpf',true],['disable-ebpf',false]])$('#'+name).onclick=async()=>{const id=$('#advanced-host').value;try{await api('/operations/'+id+'/observability','PUT',{ebpf:enabled});toast('Collector configuration updated');}catch(error){toast(error.message);}};
 let policyRequest=0;
 const loadRecoveryPolicy=async()=>{const request=++policyRequest,id=$('#advanced-host').value,form=$('#recovery-policy');form.querySelectorAll('input,button').forEach(x=>x.disabled=true);if(!id)return;try{const policy=await api('/hosts/'+id+'/patch-policy');if(request!==policyRequest||!form.isConnected)return;for(const name of ['reboot','rollback'])form.elements[name].checked=policy[name];form.querySelectorAll('input,button').forEach(x=>x.disabled=false);}catch(error){toast(error.message);}};
 $('#advanced-host').onchange=loadRecoveryPolicy;
 $('#recovery-policy').onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target),id=$('#advanced-host').value;try{await api('/operations/'+id+'/recovery','PUT',{reboot:f.has('reboot'),rollback:f.has('rollback')});toast('Recovery policy saved');}catch(error){toast(error.message);}};
 await loadRecoveryPolicy();
}


async function releasePanel(id){
 const request=++releaseRequest,revision=modalRevision;
 try{
  const rows=await api(`/hosts/${id}/releases`);
  if(request!==releaseRequest||revision!==modalRevision)return;
  modal(hostName(id)+' · Distribution upgrades',`<p>Prepare a release plan, review the package changes and configuration diffs, then make one go/no-go decision.</p><div class="notice">Planning sends eligible configuration text and authenticated vendor defaults to the configured OpenAI API. Potential secrets are blocked, but detection is heuristic. Use this only for hosts whose configuration may be processed by your API provider. No system upgrade runs during planning.</div><p class="help">GO authorizes package additions/removals, the displayed edits, service interruptions, reboot and one snapshot rollback. A tested release-capable recovery adapter is required. Unsupported migrations appear as blockers.</p><button class="primary" id="build-release">Prepare upgrade plan</button><h3>Saved plans</h3>${rows.map(r=>`<p>${badge(r.state)} ${date(r.created)} <button class="open-release" data-id="${r.id}">Review plan</button></p>`).join('')||'<p class="help">No release plans yet.</p>'}`);
  document.querySelectorAll('.open-release').forEach(b=>b.onclick=()=>reviewRelease(id,b.dataset.id));
  $('#build-release').onclick=async e=>{e.target.disabled=true;try{const r=await api(`/hosts/${id}/releases`,'POST',{});if(e.target.isConnected&&$('#modal').open)await reviewRelease(id,r.plan_id);}catch(error){toast(error.message);e.target.disabled=false;}};
 }catch(error){toast(error.message);}
}
async function updateReleaseProgress(r,view){
 if(!r.job_id)return;
 const job=await api('/jobs/'+r.job_id),panel=$('#release-progress');
 if(view===modalRevision&&panel&&panel.isConnected)panel.textContent=job.state+(job.output?'\n'+job.output:'');
}
async function reviewRelease(id,planId,poll){
 const request=++releaseRequest,revision=modalRevision;
 try{
  const r=await api(`/hosts/${id}/releases/${planId}`),p=r.plan||{},t=p.target||{},pending=['planning','approved','running'].includes(r.state);
  if(request!==releaseRequest||revision!==modalRevision)return;
  // Background polls update only the state badge and progress while the plan state is unchanged,
  // so open diffs, scroll position and dialog messages survive. A state change rebuilds the dialog
  // and restores which <details> were open.
  if(poll&&poll.view===modalRevision&&poll.state===r.state&&$('#release-progress')?.isConnected&&$('#modal').open){
   const badgeNode=$('#modal-body .toolbar .badge');if(badgeNode)badgeNode.outerHTML=badge(r.state);
   await updateReleaseProgress(r,poll.view);
   if(pending)setTimeout(()=>{if(poll.view===modalRevision&&$('#modal').open)reviewRelease(id,planId,poll);},5000);
   return;
  }
  const openDetails=poll?[...document.querySelectorAll('#modal-body details')].map(x=>x.open):[];
  modal('Release upgrade · '+hostName(id),`<div class="toolbar">${badge(r.state)}<button id="refresh-release">Refresh progress</button></div><h3>${esc(t.distribution||'Preparing inventory')} ${esc(t.from_version||'')} → ${esc(t.version||'next supported release')}</h3>${r.error?`<div class="notice">${esc(r.error)}</div>`:''}${pending?'<p class="help">Progress is durable. You can close this window and return from this server’s saved plans.</p>':''}${p.expires?`<p class="help">Approval expires ${date(p.expires)}. Inventory/configuration drift requires a new plan.</p>`:''}${(p.blockers||[]).length?`<div class="notice"><strong>Cannot proceed</strong><ul>${p.blockers.map(x=>`<li>${esc(x)}</li>`).join('')}</ul></div>`:''}${(p.warnings||[]).map(x=>`<p class="help">${esc(x)}</p>`).join('')}<details><summary>Package transaction · ${(p.transaction||[]).length} changes</summary><div class="table-wrap"><table><thead><tr><th>Action</th><th>Package</th><th>Version</th></tr></thead><tbody>${(p.transaction||[]).map(x=>`<tr><td>${esc(x.action)}</td><td>${esc(x.package)}</td><td>${esc(x.version)}</td></tr>`).join('')}</tbody></table></div></details><h3>Configuration migration</h3>${(p.reviews||[]).map(x=>`<p><strong>${esc(x.path)}</strong><br>${esc(x.reason)}</p>`).join('')}${(p.edits||[]).map(x=>`<details class="source"><summary>${esc(x.path)}</summary><pre>${esc(x.diff)}</pre></details>`).join('')}<details class="source"><summary>Repository configuration</summary>${Object.entries(p.sources||{}).map(([path,content])=>`<h3>${esc(path)}</h3><pre>${esc(content)}</pre>`).join('')}</details>${['ready','blocked'].includes(r.state)?`<div class="notice">${esc(p.authorization)}</div><div class="actions"><button id="decline-release">No-go · Keep current release</button><button class="primary" id="approve-release" ${r.state!=='ready'?'disabled':''}>GO · Execute approved plan</button></div>`:''}<pre id="release-progress"></pre>`);
  if(poll)document.querySelectorAll('#modal-body details').forEach((x,i)=>{if(openDetails[i])x.open=true;});
  const panel=$('#release-progress'),view=modalRevision;
  const current=()=>panel.isConnected&&$('#modal').open&&view===modalRevision;
  $('#refresh-release').onclick=()=>reviewRelease(id,planId);
  // Bind to this view before awaiting progress. A slow job response must never
  // attach an older plan's approval to a newly opened dialog.
  const controls=['#approve-release','#decline-release'].map(selector=>$(selector)).filter(Boolean);
  for(const [selector,decision] of [['#approve-release','go'],['#decline-release','no-go']]){
   const control=$(selector);if(!control)continue;
   control.onclick=async()=>{if(!current())return;controls.forEach(x=>x.disabled=true);try{await api(`/hosts/${id}/releases/${planId}/decision`,'POST',{decision,digest:r.digest});if(current())await reviewRelease(id,planId);}catch(error){toast(error.message);if(current())controls.forEach(x=>x.disabled=x.id==='approve-release'&&r.state!=='ready');}};
  }
  await updateReleaseProgress(r,view);
  if(pending)setTimeout(()=>{if(current())reviewRelease(id,planId,{view,state:r.state});},5000);
 }catch(error){toast(error.message);}
}

// Keyboard shortcut to the current workspace heading; route stays unchanged.
$('.skip-link').onclick=event=>{event.preventDefault();const target=$('#shell').classList.contains('hidden')?$('#login-form [name=username]'):$('#page-title');target?.focus();target?.scrollIntoView({block:'start'});};
