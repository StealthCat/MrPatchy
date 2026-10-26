'use strict';
const SERVER_TABS=[['overview','Overview'],['packages','Packages'],['patching','Patching timeline'],['investigations','Investigations'],['ai','AI activity',true],['history','History'],['repositories','Repositories',true],['maintenance','Maintenance',true]];
const serverLink=(id,tab='overview')=>'#servers/'+encodeURIComponent(id)+'/'+tab;

function serverPagination(root,offset,more,load,size=50){
 const pager=document.createElement('div');pager.className='actions server-pagination';
 pager.innerHTML=`<button ${offset?'':'disabled'}>Previous</button><span class="help">Page ${Math.floor(offset/size)+1}</span><button ${more?'':'disabled'}>Next</button>`;
 const buttons=pager.querySelectorAll('button');
 for(const [button,next] of [[buttons[0],Math.max(0,offset-size)],[buttons[1],offset+size]])button.onclick=async()=>{buttons.forEach(b=>b.disabled=true);try{await load(next);}catch(error){if(root.isConnected){buttons[0].disabled=!offset;buttons[1].disabled=!more;toast(error.message);}}};
 root.append(pager);
}

async function serverWorkspace(revision){
 const parts=location.hash.slice(1).split('/');let id;
 try{id=decodeURIComponent(parts[1]||'');}catch{id='';}
 const h=hosts.find(item=>item.id===id),root=$('#content');
 if(!h){root.innerHTML=heading('Server not found.','This server may have been removed, or the link is invalid.')+'<a class="button" href="#servers">← All servers</a>';return;}
 selected=id;
 let tab=parts[2]||'overview';if(!SERVER_TABS.some(t=>t[0]===tab)){tab='overview';history.replaceState(null,'',serverLink(id));}
 const entry=SERVER_TABS.find(t=>t[0]===tab);
 const tabs=SERVER_TABS.filter(t=>!t[2]||isAdmin());
 $('#breadcrumb').textContent='Workspace / Servers / '+h.name+' / '+entry[1];document.title=h.name+' · '+entry[1]+' · Mr Patchy';
 root.innerHTML=`<div class="server-back"><a href="#servers">← All servers</a><label>Server<select id="server-workspace-select" aria-label="Switch server">${hosts.map(item=>`<option value="${esc(item.id)}" ${item.id===id?'selected':''}>${esc(item.name)}</option>`).join('')}</select></label></div>`+
 heading(h.name,`${h.address}:${h.port} · ${h.architecture||'Architecture not reported'}`,`<span>${badge(h.state)}</span>`)+
 `<nav class="server-tabs" aria-label="Server sections">${tabs.map(t=>`<a href="${serverLink(id,t[0])}" ${t[0]===tab?'class="active" aria-current="page"':''}>${t[1]}</a>`).join('')}</nav><section id="server-tab-content" aria-label="${entry[1]}"><h2>${entry[1]}</h2><div id="server-tab-body">${PatchyUI.loading()}</div></section>`;
 $('#server-workspace-select').onchange=event=>{location.hash=serverLink(event.target.value,tab);};
 const body=$('#server-tab-body'),context={root:body,hostId:id};
 if(entry[2]&&!isAdmin()){body.innerHTML=empty('Administrator access required','Your role can view the monitoring tabs for this server.',`<a class="button" href="${serverLink(id)}">Server overview</a>`);return;}
 try{
  const views={overview:serverOverview,packages,patching:serverPatching,investigations,ai:aiDiagnostics,history:serverHistory,repositories,maintenance:serverMaintenance};
  await views[tab](revision,context);
 }catch(error){if(currentView(revision,'servers')&&body.isConnected){body.innerHTML=empty('Unable to load this server tab',esc(error.message),'<button id="retry-server-tab">Retry</button>');$('#retry-server-tab').onclick=render;}}
}

async function serverOverview(revision,{root,hostId}){
 const data=await api('/hosts/'+hostId+'/summary');if(!currentView(revision,'servers')||!root.isConnected)return;
 const {host:h,system,collector,counts,jobs,last_patch}=data;
 const fact=(label,value)=>`<div><dt>${label}</dt><dd>${esc(value??'Not reported')}</dd></div>`;
 const os=typeof system.os==='string'?system.os:JSON.stringify(system.os||{});
 const fresh=h.last_seen&&Date.now()/1000-h.last_seen<120;
 root.innerHTML=`<div class="stats server-stats"><a class="stat" href="${serverLink(hostId,'packages')}"><label>Installed packages</label><strong>${counts.packages}</strong><small>${counts.held} held / version-locked</small></a><a class="stat accent" href="${serverLink(hostId,'patching')}"><label>Pending updates</label><strong>${counts.updates}</strong><small>${counts.overdue} past policy deadline</small></a><a class="stat" href="${serverLink(hostId,'investigations')}"><label>Unapproved behaviors</label><strong>${counts.unapproved}</strong><small>${counts.pending_ai} awaiting AI / retry</small></a><div class="stat ${h.integrity.length?'danger':''}"><label>Integrity findings</label><strong>${h.integrity.length}</strong><small>${fresh?'Recent server contact':'Server contact is stale or missing'}</small></div></div>
 ${h.error?`<div class="notice">${esc(h.error)}</div>`:''}
 <div class="server-grid"><section class="card"><h3>Identity &amp; connection</h3><dl class="server-facts">${fact('Server ID',h.id)}${fact('SSH address',h.address+':'+h.port)}${fact('Architecture',system.architecture)}${fact('Package manager',system.package_manager||'Not reported')}${fact('Machine ID',system.machine_id)}${fact('Pinned SSH fingerprint',h.fingerprint||'Not pinned')}</dl><details><summary>Operating system report</summary><pre>${esc(os||'Not reported')}</pre></details></section>
 <section class="card"><h3>Collector &amp; freshness</h3><dl class="server-facts">${fact('Last server contact',date(h.last_seen))}${fact('Inventory collected',date(system.collected))}${fact('Telemetry collected',date(collector.collected))}${fact('Integrity sweep',date(collector.hashed_at))}${fact('Processes in latest sample',collector.processes)}${fact('Managed files monitored',collector.managed_files)}</dl><p class="help">These are the latest stored observations. A recent connection alone does not prove the underlying inventory is current.</p></section></div>
 <section class="card"><h3>Patching status</h3><p>${jobs.running||0} running · ${jobs.queued||0} queued · ${jobs.recovery_required||0} requiring recovery</p><p>Last repository check: ${date(h.last_repo)}</p>${h.repo_error?`<div class="notice">${esc(h.repo_error)}</div>`:''}${last_patch?`<p>Most recently submitted patch: ${badge(last_patch.state)} · ${date(last_patch.created)}</p>`:'<p class="help">No patch operations recorded yet.</p>'}<a href="${serverLink(hostId,'patching')}" class="button">View patching timeline →</a></section>
 <section class="card"><h3>Integrity findings</h3>${h.integrity.length?`<ul>${h.integrity.map(item=>`<li><strong>${esc(item.path||'Collector')}</strong> — ${esc(item.issue||JSON.stringify(item))}</li>`).join('')}</ul>`:'<p class="help">No findings in the latest stored snapshot.</p>'}</section>`;
}

async function serverPatching(revision,context){
 const {root,hostId}=context;let cursor=new Date();cursor.setHours(0,0,0,0);
 root.innerHTML=`<section class="card"><div class="toolbar"><div><h3>Scheduled start windows</h3><p class="help">Times use ${esc(Intl.DateTimeFormat().resolvedOptions().timeZone)}. These are allowed start windows, not promised completion times.</p></div><div class="actions"><button id="server-period-prev">← Previous month</button><button id="server-period-today">Today</button><button id="server-period-next">Next month →</button></div></div><p id="server-period" class="help"></p><div id="server-calendar"></div></section><div id="server-patch-policies"></div><section class="card"><h3>Pending updates &amp; expected installation</h3><div id="server-patch-forecast"></div></section><section id="server-operations"><h3>Operations for this server</h3><div id="server-job-list"></div></section>`;
 const calendar=$('#server-calendar'),policies=$('#server-patch-policies'),forecast=$('#server-patch-forecast'),jobsRoot=$('#server-job-list');let ticket=0;
 const load=async()=>{
  const turn=++ticket,start=new Date(cursor.getFullYear(),cursor.getMonth(),1),end=new Date(cursor.getFullYear(),cursor.getMonth()+1,1);
  calendar.innerHTML='<p role="status">Loading start windows…</p>';
  try{
   const data=await api(`/hosts/${hostId}/patching?start=${start.getTime()/1000}&end=${end.getTime()/1000}`);
   if(turn!==ticket||!root.isConnected||!currentView(revision,'servers'))return;
   $('#server-period').textContent=start.toLocaleDateString([],{month:'long',year:'numeric'});
   calendar.innerHTML=data.events.length?`<div class="server-timeline">${data.events.map(e=>`<article><time>${date(e.start)}</time><div><h4>${esc(e.title)} ${badge(e.trigger)}</h4><p>Start window ends ${date(e.end)}</p><p class="help">${Object.entries(e.states).map(([state,count])=>esc(state)+': '+count).join(' · ')||'Planned window; no run recorded'}${e.timezone?' · Schedule timezone '+esc(e.timezone):''}</p></div></article>`).join('')}</div>`:empty('No patch windows in this month','Check the assigned schedules below. On-demand work appears in Operations.');
   policies.innerHTML=`<div class="server-grid"><section class="card"><h3>Schedules covering this server</h3>${data.schedules.length?data.schedules.map(p=>`<div class="server-policy"><h4>${esc(p.name)} ${badge(p.enabled?'enabled':'paused')}</h4><p>${esc(scheduleDescription(p))} · ${p.window_minutes} minute start window</p><p class="help">Priorities: ${esc(p.priorities.join(', '))}<br>${['critical','high'].map(level=>esc(level+': '+(p[level].enabled?'after '+p[level].after_minutes+' minutes'+(p[level].bypass_window?' · bypasses maintenance windows':''):'off'))).join('<br>')}</p></div>`).join(''):'<p class="help">No schedule covers this server. Updates require an on-demand installation.</p>'}${isAdmin()?'<a href="#schedules" class="button">Manage fleet schedules</a>':''}</section><section class="card"><h3>Maintenance &amp; recovery policy</h3>${serverWindowText(data.windows)}<p>Automatic reboot: <strong>${data.recovery.reboot?'enabled':'disabled'}</strong><br>Snapshot rollback: <strong>${data.recovery.rollback?'enabled':'disabled'}</strong></p><p class="help">Package holds, repository verification, target health and reviewed approvals still apply.</p>${isAdmin()?`<a href="${serverLink(hostId,'maintenance')}" class="button">Server maintenance settings</a>`:''}</section></div>`;
  }catch(error){if(turn===ticket&&root.isConnected)calendar.innerHTML=`<p class="notice">${esc(error.message)}</p>`;}
 };
 $('#server-period-prev').onclick=()=>{cursor=new Date(cursor.getFullYear(),cursor.getMonth()-1,1);load();};$('#server-period-next').onclick=()=>{cursor=new Date(cursor.getFullYear(),cursor.getMonth()+1,1);load();};$('#server-period-today').onclick=()=>{cursor=new Date();load();};
 const pending=async()=>{try{const rows=await api('/hosts/'+hostId+'/packages?updates=true');if(!root.isConnected)return;forecast.innerHTML=rows.length?`<div class="table-wrap"><table><thead><tr><th>Package</th><th>Candidate</th><th>Priority / deadline</th><th>Expected installation</th></tr></thead><tbody>${rows.map(p=>`<tr><td>${esc(p.name)}${p.held?'<small>Held by target policy</small>':''}</td><td>${esc(p.candidate)}</td><td>${badge(p.priority)}<small>${date(p.due)}</small></td><td>${installationCell(p.installation)}</td></tr>`).join('')}</tbody></table></div><a href="${serverLink(hostId,'packages')}" class="button">Review &amp; install updates</a>`:'<p class="help">No pending updates in the latest repository results.</p>';}catch(error){if(root.isConnected)forecast.textContent=error.message;}};
 await Promise.all([load(),pending(),activity(revision,{hostId,root:jobsRoot})]);
}

function serverWindowText(windows){
 const time=value=>String(Math.floor(value/60)).padStart(2,'0')+':'+String(value%60).padStart(2,'0');
 return windows.length?`<ul>${windows.map(w=>`<li>${w.days.map(day=>['Mon','Tue','Wed','Thu','Fri','Sat','Sun'][day]).join(', ')} · ${time(w.start)}–${time(w.end)} UTC</li>`).join('')}</ul>`:'<p class="help">No host maintenance-window restriction. Schedule windows and safety checks still apply.</p>';
}

async function serverHistory(revision,context){
 const {root,hostId}=context;
 root.innerHTML=`${isAdmin()?'<div class="actions"><button id="server-inventory-history">Inventory revisions</button><button id="server-observation-history">Process observations</button></div>':''}<div id="server-package-history"></div>`;
 if(isAdmin()){$('#server-inventory-history').onclick=()=>historyModal(hostId);$('#server-observation-history').onclick=()=>historyModal(hostId,'observations');}
 await packageHistory(revision,{hostId,root:$('#server-package-history')});
}

async function serverMaintenance(revision,{root,hostId}){
 const [policy,window]=await Promise.all([api('/hosts/'+hostId+'/patch-policy'),api('/operations/'+hostId+'/window')]);
 if(!currentView(revision,'servers')||!root.isConnected)return;
 const h=hosts.find(item=>item.id===hostId);
 root.innerHTML=`<section class="card"><h3>Server actions</h3><p class="help">Actions apply to ${esc(h.name)}. Installation, trust and recovery approvals remain explicit.</p><div class="actions"><button id="server-manage">Installation &amp; repair actions</button><button data-action="refresh" data-operator data-id="${hostId}">Check repositories</button><button id="server-release" ${h.package_manager==='rpm'?'disabled title="RPM distribution upgrades are not supported yet"':''}>Distribution upgrade plans</button><a class="button" href="/api/hosts/${hostId}/sbom" download>Download SBOM</a></div></section>
 <div class="server-grid"><section class="card"><h3>Recovery policy</h3><form id="server-recovery-form"><label class="check"><input name="reboot" type="checkbox" ${policy.reboot?'checked':''}>Automatically reboot when required after approved patches</label><label class="check"><input name="rollback" type="checkbox" ${policy.rollback?'checked':''}>Automatically roll back failed patches</label><p class="help">Reboots interrupt services. Rollback requires a tested root-owned adapter and snapshot layout. Changing this policy invalidates previous patch approvals.</p><button>Save recovery policy</button><p class="help" role="status"></p></form></section>
 <section class="card"><h3>Maintenance windows (UTC)</h3><div id="server-window-summary">${serverWindowText(window.windows)}</div><form id="server-window-form"><label>Windows as JSON<textarea name="windows" required>${esc(JSON.stringify(window.windows,null,2))}</textarea></label><p class="help">Each window: {"days":[0,1,2,3,4],"start":120,"end":240}. Days 0–6 are Monday–Sunday; start/end are UTC minutes after midnight. An empty list removes this host restriction.</p><button>Save maintenance windows</button><p class="help" role="status"></p></form></section></div>
 <section class="card"><h3>Current recorded data</h3><p class="help">Latest stored inventory, process telemetry, managed-file hashes and enrollment baseline. Collection timestamps describe freshness; this does not contact the target.</p><button id="server-snapshot-load">Load current snapshot</button><div id="server-snapshot"></div></section>`;
 $('#server-manage').onclick=()=>inspect(hostId);$('#server-release').onclick=()=>releasePanel(hostId);
 for(const [selector,path,body] of [['#server-recovery-form','/operations/'+hostId+'/recovery',f=>({reboot:f.has('reboot'),rollback:f.has('rollback')})],['#server-window-form','/operations/'+hostId+'/window',f=>({windows:JSON.parse(f.get('windows'))})]]){
  const form=$(selector);form.onsubmit=async event=>{event.preventDefault();const button=form.querySelector('button'),status=form.querySelector('[role=status]');button.disabled=true;try{const value=body(new FormData(form));await api(path,'PUT',value);if(root.isConnected){status.textContent='Saved for '+h.name+'.';if(value.windows)root.querySelector('#server-window-summary').innerHTML=serverWindowText(value.windows);}}catch(error){if(root.isConnected)status.textContent=error.message;}finally{if(root.isConnected)button.disabled=false;}};
 }
 $('#server-snapshot-load').onclick=async event=>{const button=event.target;button.disabled=true;try{const data=await api('/hosts/'+hostId+'/snapshot');if(!root.isConnected)return;$('#server-snapshot').innerHTML=Object.entries(data).map(([name,value])=>`<details class="source"><summary>${esc(name)}</summary><pre>${esc(JSON.stringify(value,null,2))}</pre></details>`).join('');}catch(error){if(root.isConnected)toast(error.message);}finally{if(root.isConnected)button.disabled=false;}};
}
