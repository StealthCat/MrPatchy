'use strict';
const SERVER_TABS=[['overview','Overview'],['connection','Connection',true],['agent','Agent health',true],['packages','Packages'],['patching','Patching timeline'],['investigations','Investigations'],['ai','AI activity',true],['history','History'],['repositories','Repositories',true],['maintenance','Maintenance',true],['security','Security',true],['integrity','File integrity',true]];
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
  const views={overview:serverOverview,connection:serverConnection,agent:serverAgent,packages,patching:serverPatching,investigations,ai:aiDiagnostics,history:serverHistory,repositories,maintenance:serverMaintenance,security:serverSecurity,integrity:serverIntegrity};
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

function securitySignatureSummary(signatures){
 const state=signatures?.state||'not_recorded';
 const labels={recent:'Recent',stale:'Stale',future:'Future timestamp — check clock',unknown:'Unknown',changed:'Changed during scan',not_recorded:'Not recorded in this scan'};
 return '<p class="security-signatures"><strong>Signature freshness: '+esc(labels[state]||'Unknown')+'</strong>'+(signatures?.built_at?' · Database built '+date(signatures.built_at):'')+'</p><p class="help">Daily database build age uses a seven-day limit. Stale, unknown, changed or future-dated signatures leave coverage incomplete. This is not proof of current vendor signatures or a clean host.</p>';
}

async function serverSecurity(revision,context){
 const {root,hostId}=context;let offset=0,historyOffset=0,ticket=0;
 root.innerHTML='<p class="notice">Security findings are evidence for investigation, not proof of compromise. Coverage gaps remain explicit. AI plans require review and are manual-only; approval does not execute actions.</p><form id="security-scan-form"><label>Absolute directories, one per line<textarea name="paths">/usr/local/bin\n/var/www\n/tmp</textarea></label><button>Queue security scan</button></form><form id="security-policy-form"><h3>Scheduled scanning</h3><label class="check"><input name="enabled" type="checkbox">Enable recurring scans</label><label>Interval in hours<input name="interval_hours" type="number" min="1" max="720" value="24"></label><label>Scheduled directories, one per line<textarea name="paths"></textarea></label><label class="check"><input name="auto_ai_plan" type="checkbox">Automatically request AI plans for new detections</label><p class="help">Sends scanner evidence to the configured AI provider. At most ten plan requests per hour across the fleet; one automatic attempt per incident scan. Plans remain manual-only.</p><button>Save scan policy</button><p class="help">Uses the same bounded scan limits. Incomplete scans are not proof of coverage. Pending scans are not duplicated.</p></form><div class="actions"><button id="security-refresh">Refresh security records</button></div><div id="security-latest"></div><section><h3>Incidents &amp; response plans</h3><div id="security-incidents"></div><div class="actions"><button id="incident-prev">Previous incidents</button><button id="incident-next">Next incidents</button></div></section><section><h3>Scan history</h3><div id="security-history"></div><div class="actions"><button id="scan-prev">Previous scans</button><button id="scan-next">Next scans</button></div></section>';
 const policyForm=root.querySelector('#security-policy-form'),policy=await api('/hosts/'+hostId+'/security/policy');
 if(!root.isConnected||!currentView(revision,'servers'))return;
 policyForm.elements.enabled.checked=policy.enabled;policyForm.elements.auto_ai_plan.checked=!!policy.auto_ai_plan;policyForm.elements.interval_hours.value=policy.interval_hours;policyForm.elements.paths.value=policy.paths.join('\n');
 policyForm.onsubmit=async e=>{e.preventDefault();const b=policyForm.querySelector('button');b.disabled=true;try{const f=new FormData(policyForm);await api('/hosts/'+hostId+'/security/policy','PUT',{enabled:f.has('enabled'),auto_ai_plan:f.has('auto_ai_plan'),interval_hours:Number(f.get('interval_hours')),paths:f.get('paths').split('\n').map(x=>x.trim()).filter(Boolean)});toast('Scan policy saved');}catch(error){toast(error.message);}finally{if(b.isConnected)b.disabled=false;}};
 const load=async()=>{const request=++ticket;
 const [latest,items,history]=await Promise.all([api('/hosts/'+hostId+'/security'),api('/hosts/'+hostId+'/security/incidents?offset='+offset),api('/hosts/'+hostId+'/security/history?offset='+historyOffset)]);
 if(!root.isConnected||!currentView(revision,'servers')||request!==ticket)return;
 root.querySelector('#security-latest').innerHTML='<section class="card"><h3>Latest scan coverage</h3><p>'+badge(latest.state)+' · '+(latest.scanned||0)+' scanned · '+(latest.skipped||0)+' skipped</p>'+securitySignatureSummary(latest.signatures)+'<details><summary>Coverage report</summary><pre>'+esc(JSON.stringify(latest,null,2))+'</pre></details></section>';
 root.querySelector('#security-incidents').innerHTML=items.items.map(r=>'<article class="card"><h4>'+esc(r.evidence.path)+'</h4><p>'+badge(r.state)+' · Updated '+date(r.updated)+'</p><details><summary>Detection evidence</summary><pre>'+esc(JSON.stringify(r.evidence,null,2))+'</pre></details><div class="actions"><button data-incident-review="'+r.id+'">Review incident</button><button data-incident-timeline="'+r.id+'">Incident timeline</button><button data-incident-matches="'+r.id+'">Find hash across fleet</button></div><button data-plan-incident="'+r.id+'">Generate AI response plan</button>'+(r.plans||[]).map(p=>'<section class="card"><h4>Response plan · '+badge(p.state==='approved'&&p.expires<Date.now()/1000?'expired':p.state)+'</h4><p>'+esc(p.content.summary)+'</p><p class="help">'+esc(p.content.uncertainty)+'</p><ol>'+p.content.steps.map(step=>'<li><strong>'+esc(step.action)+'</strong><p>'+esc(step.reason)+'</p><p>Impact: '+esc(step.impact)+'</p><p>Verify: '+esc(step.verification)+'</p><small>Evidence: '+esc(step.evidence_ids.join(', '))+'</small></li>').join('')+'</ol><p class="help">Manual execution only. Approval does not modify the target.</p>'+(p.state==='draft'?'<button data-review-plan="'+p.id+'" data-digest="'+p.evidence_digest+'">Review approval</button>':'<p>Reviewer: '+esc(p.approved_by||'None')+' · Expires '+date(p.expires)+'</p>')+'</section>').join('')+'</article>').join('')||'<p>No stored incidents.</p>';
 root.querySelector('#security-history').innerHTML=history.items.map(r=>'<details class="card"><summary>'+date(r.created)+' · '+esc(r.report.state)+' · '+esc(r.id)+'</summary><pre>'+esc(JSON.stringify(r.report,null,2))+'</pre></details>').join('')||'<p>No durable scan receipts yet.</p>';
 for(const [id,disabled] of [['incident-prev',offset===0],['incident-next',!items.more],['scan-prev',historyOffset===0],['scan-next',!history.more]])root.querySelector('#'+id).disabled=disabled;
 serverIncidentActions(root,hostId,items.items,load);
 root.querySelectorAll('[data-plan-incident]').forEach(b=>b.onclick=async()=>{b.disabled=true;try{await api('/hosts/'+hostId+'/security/incidents/'+b.dataset.planIncident+'/plan','POST');toast('AI plan queued. Refresh after the operation completes.');}catch(e){toast(e.message);}finally{if(b.isConnected)b.disabled=false;}});
 root.querySelectorAll('[data-review-plan]').forEach(b=>b.onclick=()=>{modal('Approve manual response plan','<p>Record your review of this evidence-bound plan? Approval expires in one hour. No quarantine, isolation, deletion or other target action will run.</p><button id="approve-security-plan">Approve for manual response</button>');$('#approve-security-plan').onclick=async event=>{event.target.disabled=true;try{await api('/hosts/'+hostId+'/security/plans/'+b.dataset.reviewPlan+'/approve','POST',{evidence_digest:b.dataset.digest});$('#modal').close();if(root.isConnected)await load();}catch(e){toast(e.message);event.target.disabled=false;}};});
 };
 const reload=()=>load().catch(e=>{if(root.isConnected)toast(e.message);});
 root.querySelector('#security-refresh').onclick=reload;
 for(const [id,change] of [['incident-prev',()=>offset=Math.max(0,offset-20)],['incident-next',()=>offset+=20],['scan-prev',()=>historyOffset=Math.max(0,historyOffset-20)],['scan-next',()=>historyOffset+=20]])root.querySelector('#'+id).onclick=()=>{change();reload();};
 root.querySelector('form').onsubmit=async e=>{e.preventDefault();const b=e.target.querySelector('button');b.disabled=true;try{await api('/hosts/'+hostId+'/security','POST',{paths:new FormData(e.target).get('paths').split('\n').map(x=>x.trim()).filter(Boolean)});toast('Security scan queued. Refresh after the operation completes.');}catch(error){toast(error.message);}finally{if(b.isConnected)b.disabled=false;}};
 await load();
}

function serverIncidentActions(root,hostId,rows,reload){
 const byId=new Map(rows.map(r=>[r.id,r]));
 root.querySelectorAll('[data-incident-review]').forEach(button=>button.onclick=()=>{
  const row=byId.get(button.dataset.incidentReview);
  modal('Review incident',`<p>${esc(row.evidence.path)}</p><p class="help">This records your assessment, not an automatic cleanup. Resolved means you manually verified recovery. False positive does not suppress future detections. A new detection reopens the incident. Changing status supersedes current response plans.</p><form id="incident-review-form"><label>Status<select name="state">${['open','acknowledged','false_positive','resolved'].map(state=>`<option value="${state}" ${state===row.state?'selected':''}>${state.replace('_',' ')}</option>`).join('')}</select></label><label>Reason and verification performed<textarea name="reason" required minlength="10" maxlength="4000"></textarea></label><button>Save incident review</button></form>`);
  const form=$('#incident-review-form'),reviewRevision=modalRevision;form.onsubmit=async e=>{e.preventDefault();const save=form.querySelector('button');save.disabled=true;try{const data=new FormData(form);await api('/hosts/'+hostId+'/security/incidents/'+row.id,'PUT',{state:data.get('state'),reason:data.get('reason'),expected_updated:row.updated});if(reviewRevision!==modalRevision||!root.isConnected)return;$('#modal').close();if(root.isConnected)await reload();}catch(error){toast(error.message);}finally{if(save.isConnected)save.disabled=false;}};
 });
 const records=(title,url,format,description)=>{
  modal(title,'<p class="help">'+esc(description)+'</p><div id="incident-records"></div><div class="actions"><button id="incident-records-prev">Previous</button><button id="incident-records-next">Next</button></div>');
  const target=$('#incident-records'),previous=$('#incident-records-prev'),next=$('#incident-records-next'),revision=modalRevision;let offset=0,ticket=0;
  const load=async()=>{const turn=++ticket;previous.disabled=true;next.disabled=true;try{const data=await api(url+'?offset='+offset);if(!root.isConnected||!target.isConnected||modalRevision!==revision||ticket!==turn)return;target.innerHTML=data.items.map(format).join('')||'<p>No recorded matches or events.</p>';previous.disabled=offset===0;next.disabled=!data.more;}catch(error){if(modalRevision===revision){target.textContent=error.message;previous.disabled=offset===0;}}};
  previous.onclick=()=>{offset=Math.max(0,offset-50);load();};next.onclick=()=>{offset+=50;load();};load();
 };
 root.querySelectorAll('[data-incident-timeline]').forEach(button=>button.onclick=()=>records('Incident timeline','/hosts/'+hostId+'/security/incidents/'+button.dataset.incidentTimeline+'/timeline',e=>'<article><h3>'+esc(e.kind)+' · '+date(e.created)+'</h3><p>'+esc(e.actor)+'</p><pre>'+esc(JSON.stringify(e.details,null,2))+'</pre></article>','Timeline recording begins with this version. Older scan receipts and plans remain available.'));
 root.querySelectorAll('[data-incident-matches]').forEach(button=>button.onclick=()=>{const row=byId.get(button.dataset.incidentMatches);records('Matching file hashes','/security/indicators/'+encodeURIComponent(row.evidence.sha256),r=>'<article class="card"><a href="'+serverLink(r.host_id,'security')+'">'+esc(hostName(r.host_id))+'</a><p>'+esc(r.path)+' · '+badge(r.state)+'</p><small>Updated '+date(r.updated)+'</small></article>','Matches are recorded detections, not a new scan or proof that other servers are clean. Identical hashes do not establish malicious intent.');});
}

async function serverConnection(revision,{root,hostId}){
 let saved=await api('/hosts/'+hostId+'/connection');
 const current=()=>currentView(revision,'servers')&&root.isConnected;
 if(!current())return;
 root.innerHTML=`<section class="card"><form id="server-connection-form"><div class="form-grid">
 <label>Connection mode<select name="transport"><option value="direct">Direct SSH</option><option value="gcp_iap">Google Cloud IAP</option></select></label>
 <label>SSH address / hostname<input name="address" required maxlength="253" value="${esc(saved.address)}"></label>
 <label>SSH port<input name="port" type="number" min="1" max="65535" required value="${saved.port}"></label>
 </div><div id="iap-fields" class="form-grid">
 <label>GCP project ID<input name="project" maxlength="63" value="${esc(saved.project)}"></label>
 <label>Zone<input name="zone" placeholder="us-central1-a" maxlength="63" value="${esc(saved.zone)}"></label>
 <label>Instance name<input name="instance" maxlength="63" value="${esc(saved.instance)}"></label>
 </div><p class="help">IAP uses the project, zone and instance instead of the saved address. Install Google Cloud CLI and configure its identity in the Mr Patchy runtime first. Grant IAP tunnel access and instance read permissions, and allow the IAP source range to reach the VM’s SSH port. See docs/GCP.md for deployment instructions.</p>
 <p class="help">The pinned host fingerprint and restricted drpatch key remain required in both modes. A changed VM identity requires verification from a trusted console.</p>
 <button class="primary" type="submit">Save connection</button> <button type="button" id="server-connection-test">Test saved connection</button><p id="connection-result" role="status"></p></form></section>
 <section class="card"><h3>GCP connection checks</h3><p>For direct SSH, use a reachable private address or reserved static external IP. Ephemeral external IPs can change after stop/start. A stopped or preempted VM cannot respond to polling.</p><p>Keep drpatch separate from metadata-managed and OS Login users. After an SSH policy change, verify the local account and rerun this server’s installer if needed. IAP provides network access; it does not repair guest SSH authentication or install keys.</p></section>`;
 const form=root.querySelector('form'),mode=form.elements.transport,fields=root.querySelector('#iap-fields'),result=root.querySelector('#connection-result');
 mode.value=saved.transport;
 mode.onchange=()=>{fields.classList.toggle('hidden',mode.value!=='gcp_iap');for(const name of ['project','zone','instance'])form.elements[name].required=mode.value==='gcp_iap';};mode.onchange();
 const busy=value=>{for(const button of form.querySelectorAll('button'))button.disabled=value;};
 form.onsubmit=async event=>{event.preventDefault();busy(true);const connection=Object.fromEntries(new FormData(form));connection.port=+connection.port;
  try{const updated=await api('/hosts/'+hostId+'/connection','PUT',{connection,expected:saved});if(current()){saved=updated;result.textContent='Connection saved. Test it below or wait for normal polling.';}}
  catch(error){if(current())result.textContent=error.message;}finally{if(current())busy(false);}
 };
 root.querySelector('#server-connection-test').onclick=async()=>{busy(true);result.textContent='Testing saved connection…';
  try{const response=await api('/hosts/'+hostId+'/connection/test','POST',{});if(current())result.textContent=response.message;}
  catch(error){if(current())result.textContent=error.message;}finally{if(current())busy(false);}
 };
}

async function serverIntegrity(revision,{root,hostId}){
 let offset=0,ticket=0;
 const current=()=>root.isConnected&&currentView(revision,'servers');
 root.innerHTML=`<p class="notice">Package verification compares files with this server’s local package database. It does not independently verify vendor signatures or prove malware. Startup entries and configuration changes need review.</p>
 <section class="card"><form id="security-inspection-form"><label>Installed package names, one per line (maximum 16)<textarea name="packages" placeholder="openssh-server
coreutils"></textarea></label><label class="check"><input type="checkbox" name="persistence" checked>Inventory common startup and persistence locations</label><p class="help">Read-only: no package scripts, repairs, quarantine or AI uploads. Inventory records paths, ownership, permissions, symlink targets and hashes, without file contents. User home directories and runtime-only persistence are outside this inventory.</p><button class="primary">Queue inspection</button></form></section>
 <section id="persistence-baseline" class="card"></section><section id="persistence-monitor" class="card"></section><section id="persistence-incidents" class="card"></section><div class="actions"><button id="inspection-refresh">Refresh inspections</button></div><div id="inspection-reports"></div><div class="actions"><button id="inspection-prev">Previous inspections</button><button id="inspection-next">Next inspections</button></div>`;
 const load=async()=>{const request=++ticket;const [result,baseline]=await Promise.all([api('/hosts/'+hostId+'/security/inspections?offset='+offset),api('/hosts/'+hostId+'/security/baseline')]);if(!current()||request!==ticket)return;
 renderPersistenceBaseline(root,hostId,baseline,load,current);
 root.querySelector('#inspection-reports').innerHTML=result.items.map(item=>{const report=item.report,inventory=report.persistence;return '<section class="card"><h3>'+date(item.created)+' · '+badge(report.state)+'</h3><p>Trust basis: local package database</p>'+report.packages.map(pkg=>'<details><summary>'+esc(pkg.package)+' · '+esc(pkg.state)+' · '+pkg.findings.length+' discrepancies</summary><p>'+esc(pkg.installed_identity||'Identity unavailable')+'</p><ul>'+pkg.gaps.map(gap=>'<li>'+esc(gap)+'</li>').join('')+'</ul><div class="table-wrap"><table><thead><tr><th>Path</th><th>Result</th><th>Checks</th><th>Configuration</th></tr></thead><tbody>'+pkg.findings.map(f=>'<tr><td>'+esc(f.path)+'</td><td>'+esc(f.status)+'</td><td>'+esc(f.checks)+'</td><td>'+(f.configuration_file?'Yes':'No')+'</td></tr>').join('')+'</tbody></table></div></details>').join('')+(inventory?'<button data-compare-inspection="'+esc(item.id)+'">Compare startup inventory</button><div class="inspection-comparison"></div><details><summary>Startup inventory · '+inventory.entries.length+' entries · '+esc(inventory.state)+'</summary><pre>'+esc(JSON.stringify(inventory,null,2))+'</pre></details>':'')+'<details><summary>Full inspection receipt and coverage</summary><pre>'+esc(JSON.stringify(report,null,2))+'</pre></details></section>';}).join('')||'<p>No inspection receipts yet. Queue an inspection and refresh when its job completes.</p>';
 root.querySelectorAll('[data-compare-inspection]').forEach(button=>{button.onclick=async()=>{button.disabled=true;const output=button.nextElementSibling;try{const comparison=await api('/hosts/'+hostId+'/security/inspections/'+encodeURIComponent(button.dataset.compareInspection)+'/comparison');if(!current()||!button.isConnected)return;output.innerHTML='<p>'+esc(comparison.note)+'</p><p>Previous inventory: '+(comparison.previous_created?date(comparison.previous_created):'None')+'</p><pre>'+esc(JSON.stringify(comparison.changes,null,2))+'</pre>';}catch(error){if(current()&&button.isConnected)output.textContent=error.message;}finally{if(button.isConnected)button.disabled=false;}};});
 root.querySelector('#inspection-prev').disabled=offset===0;root.querySelector('#inspection-next').disabled=!result.more;
 };
 const reload=()=>load().catch(error=>{if(current())toast(error.message);});
 root.querySelector('#inspection-refresh').onclick=reload;
 root.querySelector('#inspection-prev').onclick=()=>{offset=Math.max(0,offset-6);reload();};
 root.querySelector('#inspection-next').onclick=()=>{offset+=6;reload();};
 root.querySelector('form').onsubmit=async event=>{event.preventDefault();const form=event.target,button=form.querySelector('button');button.disabled=true;const values=new FormData(form);
 try{await api('/hosts/'+hostId+'/security/inspections','POST',{packages:values.get('packages').split('\n').map(x=>x.trim()).filter(Boolean),persistence:values.has('persistence')});if(current())toast('Inspection queued. Refresh after the job completes.');}
 catch(error){if(current())toast(error.message);}finally{if(current())button.disabled=false;}
 };
 await load();
 await renderPersistenceMonitoring(root,hostId,current);
}


async function serverAgent(revision,{root,hostId}){
 const data=await api('/hosts/'+hostId+'/security/agent');if(!currentView(revision,'servers')||!root.isConnected)return;
 const status=data.status;
 root.innerHTML=`<section class="card"><h3>Agent health ${badge(status.state)}</h3>${data.enrolled_outdated?'<p>The enrolled helper version differs from this controller release. Live verification is required before upgrading.</p>':''}<p>Last live verification: ${date(status.checked)}${status.stale?' · verification is stale':''}</p><p class="help">Checks compare the installed helpers with the enrolled baseline and this controller release. Unexpected changes are suspected tampering or configuration drift, not proof of malware. A compromised root/kernel cannot be independently attested through this agent.</p><ul>${(status.issues||[]).map(i=>`<li>${esc(i.path)}: ${esc(i.kind)}</li>`).join('')}</ul><div class="actions"><button id="agent-check">Check agent now</button><button id="agent-update">Upgrade / repair agent</button><button id="agent-refresh">Refresh status</button></div></section>
 <section class="card"><h3>Automatic maintenance</h3><form id="agent-policy"><label class="check"><input name="auto_upgrade" type="checkbox" ${data.policy.auto_upgrade?'checked':''}>Automatically upgrade outdated enrolled helpers</label><label class="check"><input name="auto_repair" type="checkbox" ${data.policy.auto_repair?'checked':''}>Automatically repair collector/helper drift and inactive services</label><p class="help">Off by default. Checks run about every five minutes when the server is idle. Automatic updates are limited to two attempts per day, at least one hour apart. Active patch/recovery operations block maintenance. Changing SSH keys, sudo policy, bridge identity, unsafe directories or unexpected systemd overrides requires trusted-console recovery. No operating-system packages, cloud permissions or malware quarantine are changed.</p><button class="primary">Save agent policy</button></form></section><section class="card"><h3>Verification receipt</h3><pre>${esc(JSON.stringify(status.report||{},null,2))}</pre></section>`;
 for(const action of ['check','update'])root.querySelector('#agent-'+action).onclick=async()=>{try{await api('/hosts/'+hostId+'/security/agent/'+action,'POST',{});toast('Agent '+action+' queued');}catch(e){toast(e.message);}};
 root.querySelector('#agent-refresh').onclick=()=>serverAgent(revision,{root,hostId});
 root.querySelector('#agent-policy').onsubmit=async e=>{e.preventDefault();const f=e.currentTarget;try{data.policy=await api('/hosts/'+hostId+'/security/agent','PUT',{auto_upgrade:f.elements.auto_upgrade.checked,auto_repair:f.elements.auto_repair.checked,expected:data.policy});toast('Agent policy saved');}catch(error){toast(error.message);}};
}


function renderPersistenceBaseline(root,hostId,data,reload,current){
 const panel=root.querySelector('#persistence-baseline');
 panel.innerHTML='<h3>Reviewed startup baseline · '+badge(data.state)+'</h3><p>Compare future inspections with an administrator-reviewed inventory. Matches describe observed metadata, not a clean-host verdict. Queue inspections regularly; observations expire after 24 hours.</p>'+(data.baseline?'<p>Approved by '+esc(data.baseline.actor)+' · '+date(data.baseline.created)+'</p><p>'+esc(data.baseline.reason)+'</p>':'<p>No baseline has been approved.</p>')+'<details><summary>Baseline differences and coverage</summary><pre>'+esc(JSON.stringify(data.comparison,null,2))+'</pre></details><button id="review-startup-baseline" '+(!data.eligible?'disabled':'')+'>Review latest as baseline</button><button id="startup-baseline-history">Baseline review history</button><div id="startup-baseline-history-output"></div>';
 panel.querySelector('#startup-baseline-history').onclick=async()=>{try{const result=await api('/hosts/'+hostId+'/security/baseline/history');if(current())panel.querySelector('#startup-baseline-history-output').textContent=JSON.stringify(result,null,2);}catch(e){toast(e.message);}};
 panel.querySelector('#review-startup-baseline').onclick=()=>{
  modal('Review startup baseline','<p>Approve the entire displayed scope, including missing roots. This replaces the active comparison baseline and can acknowledge existing changes. It does not repair files or certify that they are safe.</p><p>Observed '+date(data.latest.created)+'</p><pre>'+esc(JSON.stringify(data.latest.inventory,null,2))+'</pre><form id="startup-baseline-approval"><label>Review reason<textarea name="reason" required minlength="10" maxlength="4000"></textarea></label><button>Approve startup baseline</button></form>');
  const revision=modalRevision;
  $('#startup-baseline-approval').onsubmit=async e=>{e.preventDefault();const button=e.currentTarget.querySelector('button');button.disabled=true;try{await api('/hosts/'+hostId+'/security/baseline','POST',{inspection_id:data.latest.id,evidence_digest:data.latest.digest,expected:data.baseline?.id||'',reason:new FormData(e.currentTarget).get('reason')});if(!current()||revision!==modalRevision)return;$('#modal').close();await reload();}catch(error){if(current()&&revision===modalRevision)toast(error.message);}finally{if(button.isConnected)button.disabled=false;}};
 };
}


async function renderPersistenceMonitoring(root,hostId,current){
 const base='/hosts/'+hostId+'/security';let policy=await api(base+'/persistence-monitor');if(!current())return;
 const panel=root.querySelector('#persistence-monitor');
 panel.innerHTML='<h3>Recurring startup inspections</h3><form id="persistence-monitor-form"><label class="check"><input name="enabled" type="checkbox">Enable scheduled inspections</label><label>Interval in hours<input name="interval_hours" type="number" min="1" max="168"></label><label class="check"><input name="link_incidents" type="checkbox">Record startup-change incidents against the approved baseline</label><p class="help">Both options are off by default. Scheduled inspections are read-only and wait for idle servers. Incident recording also applies to manual inspections. Incomplete coverage never becomes a removal detection. No AI upload or remediation is enabled.</p><button>Save startup monitoring</button></form>';
 const form=panel.querySelector('form');for(const key of ['enabled','link_incidents'])form.elements[key].checked=policy[key];form.elements.interval_hours.value=policy.interval_hours;
 form.onsubmit=async e=>{e.preventDefault();const button=form.querySelector('button');button.disabled=true;try{policy=await api(base+'/persistence-monitor','PUT',{enabled:form.elements.enabled.checked,interval_hours:Number(form.elements.interval_hours.value),link_incidents:form.elements.link_incidents.checked,expected_revision:policy.revision});if(current())toast('Startup monitoring saved');}catch(e){if(current())toast(e.message);}finally{if(button.isConnected)button.disabled=false;}};
 let offset=0,ticket=0;const container=root.querySelector('#persistence-incidents');
 const load=async()=>{const request=++ticket,result=await api(base+'/persistence-incidents?offset='+offset);if(!current()||request!==ticket)return;
 container.innerHTML='<h3>Startup-change incidents</h3><p>Changes require investigation; these are not malware verdicts. Resolving an incident does not change files or the approved baseline. A repeated detection reopens it.</p>'+result.items.map(row=>'<article class="card"><h4>'+badge(row.state)+' · '+date(row.updated)+'</h4><p>Baseline '+esc(row.baseline_id)+'</p><details><summary>Change evidence</summary><pre>'+esc(JSON.stringify(row.evidence,null,2))+'</pre></details><button data-startup-review="'+esc(row.id)+'">Review startup incident</button><button data-startup-history="'+esc(row.id)+'">Linked inspections and reviews</button></article>').join('')+'<button id="startup-prev" '+(!offset?'disabled':'')+'>Previous startup incidents</button><button id="startup-next" '+(!result.more?'disabled':'')+'>Next startup incidents</button><button id="startup-refresh">Refresh startup incidents</button>';
 container.querySelector('#startup-prev').onclick=()=>{offset=Math.max(0,offset-10);refresh();};container.querySelector('#startup-next').onclick=()=>{offset+=10;refresh();};container.querySelector('#startup-refresh').onclick=refresh;
 container.querySelectorAll('[data-startup-review]').forEach(button=>button.onclick=()=>{const row=result.items.find(r=>r.id===button.dataset.startupReview);modal('Review startup incident','<form id="startup-review-form"><label>State<select name="state"><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="false_positive">False positive</option><option value="resolved">Resolved manually</option></select></label><label>Reason<textarea name="reason" required minlength="10" maxlength="4000"></textarea></label><button>Save startup review</button></form>');const revision=modalRevision;const form=$('#startup-review-form');form.elements.state.value=row.state;form.onsubmit=async e=>{e.preventDefault();const save=form.querySelector('button');save.disabled=true;try{await api(base+'/persistence-incidents/'+row.id,'PUT',{state:form.elements.state.value,reason:form.elements.reason.value,expected_updated:row.updated});if(current()&&revision===modalRevision){$('#modal').close();await load();}}catch(e){if(current()&&revision===modalRevision)toast(e.message);}finally{if(save.isConnected)save.disabled=false;}};});
 container.querySelectorAll('[data-startup-history]').forEach(button=>button.onclick=()=>{modal('Linked startup evidence','<pre id="startup-evidence"></pre><button id="startup-evidence-prev">Previous evidence</button><button id="startup-evidence-next">Next evidence</button>');const revision=modalRevision;let page=0,request=0;const history=async()=>{const token=++request;try{const data=await api(base+'/persistence-incidents/'+button.dataset.startupHistory+'/history?offset='+page);if(!current()||revision!==modalRevision||token!==request)return;$('#startup-evidence').textContent=JSON.stringify(data,null,2);$('#startup-evidence-prev').disabled=page===0;$('#startup-evidence-next').disabled=!data.more;}catch(e){if(current()&&revision===modalRevision)toast(e.message);}};$('#startup-evidence-prev').onclick=()=>{page=Math.max(0,page-20);history();};$('#startup-evidence-next').onclick=()=>{page+=20;history();};history();});
 };
 const refresh=()=>load().catch(e=>{if(current())toast(e.message);});await load();
}
