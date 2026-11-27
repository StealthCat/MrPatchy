'use strict';
/* UI for administrator features that previously had API endpoints only (#1684).
 Each panel reuses an existing endpoint, its role checks, revisions, validation
 and audit records. No panel starts a patch, response action or recovery step. */

const AdminTools=(()=>{

 const when=t=>t?new Date(t*1000).toLocaleString():'Not recorded';
 // datetime-local values are browser-local; the API requires an explicit UTC offset.
 const toLocalInput=epoch=>{if(!epoch)return '';const d=new Date(epoch*1000),pad=n=>String(n).padStart(2,'0');return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;};
 const toIsoInstant=value=>{const d=new Date(value);if(!value||Number.isNaN(d.getTime()))throw Error('Enter a complete date and time');return d.toISOString().replace('Z','+00:00');};
 const epochToIso=epoch=>new Date(epoch*1000).toISOString().replace('Z','+00:00');
 const list=value=>String(value||'').split(/[\n,]/).map(item=>item.trim()).filter(Boolean);
 // Disable a button while one request runs; report the outcome in the given status node.
 async function run(button,status,work,success){
  if(button)button.disabled=true;if(status)status.textContent='Saving…';
  try{const result=await work();if(status&&status.isConnected)status.textContent=success||'';return result;}
  catch(error){if(status&&status.isConnected)status.textContent=error.message;else toast(error.message);return undefined;}
  finally{if(button&&button.isConnected)button.disabled=false;}
 }

 /* ---------- Saved fleet queries (Servers page) ---------- */
 const filterSummary=f=>{
  const parts=[];if(f.os)parts.push('OS contains “'+f.os+'”');if(f.package)parts.push('package contains “'+f.package+'”');
  if(f.state)parts.push('state is '+f.state);if(f.enabled===true)parts.push('enabled only');if(f.enabled===false)parts.push('disabled only');
  if(f.overdue_only)parts.push('overdue updates');else if(f.updates_only)parts.push('pending updates');
  return parts.join(' · ')||'All active servers';
 };
 async function savedFleetQueries(root){
  const admin=isAdmin();
  root.innerHTML=`<div class="card-head"><div><h2>Saved queries</h2><p class="help">Reusable server filters by OS, package, state and pending or overdue updates. Results are evaluated when you run them, and servers without a fresh observation are flagged rather than counted as compliant.</p></div>${admin?'<button id="fleet-query-new">+ New saved query</button>':''}</div><div id="fleet-query-list" role="status"><p class="help">Loading saved queries…</p></div>`;
  const target=root.querySelector('#fleet-query-list');
  let rows;
  try{rows=await api('/fleet/queries');}catch(error){if(target.isConnected)target.innerHTML=PatchyUI.error('Unable to load saved queries',esc(error.message));return;}
  if(!root.isConnected)return;
  target.innerHTML=rows.length?`<div class="table-wrap"><table class="fleet-query-table"><thead><tr><th>Name</th><th>Filter</th><th>Version</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>${rows.map(q=>`<tr><td><strong>${esc(q.name)}</strong><small>By ${esc(q.created_by||'unknown')} · updated ${esc(when(q.updated))}</small></td><td>${esc(filterSummary(q.filter))}</td><td>v${q.version}</td><td><div class="actions"><button data-query-run="${esc(q.id)}">Run</button>${admin?`<button data-query-edit="${esc(q.id)}">Edit</button><button class="danger" data-query-delete="${esc(q.id)}">Delete</button>`:''}</div></td></tr>`).join('')}</tbody></table></div>`:`<p class="help">No saved queries yet.${admin?' Create one to reuse a fleet filter.':' An administrator can create them.'}</p>`;
  const byId=new Map(rows.map(q=>[q.id,q]));
  const reload=()=>savedFleetQueries(root);
  root.querySelector('#fleet-query-new')?.addEventListener('click',()=>editFleetQuery(null,reload));
  root.querySelectorAll('[data-query-run]').forEach(b=>b.onclick=()=>runFleetQuery(byId.get(b.dataset.queryRun)));
  root.querySelectorAll('[data-query-edit]').forEach(b=>b.onclick=()=>editFleetQuery(byId.get(b.dataset.queryEdit),reload));
  root.querySelectorAll('[data-query-delete]').forEach(b=>b.onclick=()=>{
   const q=byId.get(b.dataset.queryDelete);
   modal('Delete saved query',`<p>Delete <strong>${esc(q.name)}</strong>? Servers and packages are not changed.</p><button class="primary" id="fleet-query-delete-confirm">Delete saved query</button>`);
   const confirm=$('#fleet-query-delete-confirm'),revision=modalRevision;
   confirm.onclick=async()=>{confirm.disabled=true;try{await api('/fleet/queries/'+encodeURIComponent(q.id),'DELETE');if(revision===modalRevision)$('#modal').close();toast('Saved query deleted');if(root.isConnected)await reload();}catch(error){toast(error.message);confirm.disabled=false;}};
  });
 }
 function editFleetQuery(query,reload){
  const f=query?.filter||{};
  modal(query?'Edit saved query':'New saved query',`<form id="fleet-query-form"><label>Name<input name="name" required maxlength="120" value="${esc(query?.name||'')}"></label>
   <div class="form-grid"><label>Operating system contains<input name="os" maxlength="120" value="${esc(f.os||'')}" placeholder="Ubuntu 24.04"></label><label>Package name contains<input name="package" maxlength="200" value="${esc(f.package||'')}" placeholder="openssl"></label>
   <label>Server state<input name="state" maxlength="40" value="${esc(f.state||'')}" list="fleet-query-states" placeholder="Any state"></label><label>Management<select name="enabled"><option value="">Enabled and disabled</option><option value="true">Enabled only</option><option value="false">Disabled only</option></select></label></div>
   <datalist id="fleet-query-states">${['online','offline','enrolling','error','unknown'].map(s=>`<option value="${s}">`).join('')}</datalist>
   <label class="check"><input type="checkbox" name="updates_only" ${f.updates_only?'checked':''}>Only servers with pending updates</label><label class="check"><input type="checkbox" name="overdue_only" ${f.overdue_only?'checked':''}>Only servers with updates past their priority deadline</label>
   <p class="help">Every field narrows the result. Leave a field empty to ignore it.</p><button class="primary">${query?'Save changes':'Create saved query'}</button><p class="help" role="status"></p></form>`);
  const form=$('#fleet-query-form');form.elements.enabled.value=f.enabled===true?'true':f.enabled===false?'false':'';
  form.onsubmit=async event=>{
   event.preventDefault();const d=new FormData(form),revision=modalRevision;
   const body={name:d.get('name').trim(),filter:{os:d.get('os').trim(),package:d.get('package').trim(),state:d.get('state').trim(),enabled:d.get('enabled')===''?null:d.get('enabled')==='true',updates_only:d.has('updates_only'),overdue_only:d.has('overdue_only')}};
   if(query)body.expected_version=query.version;
   const saved=await run(form.querySelector('button'),form.querySelector('[role=status]'),()=>api(query?'/fleet/queries/'+encodeURIComponent(query.id):'/fleet/queries',query?'PUT':'POST',body));
   if(saved&&revision===modalRevision){$('#modal').close();toast('Saved query stored');await reload();}
  };
 }
 function runFleetQuery(query){
  modal('Saved query · '+query.name,`<p class="help">${esc(filterSummary(query.filter))}</p><div id="fleet-query-results" role="status"><p class="help">Evaluating…</p></div><div class="actions"><button id="fleet-query-prev" disabled>Previous</button><button id="fleet-query-next" disabled>Next</button></div>`);
  const target=$('#fleet-query-results'),prev=$('#fleet-query-prev'),next=$('#fleet-query-next'),revision=modalRevision,size=50;let offset=0;
  const load=async()=>{
   prev.disabled=next.disabled=true;
   try{
    const data=await api(`/fleet/queries/${encodeURIComponent(query.id)}/results?offset=${offset}&limit=${size}`);
    if(revision!==modalRevision)return;
    const packages=h=>h.matching_packages.length?`<ul class="compact-list">${h.matching_packages.map(p=>`<li><code>${esc(p.name)}</code> ${esc(p.installed||'')}${p.candidate?' → '+esc(p.candidate):''} ${p.priority?badge(p.priority):''}${p.overdue?' <strong>overdue</strong>':''}</li>`).join('')}</ul>${h.matching_package_count>h.matching_packages.length?`<small>${h.matching_package_count-h.matching_packages.length} more matching packages</small>`:''}`:'<span class="help">No package criteria</span>';
    target.innerHTML=`<p><strong>${data.matched_hosts}</strong> matching servers · <strong>${data.stale_hosts}</strong> without a fresh observation · evaluated ${esc(when(data.as_of))}</p>${data.hosts.length?`<div class="table-wrap"><table><thead><tr><th>Server</th><th>State</th><th>Freshness</th><th>Matching packages</th></tr></thead><tbody>${data.hosts.map(h=>`<tr><td><a href="${serverLink(h.id)}">${esc(h.name)}</a>${h.enabled?'':'<small>Disabled</small>'}</td><td>${badge(h.state)}</td><td>${h.fresh?'Fresh':'<strong>Stale or missing</strong>'}<small>Last contact ${esc(when(h.last_seen))}</small></td><td>${packages(h)}</td></tr>`).join('')}</tbody></table></div>`:'<p class="help">No servers match this query.</p>'}`;
    prev.disabled=offset===0;next.disabled=offset+size>=data.matched_hosts;
   }catch(error){if(revision===modalRevision){target.innerHTML=PatchyUI.error('Unable to run this query',esc(error.message));prev.disabled=offset===0;}}
  };
  prev.onclick=()=>{offset=Math.max(0,offset-size);load();};next.onclick=()=>{offset+=size;load();};
  target.addEventListener('click',event=>{if(event.target.closest('a'))$('#modal').close();});
  load();
 }

 /* ---------- Change freezes (Patch schedules page) ---------- */
 async function changeFreezes(root){
  root.innerHTML='<h2>Change freezes</h2><p class="help">Loading change freezes…</p>';
  let view;
  try{view=await api('/operations/freezes');}catch(error){if(root.isConnected)root.innerHTML='<h2>Change freezes</h2>'+PatchyUI.error('Unable to load change freezes',esc(error.message));return;}
  if(!root.isConnected)return;
  const now=Date.now()/1000;
  const status=!view.policy_valid?`<div class="notice" role="alert">${esc(view.error)} Save a corrected list below to repair it.</div>`:view.blocked?`<div class="notice" role="status"><strong>A change freeze is active.</strong> Patch, repair and release-upgrade dispatch is blocked${view.clear_at?' until '+esc(when(view.clear_at)):''}.</div>`:'<p>'+badge('clear')+' No freeze is active now.</p>';
  const rows=view.freezes||[];
  root.innerHTML=`<h2>Change freezes</h2><p class="help">${esc(view.precedence)}</p>${status}
   <form id="freeze-form"><div class="table-wrap"><table class="freeze-table"><thead><tr><th>Starts</th><th>Ends</th><th>Reason</th><th>Owner</th><th><span class="sr-only">Remove</span></th></tr></thead><tbody id="freeze-rows"></tbody></table></div>
   <fieldset class="freeze-add"><legend>Add a freeze</legend><div class="form-grid"><label>Starts (local time)<input type="datetime-local" name="start"></label><label>Ends (local time)<input type="datetime-local" name="end"></label></div><label>Reason<input name="reason" maxlength="200" placeholder="Quarter-end trading window"></label><button type="button" id="freeze-add">Add to list</button></fieldset>
   <p class="help">Freezes are saved as one list. Times are shown in ${esc(Intl.DateTimeFormat().resolvedOptions().timeZone)} and stored in UTC. A freeze ends on its own at its end time.</p><button class="primary" id="freeze-save">Save change freezes</button><p class="help" role="status" id="freeze-status"></p></form>`;
  const draft=rows.map(r=>({start:epochToIso(r.start),end:epochToIso(r.end),reason:r.reason,owner:r.owner,startEpoch:r.start,endEpoch:r.end}));
  const body=root.querySelector('#freeze-rows'),form=root.querySelector('#freeze-form'),statusNode=root.querySelector('#freeze-status');
  const draw=()=>{body.innerHTML=draft.length?draft.map((r,i)=>`<tr><td>${esc(when(r.startEpoch))}</td><td>${esc(when(r.endEpoch))}${r.endEpoch<=now?' <small>ended</small>':r.startEpoch<=now?' <small>active</small>':''}</td><td>${esc(r.reason)}</td><td>${esc(r.owner||'You, when saved')}</td><td><button type="button" data-freeze-remove="${i}">Remove</button></td></tr>`).join(''):'<tr><td colspan="5" class="help">No change freezes are saved.</td></tr>';
   body.querySelectorAll('[data-freeze-remove]').forEach(b=>b.onclick=()=>{draft.splice(+b.dataset.freezeRemove,1);draw();statusNode.textContent='Removed from the list. Save to apply.';});};
  draw();
  root.querySelector('#freeze-add').onclick=()=>{
   const start=form.elements.start.value,end=form.elements.end.value,reason=form.elements.reason.value.trim();
   try{
    if(!reason)throw Error('Enter a reason for the freeze');
    const s=toIsoInstant(start),e=toIsoInstant(end),se=new Date(start).getTime()/1000,ee=new Date(end).getTime()/1000;
    if(ee<=se)throw Error('A freeze must end after it starts');
    draft.push({start:s,end:e,reason,owner:'',startEpoch:se,endEpoch:ee});draft.sort((a,b)=>a.startEpoch-b.startEpoch);
    form.elements.start.value=form.elements.end.value=form.elements.reason.value='';draw();statusNode.textContent='Added to the list. Save to apply.';
   }catch(error){statusNode.textContent=error.message;}
  };
  form.onsubmit=async event=>{
   event.preventDefault();
   const saved=await run(root.querySelector('#freeze-save'),statusNode,()=>api('/operations/freezes','PUT',{freezes:draft.map(({start,end,reason})=>({start,end,reason})),expected_revision:view.revision}));
   if(saved&&root.isConnected){toast('Change freezes saved');await changeFreezes(root);}
  };
 }

 /* ---------- Application probes (server Maintenance tab) ---------- */
 async function applicationProbes(root,hostId){
  root.innerHTML='<h3>Application probes</h3><p class="help">Loading probes…</p>';
  let data;
  try{data=await api('/operations/'+encodeURIComponent(hostId)+'/probes');}catch(error){if(root.isConnected)root.innerHTML='<h3>Application probes</h3>'+PatchyUI.error('Unable to load probes',esc(error.message));return;}
  if(!root.isConnected)return;
  const probes=data.probes.map(p=>({...p}));
  root.innerHTML=`<h3>Application probes</h3><p class="help">Staged rollouts check these loopback HTTP or TCP probes on this server before and after patching. A required probe that was healthy and then fails stops later rollout stages. Probes are reviewed definitions, never commands, and they only connect to the server's own loopback address.${data.reviewed_by?' Last reviewed by '+esc(data.reviewed_by)+'.':''}</p>
   <form id="probe-form"><div id="probe-rows"></div><div class="actions"><button type="button" id="probe-add">+ Add probe</button><button class="primary" id="probe-save">Save probes</button></div><p class="help" role="status" id="probe-status"></p></form>`;
  const rowsNode=root.querySelector('#probe-rows'),form=root.querySelector('#probe-form'),statusNode=root.querySelector('#probe-status');
  const capture=()=>{rowsNode.querySelectorAll('[data-probe]').forEach(fs=>{const i=+fs.dataset.probe,v=name=>fs.querySelector(`[name=${name}]`);
   probes[i]={name:v('name').value.trim(),kind:v('kind').value,port:v('port').value,path:v('path').value,expect_status:v('expect_status').value,timeout:v('timeout').value,required:v('required').checked,reason:v('reason').value};});};
  const draw=()=>{
   rowsNode.innerHTML=probes.length?probes.map((p,i)=>`<fieldset class="probe-row" data-probe="${i}"><legend>Probe ${i+1}</legend><div class="form-grid"><label>Name<input name="name" required pattern="[a-z0-9][a-z0-9_.\\-]{0,39}" value="${esc(p.name||'')}" placeholder="web-health"></label><label>Type<select name="kind"><option value="http">HTTP</option><option value="tcp">TCP</option></select></label><label>Port<input name="port" type="number" min="1" max="65535" required value="${esc(p.port??'')}"></label><label>Timeout · seconds<input name="timeout" type="number" min="1" max="10" value="${esc(p.timeout??5)}"></label><label data-http>Path<input name="path" value="${esc(p.path??'/')}"></label><label data-http>Expected HTTP status<input name="expect_status" type="number" min="100" max="599" value="${esc(p.expect_status??200)}"></label></div><label>Why this probe is required<input name="reason" required maxlength="200" value="${esc(p.reason||'')}"></label><div class="actions"><label class="check"><input type="checkbox" name="required" ${p.required!==false?'checked':''}>Required: a new failure stops the rollout</label><button type="button" data-probe-remove="${i}">Remove probe</button></div></fieldset>`).join(''):'<p class="help">No probes are configured. Rollouts rely on patch results and service health only.</p>';
   rowsNode.querySelectorAll('[data-probe]').forEach(fs=>{const kind=fs.querySelector('[name=kind]'),sync=()=>fs.querySelectorAll('[data-http]').forEach(n=>n.hidden=kind.value!=='http');kind.value=probes[+fs.dataset.probe].kind||'http';kind.onchange=sync;sync();});
   rowsNode.querySelectorAll('[data-probe-remove]').forEach(b=>b.onclick=()=>{capture();probes.splice(+b.dataset.probeRemove,1);draw();});
  };
  draw();
  root.querySelector('#probe-add').onclick=()=>{capture();if(probes.length>=16){statusNode.textContent='At most 16 probes are allowed.';return;}probes.push({kind:'http',path:'/',expect_status:200,timeout:5,required:true});draw();rowsNode.querySelector('[data-probe]:last-of-type [name=name]')?.focus();};
  form.onsubmit=async event=>{
   event.preventDefault();capture();
   const body=probes.map(p=>{const item={name:p.name,kind:p.kind,port:Number(p.port),timeout:Number(p.timeout)||5,required:p.required,reason:p.reason.trim()};if(p.kind==='http'){item.path=p.path||'/';item.expect_status=Number(p.expect_status)||200;}return item;});
   const saved=await run(root.querySelector('#probe-save'),statusNode,()=>api('/operations/'+encodeURIComponent(hostId)+'/probes','PUT',{probes:body}),'Probes saved.');
   if(saved&&root.isConnected){probes.splice(0,probes.length,...saved.probes);draw();statusNode.textContent='Probes saved.';}
  };
 }

 /* ---------- Agent spool batch limit (server Agent health tab) ---------- */
 function spoolBatchLimit(root,hostId){
  root.innerHTML=`<h3>Event spool batch size</h3><p class="help">Sets the largest event batch the agent sends in one delivery (16–1024 KiB). Saving contacts the agent over SSH and checks the result by reading it back. Nothing is saved if the agent does not confirm the change.</p><form id="spool-limit-form" class="inline-form"><label>Batch limit · KiB<input name="kib" type="number" min="16" max="1024" step="1" required value="256"></label><button class="primary">Apply to agent</button></form><p class="help" role="status" id="spool-limit-status"></p>`;
  const form=root.querySelector('#spool-limit-form');
  form.onsubmit=async event=>{
   event.preventDefault();const kib=Number(form.elements.kib.value);
   const status=root.querySelector('#spool-limit-status');
   if(!Number.isInteger(kib)||kib<16||kib>1024){status.textContent='Enter a whole number from 16 to 1024.';return;}
   const result=await run(form.querySelector('button'),status,()=>api('/operations/'+encodeURIComponent(hostId)+'/spool','PUT',{batch_limit_bytes:kib*1024}));
   if(result&&status.isConnected)status.textContent=`The agent confirmed a ${Math.round(result.batch_limit_bytes/1024)} KiB batch limit.`;
  };
 }

 /* ---------- SSO identity bindings (Users page) ---------- */
 async function ssoBindings(root){
  root.innerHTML='<h2>Single sign-on identities</h2><p class="help">Loading bindings…</p>';
  let rows,users;
  try{[rows,users]=await Promise.all([api('/operations/sso-bindings'),api('/users')]);}catch(error){if(root.isConnected)root.innerHTML='<h2>Single sign-on identities</h2>'+PatchyUI.error('Unable to load SSO bindings',esc(error.message));return;}
  if(!root.isConnected)return;
  root.innerHTML=`<h2>Single sign-on identities</h2><p class="help">Each identity-provider subject signs in as one existing account and gets that account's role. Email matching never grants access. The OIDC deployment variables must be set before you can bind an identity.</p>
   ${rows.length?`<div class="table-wrap"><table><thead><tr><th>Subject fingerprint</th><th>Signs in as</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>${rows.map(r=>`<tr><td><code>${esc(r.subject_digest)}</code></td><td>${esc(r.username||'')}</td><td><button data-sso-unbind="${esc(r.subject_digest)}">Unbind</button></td></tr>`).join('')}</tbody></table></div>`:'<p class="help">No SSO identities are bound.</p>'}
   <details class="sso-bind"><summary>Bind an identity</summary><form id="sso-bind-form"><div class="form-grid"><label>Provider subject (sub claim)<input name="subject" required maxlength="500" autocomplete="off"></label><label>Account<select name="username" required>${users.map(u=>`<option value="${esc(u.username)}">${esc(u.username)} · ${esc(u.role)}</option>`).join('')}</select></label></div><button class="primary">Bind identity</button><p class="help" role="status" id="sso-bind-status"></p></form></details>`;
  const reload=()=>ssoBindings(root);
  root.querySelectorAll('[data-sso-unbind]').forEach(b=>b.onclick=()=>{
   const row=rows.find(r=>r.subject_digest===b.dataset.ssoUnbind);
   modal('Unbind SSO identity',`<p>Stop subject <code>${esc(row.subject_digest)}</code> from signing in as <strong>${esc(row.username)}</strong>? The local account and its sessions are not changed.</p><button class="primary" id="sso-unbind-confirm">Unbind identity</button>`);
   const confirm=$('#sso-unbind-confirm'),revision=modalRevision;
   confirm.onclick=async()=>{confirm.disabled=true;try{await api('/operations/sso-bindings/'+encodeURIComponent(row.subject_digest),'DELETE');if(revision===modalRevision)$('#modal').close();toast('SSO identity unbound');if(root.isConnected)await reload();}catch(error){toast(error.message);confirm.disabled=false;}};
  });
  const form=root.querySelector('#sso-bind-form'),status=root.querySelector('#sso-bind-status');
  // Each submit is one attempt. A replacement confirmation is pinned to the exact subject and
  // account that attempt sent. Any edit or a newer attempt makes the attempt stale, including
  // while its request is still pending, and a stale response never writes the status or offers
  // a confirmation (#1685 review).
  let attempt=0;
  const withdraw=()=>{attempt++;status.textContent='';};
  form.addEventListener('input',withdraw);form.addEventListener('change',withdraw);
  const bind=async body=>{
   const turn=++attempt,button=form.querySelector('button');
   const fresh=()=>turn===attempt&&root.isConnected&&status.isConnected;
   button.disabled=true;status.textContent='Saving…';
   let failure;
   try{await api('/operations/sso-binding','PUT',body);}catch(error){failure=error;}
   finally{if(button.isConnected)button.disabled=false;}
   if(!failure){
    // The binding was saved even if the form changed meanwhile; say so without touching the form.
    toast('SSO identity bound');if(fresh())await reload();return;
   }
   if(!fresh())return;
   const match=/already bound to (.+?)\. Resend/.exec(failure.message);
   if(!match||body.replace_username){status.textContent=failure.message;return;}
   const pinned={subject:body.subject,username:body.username,replace_username:match[1]};
   status.innerHTML=`This subject already signs in as <strong>${esc(pinned.replace_username)}</strong>. <button type="button" id="sso-replace">Replace with ${esc(pinned.username)}</button>`;
   status.querySelector('#sso-replace').onclick=()=>{if(turn===attempt)bind(pinned);};
  };
  form.onsubmit=event=>{event.preventDefault();const d=new FormData(form);bind({subject:d.get('subject'),username:d.get('username')});};
 }

 /* ---------- Recovery readiness (Settings → Backup & recovery) ---------- */
 const stageLabels={backup:'Backup',archive_verification:'Archive verification',isolated_restore:'Isolated restore',boot_recovery:'Boot recovery',application_recovery:'Application recovery'};
 async function recoveryReadiness(container,revision){
  container.innerHTML='<div class="card"><p class="help">Loading recovery readiness…</p></div>';
  let data;
  try{data=await api('/recovery/readiness');}catch(error){if(container.isConnected)container.innerHTML='<div class="card">'+PatchyUI.error('Unable to load recovery readiness',esc(error.message))+'</div>';return;}
  if(!currentView(revision,'settings')||!container.isConnected)return;
  const stageRows=Object.entries(data.stages).map(([key,s])=>`<tr><td>${esc(stageLabels[key]||key)}${s.required?'':' <small>optional</small>'}</td><td>${badge(s.state)}</td><td>${s.receipt?esc(when(s.receipt.completed)):'—'}</td><td>${s.receipt?`<code class="receipt-id">${esc(s.receipt.id)}</code>`:'—'}</td></tr>`).join('');
  container.innerHTML=`<section class="card"><h2>Recovery readiness ${badge(data.ready?'ready':'not ready')}</h2><p class="help">${esc(data.note)}</p>
   ${data.blockers.length?`<div class="notice" role="status"><strong>What is missing</strong><ul>${data.blockers.map(b=>`<li>${esc(b.replace(/_/g,' '))}</li>`).join('')}</ul></div>`:''}
   <div class="table-wrap"><table><thead><tr><th>Stage</th><th>State</th><th>Completed</th><th>Receipt ID</th></tr></thead><tbody>${stageRows}</tbody></table></div>
   <p class="help">Key custody: <strong>${esc(data.key_custody)}</strong>${data.declared_scope.length?' · Declared scope: '+esc(data.declared_scope.join(', ')):''}${data.unverified_scope.length?' · Not yet verified by a restore: '+esc(data.unverified_scope.join(', ')):''}</p></section>
   <details class="card recovery-receipt"><summary><h2>Record a drill receipt</h2></summary><form id="recovery-receipt-form"><p class="help">Record evidence of a backup or drill that already happened. Recording never starts a backup, restore or stop. Never enter key material: only identities and SHA-256 fingerprints are accepted. Each stage after a backup names its parent receipt ID from the table above.</p><fieldset>
   <div class="form-grid"><label>Stage<select name="stage">${Object.entries(stageLabels).map(([k,v])=>`<option value="${k}">${v}</option>`).join('')}</select></label><label>Result<select name="result"><option value="success">Success</option><option value="failure">Failure</option></select></label><label>Completed<input type="datetime-local" name="completed" required></label><label>Parent receipt ID<input name="parent_id" pattern="[a-f0-9]{32}" placeholder="Not needed for a backup"></label></div>
   <div class="form-grid"><label>Environment<input name="environment" required maxlength="80" placeholder="isolated-dr"></label><label>Adapter<input name="adapter" required maxlength="80" placeholder="restic"></label><label>Backup ID<input name="backup_id" required maxlength="80"></label><label>Database ID<input name="database_id" required maxlength="80"></label><label>Trust ID<input name="trust_id" required maxlength="80"></label><label>Key custody<select name="key_custody"><option value="external">Held outside this deployment</option><option value="local">Held in this deployment</option><option value="unknown">Unknown</option></select></label></div>
   <div class="form-grid"><label>Archive SHA-256<input name="archive_sha256" required pattern="[a-f0-9]{64}" autocomplete="off"></label><label>Encryption key fingerprint (SHA-256)<input name="key_fingerprint" required pattern="[a-f0-9]{64}" autocomplete="off"></label><label>Key verified at<input type="datetime-local" name="key_verified_at" required></label></div>
   <div class="form-grid"><label>Declared scope (backups; comma separated)<input name="declared_scope" placeholder="database, uploads"></label><label>Verified items (comma separated)<input name="verified"></label><label>Known gaps (comma separated)<input name="gaps"></label></div>
   <button class="primary">Record receipt</button></fieldset><p class="help" role="status" id="recovery-receipt-status"></p></form></details>`;
  const form=container.querySelector('#recovery-receipt-form'),status=container.querySelector('#recovery-receipt-status');
  form.onsubmit=async event=>{
   event.preventDefault();const d=new FormData(form);
   const epoch=name=>{const t=new Date(d.get(name)).getTime()/1000;return Number.isFinite(t)?t:0;};
   const body={version:2,stage:d.get('stage'),result:d.get('result'),completed:epoch('completed'),environment:d.get('environment'),adapter:d.get('adapter'),backup_id:d.get('backup_id'),database_id:d.get('database_id'),trust_id:d.get('trust_id'),archive_sha256:d.get('archive_sha256'),key_fingerprint:d.get('key_fingerprint'),key_verified_at:epoch('key_verified_at'),key_custody:d.get('key_custody'),declared_scope:list(d.get('declared_scope')),verified:list(d.get('verified')),gaps:list(d.get('gaps'))};
   if(body.stage!=='backup')body.parent_id=d.get('parent_id').trim();
   const result=await run(form.querySelector('button'),status,()=>api('/recovery/receipts','POST',body));
   if(result&&container.isConnected){toast('Receipt recorded: '+result.receipt.id);await recoveryReadiness(container,revision);}
  };
 }

 /* ---------- AI provider connection inventory (Settings → AI) ---------- */
 const featureLabels={triage_first:'First-pass behavior triage',triage_followup:'Follow-up triage',update_scoring:'Update scoring',incident_plan:'Incident response plans',startup_plan:'Startup-file plans',release_configuration:'Distribution upgrade planning',connection_test:'Connection test',model_discovery:'Model discovery'};
 async function aiConnections(root){
  root.innerHTML='<h2>Where AI is used</h2><p class="help">Loading connection inventory…</p>';
  let data;
  try{data=await api('/settings/ai-connections');}catch(error){if(root.isConnected)root.innerHTML='<h2>Where AI is used</h2>'+PatchyUI.error('Unable to load the connection inventory',esc(error.message));return;}
  if(!root.isConnected)return;
  const c=data.connections[0]||{};
  root.innerHTML=`<h2>Where AI is used</h2><p class="help">Read-only. Shows which features use the saved provider connection, and whether current settings enable each one.</p><p>Connection: <strong>${esc(c.provider||'none')}</strong> · key ${c.credential_saved?'saved':'not saved'} · default model ${esc(c.default_model||'not set')}</p>
   <div class="table-wrap"><table><thead><tr><th>Feature</th><th>Scope</th><th>Enabled</th><th>Ready</th><th>Billable</th></tr></thead><tbody>${data.features.map(f=>`<tr><td>${esc(featureLabels[f.id]||f.id)}</td><td>${f.scope==='host'?'Per server':'Connection'}</td><td>${f.enabled_by_settings?'Yes':'No'}</td><td>${badge(f.configuration_complete?'complete':'incomplete')}</td><td>${f.billable?'Yes':'No'}</td></tr>`).join('')}</tbody></table></div>`;
 }

 /* ---------- Incident case owner and notes (server Security tab) ---------- */
 async function incidentCase(hostId,incident,reload){
  const base='/hosts/'+encodeURIComponent(hostId)+'/security/incidents/'+encodeURIComponent(incident.id);
  // Discard the responses if the administrator navigated or opened another dialog meanwhile,
  // so a late dialog can never show one server's incident on another server's page.
  const view=page,opened=renderRevision,dialog=modalRevision;
  const stale=()=>!currentView(opened,view)||modalRevision!==dialog;
  let state,users;
  try{[state,users]=await Promise.all([api(base+'/case'),api('/users')]);}catch(error){if(!stale())toast(error.message);return;}
  if(stale())return;
  const admins=users.filter(u=>u.role==='admin'&&u.enabled);
  modal('Incident case',`<p>Server: <strong>${esc(hostName(hostId))}</strong></p><p>${esc(incident.evidence?.path||incident.id)}</p><p>Owner: <strong>${esc(state.owner||'Unassigned')}</strong></p><p class="help">Ownership and notes are recorded on the incident timeline and in the audit log. They never change the incident status, evidence or response plans.</p>
   <form id="incident-owner-form"><h3>Assign owner</h3><label>Responsible administrator<select name="owner"><option value="">Unassigned</option>${admins.map(u=>`<option value="${esc(u.username)}" ${u.username===state.owner?'selected':''}>${esc(u.username)}</option>`).join('')}</select></label><label>Reason<textarea name="reason" required minlength="10" maxlength="4000"></textarea></label><button>Save owner</button><p class="help" role="status"></p></form>
   <form id="incident-note-form"><h3>Add investigator note</h3><label>Note<textarea name="note" required maxlength="4000"></textarea></label><button>Add note</button><p class="help" role="status"></p></form>`);
  const revision=modalRevision,owner=$('#incident-owner-form'),note=$('#incident-note-form');
  owner.onsubmit=async event=>{event.preventDefault();const d=new FormData(owner);
   const saved=await run(owner.querySelector('button'),owner.querySelector('[role=status]'),()=>api(base+'/owner','PUT',{owner:d.get('owner'),reason:d.get('reason'),expected_revision:state.revision}));
   if(saved&&revision===modalRevision){$('#modal').close();toast('Case owner saved');if(reload)await reload();}};
  note.onsubmit=async event=>{event.preventDefault();const d=new FormData(note);
   const saved=await run(note.querySelector('button'),note.querySelector('[role=status]'),()=>api(base+'/notes','POST',{note:d.get('note')}),'Note added to the incident timeline.');
   if(saved&&revision===modalRevision)note.reset();};
 }

 /* ---------- Settings → Alerts & sign-in (links to existing dialogs) ---------- */
 function integrations(container){
  container.innerHTML=`<section class="card"><h2>Alert delivery</h2><p class="help">Webhook delivery, alert acknowledgement and fleet maintenance windows.</p><button type="button" id="open-operations">Open alert delivery</button></section>
   <section class="card"><h2>SMTP, sign-in and key rotation</h2><p class="help">SMTP alert mail, SSO identity binding, SSH key rotation, collector observability and per-server recovery policy.</p><div class="actions"><button type="button" id="open-advanced">Open enterprise controls</button><a class="button" href="#users">SSO identities on Users →</a></div></section>
   <section class="card"><h2>Staged rollout and advisory matching</h2><p class="help">Queue a reviewed canary rollout across servers, or check packages against advisories.</p><button type="button" id="open-expert">Open fleet workflows</button></section>`;
  container.querySelector('#open-operations').onclick=operationsPanel;
  container.querySelector('#open-advanced').onclick=advancedControls;
  container.querySelector('#open-expert').onclick=expertWorkflows;
 }

 return {savedFleetQueries,changeFreezes,applicationProbes,spoolBatchLimit,ssoBindings,recoveryReadiness,aiConnections,incidentCase,integrations,toLocalInput,toIsoInstant};
})();
