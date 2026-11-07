'use strict';

async function fileStatusPanel(root,hostId,current){
 let offset=0,ticket=0;
 const labels={verified:'Verified artifact',known_good:'Known-good exact match',changed:'Hash differs',missing:'Missing',unavailable:'Unavailable',unassessed:'Unassessed',behavior_assessed:'Behavior assessed; file unverified'};
 root.innerHTML=`<h3>File assessment status</h3><p class="help">Assessment order: signed repository artifacts and SHA-256 → exact known-good database → AI for unresolved behavior. File authenticity and behavior risk are separate.</p><form class="toolbar"><label>Path<input name="q" type="search" maxlength="200"></label><label>Status<select name="status"><option value="">All statuses</option>${Object.entries(labels).map(([key,label])=>`<option value="${key}">${label}</option>`).join('')}</select></label><button>Apply filters</button></form><p class="file-status-count" role="status"></p><div class="file-status-results"></div><div class="actions"><button data-prev>Previous</button><button data-next>Next</button><button data-retry>Refresh</button><a class="button" href="${serverLink(hostId,'files')}">Open file status page</a></div>`;
 const form=root.querySelector('form'),results=root.querySelector('.file-status-results'),count=root.querySelector('.file-status-count');
 const load=async()=>{
  const turn=++ticket;
  try{
   const data=await api('/hosts/'+encodeURIComponent(hostId)+'/file-status?'+new URLSearchParams({offset,q:form.elements.q.value,status:form.elements.status.value}));
   if(!current()||!root.isConnected||turn!==ticket)return;
   count.textContent=`${data.total} matching file observations / ${data.recorded} recorded. `+Object.entries(data.counts).map(([k,v])=>`${labels[k]||k}: ${v}`).join(' · ');
   results.innerHTML=`<p class="help">${esc(data.note)}</p>${data.coverage.length?`<p class="notice">Coverage: ${data.coverage.map(esc).join('; ')}</p>`:''}<p>Reviewed baseline: ${esc(data.baseline_state)}</p><div class="table-wrap"><table><thead><tr><th>File / SHA-256</th><th>File status</th><th>Assessment evidence</th><th>Observed</th></tr></thead><tbody>${data.items.map(row=>`<tr><td><code>${esc(row.path)}</code><details><summary>SHA-256 &amp; sources</summary><code class="file-status-hash">${esc(row.sha256||'Not recorded')}</code><p>${row.sources.map(esc).join(', ')}</p></details></td><td>${esc(labels[row.status]||row.status)}${row.baseline_status?`<p>Baseline: ${esc(row.baseline_status)}</p>`:''}</td><td>${esc(row.reason)}${row.reference?`<p>Signed artifact: ${esc(row.reference.package)} ${esc(row.reference.version)}</p><details><summary>Authentication reference</summary><code>${esc(row.reference.inspection_id)}</code><p class="file-status-hash">Proof SHA-256: ${esc(row.reference.proof_sha256)}</p><p>Inspection: ${date(row.reference.created)}</p></details>`:''}${(row.behaviors||[]).map(b=>`<p>Behavior: ${esc(b.risk)} · ${esc(b.method)}${b.known_good?.review_required?' · Cache revoked: review required':''} · ${b.approved?'manually approved':'not approved'} <a href="${serverLink(hostId,'investigations')}/item/${encodeURIComponent(b.id)}/history">Assessment history</a></p>`).join('')}</td><td>${date(row.observed)}${row.stale?'<p>Stale or unavailable</p>':''}</td></tr>`).join('')||'<tr><td colspan="4">No matching recorded files. This does not establish filesystem coverage.</td></tr>'}</tbody></table></div>`;
   root.querySelector('[data-prev]').disabled=offset===0;
   root.querySelector('[data-next]').disabled=!data.more;
  }catch(error){if(current()&&root.isConnected&&turn===ticket){count.textContent='File status unavailable';results.innerHTML=PatchyUI.error('Unable to load file status',esc(error.message));}}
 };
 form.onsubmit=event=>{event.preventDefault();offset=0;load();};
 root.querySelector('[data-prev]').onclick=()=>{offset=Math.max(0,offset-50);load();};
 root.querySelector('[data-next]').onclick=()=>{offset+=50;load();};
 root.querySelector('[data-retry]').onclick=load;
 await load();
}

async function serverFileStatus(revision,{root,hostId}){
 return fileStatusPanel(root,hostId,()=>currentView(revision,'servers'));
}

async function fleetFileStatus(revision,root=$('#content'),view='files'){
 if(!isAdmin()){root.innerHTML=PatchyUI.error('Administrator access required','File evidence uses the existing administrator permissions.');return;}
 root.innerHTML='<a class="button" href="#overview">Back to overview</a><h2>File status</h2><label>Server<select aria-label="File status server">'+hosts.map(h=>`<option value="${esc(h.id)}">${esc(h.name)}</option>`).join('')+'</select></label><section class="card file-status-panel"></section>';
 const select=root.querySelector('select'),panel=root.querySelector('section');let selection=0;
 const load=()=>{const turn=++selection;return fileStatusPanel(panel,select.value,()=>currentView(revision,view)&&turn===selection);};
 select.onchange=load;
 if(hosts.length)await load();else panel.textContent='No servers available.';
}
