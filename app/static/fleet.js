'use strict';
const assessmentOffsets=new Map();

async function requestInvestigationRetriage(id){
 const view=renderRevision,session=sessionRevision,startedModal=modalRevision;
 try{
  const data=await api('/investigations/'+encodeURIComponent(id)+'/history');
  if(view!==renderRevision||session!==sessionRevision||startedModal!==modalRevision)return;
  const current=data.current;
  if(!current.can_retriage)return toast('Only completed assessments on active servers can be re-triaged. Pending or failed work uses Retry.');
  modal('Request fresh AI triage',`<p>Investigate <strong class="assessment-artifact">${esc(current.executable)}</strong> again on ${esc(hostName(current.host_id))}? The saved ${esc(current.verdict)} result stays in Assessment history. This queues a new investigation, may incur provider charges, and does not approve any response.</p><p class="help">This requests fresh work for this observation only. AI pause, data sharing, saved model and admission limits still apply. No fleet trust is changed.</p><form id="retriage-form"><label>Reason<textarea name="reason" minlength="10" maxlength="4000" required></textarea></label>${current.approved?'<label class="check"><input name="withdraw" type="checkbox" required>I withdraw this behavior’s current approval until it is reviewed again.</label>':''}<button class="primary">Queue fresh triage</button></form>`);
  const form=$('#retriage-form'),dialog=modalRevision;
  const active=()=>form.isConnected&&dialog===modalRevision&&view===renderRevision&&session===sessionRevision;
  form.onsubmit=async event=>{
   event.preventDefault();const button=form.querySelector('button');if(button.disabled)return;button.disabled=true;
   try{
    const values=new FormData(form);
    const result=await api('/investigations/'+encodeURIComponent(id)+'/retriage','POST',{expected_revision:current.revision,reason:values.get('reason'),withdraw_approval:values.has('withdraw')});
    if(!active())return;$('#modal').close();toast(result.detail);await render();
   }catch(error){if(active())toast(error.message);}finally{if(active())button.disabled=false;}
  };
 }catch(error){if(view===renderRevision&&session===sessionRevision)toast(error.message);}
}

function requestKnownGoodRevocation(fingerprint,version,linked){
 const view=renderRevision,session=sessionRevision;
 modal('Revoke fleet safe candidate',`<p>Stop all future reuse of exact fingerprint <code class="known-good-fingerprint">${esc(fingerprint)}</code>? ${esc(linked)} linked assessment(s) will be marked for review without changing their saved results.</p><p class="help">This does not re-run AI, remove historical evidence, approve a response or suppress deterministic protection. Do not enter credentials or raw endpoint evidence.</p><form id="known-good-revoke-form"><label>Reason<textarea name="reason" minlength="10" maxlength="1000" required></textarea></label><label class="check"><input name="confirm" type="checkbox" required>I understand this invalidates the candidate across the fleet.</label><button class="primary">Revoke fleet candidate</button></form>`);
 const form=$('#known-good-revoke-form'),dialog=modalRevision;
 const active=()=>form.isConnected&&dialog===modalRevision&&view===renderRevision&&session===sessionRevision;
 form.onsubmit=async event=>{
  event.preventDefault();const button=form.querySelector('button');if(button.disabled)return;button.disabled=true;
  try{
   const values=new FormData(form);
   const result=await api('/ai/known-good/'+encodeURIComponent(fingerprint)+'/revoke','POST',{expected_version:Number(version),reason:values.get('reason')});
   if(!active())return;$('#modal').close();toast(result.detail);await render();
  }catch(error){if(active())toast(error.message);}finally{if(active())button.disabled=false;}
 };
}

function assessmentContextCoverage(item){
 const details=item.snapshot?.investigation?.details,context=details?.context;
 const labels={original_observation_process_not_identified:'The original observation’s process is not identified.',package_authentication_missing:'Package ownership is not authenticated vendor provenance.',configuration_not_collected:'Relevant configuration is not collected.',startup_not_collected:'Startup and trigger context is not collected.',network_history_not_collected:'Historical network behavior is not collected.',arguments_and_environment_not_collected:'Arguments and environment are not collected.',script_execution_not_attested:'Script file identity does not attest executed content.',memory_not_attested:'Process memory is not attested.',artifact_coverage_incomplete:'Some script or mapped-file identities are unavailable.'};
 if(details?.version!==2||details.identity_verified!==true||context?.version!==1||!Array.isArray(context.coverage?.gaps))return '<section class="notice"><h3>Follow-up context unavailable</h3><p>No identity-bound context is recorded for this result. A follow-up may not have been requested, the helper may predate context collection, or the process could not be verified. This result is ineligible for fleet reuse.</p></section>';
 const artifacts=Array.isArray(context.artifacts)?context.artifacts:[],verified=artifacts.filter(a=>a?.identity_verified===true).length;
 const recorded=context.coverage.scope==='recorded_process_identity'&&!context.coverage.gaps.includes('original_observation_process_not_identified');
 return `<section class="notice assessment-context"><h3>Follow-up context sampled</h3><p>${recorded?'The recorded process identity was found and rechecked.':'One current matching executable was sampled and rechecked; the original observation is not identified.'} This does not certify safety. <strong>Fleet reuse unavailable.</strong></p><dl class="ai-run-facts"><div><dt>Context collected</dt><dd>${date(item.snapshot.investigation.collected)}</dd></div><div><dt>${recorded?'Recorded':'Sampled'} PID</dt><dd>${esc(context.process?.pid)}</dd></div><div><dt>Start identity</dt><dd>${esc(context.process?.start_ticks)}</dd></div><div><dt>Effective UID</dt><dd>${esc(context.credentials?.Uid?.[1])}</dd></div><div><dt>Artifact identities</dt><dd>${verified} / ${artifacts.length} verified</dd></div></dl><details><summary>Context coverage gaps</summary><ul>${context.coverage.gaps.map(g=>`<li>${esc(labels[g]||g)}</li>`).join('')}</ul><p class="help">Matching before/after samples are not an atomic snapshot. Evidence relies on the target kernel and local files.</p></details></section>`;
}

function assessmentKnownGood(item){
 const value=item.known_good;
 if(!value)return '<section class="notice"><h3>Fleet match readiness unavailable</h3><p>This assessment predates canonical fingerprint evaluation. It is not reusable across servers.</p></section>';
 const revoke=value.published?`<button data-admin data-action="revoke-known-good" data-fingerprint="${esc(value.fingerprint)}" data-version="${esc(value.version)}" data-linked="${esc(value.linked_assessments||1)}">Revoke fleet candidate</button>`:'';
 if(value.review_required){const source=value.reused?`<a class="button" href="#investigations/item/${encodeURIComponent(value.source_subject)}/history/${encodeURIComponent(value.source_assessment_id)}">Review original assessment</a>`:'';const contradiction=value.contradiction_assessment_id?`<a class="button" href="#investigations/item/${encodeURIComponent(value.contradiction_subject)}/history/${encodeURIComponent(value.contradiction_assessment_id)}">Review contradictory assessment</a>`:'';return `<section class="notice assessment-known-good"><h3>Fleet candidate revoked · review required</h3><p>Fingerprint v${esc(value.version)} <code>${esc(value.fingerprint)}</code> was revoked by ${esc(value.revoked_by||'an administrator')} on ${date(value.revoked_at)}. Future exact matches cannot reuse it. ${esc(value.linked_assessments||0)} linked assessment(s) retain their original result but now require review.</p>${contradiction?`<p>A retained ${esc(value.contradiction_risk)}-risk provider result contradicted this exact verified context. The result is advisory and does not authorize a response.</p>`:''}<pre class="ai-run-message">${esc(value.revoked_reason||'No revocation reason recorded.')}</pre>${source||contradiction?`<p>${source} ${contradiction}</p>`:''}<p class="help">This historical result is unchanged and does not authorize a response. Re-triage requests a fresh provider assessment under current controls.</p></section>`;}
 if(value.reused){const source=`#investigations/item/${encodeURIComponent(value.source_subject)}/history/${encodeURIComponent(value.source_assessment_id)}`;return `<section class="notice assessment-known-good"><h3>Reused exact safe candidate</h3><p>Mr Patchy matched the complete verified context to fingerprint v${esc(value.version)} <code>${esc(value.fingerprint)}</code> from assessment <code>${esc(value.source_assessment_id)}</code> on ${esc(hostName(value.source_host_id))}. No provider request was sent for this assessment. <strong>This advisory result grants no approval and authorizes no response.</strong></p><p><a class="button" href="${source}">Review original assessment</a> ${revoke}</p><p class="help">Original candidate recorded ${date(value.source_created)}. Re-triage bypasses reuse and remains subject to AI pause, sharing and admission controls.</p></section>`;}
 if(value.eligible&&value.published){return `<section class="notice assessment-known-good"><h3>Published safe candidate</h3><p>The complete verified context produced fingerprint v${esc(value.version)} <code>${esc(value.fingerprint)}</code> and its minimal provenance is durably recorded. <strong>This candidate has not been reused and grants no approval.</strong> Contradiction review remains a separate safeguard.</p>${revoke}</section>`;}
 if(value.eligible){return `<section class="notice assessment-known-good"><h3>Canonical match candidate</h3><p>The verified context produced fingerprint v${esc(value.version)} <code>${esc(value.fingerprint)}</code>. <strong>No safe candidate has been durably published or reused.</strong> Publication, lookup, revocation and contradiction review remain separate safeguards.</p></section>`;}
 const reasons=Array.isArray(value.reasons)?value.reasons:[];
 return `<section class="notice assessment-known-good"><h3>Fleet match unavailable</h3><p>This result remains host-specific and cannot avoid a provider investigation.</p>${reasons.length?`<details><summary>Why this is a cache miss</summary><ul>${reasons.map(reason=>`<li>${esc(reason.detail||reason.code||'Incomplete evidence')}</li>`).join('')}</ul></details>`:''}<p class="help">A hash, filename, low-risk result, or locally reported package owner is never sufficient by itself.</p></section>`;
}

async function investigationAssessmentPage(revision,context,base){
 const root=context?.root||$('#content'),view=context?'servers':'investigations';
 if(!isAdmin()){root.innerHTML=PatchyUI.error('Administrator access required','Assessment history contains retained evidence.');return;}
 const raw=location.hash.slice((base+'/item/').length).split('/');let id,record;
 try{id=decodeURIComponent(raw[0]||'');record=decodeURIComponent(raw[2]||'');}catch{id='';}
 const back=`<a class="button" href="${base}">← Investigations</a>`;
 if(!id||id.length>64||id.includes('/')||raw[1]!=='history'||record.length>36){root.innerHTML=PatchyUI.error('Invalid assessment link','Return to investigations and select a saved assessment.',back);return;}
 const historyBase=base+'/item/'+encodeURIComponent(id)+'/history';
 const scope=context?'&host_id='+encodeURIComponent(context.hostId):'';
 const key=(context?.hostId||'fleet')+':'+id,offset=assessmentOffsets.get(key)||0;
 let data,item;
 try{
  data=await api('/investigations/'+encodeURIComponent(id)+'/history?offset='+offset+scope);
  if(record)item=await api('/investigations/'+encodeURIComponent(id)+'/history/'+encodeURIComponent(record)+'?'+scope.slice(1));
 }catch(error){if(currentView(revision,view)&&root.isConnected)root.innerHTML=PatchyUI.error('Unable to open assessment history',esc(error.message),back+'<button id="retry-assessment-view">Retry</button>');const retry=root.querySelector('#retry-assessment-view');if(retry)retry.onclick=render;return;}
 if(!currentView(revision,view)||!root.isConnected)return;
 const current=data.current;
 document.title='Assessment history · Mr Patchy';$('#breadcrumb').textContent+=' / Assessment history';
 const intro=(context?'':heading('A record of every second look.','Retained process assessments and explicit refresh requests.'))+back+`<section class="card assessment-summary"><h2>Assessment history</h2><p><code>${esc(current.executable)}</code></p><p>Current behavior on ${esc(hostName(current.host_id))} · ${badge(current.approved?'approved':current.verdict)}</p><p class="help">Saved assessments are advisory. History never approves a behavior, certifies safety or changes fleet trust. Older results captured before retained history have no verified model/input binding.</p>${current.refresh?.id?`<p class="notice">Fresh triage requested by ${esc(current.refresh.actor)} · ${date(current.refresh.created)}. Previous result retained; failed attempts use the existing retry workflow.${current.approved?' A subsequent approval holds this refresh; revoke that approval to resume.':''}</p>`:''}${current.can_retriage?`<button data-action="retriage-investigation" data-id="${esc(id)}">Re-triage</button>`:''}</section>`;
 if(item){
  const explanation=item.source==='legacy'?item.result.saved_analysis:item.result.explanation;
  const reused=item.source==='known_good',provider=item.source==='ai';
  root.innerHTML=intro+`<a class="button" href="${historyBase}">← Assessment list</a><section class="card"><h2>${item.source==='legacy'?'Preserved legacy result':reused?'Reused exact-match assessment':'Recorded AI assessment'}</h2><dl class="ai-run-facts"><div><dt>Recorded</dt><dd>${date(item.created)}</dd></div><div><dt>Risk</dt><dd>${esc(item.result.risk)}</dd></div><div><dt>Requested model</dt><dd>${esc(item.model||'Not recorded')}</dd></div><div><dt>Assessment ID</dt><dd><code>${esc(item.id)}</code></dd></div></dl><pre class="ai-run-message">${esc(explanation||'No explanation saved.')}</pre>${provider||reused?`<h3>Recommended checks</h3><pre class="ai-run-message">${esc(item.result.recommended_checks)}</pre>`:'<p class="notice">Preserved at refresh request time, not a reconstructed original assessment timestamp. Original model, run and exact inputs are unavailable.</p>'}${item.refresh?.id?`<p class="help">Refresh requested by ${esc(item.refresh.actor)} · ${date(item.refresh.created)}${item.refresh.withdrew_approval?' · Prior approval explicitly withdrawn':''}</p><pre class="ai-run-message">${esc(item.refresh.reason)}</pre>`:''}${assessmentContextCoverage(item)}${assessmentKnownGood(item)}<details><summary>Evidence snapshot and supplied inputs</summary>${provider||reused?`<p class="help assessment-policy">Recorded policy digest: <code>${esc(item.policy_hash)}</code>. ${reused?'No provider input was sent; the exact candidate context was revalidated locally.':'Inputs retain their original collection limits; this is not verified fleet-wide matching.'}</p>`:''}<pre class="ai-run-message">${esc(JSON.stringify({snapshot:item.snapshot,inputs:item.inputs},null,2))}</pre></details>${item.run_id?`<a class="button" href="${context?serverLink(context.hostId,'ai'):'#ai-logs'}/run/${encodeURIComponent(item.run_id)}/summary">Original run diagnostics</a><p class="help">Diagnostics may expire under normal retention. This assessment and evidence remain available.</p>`:''}</section>`;
 }else{
  root.innerHTML=intro+`<section class="card">${data.items.length?`<div class="table-wrap"><table><thead><tr><th>Recorded</th><th>Source</th><th>Risk</th><th>Requested model</th><th></th></tr></thead><tbody>${data.items.map(r=>`<tr><td>${date(r.created)}</td><td>${esc(r.source==='legacy'?'Preserved legacy result':r.source==='known_good'?'Exact-match reuse':'AI assessment')}</td><td>${badge(r.risk)}</td><td>${esc(r.model||'Not recorded')}</td><td><a class="button" href="${historyBase}/${encodeURIComponent(r.id)}">Review assessment</a></td></tr>`).join('')}</tbody></table></div>`:empty('No retained assessments yet','History starts with the next completed triage or a preserved result when Re-triage is requested. Existing AI diagnostics remain separate.')}</section><div class="actions"><button id="assessment-previous" ${offset?'':'disabled'}>Previous assessments</button><button id="assessment-next" ${data.more?'':'disabled'}>Next assessments</button></div>`;
  root.querySelector('#assessment-previous').onclick=()=>{assessmentOffsets.set(key,Math.max(0,offset-20));render();};root.querySelector('#assessment-next').onclick=()=>{assessmentOffsets.set(key,offset+20);render();};
 }
}
// Fleet views share the same API, escaping, role and modal helpers as app.js.
function assessmentCell(value){
 if(!value)return '—';
 const scored=value.state==='complete'&&Number.isInteger(value.score);
 return `<details class="package-assessment"><summary>${scored?`<span class="score ${value.score>=80?'urgent':value.score>=60?'important':''}">${value.score}<small>/100</small></span>`:badge(value.state)} <span>${value.historical?'Historical AI score':scored?'Why this score':'Details'}</span></summary><p>${esc(value.explanation)}</p>${value.historical?`<p class="help">Assessed update: ${esc(value.from_version)} → ${esc(value.to_version)}. This is a saved update-importance assessment, not a current security verdict.</p>`:''}${value.limitations?`<p class="help">${esc(value.limitations)}</p>`:''}${value.next_at?`<p class="help">Next eligible scoring attempt: ${date(value.next_at)}. The saved package evidence remains queued.</p>`:''}${scored?`<small>${esc(value.confidence)} confidence · ${esc(value.model)} · ${date(value.completed)}</small>`:''}</details>`;
}
function installationCell(value){
 if(!value)return '—';
 return `<strong>${value.at?date(value.at):esc(value.state==='unscheduled'?'Not scheduled':value.state==='installing'?'In progress':value.state==='blocked'?'Blocked':'Waiting')}</strong><small>${esc(value.schedule||value.state)}</small><details><summary>Timing details</summary><p class="help">${esc(value.reason)}</p>${value.at?'<p class="help">Estimated earliest start, not a guaranteed completion time.</p>':''}</details>`;
}
// Describes the admission control that actually gates new AI work. The legacy
// hourly limit applies only in legacy mode; other modes must not advertise it.
function aiAdmissionControl(status){
 const count=value=>Number.isSafeInteger(value)&&value>=0?value:'Unavailable';
 const admission=status?.admission||{mode:'legacy'};
 if(['rate','rate_and_daily'].includes(admission.mode))return `${count(admission.rate_per_hour)} shared starts/hour`+(admission.mode==='rate_and_daily'?' + daily spend cap':'');
 if(admission.mode==='unthrottled')return 'Unthrottled by Mr Patchy';
 if(admission.mode==='daily_cap')return 'Daily spend cap';
 return `${count(status?.recent_attempts||0)} / ${count(status?.hourly_limit)} legacy attempts`;
}
// Shared AI start gates (#727): renders the administrator-only control snapshot
// from /api/settings/ai-control-status (#546). Display-only; never a promise that
// a specific call will start.
const AI_GATE_LABELS={disabled:'Central AI disabled',configuration:'Configuration incomplete',provider_backoff:'Shared provider backoff',rate_throttle:'Smooth-rate throttle',daily_cap:'Daily spend cap'};
function aiControlGates(snapshot){
 const when=value=>Number.isFinite(value)&&value>0?date(value):null;
 const head=state=>`<div class="card-head"><h2 id="ai-control-gates-title">Shared AI start gates</h2>${badge(state)}</div>`;
 if(!snapshot||snapshot.unavailable||typeof snapshot.can_start_now!=='boolean'||!Array.isArray(snapshot.blockers)){
  return head('unavailable')+`<p class="notice" role="status">Shared AI start gates are unavailable right now. The rest of the queue status is unaffected, and an unavailable snapshot never means AI work may start.</p><div class="actions"><button type="button" data-ai-control-retry>Retry start gates</button></div>`;
 }
 const limitations=Array.isArray(snapshot.limitations)&&snapshot.limitations.length?`<ul class="help">${snapshot.limitations.map(item=>`<li>${esc(item)}</li>`).join('')}</ul>`:'';
 const refresh=`<div class="actions"><button type="button" data-ai-control-retry>Refresh start gates</button></div>`;
 if(snapshot.can_start_now&&!snapshot.blockers.length){
  return head('open')+`<p>All shared global gates are open now. Queued work can start when a worker slot is free, subject to the remaining checks below.</p>${limitations}${refresh}`;
 }
 const items=snapshot.blockers.map(blocker=>{
  const code=typeof blocker?.code==='string'?blocker.code:'unknown';
  const next=when(blocker?.next_at),recheck=when(blocker?.recheck_at);
  const timing=next?`Next eligible ${next}`:recheck?`Recheck at ${recheck}. This is not a promised start`:'No scheduled end. An administrator must change this';
  return `<li><strong>${esc(AI_GATE_LABELS[code]||code.replaceAll('_',' '))}</strong> · ${esc(blocker?.message||'')}<br><small>${esc(timing)}.</small></li>`;
 }).join('');
 const nextStart=when(snapshot.next_start_at);
 const summary=nextStart?`<p><strong>Next eligible start:</strong> ${nextStart}. This is the latest time among the blocking gates. Work may still wait after it.</p>`:`<p><strong>No automatic next start.</strong> At least one hold has no scheduled end, or its time is only a recheck boundary.</p>`;
 return head('blocked')+`<p>New AI provider calls are held by ${snapshot.blockers.length} shared ${snapshot.blockers.length===1?'gate':'gates'}. Queued work stays queued until the gates open.</p><ul>${items}</ul>${summary}${limitations}${refresh}`;
}
async function loadAiControlGates(root,revision){
 const section=root.querySelector('#ai-control-gates');if(!section)return;
 const token=(Number(section.dataset.request)||0)+1;section.dataset.request=String(token);
 section.setAttribute('aria-busy','true');
 let snapshot;try{snapshot=await api('/settings/ai-control-status');}catch{snapshot={unavailable:true};}
 if(!currentView(revision,'investigations')||!section.isConnected||section.dataset.request!==String(token))return;
 section.innerHTML=aiControlGates(snapshot);section.removeAttribute('aria-busy');
 section.querySelectorAll('[data-ai-control-retry]').forEach(button=>button.onclick=()=>loadAiControlGates(root,revision));
}
function triageStatus(status){
 const count=value=>Number.isSafeInteger(value)&&value>=0?value:'Unavailable';
 const control=aiAdmissionControl(status);
 const budget=status.budget||{};const spend=budget.enabled?`<p class="help">Daily budget: $${esc(budget.counted_usd)} counted · $${esc(budget.remaining_usd)} remaining · $${esc(budget.uncertain_usd)} uncertain · resets ${date(budget.next_reset)} (${esc(budget.timezone)}). Public price estimates are not provider invoices.</p>`:'';
 const plans=status.plan_deferred_by_action;
 const planDetails=plans&&status.plan_deferred>0?`<details><summary>Deferred plans by purpose</summary>
 <p class="help">Queue-ready means the job is due and server AI is active. Shared controls can still delay a start. Recorded retry times may belong to paused servers.</p>
 <ul>${[['release-plan','Release plans'],['security-plan','Incident plans'],['startup-plan','Startup plans']].map(([action,label])=>{
  const row=plans[action]||{};
  return `<li><strong>${label}</strong> · ${count(row.deferred)} deferred · ${count(row.ready)} queue-ready${row.next_at?' · Recorded retry '+date(row.next_at):''}</li>`;
 }).join('')}</ul></details>`:'';
 const provider=status.provider_backoff||{};const providerWait=provider.blocked?`<p class="help"><strong>Shared provider backoff:</strong> ${esc(provider.failures)} consecutive transient failure(s) · next eligible ${date(provider.next_at)}. New calls are blocked before rate or budget admission.</p>`:'';
 const leaseExpiry=status.active_lease_expires_at?`<p class="help"><strong>Earliest live lease expiry:</strong> ${date(status.active_lease_expires_at)}. If no renewal arrives, expiry permits fenced recovery; it does not prove that a provider request stopped or was not billed.</p>`:'';
 const minimum=count(status.per_server_limit_min??1),maximum=count(status.per_server_limit_max??status.per_server_limit);
 const waitAge=seconds=>{const s=Math.max(0,Math.floor(seconds));if(s<60)return s+'s';const m=Math.floor(s/60);if(m<60)return m+'m';const h=Math.floor(m/60);if(h<48)return h+'h '+(m%60)+'m';return Math.floor(h/24)+'d '+(h%24)+'h';};
 const oldestUnclaimed=status.oldest_eligible_unclaimed_observation_at;
 const unclaimedWait=Number.isFinite(oldestUnclaimed)&&oldestUnclaimed>0?`<p class="help"><strong>Oldest eligible unclaimed observation:</strong> first seen ${date(oldestUnclaimed)} (about ${waitAge(Date.now()/1000-oldestUnclaimed)} ago). This is observation age, not time since it became eligible. Shared rate, budget and provider admission and available worker capacity may still delay dispatch.</p>`:'';
 return `<div class="card"><div class="card-head"><h2>AI worker status</h2>${badge(status.reason||'unknown')}</div><p>${esc(status.message||'Refresh to see worker status.')}</p><div class="status-facts"><span><strong>${status.pending||0}</strong> pending</span><span><strong>${count(status.active)}</strong> active investigations</span><span><strong>${count(status.queued)}</strong> queued</span><span><strong>${count(status.scoring_deferred)}</strong> scoring deferred</span><span><strong>${count(status.plan_deferred)}</strong> plans deferred</span><span><strong>${count(status.plan_ready)}</strong> plans eligible now</span><span><strong>${count(status.reported_capacity)}</strong> reported AI slots</span><span><strong>${status.ready||0}</strong> investigations eligible now</span><span><strong>${count(status.eligible_unclaimed)}</strong> eligible, unclaimed</span><span><strong>${status.blocked||0}</strong> need review</span><span><strong>${status.paused||0}</strong> paused</span><span><strong>${esc(control)}</strong></span></div><p class="help">Independent investigations can run in parallel. Each server is configurable from ${minimum} to ${maximum} process investigations (default ${count(status.per_server_limit)}), still bounded by global capacity. Update scoring and advisory plans retain their exact next eligibility after a shared refusal. Reported capacity includes draining workers; it does not guarantee available capacity.</p>${spend}${providerWait}${planDetails}${leaseExpiry}${unclaimedWait}<p class="help">Worker heartbeat: ${date(status.worker_seen)}${status.retry_at?' · Next eligibility: '+date(status.retry_at):''}${status.scoring_next_at?' · Scoring: '+date(status.scoring_next_at):''}${status.plan_next_at?' · Advisory plans: '+date(status.plan_next_at):''}</p>${status.last_error?`<div class="notice">${esc(status.last_error)}</div>`:''}<div class="actions"><a href="#ai-logs" class="button" data-admin>View AI run logs</a><a href="#settings/ai" class="button" data-admin>AI settings &amp; connection test</a></div></div>`;
}
function aiMoney(amount){
 if(amount===null||amount===undefined||!Number.isFinite(Number(amount)))return 'Unavailable';
 const value=Number(amount);return value>0&&value<0.000001?'<$0.000001':'$'+value.toFixed(6);
}
function aiCost(cost){
 if(!cost)return '<strong>Unavailable</strong><small>No usage recorded</small>';
 const note=cost.in_progress?' · In progress':'';
 if(cost.status==='no_calls')return `<strong>$0.000000</strong><small>No API calls${note}</small>`;
 if(cost.status==='unavailable')return `<strong>Unavailable</strong><small>Usage or pricing missing${note}</small>`;
 return `<strong>${aiMoney(cost.estimated_usd)}</strong><small>${cost.status==='partial'?`Partial · ${cost.priced_calls} of ${cost.total_calls} calls`:'Estimated'}${note}</small>`;
}
function aiCostDetails(run){
 const cost=run.cost,calls=run.api_calls||[];
 const tokens=value=>Number.isInteger(value)?value.toLocaleString():'Unavailable';
 return `<section class="ai-cost-detail"><h2>Estimated API cost (USD)</h2><div class="ai-cost-total">${aiCost(cost)}</div><p class="help">Public token-rate estimates, not an OpenAI invoice. Partial amounts cover only priced calls. Failed responses can still incur charges. Output tokens include reasoning.</p>${calls.map(c=>`<section class="ai-call"><h3>API call ${c.number} · ${c.status==='estimated'?aiMoney(c.pricing.estimated_usd):'Cost unavailable'}</h3><p class="help">${esc(c.response_model||c.requested_model)} · ${esc(c.service_tier||'Processing tier unavailable')}</p><div class="ai-token-grid"><span>Input<strong>${tokens(c.usage.input_tokens)}</strong></span><span>Cached input<strong>${tokens(c.usage.cached_tokens)}</strong></span><span>Cache writes<strong>${tokens(c.usage.cache_write_tokens)}</strong></span><span>Output<strong>${tokens(c.usage.output_tokens)}</strong></span><span>Reasoning (included in output)<strong>${tokens(c.usage.reasoning_tokens)}</strong></span></div>${c.status==='estimated'?`<details><summary>Rates used · ${esc(c.pricing.version)}</summary><p class="help">USD per million tokens: input $${esc(c.pricing.per_million.input)} · cached input $${esc(c.pricing.per_million.cached_input)} · output $${esc(c.pricing.per_million.output)} · cache writes $${esc(c.pricing.per_million.cache_write)}${c.pricing.cache_ttl?' ('+esc(c.pricing.cache_ttl)+')':''}. Rates are saved with this call.</p></details>`:`<p class="help">${esc(c.reason)}</p>`}</section>`).join('')}${!calls.length&&run.calls?'<p class="help">No token receipts were stored for this run. Historical costs cannot be reconstructed.</p>':''}</section>`;
}
async function aiDiagnostics(revision=renderRevision,context=null){
 const root=context?.root||$('#content');
 const base=context?serverLink(context.hostId,'ai'):'#ai-logs',parts=location.hash.slice(1).split('/'),index=context?3:1;
 if(parts[index]==='run')return aiRunPage(revision,context,base,parts.slice(index+1));
 const key=context?.hostId||'fleet',saved=aiListContext.get(key)||{purpose:'',state:'',offset:0};
 const status=context?null:await api('/investigation-status');if(!currentView(revision,context?'servers':'ai-logs')||!root.isConnected)return;
 root.innerHTML=(context?'<p class="help">AI activity linked to this server. Shared scoring batches show the whole batch cost, not a per-server charge. Older runs without a server association remain in fleet AI logs.</p>':heading('Know what Mr Patchy is thinking.','Persistent run stages, provider errors, retries, and worker health.')+triageStatus(status))+`<div class="toolbar"><label>Purpose<select id="ai-log-purpose"><option value="">All logged AI activity</option><option value="triage">Process triage</option><option value="update_scoring">Update importance</option><option value="connection_test">Connection tests</option><option value="release_configuration">Release configuration</option><option value="security_plan">Security response plans</option><option value="worker">Worker failures</option></select></label><label>State<select id="ai-log-state"><option value="">All run states</option><option value="running">Running</option><option value="complete">Complete</option><option value="error">Failed</option><option value="deferred">Deferred</option><option value="interrupted">Interrupted</option></select></label><p class="help">API keys, raw prompts and provider bodies are excluded.</p></div><p class="help">Costs are estimated in USD from returned token usage and saved public rates. Older activity and calls without usage or known pricing show Unavailable.</p><div class="card" id="ai-log-table"></div><div class="actions"><button id="ai-log-prev">Previous</button><button id="ai-log-next">Next</button></div>`;
 if(!context&&isAdmin())bindTriageTimingSummary(root,revision);
 let offset=saved.offset,ticket=0;
 const table=$('#ai-log-table'),purposeFilter=$('#ai-log-purpose'),stateFilter=$('#ai-log-state');
 purposeFilter.value=saved.purpose;stateFilter.value=saved.state;
 const load=async()=>{
  const turn=++ticket,purpose=purposeFilter.value,state=stateFilter.value;
  aiListContext.set(key,{purpose,state,offset});
  const params=new URLSearchParams({purpose,offset});
  if(state)params.set('state',state);
  if(context)params.set('host_id',context.hostId);
  try{const data=await api('/ai/runs?'+params);if(turn!==ticket||!table.isConnected)return;
 table.innerHTML=data.items.length?`<div class="table-wrap"><table><thead><tr><th>Started</th><th>Purpose / model</th><th>State</th><th>Est. API cost (USD)</th><th>Last diagnostic</th><th></th></tr></thead><tbody>${data.items.map(r=>`<tr><td>${date(r.started)}</td><td>${esc(r.purpose)}<small>${esc(r.model)} · ${r.calls} API calls${r.shared_batch?' · Shared batch':''}</small></td><td>${badge(r.state)}</td><td class="ai-cost-cell">${aiCost(r.cost)}</td><td class="log-message">${esc(r.message)}</td><td><a class="button" data-ai-run="${esc(r.id)}" href="${base}/run/${encodeURIComponent(r.id)}/summary">Inspect run</a></td></tr>`).join('')}</tbody></table></div>`:purpose||state?empty('No matching AI runs','Change the purpose or state filter to see more activity.'):empty('No AI runs recorded yet',context?'No saved AI runs are linked to this server yet. Older unlinked activity is available in fleet AI logs.':'Check worker status above. Disabled or misconfigured AI does not send requests.');
 $('#ai-log-prev').disabled=offset===0;$('#ai-log-next').disabled=!data.more;

 }catch(e){if(turn===ticket&&table.isConnected)toast(e.message);}};
 purposeFilter.onchange=stateFilter.onchange=()=>{offset=0;load();};$('#ai-log-prev').onclick=()=>{offset=Math.max(0,offset-50);load();};$('#ai-log-next').onclick=()=>{offset+=50;load();};await load();
}
function bindTriageTimingSummary(root,revision){
 const panel=document.createElement('section');
 panel.className='card';
 panel.setAttribute('aria-labelledby','ai-triage-timing-title');
 panel.innerHTML='<h2 id="ai-triage-timing-title">Process triage timings</h2><p class="help">Compare elapsed times across recent completed and failed investigations. Stages can overlap. Retained diagnostics may have gaps.</p><button type="button">Load timing summary</button><p class="help" role="status"></p><div class="table-wrap" tabindex="0" role="region" aria-label="Timing percentiles by stage" hidden></div>';
 root.querySelector('.toolbar').before(panel);
 const button=panel.querySelector('button'),status=panel.querySelector('[role=status]'),table=panel.querySelector('.table-wrap');
 const active=()=>panel.isConnected&&currentView(revision,'ai-logs')&&isAdmin();
 const count=value=>Number.isSafeInteger(value)&&value>=0?value.toLocaleString():'Unavailable';
 const duration=value=>Number.isFinite(value)&&value>=0?value.toLocaleString(undefined,{maximumFractionDigits:3}):'—';
 button.onclick=async()=>{
  if(!active()||button.disabled)return;
  button.disabled=true;status.textContent='Loading timing summary…';
  try{
   const data=await api('/ai/triage/timings');
   if(!active())return;
   const rows=Object.entries(data.stages).map(([stage,row])=>`<tr><th scope="row">${esc(stage.replaceAll('_',' '))}</th><td>${count(row.samples)}</td><td>${count(row.errors)}</td><td>${duration(row.p50_ms)}</td><td>${duration(row.p95_ms)}</td></tr>`);
   const hasSamples=Object.values(data.stages).some(row=>row.samples>0);
   table.innerHTML=hasSamples?`<table><thead><tr><th scope="col">Stage</th><th scope="col">Samples</th><th scope="col">Errors</th><th scope="col">p50 (ms)</th><th scope="col">p95 (ms)</th></tr></thead><tbody>${rows.join('')}</tbody></table>`:'';
   table.hidden=!hasSamples;
   status.textContent=(hasSamples?'':'No retained timing samples. ')+`${count(data.sampled_runs)} runs sampled. ${count(data.runs_without_samples)} without valid samples. ${count(data.discarded_events)} malformed events discarded.`+(data.events_truncated?` Sample limited to the latest ${count(data.event_limit)} timing events.`:'');
   button.textContent='Refresh timing summary';
  }catch{
   if(!active())return;
   table.hidden=true;table.innerHTML='';
   status.textContent='Timing summary is unavailable. You can still inspect individual AI runs.';
   button.textContent='Retry timing summary';
  }finally{if(active())button.disabled=false;}
 };
}

async function packageHistory(revision=renderRevision,context=null){
 const root=context?.root||$('#content');
 root.innerHTML=(context?'':heading('Every package has a history.','Observed installations, version changes, removals, and package-state changes.'))+`<div class="toolbar">${context?'':`<label>Server<select id="history-host"><option value="">All servers</option>${hosts.map(h=>`<option value="${h.id}">${esc(h.name)}</option>`).join('')}</select></label>`}<label>Package<input id="history-search" placeholder="Filter package names"></label></div><p class="help">Baseline means present when history began, not installed at that time. Dates are observation times; external changes may have happened earlier. Job links show the operation during which a change was observed, including dependencies.</p><div class="card" id="package-history-table"></div><div class="actions"><button id="package-history-prev">Previous</button><button id="package-history-next">Next</button></div>`;
 let offset=0,ticket=0,timer;const table=$('#package-history-table');
 const load=async()=>{const turn=++ticket;try{const data=await api('/package-history?host_id='+encodeURIComponent(context?.hostId||$('#history-host').value)+'&q='+encodeURIComponent($('#history-search').value)+'&offset='+offset);if(turn!==ticket||!currentView(revision,context?'servers':'history')||!table.isConnected)return;
 table.innerHTML=data.items.length?`<div class="table-wrap"><table><thead><tr><th>Observed</th><th>Server / package</th><th>Change</th><th>Before → after</th><th>Origin</th><th>Historical AI importance</th></tr></thead><tbody>${data.items.map(r=>`<tr><td>${date(r.observed)}<small>Recorded ${date(r.recorded)}</small></td><td>${esc(r.name)}<small>${esc(hostName(r.host_id))}</small></td><td>${badge(r.action)}</td><td>${esc(r.before.join(', ')||'—')} → ${esc(r.after.join(', ')||'—')}${r.state_before!==r.state_after?`<small>${esc(r.state_before||'—')} → ${esc(r.state_after||'—')}</small>`:''}</td><td>${esc(r.source)}<small>${esc(r.actor||'Observed; actor unknown')}</small>${r.job_id?`<button data-history-job="${r.job_id}">View operation</button>`:''}</td><td>${r.assessment?assessmentCell(r.assessment):'No saved assessment'}</td></tr>`).join('')}</tbody></table></div>`:empty('No package changes recorded','History begins with the next inventory collected after this version is deployed.');
 $('#package-history-prev').disabled=offset===0;$('#package-history-next').disabled=!data.more;
 table.querySelectorAll('[data-history-job]').forEach(button=>button.onclick=async()=>{const rev=modalRevision;try{const j=await api('/jobs/'+button.dataset.historyJob);if(rev!==modalRevision||!table.isConnected)return;modal('Package operation',`<p>${esc(j.action)} · ${badge(j.state)} · ${date(j.created)}</p><pre>${esc(j.output||'Awaiting execution')}</pre>`);}catch(e){toast(e.message);}});
 }catch(e){if(table.isConnected)toast(e.message);}};
 if(!context)$('#history-host').onchange=()=>{offset=0;load();};$('#history-search').oninput=()=>{clearTimeout(timer);timer=setTimeout(()=>{if(table.isConnected){offset=0;load();}},250);};$('#package-history-prev').onclick=()=>{offset=Math.max(0,offset-100);load();};$('#package-history-next').onclick=()=>{offset+=100;load();};await load();
}
async function users(revision=renderRevision){
 const rows=await api('/users');if(!currentView(revision,'users'))return;
 $('#content').innerHTML=heading('A workspace for your whole team.','Named accounts, explicit roles, and personal passwords.','<button class="primary" id="new-user">+ Add user</button>')+`<div class="card"><h2>Accounts</h2><p class="help">Each person signs in with their own username and password. They can change their password under <strong>Account → Change password</strong>; this revokes their existing sessions. MFA stays enabled. SSO identities use the same roles.</p><div class="table-wrap"><table><thead><tr><th>Username</th><th>Role</th><th>Access</th><th>MFA</th><th></th></tr></thead><tbody>${rows.map(u=>`<tr><td>${esc(u.username)}${u.username===currentUser.username?'<small>Your account</small>':''}</td><td>${esc(u.role)}</td><td>${badge(u.enabled?'enabled':'disabled')}</td><td>${u.mfa?'Enabled':'Not configured'}</td><td><button data-edit-user="${esc(u.username)}">Edit user</button></td></tr>`).join('')}</tbody></table></div></div><div class="card"><h2>Choose the right access</h2><div class="role-grid"><section><h3>Viewer</h3><p class="help">Read monitoring, package inventory and package history.</p></section><section><h3>Operator</h3><p class="help">Viewer access, plus reviewed patch installation and repository refresh.</p></section><section><h3>Administrator</h3><p class="help">Manage servers, settings, users, AI logs, schedules and trust decisions.</p></section></div></div>`;
 const edit=user=>{
 modal(user?'Edit user · '+user.username:'Add a user',`<form id="user-form"><label>Username<input name="username" value="${esc(user?.username||'')}" ${user?'readonly':''} pattern="[A-Za-z0-9_.-]{1,64}" required autocomplete="off"></label><label>${user?'Reset password (leave blank to keep it)':'Initial password'}<input name="password" type="password" ${user?'':'required'} minlength="12" maxlength="1024" autocomplete="new-password"></label><label>Confirm ${user?'reset':'initial'} password<input name="confirm_password" type="password" autocomplete="new-password"></label><p class="help">Share initial credentials through a trusted channel. The user can choose their own password in Account. Saving access changes revokes this user's existing sessions.</p><label>Role<select name="role"><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Administrator</option></select></label><label class="check"><input name="enabled" type="checkbox" ${!user||user.enabled?'checked':''}>Enable sign-in</label><button class="primary">Save user</button></form>${user&&user.mfa&&user.username!==currentUser.username?`<form id="mfa-reset"><h3>Lost authenticator</h3><p class="help">Removes this user’s MFA enrollment and revokes their sessions. Confirm with your own password (and authenticator code if you use MFA).</p><label>Your password<input name="password" type="password" required autocomplete="current-password"></label><label>Your authenticator code<input name="otp" maxlength="6" autocomplete="one-time-code"></label><button>Reset MFA</button></form>`:''}`);
 const form=$('#user-form'),dialog=modalRevision,session=sessionRevision;const current=()=>session===sessionRevision&&dialog===modalRevision&&form.isConnected&&$('#modal').open&&currentView(revision,'users');form.elements.role.value=user?.role||'viewer';const reset=$('#mfa-reset');if(reset)reset.onsubmit=async event=>{event.preventDefault();const button=reset.querySelector('button');button.disabled=true;try{await api('/users/'+encodeURIComponent(user.username)+'/mfa/reset','POST',Object.fromEntries(new FormData(reset)));if(!current())return;$('#modal').close();await users(revision);toast('MFA reset. The user can enroll again after signing in.');}catch(error){if(current()){toast(error.message);button.disabled=false;}}};form.onsubmit=async event=>{event.preventDefault();const f=new FormData(form);if(f.get('password')!==f.get('confirm_password'))return toast('Passwords do not match');const button=form.querySelector('button');button.disabled=true;try{await api('/users','PUT',{username:f.get('username'),password:f.get('password'),role:f.get('role'),enabled:f.has('enabled'),create:!user});if(!current())return;$('#modal').close();if(f.get('username')===currentUser.username){showLogin();return;}await users(revision);toast('User saved. Existing sessions for that account were revoked.');}catch(error){if(current()){toast(error.message);button.disabled=false;}}};
 };
 $('#new-user').onclick=()=>edit();document.querySelectorAll('[data-edit-user]').forEach(b=>b.onclick=()=>edit(rows.find(u=>u.username===b.dataset.editUser)));
}


async function fleetSecurityCoverage(revision){
 const root=$('#content');let offset=0,query='',ticket=0;
 root.innerHTML=heading('Security coverage','Recorded scanner coverage across your fleet. Each engine stands on its own.')+'<section class="card"><p class="notice">Recorded results describe bounded scans, not a clean server or complete protection. This page reads stored data and does not contact targets.</p><form id="coverage-search"><label>Server name<input name="q" maxlength="200" type="search" placeholder="Find a server"></label><button>Find servers</button></form><div id="coverage-results" aria-live="polite"></div><div class="actions"><button id="coverage-prev">Previous servers</button><button id="coverage-next">Next servers</button><button id="coverage-refresh">Refresh coverage</button></div></section>';
 const current=()=>currentView(revision,'security')&&root.isConnected;
 const load=async()=>{const turn=++ticket;try{
  const data=await api('/security/coverage?offset='+offset+'&q='+encodeURIComponent(query));if(!current()||turn!==ticket)return;
  const labels={never_scanned:'No durable receipt',recorded:'Coverage recorded',attempt_failed:'Latest attempt failed',receipt_missing:'Receipt missing',pending:'Scan pending',overdue:'Scan overdue',incomplete:'Incomplete coverage',findings:'Findings recorded'};
  const engine=(name,r)=>'<section class="card"><h3>'+name+' · <span class="badge '+esc(r.state)+'">'+esc(labels[r.state]||r.state)+'</span>'+'</h3><p>'+date(r.created)+' · Signatures: '+esc(r.signatures)+(r.overdue?' · Coverage is overdue or absent':'')+'</p><p>'+r.scanned+' files scanned · '+r.findings+' findings in latest receipt</p><details><summary>Scope, gaps and latest attempt</summary><pre>'+esc(JSON.stringify({roots:r.roots,gaps:r.gaps,last_attempt:r.last_attempt,scan_id:r.scan_id},null,2))+'</pre></details></section>';
  root.querySelector('#coverage-results').innerHTML='<p>'+data.summary.servers+' servers on this page · '+data.summary.disabled+' disabled · '+data.summary.open_incidents+' open or acknowledged scanner incidents</p>'+data.items.map(h=>'<article class="card"><div class="card-head"><h2>'+esc(h.name)+'</h2><a class="button" href="'+serverLink(h.id,'security')+'">Review server security</a></div><p>'+badge(h.enabled?'enabled':'disabled')+' · Last contact '+date(h.last_seen)+' · '+h.open_incidents+' open incidents · ClamAV age limit '+h.expected_hours+' hours · YARA age limit 24 hours</p>'+(!h.enabled?'<p class="notice">Management is disabled. These results are historical; collection is suspended.</p>':'')+'<div class="server-grid">'+engine('ClamAV',h.engines.ClamAV)+engine('YARA',h.engines.YARA)+'</div></article>').join('')+(data.items.length?'':'<p>No matching managed servers.</p>');
  root.querySelector('#coverage-prev').disabled=!offset;root.querySelector('#coverage-next').disabled=!data.more;
 }catch(error){if(current()&&turn===ticket)root.querySelector('#coverage-results').innerHTML=PatchyUI.error('Unable to load coverage',esc(error.message));}};
 root.querySelector('#coverage-search').onsubmit=e=>{e.preventDefault();query=new FormData(e.currentTarget).get('q').trim();offset=0;load();};root.querySelector('#coverage-prev').onclick=()=>{offset=Math.max(0,offset-50);load();};root.querySelector('#coverage-next').onclick=()=>{offset+=50;load();};root.querySelector('#coverage-refresh').onclick=load;await load();
}

async function aiRunPage(revision,context,base,parts){
 const root=context?.root||$('#content'),name=context?'servers':'ai-logs';
 const back=`<a class="button" href="${base}">← AI activity</a>`;
 let id;try{id=decodeURIComponent(parts[0]||'');}catch{id='';}
 if(!id||id.length>128||id.includes('/')){root.innerHTML=PatchyUI.error('Invalid AI run link','Return to AI activity and select a saved run.',back);return;}
 const tab=['summary','cost','timeline'].includes(parts[1])?parts[1]:'summary';
 let run;
 try{run=await api('/ai/runs/'+encodeURIComponent(id)+(context?'?host_id='+encodeURIComponent(context.hostId):''));}
 catch(error){if(!currentView(revision,name)||!root.isConnected)return;root.innerHTML=PatchyUI.error('Unable to open AI run',esc(error.message),back+'<button id="retry-ai-run">Retry</button>');const retry=root.querySelector('#retry-ai-run');if(retry)retry.onclick=render;return;}
 if(!currentView(revision,name)||!root.isConnected)return;
 document.title='AI run · '+run.purpose+' · Mr Patchy';$('#breadcrumb').textContent+=' / AI run / '+tab;
 const nav=`<nav class="overview-sections" aria-label="AI run pages">${[['summary','Summary'],['cost','Cost'],['timeline','Timeline']].map(([key,label])=>`<a href="${base}/run/${encodeURIComponent(id)}/${key}" ${key===tab?'class="active" aria-current="page"':''}>${label}</a>`).join('')}</nav>`;
 const summary=`<section class="card"><h2>Saved run</h2><dl class="ai-run-facts"><div><dt>Purpose</dt><dd>${esc(run.purpose)}</dd></div><div><dt>Model</dt><dd>${esc(run.model)}</dd></div><div><dt>Started</dt><dd>${date(run.started)}</dd></div><div><dt>Finished</dt><dd>${run.finished?date(run.finished):run.state==='running'?'Not yet':'Not recorded'}</dd></div><div><dt>API calls</dt><dd>${esc(run.calls)}</dd></div><div><dt>Run ID</dt><dd><code>${esc(run.id)}</code></dd></div></dl><h3>Last diagnostic</h3><pre class="ai-run-message">${esc(run.message||'No diagnostic saved.')}</pre><div class="ai-cost-total">${aiCost(run.cost)}</div></section>`;
 const timeline=`<section class="card"><h2>Run timeline</h2><p class="help">Saved stages describe processing at the recorded time; they do not certify current server health or response execution. Timing records use monotonic elapsed milliseconds and can overlap; do not add them together. Queue age includes policy/backoff waits. Older or interrupted runs may have incomplete timing coverage.</p><div class="timeline">${(run.events||[]).map(event=>`<div><section><h3>${esc(typeof event.stage==='string'&&event.stage.startsWith('timing_')?'Timing · '+event.stage.slice(7).replaceAll('_',' '):event.stage)}</h3><small>${date(event.created)}</small><pre class="ai-run-message">${esc(event.message)}</pre></section></div>`).join('')||'<p>No stage events were saved for this run.</p>'}</div></section>`;
 root.innerHTML=(context?'':heading('A closer look at the work.','Saved AI processing, usage and diagnostic evidence.'))+back+`<div class="ai-run-title"><h2>AI run · ${esc(run.purpose)}</h2>${badge(run.state)}</div><p class="help">Read-only history. Browsing does not retry AI requests or approve actions. ${run.shared_batch?'Shared batch: displayed cost covers the whole run, not a per-server charge.':''}</p>`+nav+(tab==='cost'?`<section class="card">${aiCostDetails(run)}</section>`:tab==='timeline'?timeline:summary);
}
