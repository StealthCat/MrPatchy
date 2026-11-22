/* Separate settings routes. Persistence never depends on a provider test. */
const SETTINGS_SECTIONS={
 ai:['AI & models','Save your API key, choose a model, and test it.','openai api key model investigations budget spend rate limit scoring'],
 patching:['Patch policy','Repository checks and priority deadlines.','repository checks interval deadlines critical high normal low priority overdue telemetry lost offline notification'],
 database:['Database','MySQL connection details and offline migrations.','mysql sqlite connection migration host port password'],
 https:['HTTPS & certificates','Internal and external TLS profiles.','tls ssl certificate acme lets encrypt local ca domain port'],
 history:['History retention','Observation and inventory retention.','retention observation inventory history days cleanup'],
 agents:['Agent maintenance','Fleet defaults for automatic agent upgrade and repair.','agent health maintenance automatic upgrade repair helper collector drift default override inherit'],
 malware:['Malware response','Fleet automatic-response policy for detected malware. Recorded only; not enforced yet.','malware quarantine terminate containment automatic response exclusions signature unknown policy']
};
function settingsMatches(query,sections=SETTINGS_SECTIONS){
 const terms=String(query||'').toLowerCase().split(/\s+/).filter(Boolean);
 return Object.entries(sections).filter(([,[name,detail,keywords='']])=>{const text=(name+' '+detail+' '+keywords).toLowerCase();return terms.every(t=>text.includes(t));}).map(([key])=>key);
}
function settingsHubCards(query){
 const keys=settingsMatches(query);
 return keys.map(key=>{const [name,detail]=SETTINGS_SECTIONS[key];return `<a class="card settings-link" href="#settings/${key}"><h2>${esc(name)} <span aria-hidden="true">↗</span></h2><p class="help">${esc(detail)}</p></a>`;}).join('')||'<p class="help">No settings match. Try “API key”, “certificate”, “MySQL” or “retention”.</p>';
}
function settingsNav(section){
 return `<div class="settings-nav" role="navigation" aria-label="Settings sections">${[['','All settings'],...Object.entries(SETTINGS_SECTIONS).map(([key,value])=>[key,value[0]])].map(([key,label])=>`<a href="#settings${key?'/'+key:''}" ${key===section?'aria-current="page" class="active"':''}>${esc(label)}</a>`).join('')}</div>`;
}
/* Unsaved-change guard. Each Settings form keeps a snapshot of the values it
 loaded or last saved successfully; leaving with a different value asks first.
 View filters (Settings search, spend-history period) are not tracked. */
const trackedSettingsForms=new Set();
function settingsFormState(form){
 return JSON.stringify([...form.elements].filter(e=>/^(INPUT|SELECT|TEXTAREA)$/.test(e.tagName)&&!['submit','button','reset'].includes(e.type)&&(e.name||e.id))
  .map(e=>[e.name||e.id,e.type==='checkbox'||e.type==='radio'?e.checked:e.value]));
}
function trackSettingsForm(form){if(form){form.dataset.savedState=settingsFormState(form);trackedSettingsForms.add(form);}}
function settingsFormSaved(form){if(form&&form.isConnected)form.dataset.savedState=settingsFormState(form);}
function settingsHasUnsavedChanges(){
 for(const form of [...trackedSettingsForms]){
  if(!form.isConnected){trackedSettingsForms.delete(form);continue;}
  if(form.dataset.savedState!==settingsFormState(form))return true;
 }
 return false;
}
function discardSettingsChanges(){trackedSettingsForms.clear();}
// Leaving with unsaved edits asks first. settings.js loads before app.js, so these
// listeners run before the shell's navigation and Refresh handlers and can hold
// them. A hashchange cannot be cancelled, so it is undone by moving back through
// session history (never by rewriting an entry, which would drop the page the
// user came from) and redone with the same move on Discard changes. Entry
// positions come from the Navigation API, or else from an index kept in
// history.state that replaceState preserves.
const SETTINGS_HISTORY_KEY='mrpatchyHistoryIndex';
// Where the Navigation API reports entry positions, nothing is written to history:
// stamping every entry adds a same-document navigation per hashchange, and a reload
// issued right after a hash navigation could then restore an older entry.
const navigationIndex=()=>{const entry=window.navigation?.currentEntry;return entry&&Number.isInteger(entry.index)&&entry.index>=0?entry.index:null;};
const stampsHistory=navigationIndex()===null;
const stampedIndex=()=>{const s=history.state;return s&&typeof s==='object'&&Number.isInteger(s[SETTINGS_HISTORY_KEY])?s[SETTINGS_HISTORY_KEY]:null;};
const historyIndex=()=>stampsHistory?stampedIndex():navigationIndex();
const nativeReplaceState=history.replaceState.bind(history);
const stampHistory=(state,index)=>index===null||(state!==null&&typeof state!=='object')?state:{...(state||{}),[SETTINGS_HISTORY_KEY]:index};
if(stampsHistory){
 history.replaceState=function(state,...rest){const s=state&&typeof state==='object'&&SETTINGS_HISTORY_KEY in state?state:stampHistory(state,historyIndex());return nativeReplaceState(s,...rest);};
 if(historyIndex()===null)nativeReplaceState(stampHistory(history.state,0),'');
}
// The Navigation API also names each entry by key. Moving to a key is absolute, so
// a dropped or repeated move cannot overshoot the way a relative history.go can.
const navigationKey=()=>{const entry=window.navigation?.currentEntry;return entry&&typeof entry.key==='string'&&entry.key?entry.key:null;};
let settledSettingsHash=location.hash,settledHistoryIndex=historyIndex(),settledHistoryKey=navigationKey();
// Set only while the guard's own undo (by key or history.go) is in flight. Entries can share
// an index (rapid back-to-back hash changes settle the newer entry first), so
// arriving on the settled index is not by itself evidence of an undo.
let pendingHistoryUndo=null,pendingHistoryUndoKey=null;
// Each held move gets its own generation, so retries from an earlier prompt never
// act after a newer prompt or a settled navigation.
let historyGuardGeneration=0;
function settleHistory(){
 historyGuardGeneration++;
 let index=historyIndex();
 if(index===null&&stampsHistory){index=(settledHistoryIndex??-1)+1;nativeReplaceState(stampHistory(history.state,index),'');}
 settledSettingsHash=location.hash;settledHistoryIndex=index;settledHistoryKey=navigationKey();
}
// A traversal started while another is still settling can be dropped (issue #1083:
// a guard undo issued during browser Back never landed). Moving by key is retried a
// bounded number of times, while it is still wanted, until the page is on that entry.
function traverseToEntry(key,stillWanted,attempt=0){
 if(!key||navigationKey()===key||!stillWanted())return;
 let result;
 try{result=window.navigation.traverseTo(key);}catch{result=null;}
 const retry=()=>{if(attempt<3)setTimeout(()=>traverseToEntry(key,stillWanted,attempt+1),50*(attempt+1));};
 if(!result||!result.finished){retry();return;}
 result.finished.then(()=>{if(navigationKey()!==key)retry();},retry);
}
const canTraverseByKey=()=>typeof window.navigation?.traverseTo==='function'&&navigationKey()!==null;
function unsavedSettingsPending(){return !document.getElementById('shell').classList.contains('hidden')&&settingsHasUnsavedChanges();}
function confirmLeaveUnsaved(proceed,stay=()=>{}){
 modal('Leave without saving?','<p>You have unsaved Settings changes. Leaving this page discards them.</p><div class="actions"><button type="button" id="unsaved-stay">Stay on this page</button><button type="button" id="unsaved-discard" class="danger">Discard changes</button></div>');
 const dialog=modalRevision,box=document.getElementById('modal');
 document.getElementById('unsaved-stay').onclick=()=>{if(dialog!==modalRevision)return;box.close();stay();};
 document.getElementById('unsaved-discard').onclick=()=>{if(dialog!==modalRevision)return;discardSettingsChanges();box.close();proceed();};
 document.getElementById('unsaved-stay').focus();
}
window.addEventListener('hashchange',event=>{
 const index=historyIndex(),undo=pendingHistoryUndo,undoKey=pendingHistoryUndoKey;pendingHistoryUndo=pendingHistoryUndoKey=null;
 // Landing back on the settled entry after the guard's own undo: restore it without rendering.
 // A key survives the eviction of the oldest entry at the history cap; an index shifts.
 const undone=undoKey!==null?navigationKey()===undoKey:undo!==null&&index===undo;
 if(undone&&location.hash===settledSettingsHash){event.stopImmediatePropagation();return;}
 if(!unsavedSettingsPending()){settleHistory();return;}
 event.stopImmediatePropagation();
 const settledKey=settledHistoryKey,targetKey=navigationKey();
 if(settledKey&&targetKey&&settledKey!==targetKey&&canTraverseByKey()&&window.navigation.entries().some(e=>e.key===settledKey)){
  // The settled entry is still in session history: move to it by key, even where entries share
  // an index. Stay re-checks the undo; Discard moves to the requested entry from wherever the
  // undo left the page.
  let discarded=false;
  const generation=++historyGuardGeneration;
  const undoWanted=()=>!discarded&&generation===historyGuardGeneration&&settledHistoryKey===settledKey;
  const undoNow=()=>{pendingHistoryUndoKey=settledKey;traverseToEntry(settledKey,undoWanted);};
  undoNow();
  const leave=()=>{
   const pending=window.navigation.transition;
   if(pending){pending.finished.then(leave,leave);return;}
   if(navigationKey()===targetKey){settleHistory();render();}else traverseToEntry(targetKey,()=>generation===historyGuardGeneration&&settledHistoryKey===settledKey);
  };
  confirmLeaveUnsaved(()=>{discarded=true;pendingHistoryUndoKey=null;leave();},
   ()=>{if(undoWanted()&&navigationKey()!==settledKey)undoNow();});
  return;
 }
 // Without a measurable move (no index, or an entry sharing the settled index) the
 // address is restored in place; history.go(0) would reload and drop the edits.
 if(settledHistoryIndex===null||index===settledHistoryIndex){
  const target=event.newURL;
  nativeReplaceState(history.state,'',settledSettingsHash||location.pathname+location.search);
  confirmLeaveUnsaved(()=>{location.href=target;});
  return;
 }
 // A new entry (link, typed address) sits right after the settled one; Back/Forward reports its own position.
 const delta=index===null?1:index-settledHistoryIndex;
 pendingHistoryUndo=settledHistoryIndex;history.go(-delta);
 confirmLeaveUnsaved(()=>history.go(delta));
});
document.addEventListener('click',event=>{
 if(!event.target.closest?.('#refresh-page')||!unsavedSettingsPending())return;
 event.preventDefault();event.stopImmediatePropagation();
 confirmLeaveUnsaved(()=>render());
},true);
window.addEventListener('beforeunload',event=>{if(unsavedSettingsPending()){event.preventDefault();event.returnValue='';}});
async function settings(revision=renderRevision){
 const data=await api('/settings');
 if(!currentView(revision,'settings'))return;
 let section=location.hash.split('/')[1]||'';
 if(!SETTINGS_SECTIONS[section])section='';
 const title=section?SETTINGS_SECTIONS[section][0]:'Set your own rhythm.';
 $('#content').innerHTML=heading(title,section?SETTINGS_SECTIONS[section][1]:'Choose a settings section. Each has its own controls and save action.')+settingsNav(section)+'<section id="settings-section" class="settings-section"></section>';
 const container=$('#settings-section');
 if(!section){
  container.innerHTML='<label class="settings-search">Find a setting<input type="search" id="settings-search" placeholder="API key, certificate, MySQL, retention…" autocomplete="off"></label><div class="settings-hub" id="settings-hub" role="region" aria-label="Settings sections" aria-live="polite"></div>';
  const hub=$('#settings-hub'),input=$('#settings-search');
  const draw=()=>{hub.innerHTML=settingsHubCards(input.value);};
  input.oninput=draw;draw();return;
 }
 if(section==='ai'){renderAISettings(data,revision,container);return;}
 if(section==='agents'){container.innerHTML='<div class="card" id="agent-defaults"><p class="help">Loading agent maintenance defaults…</p></div>';await agentMaintenanceDefaults(revision);return;}
 if(section==='malware'){container.innerHTML='<div class="card" id="malware-policy"><p class="help">Loading malware response policy…</p></div>';await malwarePolicySettings(revision);return;}
 if(section==='database'){container.innerHTML='<div class="card" id="database-settings"><p class="help">Loading database settings…</p></div>';await databaseSettings(revision);return;}
 if(section==='https'){
  container.innerHTML=`<div class="card"><h2>HTTPS profiles</h2><p>Configure independent internal and external profiles with uploaded certificates, ACME, or the built-in local CA.</p><p>${Object.entries(data.tls.profiles||{}).filter(([,p])=>p.enabled).map(([name,p])=>esc(name+': '+p.domain+' · browser port '+p.effective_https_port)+' · '+badge(p.mode)).join('<br>')||'Initial HTTPS configured by deployment'}</p><button type="button" id="tls-button">Configure HTTPS →</button></div>`;
  $('#tls-button').onclick=tlsModal;return;
 }
 if(section==='patching')container.innerHTML=`<form id="patch-settings-form" class="card"><h2>Patch policy</h2><p class="help">Deadlines begin when a candidate is discovered. They flag overdue work; they do not authorize unattended installation or represent CVSS scores.</p><fieldset><div class="form-grid">${['critical','high','normal','low'].map(k=>`<label>${k[0].toUpperCase()+k.slice(1)} · hours<input name="${k}" type="number" min="1" max="8760" value="${data.deadlines[k]}" required></label>`).join('')}</div><label>Repository check interval · minutes<input name="repo_minutes" type="number" min="5" max="10080" value="${data.repo_minutes}" required></label><p class="help">Target process sampling: 30 seconds. Full managed-file and executable hash refresh: 5 minutes.</p><label>OS support-end advance warning · days<input name="os_lifecycle_warning_days" type="number" min="0" max="730" value="${esc(data.os_lifecycle_warning_days??90)}" required></label><p class="help">Administrators get an in-app notice this many days before a server's verified release leaves standard support or verified Debian LTS coverage. 0 turns the advance notice off; notices after support ends are unchanged.</p><label>Telemetry-loss notice after · minutes<input name="telemetry_lost_minutes" type="number" min="5" max="1440" step="1" value="${esc(data.telemetry_lost_minutes??15)}" required></label><p class="help">Administrators get an in-app notice when an enabled server sends no telemetry for this long. Shorter values report outages sooner but can flag brief network interruptions. The two-minute stale alert and email or webhook delivery are unchanged.</p><button type="submit" class="primary">Save patch policy</button></fieldset><p class="help" role="status" id="section-save-result"></p></form>`;
 if(section==='history')container.innerHTML=`<form id="history-settings-form" class="card"><h2>History retention</h2><fieldset><label>Days to retain observations and inventory revisions<input name="history_days" type="number" min="1" max="3650" value="${data.history_days}" required></label><p class="help">The worker uses this period for observation, inventory revision and completed AI log cleanup. Package change history is retained separately.</p><button type="submit" class="primary">Save history retention</button></fieldset><p class="help" role="status" id="section-save-result"></p></form>`;
 const form=container.querySelector('form'),result=$('#section-save-result');
 trackSettingsForm(form);
 form.onsubmit=async event=>{
  event.preventDefault();const f=new FormData(form),fieldset=form.querySelector('fieldset');
  const body=section==='patching'?{repo_minutes:+f.get('repo_minutes'),os_lifecycle_warning_days:+f.get('os_lifecycle_warning_days'),telemetry_lost_minutes:+f.get('telemetry_lost_minutes'),deadlines:Object.fromEntries(['critical','high','normal','low'].map(k=>[k,+f.get(k)]))}:{history_days:+f.get('history_days')};
  fieldset.disabled=true;result.textContent='Saving…';
  try{await api('/settings/'+section,'PUT',body);settingsFormSaved(form);if(currentView(revision,'settings')&&result.isConnected)result.textContent=section==='patching'?'Patch policy saved.':'History retention saved.';}
  catch(error){if(currentView(revision,'settings')&&result.isConnected)result.textContent=error.message;}
  finally{if(fieldset.isConnected)fieldset.disabled=false;}
 };
}
function modelPicker(data){
 return `<label>Model ID<select name="ai_model" id="ai-model"><option value="">Choose an available model</option>${data.ai_model?`<option value="${esc(data.ai_model)}" selected>${esc(data.ai_model)} · saved, not verified</option>`:''}<option value="__manual__">Enter a model ID manually…</option></select></label><label id="ai-manual-label" hidden>Exact model ID<input id="ai-model-manual" maxlength="100" autocomplete="off" placeholder="API model ID, not a ChatGPT display label"></label><button type="button" id="ai-model-refresh">Refresh available models</button><p id="ai-model-status" class="help" role="status">Load models using your saved API key, or enter an exact model ID manually. Discovery and test failures do not prevent saving.</p>`;
}
function migrationNotice(m){
 const rate=n=>n?`${esc(n)}/hour`:'off',legacy=m.legacy_hourly_starts||{};
 return `<div class="notice ai-migration" id="ai-migration"><strong>Admission migration review required.</strong> Existing separate limits remain active until saved. Suggested shared rate: ${esc(m.suggested_rate_per_hour)} work starts/hour, no accumulated burst.<br><small>Current hidden allowances: process triage ${rate(legacy.triage)} · update scoring ${rate(legacy.update_scoring)} · automatic incident/startup plans ${rate(legacy.automatic_plans)}. ${m.proposal_expands?'This suggestion would raise an allowance; review the effects before saving.':'The suggested rate is the lowest enabled allowance, so no purpose can start more work per hour than it does now. All purposes then share it.'}</small><br><button type="button" id="ai-migration-apply">Use suggested shared rate</button> <small>Fills the form only. Review “Effects of this change”, then save.</small></div>`;
}
function renderAISettings(data,revision,container){
 const migration=data.ai_control_migration?.required;
 const budget=data.ai_budget||{},catalog=budget.pricing_catalog||{},providerBackoff=data.ai_provider_backoff||{};
 container.innerHTML=`<form class="card" id="ai-key-form"><h2>1. API key</h2><p class="help">Save your key independently—even if the old model is invalid. Saving does not call OpenAI.</p><fieldset><label>OpenAI API key <span id="ai-key-state">${data.api_key_configured?'· saved':'· not configured'}</span><input name="api_key" type="password" autocomplete="new-password" placeholder="Enter a new key to replace the saved key" required maxlength="1000"></label><button class="primary" type="submit">Save API key</button></fieldset><p id="ai-key-result" class="help" role="status"></p></form><form class="card" id="ai-settings-form"><h2>2. Model &amp; investigations</h2><p id="ai-saved-model" class="settings-saved">Saved model: ${esc(data.ai_model||'None')}</p><fieldset>${modelPicker(data)}<div class="actions ai-save-actions"><button type="submit" class="primary">Save AI settings</button><button type="submit" id="ai-test">Save and test selected model</button></div><p id="ai-save-result" class="help" role="status"></p><p id="ai-test-result" class="help" role="status"></p><p class="help">Save and test first saves the selected model, then sends one small structured-output request. No server evidence is included. The result identifies the exact model tested. An accessible model may still lack Responses API or JSON-schema support.</p><label class="check"><input name="ai_enabled" type="checkbox" ${data.ai_enabled?'checked':''}>Enable central OpenAI API investigations</label><p class="help">Sends executable paths, SHA-256 hashes, UIDs, and network endpoint metadata. Investigations may request fixed read-only package, executable and service checks. Arguments, environment variables and arbitrary file contents are excluded. Each investigation uses up to two calls. Responses use store: false; your API organization’s data policies still apply.</p>${migration?migrationNotice(data.ai_control_migration):''}<label>Mr Patchy admission mode<select name="ai_control_mode"><option value="legacy" ${data.ai_control_mode==='legacy'?'selected':''}>Legacy separate hourly limits</option><option value="rate" ${data.ai_control_mode==='rate'?'selected':''}>Shared smooth rate throttle</option><option value="daily_cap" ${data.ai_control_mode==='daily_cap'?'selected':''}>Daily spend cap</option><option value="rate_and_daily" ${data.ai_control_mode==='rate_and_daily'?'selected':''}>Rate throttle + daily spend cap</option><option value="unthrottled" ${data.ai_control_mode==='unthrottled'?'selected':''}>Unthrottled by Mr Patchy</option></select></label><label>Shared AI work starts per hour<input name="ai_rate_per_hour" type="number" min="1" max="1000" value="${data.ai_rate_per_hour}" required></label><div class="form-grid"><label>Daily AI cap · USD<input name="ai_daily_cap_usd" type="number" min="0.01" max="1000000" step="0.01" value="${esc(data.ai_daily_cap_usd)}" required></label><label>Budget reset · IANA timezone<input name="ai_budget_timezone" maxlength="64" value="${esc(data.ai_budget_timezone)}" required placeholder="America/New_York"></label><label>Advance cap warning · % of cap<input name="ai_daily_cap_warning_percent" type="number" min="0" max="99" step="1" value="${esc(data.ai_daily_cap_warning_percent??80)}" required aria-describedby="ai-cap-warning-help"></label></div><p class="help" id="ai-cap-warning-help">Administrators get one in-app notification per budget day when counted spend reaches this share of the cap. Enter 0 to turn the advance warning off; the cap-reached notification and admission are unchanged.</p><div class="notice"><strong>Current budget window</strong><br>Counted $${esc(budget.counted_usd||'0')} · settled $${esc(budget.settled_usd||'0')} · reserved $${esc(budget.reserved_usd||'0')} · uncertain $${esc(budget.uncertain_usd||'0')} · remaining $${esc(budget.remaining_usd||data.ai_daily_cap_usd)}${budget.next_reset?' · resets '+date(budget.next_reset):''}${providerBackoff.blocked?`<br><strong>Provider backoff active</strong> · ${esc(providerBackoff.failures)} consecutive transient failure(s) · recorded ${date(providerBackoff.updated_at)} · next eligible ${date(providerBackoff.next_at)}<br>${esc(providerBackoff.reason)}<br><button type="button" id="provider-backoff-clear">Review and clear provider backoff</button>`:''}</div><p class="help">Capped modes reserve a conservative ceiling before every provider call and reconcile valid usage receipts. Unknown model/tier pricing is blocked, never treated as free. Sent calls without reliable usage retain the full reservation after timeout or restart. Provider Retry-After and transient backoff are shared across workers and purposes. Clearing a reviewed provider floor sends no request and does not bypass rate, budget, retry, pause, lifecycle or concurrency controls. Estimates use a versioned public price catalog and are not provider invoices. Unthrottled removes Mr Patchy rate/spend controls only; finite concurrency, provider limits, global/per-server pause, roles and data sharing still apply.</p><label>Legacy maximum investigations per hour<input name="ai_hourly_limit" type="number" min="1" max="1000" value="${data.ai_hourly_limit}" required></label><label class="check"><input name="ai_updates_enabled" type="checkbox" ${data.ai_updates_enabled?'checked':''}>Automatically score pending updates</label><p class="help">Sends package names, versions, OS release and priority classification. Scores are advisory estimates, not verified CVSS ratings, and never authorize installation.</p><label>Legacy maximum scoring batches per hour · up to 5 updates each<input name="ai_update_hourly_limit" type="number" min="1" max="1000" value="${data.ai_update_hourly_limit}" required></label></fieldset><a class="mint" href="#ai-logs">Inspect AI run logs →</a></form>`;
 container.insertAdjacentHTML('beforeend',`<section class="card" id="ai-spend-history" aria-labelledby="ai-spend-history-title"><h2 id="ai-spend-history-title">3. Retained spend history</h2><form id="ai-spend-history-filter" class="form-grid"><label>Period<select id="ai-spend-history-days" aria-describedby="ai-spend-history-help"><option value="7">7 days</option><option value="30" selected>30 days</option><option value="90">90 days</option></select></label><label>Budget timezone<input id="ai-spend-history-timezone" maxlength="64" placeholder="America/New_York" aria-describedby="ai-spend-history-timezone-help"></label><div class="actions full"><button type="submit">Apply timezone filter</button><button type="button" id="ai-spend-history-download">Download CSV</button></div></form><p class="help" id="ai-spend-history-download-status" role="status"></p><p class="help" id="ai-spend-history-timezone-help">Use the recorded IANA timezone. Clear the field and apply to show all timezones.</p><p class="help" id="ai-spend-history-help">Settled amounts are local public-price estimates based on retained usage—not provider invoices. Transmitted, uncertain and unrecognized unreleased calls retain their conservative ceiling. The CSV download uses the selected period and applied timezone filter and contains only these window totals, for comparison with your provider’s billing records.</p><div id="ai-spend-history-results"><p class="help" role="status">Loading retained AI spend history…</p></div></section>`);
 container.insertAdjacentHTML('beforeend',`<section class="card" id="ai-spend-purpose" aria-labelledby="ai-spend-purpose-title"><h2 id="ai-spend-purpose-title">4. Current window spend by activity</h2><p class="help" id="ai-spend-purpose-help">Shows which AI activity the daily spend cap is currently counting. This is read-only: it does not change admission, reservations or the cap.</p><div id="ai-spend-purpose-results"><p class="help" role="status">Loading current-window AI spend by activity…</p></div><div class="actions"><button type="button" id="ai-spend-purpose-refresh" aria-describedby="ai-spend-purpose-help">Refresh</button></div></section>`);
 const notices=container.querySelectorAll('.notice'),budgetNotice=notices[notices.length-1];
 if(budget.enabled&&Number.isInteger(budget.unreconciled_call_count)){
  const count=budget.unreconciled_call_count;
  const reconciliation=document.createElement('div');
  reconciliation.textContent=count
   ? `${count} transmitted AI ${count===1?'call awaits':'calls await'} reconciliation · Oldest reservation ${date(budget.oldest_unreconciled_reservation_at)}`
   : 'No transmitted AI calls await reconciliation.';
  budgetNotice.append(reconciliation);
  const amounts=[budget.sent_usd,budget.uncertain_outcome_usd];
  if(count>0&&amounts.every(amount=>typeof amount==='string'&&/^\d+(?:\.\d{1,9})?$/.test(amount))){
   const breakdown=document.createElement('div');
   breakdown.textContent=`Sent without reconciled usage $${budget.sent_usd} · Recorded uncertain outcome $${budget.uncertain_outcome_usd}. Both count toward the cap.`;
   budgetNotice.append(breakdown);
  }
 }
 budgetNotice.insertAdjacentHTML('beforeend',`<br><strong>Price catalog ${catalog.fresh?'current':catalog.state==='expired'?'expired':'unavailable'}</strong> · ${esc(catalog.version||'unknown version')}${catalog.expires_at?' · expires '+date(catalog.expires_at):''}${!catalog.fresh&&catalog.reason?' · '+esc(catalog.reason):''}`);
 const keyForm=$('#ai-key-form'),form=$('#ai-settings-form'),select=$('#ai-model'),manual=$('#ai-model-manual');
 const keyResult=$('#ai-key-result'),saveResult=$('#ai-save-result'),testResult=$('#ai-test-result'),status=$('#ai-model-status'),refresh=$('#ai-model-refresh');
 const alive=()=>currentView(revision,'settings')&&container.isConnected;
 // Read-only scoring queue summary (#917), fetched separately so its exact-identity pass never delays Settings.
 // Counts and times only; never a promise that a batch starts now.
 container.querySelector('input[name=ai_updates_enabled]')?.closest('label')?.nextElementSibling?.insertAdjacentHTML('afterend','<div class="notice" id="scoring-queue" role="status" aria-live="polite"><strong>Scoring queue</strong> · Loading…</div>');
 (async()=>{const target=$('#scoring-queue');if(!target)return;let q;try{q=await api('/update-scores/status');}catch{q=null;}
  if(!currentView(revision,'settings')||!target.isConnected)return;
  target.innerHTML=scoringQueueSummary(q);})();
 // Inserted after the budget notice lookup so this notice never receives budget details.
 if(data.ai_scoring_blocked>0)container.querySelector('input[name=ai_updates_enabled]')?.closest('label')?.nextElementSibling?.insertAdjacentHTML('afterend',`<div class="notice" id="scoring-blocked"><strong>${esc(data.ai_scoring_blocked)} update ${data.ai_scoring_blocked===1?'score is':'scores are'} blocked</strong> by a non-transient AI provider failure under the saved model and key. No automatic retry is scheduled. After resolving the cause (for example restored quota or access), retry them; changing the saved model or key also makes them eligible.<br><button type="button" id="scoring-blocked-retry">Retry blocked scores</button><span id="scoring-blocked-result" class="help" role="status"></span></div>`);
 const retryScoring=$('#scoring-blocked-retry');
 if(retryScoring)retryScoring.onclick=async()=>{
  const result=$('#scoring-blocked-result');retryScoring.disabled=true;result.textContent=' Queuing…';
  try{const reply=await api('/update-scores/blocked/retry','POST');if(currentView(revision,'settings')&&result.isConnected)result.textContent=' '+reply.detail;}
  catch(error){if(currentView(revision,'settings')&&result.isConnected)result.textContent=' '+error.message;retryScoring.disabled=false;}
 };
 const clearBackoff=$('#provider-backoff-clear');
 if(clearBackoff)clearBackoff.onclick=()=>{
  modal('Review shared provider backoff',`<p>This floor was recorded ${date(providerBackoff.updated_at)} and currently blocks every new provider call until ${date(providerBackoff.next_at)}. Clear it only after reviewing provider availability, quota and the recorded reason. A newer or expired floor will be preserved.</p><p class="help">This sends no provider or target request. Rate, budget, item retry, pause, lifecycle and concurrency controls remain authoritative.</p><form id="provider-backoff-clear-form"><label>Reason<textarea name="reason" minlength="10" maxlength="1000" required></textarea></label><label>Type CLEAR BACKOFF<input name="confirmation" pattern="CLEAR BACKOFF" autocomplete="off" required></label><button class="primary">Clear reviewed provider backoff</button></form>`);
  const dialogRevision=modalRevision,clearForm=$('#provider-backoff-clear-form');
  clearForm.onsubmit=async event=>{event.preventDefault();const button=clearForm.querySelector('button');button.disabled=true;
   try{await api('/ai/provider-backoff/clear','POST',{expected_revision:providerBackoff.revision,reason:clearForm.elements.reason.value,confirmation:clearForm.elements.confirmation.value});if(alive()&&dialogRevision===modalRevision){$('#modal').close();toast('Reviewed provider backoff cleared.');await settings(revision);}}
   catch(error){if(alive()&&dialogRevision===modalRevision)toast(error.message);}
   finally{if(button.isConnected)button.disabled=false;}
  };
 };
 const historyDays=$('#ai-spend-history-days'),historyResults=$('#ai-spend-history-results');
 const historyTimezone=$('#ai-spend-history-timezone');let historyGeneration=0,appliedTimezone='';
 const loadHistory=async()=>{
  const ticket=++historyGeneration;historyResults.innerHTML='<p class="help" role="status">Loading retained AI spend history…</p>';
  try{
   const params=new URLSearchParams({days:historyDays.value});
   if(appliedTimezone)params.set('timezone',appliedTimezone);
   const result=await api('/settings/ai-spend-history?'+params);
   if(!alive()||ticket!==historyGeneration)return;
   const clipped=result.truncated?`<p class="notice" role="status">Showing the newest ${esc(result.max_windows)} accounting windows. Additional reset/timezone groups exist in this period.</p>`:'';
   if(!result.windows.length){historyResults.innerHTML=clipped+'<p class="help" role="status">No retained billable AI calls match the selected period and timezone filter.</p>';return;}
   const rows=result.windows.map(row=>`<tr><td>${row.window_start?date(row.window_start):'Unknown start'}<small>Resets ${date(row.reset_at)} · ${esc(row.timezone)}</small></td><td>${esc(row.call_count)}</td><td>$${esc(row.settled_usd)}</td><td>$${esc(row.reserved_usd)}</td><td>$${esc(row.sent_usd)}</td><td>$${esc(row.uncertain_usd)}</td><td>$${esc(row.other_usd)}</td><td><strong>$${esc(row.counted_usd)}</strong></td></tr>`).join('');
   historyResults.innerHTML=clipped+`<div class="table-wrap"><table><caption>Retained AI spend accounting windows</caption><thead><tr><th>Budget window</th><th>Calls</th><th>Settled estimate</th><th>Reserved</th><th>Sent</th><th>Uncertain</th><th>Other</th><th>Counted</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }catch(error){if(alive()&&ticket===historyGeneration){historyResults.innerHTML=PatchyUI.error('Retained spend history could not be loaded',esc(error.message));}}
 };
 historyDays.onchange=loadHistory;
 const historyDownload=$('#ai-spend-history-download'),historyDownloadStatus=$('#ai-spend-history-download-status');
 historyDownload.onclick=async()=>{
  const session=sessionRevision,days=historyDays.value,timezone=appliedTimezone;
  historyDownload.disabled=true;historyDownloadStatus.textContent='Preparing retained spend history CSV…';
  try{
   const params=new URLSearchParams({days});if(timezone)params.set('timezone',timezone);
   const response=await fetch('/api/settings/ai-spend-history.csv?'+params,{headers:{'X-CSRF-Token':csrf}});
   if(session!==sessionRevision||!alive())return;
   if(!response.ok){
    let detail;try{detail=(await response.json()).detail;}catch{}
    if(response.status===401)showLogin(csrf?'Session expired. Sign in again.':'');
    throw Error(apiErrorMessage(detail)||`Spend history download failed (HTTP ${response.status})`);
   }
   const truncated=response.headers.get('X-MrPatchy-Spend-History-Truncated')==='true';
   const limit=response.headers.get('X-MrPatchy-Spend-History-Max-Windows')||'';
   const blob=await response.blob();
   if(session!==sessionRevision||!alive())return;
   const url=URL.createObjectURL(new Blob([blob],{type:'text/csv'})),link=document.createElement('a');
   link.href=url;link.download=`mrpatchy-ai-spend-${Number(days)}d${timezone?'-'+timezone.replace(/[^A-Za-z0-9_+-]+/g,'_'):''}.csv`;
   document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
   historyDownloadStatus.textContent=truncated?`Downloaded the newest ${limit} accounting windows. Additional reset/timezone groups exist in this period and are not in the file.`:'Retained spend history CSV downloaded. Amounts are local public-price estimates, not provider invoices.';
  }catch(error){if(session===sessionRevision&&alive())historyDownloadStatus.textContent='Download failed: '+error.message;}
  finally{if(historyDownload.isConnected)historyDownload.disabled=false;}
 };

 const SPEND_PURPOSE_LABELS={triage:'Process triage',update_scoring:'Update importance scoring',security_plan:'Incident and startup response plans',release_configuration:'Release configuration reviews',connection_test:'AI connection tests',other:'Other recorded activity',unattributed:'Not attributed (run history pruned or no run)'};
 const purposeResults=$('#ai-spend-purpose-results'),purposeRefresh=$('#ai-spend-purpose-refresh');let purposeGeneration=0;
 const loadSpendByPurpose=async()=>{
  const ticket=++purposeGeneration;purposeRefresh.disabled=true;
  purposeResults.innerHTML='<p class="help" role="status">Loading current-window AI spend by activity…</p>';
  try{
   const result=await api('/settings/ai-spend-by-purpose');
   if(!alive()||ticket!==purposeGeneration)return;
   const notes=(Array.isArray(result.limitations)?result.limitations:[]).map(text=>`<li>${esc(text)}</li>`).join('');
   const caveats=notes?`<ul class="help">${notes}</ul>`:'';
   if(!result.enabled){purposeResults.innerHTML='<p class="help" role="status">No daily spend cap applies in the current control mode, so no spend is being counted against a cap.</p>';return;}
   const windowText=`Budget window resets ${date(result.next_reset)} · ${esc(result.timezone)}`;
   if(!result.groups.length){purposeResults.innerHTML=`<p class="help" role="status">No billable AI calls are counted in the current budget window. ${windowText}.</p>`+caveats;return;}
   const rows=result.groups.map(row=>`<tr><th scope="row">${esc(SPEND_PURPOSE_LABELS[row.purpose]||'Other recorded activity')}</th><td>${esc(row.call_count)}</td><td>$${esc(row.settled_usd)}</td><td>$${esc(row.reserved_usd)}</td><td>$${esc(row.uncertain_usd)}</td><td><strong>$${esc(row.counted_usd)}</strong></td></tr>`).join('');
   purposeResults.innerHTML=`<p class="help">${windowText}</p><div class="table-wrap"><table><caption>AI spend counted against the daily cap, by activity</caption><thead><tr><th scope="col">Activity</th><th scope="col">Calls</th><th scope="col">Settled estimate</th><th scope="col">Reserved</th><th scope="col">Sent or uncertain</th><th scope="col">Counted</th></tr></thead><tbody>${rows}</tbody><tfoot><tr><th scope="row">All activity</th><td>${esc(result.call_count)}</td><td colspan="3"></td><td><strong>$${esc(result.counted_usd)}</strong></td></tr></tfoot></table></div>`+caveats;
  }catch(error){if(alive()&&ticket===purposeGeneration){purposeResults.innerHTML=PatchyUI.error('Current-window spend by activity could not be loaded',esc(error.message));}}
  finally{if(ticket===purposeGeneration&&purposeRefresh.isConnected)purposeRefresh.disabled=false;}
 };
 purposeRefresh.onclick=loadSpendByPurpose;
 $('#ai-spend-history-filter').onsubmit=event=>{
  event.preventDefault();
  appliedTimezone=historyTimezone.value.trim();
  loadHistory();
 };
 let keyRevision=data.api_key_revision||'',controlsRevision=data.ai_controls_revision||'',listGeneration=0,busy=false;
 const chosen=()=>select.value==='__manual__'?manual.value.trim():select.value;
 const toggleManual=()=>{const enabled=select.value==='__manual__';$('#ai-manual-label').hidden=!enabled;manual.required=enabled;manual.disabled=!enabled;};
 const markChanged=()=>{saveResult.textContent='Unsaved changes.';testResult.textContent='';toggleManual();};
 form.addEventListener('input',markChanged);form.addEventListener('change',markChanged);toggleManual();trackSettingsForm(keyForm);trackSettingsForm(form);
 const setBusy=value=>{busy=value;keyForm.querySelector('fieldset').disabled=value;form.querySelector('fieldset').disabled=value;};
 // Effects of this change (#871): read-only preview of admission/spend ceilings before save.
 $('#ai-test-result').insertAdjacentHTML('afterend','<div class="notice ai-control-effects" id="ai-control-effects" role="status" aria-live="polite" hidden></div>');
 const effectsPanel=$('#ai-control-effects'),CONTROL_KEYS=['ai_enabled','ai_control_mode','ai_rate_per_hour','ai_daily_cap_usd','ai_budget_timezone','ai_hourly_limit','ai_update_hourly_limit','ai_updates_enabled'];
 const controlBody=()=>{const f=new FormData(form);return {ai_enabled:f.has('ai_enabled'),ai_control_mode:f.get('ai_control_mode'),ai_rate_per_hour:+f.get('ai_rate_per_hour'),ai_daily_cap_usd:+f.get('ai_daily_cap_usd'),ai_budget_timezone:String(f.get('ai_budget_timezone')||'').trim(),ai_hourly_limit:+f.get('ai_hourly_limit'),ai_update_hourly_limit:+f.get('ai_update_hourly_limit'),ai_updates_enabled:f.has('ai_updates_enabled')};};
 const controlsValid=()=>CONTROL_KEYS.every(name=>{const field=form.elements[name];return !field||field.checkValidity();});
 const effectsHtml=result=>result.changed?`<strong>Effects of this change</strong><ul class="ai-control-effects-list">${result.effects.map(item=>`<li${item.expands?' class="expands"':''}>${item.expands?'<strong>Expands:</strong> ':''}${esc(item.text)}</li>`).join('')}</ul><small>${esc(result.limitation)}</small>`:'<strong>Effects of this change</strong><br>No change to Mr Patchy admission or spend ceilings.';
 let effectsGeneration=0,effectsTimer=0;
 const refreshEffects=()=>{
  clearTimeout(effectsTimer);const ticket=++effectsGeneration;
  if(!controlsValid()){effectsPanel.hidden=false;effectsPanel.textContent='Effects of this change: correct the highlighted control values to preview them.';return;}
  effectsTimer=setTimeout(async()=>{
   try{const result=await api('/settings/ai/preview','POST',controlBody());if(!alive()||ticket!==effectsGeneration)return;effectsPanel.hidden=false;effectsPanel.innerHTML=effectsHtml(result);}
   catch(error){if(alive()&&ticket===effectsGeneration){effectsPanel.hidden=false;effectsPanel.textContent='Effects could not be previewed. '+error.message;}}
  },250);
 };
 const onControlEdit=event=>{if(CONTROL_KEYS.includes(event.target?.name))refreshEffects();};
 form.addEventListener('input',onControlEdit);form.addEventListener('change',onControlEdit);
 $('#ai-migration-apply')?.addEventListener('click',()=>{const proposal=data.ai_control_migration?.proposal;if(!proposal)return;form.elements.ai_control_mode.value=proposal.ai_control_mode;form.elements.ai_rate_per_hour.value=proposal.ai_rate_per_hour;form.elements.ai_control_mode.dispatchEvent(new Event('change',{bubbles:true}));form.elements.ai_rate_per_hour.dispatchEvent(new Event('input',{bubbles:true}));form.elements.ai_rate_per_hour.focus();});
 const confirmExpansion=async body=>{
  const controls=Object.fromEntries(CONTROL_KEYS.map(key=>[key,body[key]]));
  let result;
  try{result=await api('/settings/ai/preview','POST',controls);}
  catch(error){if(alive())saveResult.textContent='AI settings were not saved. Effects could not be previewed: '+error.message;return false;}
  if(!alive())return false;
  if(!result.expands)return {};
  // The server refuses an unconfirmed expansion (#881); send back the confirmation bound to what was shown.
  const confirmation={confirm_ai_expansion:result.expansion_confirmation};
  return new Promise(resolve=>{
   modal('Confirm expanded AI admission or spend',`<p>Saving these AI settings lets Mr Patchy start more AI work or spend more than the saved controls allow:</p><ul id="ai-expansion-list">${result.expansions.map(text=>`<li>${esc(text)}</li>`).join('')}</ul><p class="help">${esc(result.limitation)}</p><div class="actions"><button type="button" class="primary" id="ai-expansion-confirm">Save with these expansions</button><button type="button" id="ai-expansion-cancel">Cancel</button></div>`);
   const dialog=$('#modal'),dialogRevision=modalRevision;let settled=false;
   const finish=value=>{if(settled)return;settled=true;dialog.removeEventListener('close',onClose);if(dialog.open&&dialogRevision===modalRevision)dialog.close();resolve(value);};
   const onClose=()=>finish(false);dialog.addEventListener('close',onClose);
   $('#ai-expansion-confirm').onclick=()=>finish(confirmation);$('#ai-expansion-cancel').onclick=()=>finish(false);
   $('#ai-expansion-cancel').focus();
  });
 };
 const load=async()=>{
  if(busy)return;const ticket=++listGeneration,version=keyRevision;
  refresh.disabled=true;status.textContent='Loading models using the saved API key…';
  try{
   const response=await api('/settings/ai-models');
   if(!alive()||ticket!==listGeneration||version!==keyRevision)return;
   const selected=select.value,models=response.models;
   select.replaceChildren(new Option('Choose an available model',''));
   if(selected&&selected!=='__manual__'&&!models.includes(selected))select.add(new Option(selected+' · not listed for this key',selected));
   for(const id of models)select.add(new Option(id,id));
   select.add(new Option('Enter a model ID manually…','__manual__'));select.value=selected;toggleManual();
   status.textContent=(selected&&selected!=='__manual__'&&!models.includes(selected)?'The selected model is not listed for this key. Choose another model. ':models.length+' available model IDs loaded. ')+'Listing does not confirm Responses API / structured-output support. Saving is separate from testing.';
  }catch(error){if(alive()&&ticket===listGeneration&&version===keyRevision)status.textContent=error.message+' Your selection is preserved. You can enter a model ID manually and save it.';}
  finally{if(alive()&&ticket===listGeneration)refresh.disabled=false;}
 };
 refresh.onclick=load;
 keyForm.onsubmit=async event=>{
  event.preventDefault();if(busy)return;
  const input=keyForm.elements.api_key,secret=input.value;let saved=false;
  ++listGeneration;refresh.disabled=false;setBusy(true);keyResult.textContent='Saving API key…';testResult.textContent='';
  try{
   const response=await api('/settings/ai-key','PUT',{api_key:secret});if(!alive())return;
   keyRevision=response.api_key_revision;input.value='';$('#ai-key-state').textContent='· saved';
   keyResult.textContent='API key saved. Your model selection is unchanged.';saved=true;settingsFormSaved(keyForm);
  }catch(error){if(alive())keyResult.textContent='API key was not saved. '+error.message;}
  finally{if(alive()){setBusy(false);if(saved)load();}}
 };
 form.onsubmit=async event=>{
  event.preventDefault();if(busy)return;
  if(keyForm.elements.api_key.value){saveResult.textContent='Save the new API key above first, or clear that field to keep using the saved key.';return;}
  const test=event.submitter?.id==='ai-test',f=new FormData(form),model=chosen();
  if(test&&!model){saveResult.textContent='Select or enter a model to test.';return;}
  const body={ai_model:model,ai_enabled:f.has('ai_enabled'),ai_hourly_limit:+f.get('ai_hourly_limit'),ai_updates_enabled:f.has('ai_updates_enabled'),ai_update_hourly_limit:+f.get('ai_update_hourly_limit'),ai_control_mode:f.get('ai_control_mode'),ai_rate_per_hour:+f.get('ai_rate_per_hour'),ai_daily_cap_usd:+f.get('ai_daily_cap_usd'),ai_budget_timezone:f.get('ai_budget_timezone').trim(),ai_daily_cap_warning_percent:+f.get('ai_daily_cap_warning_percent')};
  if(controlsRevision)body.expected_ai_controls_revision=controlsRevision;
  const confirmed=await confirmExpansion(body);
  if(!confirmed){if(alive()&&!saveResult.textContent.startsWith('AI settings were not saved'))saveResult.textContent='Save cancelled. Nothing was saved; your entries are still in the form.';return;}
  Object.assign(body,confirmed);
  ++listGeneration;refresh.disabled=false;setBusy(true);saveResult.textContent='Saving AI settings…';testResult.textContent='';
  try{
   const response=await api('/settings/ai','PUT',body);if(!alive())return;
   keyRevision=response.api_key_revision;if(response.ai_controls_revision)controlsRevision=response.ai_controls_revision;
   effectsPanel.hidden=true;effectsPanel.textContent='';
   $('#ai-saved-model').textContent='Saved model: '+(response.ai_model||'None');
   saveResult.textContent='AI settings saved. Model: '+(response.ai_model||'None')+'.';settingsFormSaved(form);
   if(test){
    testResult.textContent='Testing saved model '+response.ai_model+'…';
    try{
     const result=await api('/settings/ai-test','POST',{expected_model:response.ai_model,expected_key_revision:keyRevision});
     if(alive())testResult.textContent=result.detail;
    }catch(error){if(alive())testResult.textContent='Connection test failed. '+error.message+' The AI settings save succeeded.';}
   }
  }catch(error){if(alive())saveResult.textContent='AI settings were not saved. '+error.message+(error.status===409?' Your entries are still in the form; reload Settings to compare them with the current saved controls.':'');}
  finally{if(alive())setBusy(false);}
 };
 loadHistory();loadSpendByPurpose();if(data.api_key_configured)load();
}
async function databaseSettings(revision){
 const container=$('#database-settings');
 try{
  const state=await api('/settings/database');
  if(!currentView(revision,'settings')||!container.isConnected)return;
  const active=state.active,target=state.target||{backend:active.backend==='sqlite'?'mysql':'sqlite',host:'',port:3306,database:'mrpatchy',username:'',tls:true,ca_file:'',sqlite_file:'mrpatchy-migrated.db'};
  container.innerHTML=`<h2>Database &amp; offline migration</h2><p><strong>Active: ${esc(active.backend==='sqlite'?'SQLite':'MySQL')}</strong> · ${esc(active.database)}${active.host?' on '+esc(active.host):''}</p><p class="help">Configuration source: ${esc(state.source)}. Destination settings are staged separately; saving does not switch databases.</p><form id="database-form"><label>Migration destination<select name="backend"><option value="mysql" ${target.backend==='mysql'?'selected':''}>MySQL</option><option value="sqlite" ${target.backend==='sqlite'?'selected':''}>SQLite</option></select></label><div id="database-mysql"><div class="form-grid"><label>MySQL host<input name="host" maxlength="253" value="${esc(target.host)}"></label><label>Port<input name="port" type="number" min="1" max="65535" value="${target.port}"></label><label>Database name<input name="database" value="${esc(target.database)}" pattern="[A-Za-z0-9_]{1,64}"></label><label>Username<input name="username" autocomplete="off" value="${esc(target.username)}"></label></div><label>Password ${target.password_configured?'· saved':''}<input name="password" type="password" autocomplete="new-password" placeholder="Blank keeps the staged password for an unchanged destination"></label><label class="check"><input type="checkbox" name="clear_password">Explicitly use no password</label><label class="check"><input type="checkbox" name="tls" ${target.tls?'checked':''}>Verify database TLS certificate and hostname</label><label>CA certificate file · optional<input name="ca_file" value="${esc(target.ca_file)}" placeholder="/data/mysql-ca.pem"></label><p class="help">Create an empty MySQL 8+ database first. The account needs schema creation and data permissions. A CA file must be mounted at this path in both app and worker containers; leave blank to use system trust.</p></div><div id="database-sqlite"><label>New SQLite filename in the app data volume<input name="sqlite_file" value="${esc(target.sqlite_file)}" pattern="[A-Za-z0-9][A-Za-z0-9_.-]{0,119}\\.db"></label><p class="help">Choose a new filename. Existing data is never overwritten.</p></div><button class="primary" type="submit">Save migration destination</button><p id="database-result" class="help" role="status"></p><div id="database-test-group"><button type="button" id="database-test" aria-describedby="database-test-help">Test connection</button><p id="database-test-result" class="help" role="status" aria-live="polite"></p><p id="database-test-help" class="help">Tests the values entered above without saving. Success only shows this controller can connect and run a read-only query.</p></div></form><details id="database-migration-steps"><summary>Run an offline migration</summary><p>Finish running jobs, back up the database and persistent volumes, and stop <strong>every app and worker replica</strong>, including any on other hosts. Keep the same app data volume and secret.key. The following commands run from your deployment directory:</p><pre>docker compose stop app worker
# Validate source and destination without copying or switching:
docker compose run --rm --no-deps app python -m app.database_migrate --confirm-offline --dry-run
# Only after a successful dry run, copy, verify and activate:
docker compose run --rm --no-deps app python -m app.database_migrate --confirm-offline --activate
# Only after migration succeeds, restart (retain your worker scale):
docker compose up -d app worker</pre><p class="help">The offline command copies all application tables and verifies row counts and content fingerprints before activation. The original database stays intact. Failed verification leaves the active database unchanged; inspect the destination before retrying. An activated profile overrides DATABASE_URL for both app and workers. Do not restart against the old copy after using the new database.</p></details>`;
  const form=$('#database-form'),result=$('#database-result');
  const toggle=()=>{for(const name of ['mysql','sqlite']){const section=$('#database-'+name),enabled=form.elements.backend.value===name;section.hidden=!enabled;for(const input of section.querySelectorAll('input'))input.disabled=!enabled;}};
  form.elements.backend.onchange=toggle;toggle();trackSettingsForm(form);
  const testButton=$('#database-test'),testResult=$('#database-test-result');
  let testing=false,testRevision=0;
  const syncTest=()=>{testRevision++;$('#database-test-group').hidden=form.elements.backend.value!=='mysql';testResult.textContent='';};
  form.addEventListener('input',syncTest);form.addEventListener('change',syncTest);syncTest();
  testButton.onclick=async()=>{
   if(testing||form.elements.backend.value!=='mysql'||!form.reportValidity())return;
   const f=new FormData(form),body={backend:'mysql',host:f.get('host').trim(),port:+f.get('port'),database:f.get('database'),username:f.get('username'),password:f.get('password'),clear_password:f.has('clear_password'),tls:f.has('tls'),ca_file:f.get('ca_file').trim()};
   const testedRevision=testRevision;
   const stillCurrent=()=>testedRevision===testRevision&&currentView(revision,'settings')&&testResult.isConnected;
   testing=true;testButton.setAttribute('aria-disabled','true');testResult.textContent='Testing connection…';
   try{
    const outcome=await api('/settings/database/test','POST',body);
    if(stillCurrent())testResult.textContent=(outcome.ok?'Success ('+outcome.elapsed_ms+' ms). ':'Failed: ')+outcome.detail+' '+outcome.scope;
   }catch(error){if(stillCurrent())testResult.textContent='Test not completed: '+error.message;}
   finally{testing=false;testButton.removeAttribute('aria-disabled');}
  };
  form.onsubmit=async event=>{
   event.preventDefault();const f=new FormData(form),button=form.querySelector('[type=submit]');
   const body={backend:f.get('backend')};
   if(body.backend==='mysql')Object.assign(body,{host:f.get('host').trim(),port:+f.get('port'),database:f.get('database'),username:f.get('username'),password:f.get('password'),clear_password:f.has('clear_password'),tls:f.has('tls'),ca_file:f.get('ca_file').trim()});
   else body.sqlite_file=f.get('sqlite_file');
   button.disabled=true;result.textContent='Saving destination…';
   try{
    await api('/settings/database','PUT',body);
    if(!currentView(revision,'settings')||!result.isConnected)return;
    form.elements.password.value='';form.elements.clear_password.checked=false;
    settingsFormSaved(form);
    syncTest();
    result.textContent='Destination saved. Active database unchanged. Follow the offline migration steps below.';
    $('#database-migration-steps').open=true;
   }catch(error){if(currentView(revision,'settings')&&result.isConnected)result.textContent=error.message;}
   finally{if(button.isConnected)button.disabled=false;}
  };
 }catch(error){if(currentView(revision,'settings')&&container.isConnected)container.innerHTML=PatchyUI.error('Could not load database settings',esc(error.message));}
}

/* Fleet-wide defaults for the per-server Agent health options (#621). Servers
 inherit each option unless they hold an explicit override; this form never
 changes an override. */
const AGENT_MAINTENANCE_OPTIONS=[
 ['auto_upgrade','Automatically upgrade outdated enrolled helpers'],
 ['auto_repair','Automatically repair collector/helper drift and inactive services']
];
async function agentMaintenanceDefaults(revision){
 const box=$('#agent-defaults');if(!box)return;
 const live=()=>currentView(revision,'settings')&&box.isConnected;
 let saved;
 try{saved=await api('/settings/agent-maintenance');}
 catch(error){if(live()){box.innerHTML='<h2>Agent maintenance defaults</h2><p class="help" role="alert">Agent maintenance defaults are unavailable: '+esc(error.message)+'</p><button type="button" id="agent-defaults-retry">Retry</button>';$('#agent-defaults-retry').onclick=()=>agentMaintenanceDefaults(revision);}return;}
 if(!live())return;
 const value=key=>saved&&saved[key]===true;
 box.innerHTML=`<form id="agent-defaults-form"><h2>Agent maintenance defaults</h2><p class="help">Servers use these defaults for each option unless the server has its own override. Changing a default updates every inheriting server and keeps every server override. Reset an override from the server's <strong>Agent health</strong> page with <strong>Use global default</strong>.</p><fieldset>${AGENT_MAINTENANCE_OPTIONS.map(([key,label])=>`<label class="check"><input name="${key}" type="checkbox" ${value(key)?'checked':''}>${esc(label)}</label>`).join('')}<p class="help">Off by default. Checks run about every five minutes while a server is idle. Automatic updates are limited to two attempts per day, at least one hour apart, and active patch or recovery work blocks them. Changes to SSH keys, sudo policy, bridge identity, unsafe directories or unexpected systemd overrides still need trusted-console recovery. No operating-system packages, cloud permissions or malware quarantine are changed.</p><button type="submit" class="primary">Save agent maintenance defaults</button></fieldset><p class="help" role="status" id="agent-defaults-result"></p></form>`;
 const form=$('#agent-defaults-form'),result=$('#agent-defaults-result');
 form.onsubmit=async event=>{
  event.preventDefault();const fieldset=form.querySelector('fieldset');
  const body={...Object.fromEntries(AGENT_MAINTENANCE_OPTIONS.map(([key])=>[key,form.elements[key].checked])),expected:saved};
  fieldset.disabled=true;result.textContent='Saving…';
  try{const value=await api('/settings/agent-maintenance','PUT',body);saved=value;if(live())result.textContent='Agent maintenance defaults saved. Inheriting servers now use them.';}
  catch(error){if(live())result.textContent=error.message;}
  finally{if(fieldset.isConnected)fieldset.disabled=false;}
 };
}
const MALWARE_ACTION_LABELS={quarantine_file:'Quarantine the verified file',terminate_process:'Terminate the verified process'};
const MALWARE_MODE_LABELS={disabled:'Disabled',monitor_only:'Monitor only (record what would happen)',enforce:'Enforce (unavailable)'};
function malwarePolicyForm(data){
 const p=data.policy,l=data.limits,actions=(name,chosen)=>data.actions.map(a=>`<label class="check"><input type="checkbox" name="${name}" value="${esc(a)}" ${chosen.includes(a)?'checked':''}><span>${esc(MALWARE_ACTION_LABELS[a]||a)}<br><small class="help">${esc(data.effects[a]||'')}</small></span></label>`).join('');
 const modes=data.modes.map(m=>{const off=m==='enforce'&&!data.enforcement_available;return `<option value="${esc(m)}" ${m===p.mode?'selected':''} ${off?'disabled':''}>${esc(MALWARE_MODE_LABELS[m]||m)}</option>`;}).join('');
 return `<form id="malware-policy-form" class="card"><h2>Fleet malware automatic response</h2>
<div class="notice" id="malware-enforcement-notice"><strong>Not enforced.</strong> No containment executor exists yet, so this policy is recorded and audited but never quarantines a file or terminates a process. Enforce stays unavailable until an executor is delivered and reviewed.</div>
${data.stored_invalid?`<div class="notice" id="malware-invalid-notice" role="alert"><strong>The stored policy is invalid and is treated as Disabled.</strong> ${esc(data.stored_invalid_reason||'')}. Saving replaces it.</div>`:''}
<p class="help">A detection qualifies only under the contract's checks: authenticated, fresh signatures bound to the artifact hash, or a bound AI malicious verdict with independent corroborating evidence. AI output alone never authorizes an action. Unknown-malware responses also need AI to be available and unpaused for that server; signature matches do not.</p>
<fieldset><label>Mode<select name="mode">${modes}</select></label>
<p class="help" id="malware-enforce-help">Enforce is shown for clarity but disabled: saving it is refused while no executor exists.</p>
<fieldset class="malware-actions"><legend>Known malware (signature or indicator match)</legend>${actions('known_actions',p.known_actions)}</fieldset>
<fieldset class="malware-actions"><legend>Unknown malware (evidence-supported AI discovery)</legend><label class="check"><input type="checkbox" name="allow_unknown" ${p.allow_unknown?'checked':''}> Allow responses to evidence-supported unknown malware</label>${actions('unknown_actions',p.unknown_actions)}</fieldset>
<div class="form-grid"><label>Minimum AI confidence<input name="min_ai_confidence" type="number" min="${l.min_ai_confidence}" max="1" step="0.01" value="${esc(p.min_ai_confidence)}" required></label>
<label>Corroborating evidence kinds<input name="min_corroborating_kinds" type="number" min="${l.min_corroborating_kinds}" max="${l.max_corroborating_kinds}" step="1" value="${esc(p.min_corroborating_kinds)}" required></label>
<label>Maximum signature age · seconds<input name="max_signature_age_seconds" type="number" min="1" max="${l.max_signature_age_seconds}" step="1" value="${esc(p.max_signature_age_seconds)}" required></label></div>
<label>Excluded paths · one absolute path per line<textarea name="excluded_paths" rows="3" spellcheck="false" autocomplete="off">${esc(p.excluded_paths.join('\n'))}</textarea></label>
<label>Excluded SHA-256 hashes · one per line<textarea name="excluded_sha256" rows="3" spellcheck="false" autocomplete="off">${esc(p.excluded_sha256.join('\n'))}</textarea></label>
<p class="help">Path exclusions also match a process's verified executable path. At most ${esc(l.max_exclusions)} of each.</p>
<button type="submit" class="primary">Save malware response policy</button></fieldset><p class="help" role="status" id="malware-policy-result"></p></form>`;
}
const MALWARE_CAP_LABELS={inherit:'Follows the fleet policy',monitor_only:'At most Monitor only',disabled:'Disabled'};
const malwarePlural=(n,one,many)=>`${n} ${n===1?one:many}`;
function malwareOverrideRows(data){
 if(!data.servers.length)return `<p class="help" id="malware-overrides-empty">No server restricts the fleet policy. Every server follows it${data.inheriting_rows?` (${esc(malwarePlural(data.inheriting_rows,'saved override','saved overrides'))} set back to follow the fleet policy)`:''}.</p>`;
 const row=r=>{
  const name=r.server_exists?`<a href="${serverLink(r.server_id,'security')}">${esc(r.server_name||r.server_id)}</a>`:`<span>${esc(r.server_id)}</span><small>Server no longer exists · override retained</small>`;
  const state=r.stored_invalid?`<strong>Invalid, treated as Disabled</strong><small>${esc(r.stored_invalid_reason||'')}</small>`:r.effective_invalid_reason?`<strong>Treated as Disabled</strong><small>${esc(r.effective_invalid_reason)}</small>`:'';
  return `<tr><td data-label="Server">${name}</td><td data-label="Mode cap">${esc(MALWARE_CAP_LABELS[r.mode_cap]||r.mode_cap)}</td><td data-label="Effective mode">${state||esc(MALWARE_MODE_LABELS[r.effective_mode]||r.effective_mode)}</td><td data-label="Extra exclusions">${esc(malwarePlural(r.excluded_paths,'path','paths'))}<small>${esc(malwarePlural(r.excluded_sha256,'hash','hashes'))}</small></td></tr>`;
 };
 return `<div class="table-wrap"><table class="malware-override-table" id="malware-overrides-table"><thead><tr><th>Server</th><th>Mode cap</th><th>Effective mode</th><th>Extra exclusions</th></tr></thead><tbody>${data.servers.map(row).join('')}</tbody></table></div>`
  +(data.inheriting_rows?`<p class="help">${esc(malwarePlural(data.inheriting_rows,'other saved override','other saved overrides'))} follow${data.inheriting_rows===1?'s':''} the fleet policy and restrict${data.inheriting_rows===1?'s':''} nothing.</p>`:'')
  +(data.truncated?`<p class="notice" role="status">Only the first ${esc(data.scan_limit)} stored overrides were read. More exist and are not listed here.</p>`:'');
}
async function malwareOverrideList(revision){
 const body=$('#malware-overrides-body'),alive=()=>currentView(revision,'settings')&&body?.isConnected;
 if(!body)return;
 try{
  const data=await api('/settings/malware-response/overrides');if(!alive())return;
  body.innerHTML=`<p class="help">Server overrides can only lower the mode or add exclusions; they never add actions or relax thresholds. Exclusion paths and hashes are shown on each server's Security tab. Nothing here is enforced.</p>`+malwareOverrideRows(data);
 }catch(error){if(alive())body.innerHTML=PatchyUI.error('Could not load server overrides',esc(error.message));}
}
async function malwarePolicySettings(revision){
 const container=$('#malware-policy'),alive=()=>currentView(revision,'settings')&&container.isConnected;
 try{
  let data=await api('/settings/malware-response');if(!alive())return;
  container.outerHTML=malwarePolicyForm(data)+'<section class="card" id="malware-overrides" aria-labelledby="malware-overrides-title"><h2 id="malware-overrides-title">Servers with overrides</h2><div id="malware-overrides-body"><p class="help">Loading server overrides…</p></div></section>';
  const form=$('#malware-policy-form'),result=$('#malware-policy-result'),ok=()=>currentView(revision,'settings')&&result.isConnected;
  malwareOverrideList(revision);
  const lines=v=>String(v||'').split('\n').map(x=>x.trim()).filter(Boolean);
  form.onsubmit=async event=>{
   event.preventDefault();const f=new FormData(form),fieldset=form.querySelector('fieldset');
   const policy={mode:f.get('mode'),known_actions:f.getAll('known_actions'),unknown_actions:f.getAll('unknown_actions'),allow_unknown:f.has('allow_unknown'),
    min_ai_confidence:+f.get('min_ai_confidence'),min_corroborating_kinds:+f.get('min_corroborating_kinds'),max_signature_age_seconds:+f.get('max_signature_age_seconds'),
    excluded_paths:lines(f.get('excluded_paths')),excluded_sha256:lines(f.get('excluded_sha256')).map(h=>h.toLowerCase())};
   fieldset.disabled=true;result.textContent='Saving…';
   try{data=await api('/settings/malware-response','PUT',{policy,expected_revision:data.revision});if(ok()){result.textContent='Malware response policy saved. It is recorded only and not enforced.';$('#malware-invalid-notice')?.remove();malwareOverrideList(revision);}}
   catch(error){if(ok())result.textContent='Malware response policy was not saved. '+error.message+(error.status===409&&/refresh/i.test(error.message)?' Your entries are still in the form; reload Settings to see the current saved policy.':'');}
   finally{if(fieldset.isConnected)fieldset.disabled=false;}
  };
 }catch(error){if(alive())container.innerHTML=PatchyUI.error('Could not load the malware response policy',esc(error.message));}
}
