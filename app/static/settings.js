/* Separate settings routes. Persistence never depends on a provider test. */
const SETTINGS_SECTIONS={
 ai:['AI & models','Save your API key, choose a model, and test it.'],
 patching:['Patch policy','Repository checks and priority deadlines.'],
 database:['Database','MySQL connection details and offline migrations.'],
 https:['HTTPS & certificates','Internal and external TLS profiles.'],
 history:['History retention','Observation and inventory retention.']
};
function settingsNav(section){
 return `<div class="settings-nav" role="navigation" aria-label="Settings sections">${[['','All settings'],...Object.entries(SETTINGS_SECTIONS).map(([key,value])=>[key,value[0]])].map(([key,label])=>`<a href="#settings${key?'/'+key:''}" ${key===section?'aria-current="page" class="active"':''}>${esc(label)}</a>`).join('')}</div>`;
}
async function settings(revision=renderRevision){
 const data=await api('/settings');
 if(!currentView(revision,'settings'))return;
 cfg=data;
 let section=location.hash.split('/')[1]||'';
 if(!SETTINGS_SECTIONS[section])section='';
 const title=section?SETTINGS_SECTIONS[section][0]:'Set your own rhythm.';
 $('#content').innerHTML=heading(title,section?SETTINGS_SECTIONS[section][1]:'Choose a settings section. Each has its own controls and save action.')+settingsNav(section)+'<section id="settings-section" class="settings-section"></section>';
 const container=$('#settings-section');
 if(!section){
  container.classList.add('settings-hub');
  container.innerHTML=Object.entries(SETTINGS_SECTIONS).map(([key,[name,detail]])=>`<a class="card settings-link" href="#settings/${key}"><h2>${esc(name)} <span aria-hidden="true">↗</span></h2><p class="help">${esc(detail)}</p></a>`).join('');return;
 }
 if(section==='ai'){renderAISettings(data,revision,container);return;}
 if(section==='database'){container.innerHTML='<div class="card" id="database-settings"><p class="help">Loading database settings…</p></div>';await databaseSettings(revision);return;}
 if(section==='https'){
  container.innerHTML=`<div class="card"><h2>HTTPS profiles</h2><p>Configure independent internal and external profiles with uploaded certificates, ACME, or the built-in local CA.</p><p>${Object.entries(data.tls.profiles||{}).filter(([,p])=>p.enabled).map(([name,p])=>esc(name+': '+p.domain+' · browser port '+p.effective_https_port)+' · '+badge(p.mode)).join('<br>')||'Initial HTTPS configured by deployment'}</p><button type="button" id="tls-button">Configure HTTPS →</button></div>`;
  $('#tls-button').onclick=tlsModal;return;
 }
 if(section==='patching')container.innerHTML=`<form id="patch-settings-form" class="card"><h2>Patch policy</h2><p class="help">Deadlines begin when a candidate is discovered. They flag overdue work; they do not authorize unattended installation or represent CVSS scores.</p><fieldset><div class="form-grid">${['critical','high','normal','low'].map(k=>`<label>${k[0].toUpperCase()+k.slice(1)} · hours<input name="${k}" type="number" min="1" max="8760" value="${data.deadlines[k]}" required></label>`).join('')}</div><label>Repository check interval · minutes<input name="repo_minutes" type="number" min="5" max="10080" value="${data.repo_minutes}" required></label><p class="help">Target process sampling: 30 seconds. Full managed-file and executable hash refresh: 5 minutes.</p><button type="submit" class="primary">Save patch policy</button></fieldset><p class="help" role="status" id="section-save-result"></p></form>`;
 if(section==='history')container.innerHTML=`<form id="history-settings-form" class="card"><h2>History retention</h2><fieldset><label>Days to retain observations and inventory revisions<input name="history_days" type="number" min="1" max="3650" value="${data.history_days}" required></label><p class="help">The worker uses this period for observation, inventory revision and completed AI log cleanup. Package change history is retained separately.</p><button type="submit" class="primary">Save history retention</button></fieldset><p class="help" role="status" id="section-save-result"></p></form>`;
 const form=container.querySelector('form'),result=$('#section-save-result');
 form.onsubmit=async event=>{
  event.preventDefault();const f=new FormData(form),fieldset=form.querySelector('fieldset');
  const body=section==='patching'?{repo_minutes:+f.get('repo_minutes'),deadlines:Object.fromEntries(['critical','high','normal','low'].map(k=>[k,+f.get(k)]))}:{history_days:+f.get('history_days')};
  fieldset.disabled=true;result.textContent='Saving…';
  try{await api('/settings/'+section,'PUT',body);if(currentView(revision,'settings')&&result.isConnected)result.textContent=section==='patching'?'Patch policy saved.':'History retention saved.';}
  catch(error){if(currentView(revision,'settings')&&result.isConnected)result.textContent=error.message;}
  finally{if(fieldset.isConnected)fieldset.disabled=false;}
 };
}
function modelPicker(data){
 return `<label>Model ID<select name="ai_model" id="ai-model"><option value="">Choose an available model</option>${data.ai_model?`<option value="${esc(data.ai_model)}" selected>${esc(data.ai_model)} · saved, not verified</option>`:''}<option value="__manual__">Enter a model ID manually…</option></select></label><label id="ai-manual-label" hidden>Exact model ID<input id="ai-model-manual" maxlength="100" autocomplete="off" placeholder="API model ID, not a ChatGPT display label"></label><button type="button" id="ai-model-refresh">Refresh available models</button><p id="ai-model-status" class="help" role="status">Load models using your saved API key, or enter an exact model ID manually. Discovery and test failures do not prevent saving.</p>`;
}
function renderAISettings(data,revision,container){
 const migration=data.ai_control_migration?.required;
 const budget=data.ai_budget||{},providerBackoff=data.ai_provider_backoff||{};
 container.innerHTML=`<form class="card" id="ai-key-form"><h2>1. API key</h2><p class="help">Save your key independently—even if the old model is invalid. Saving does not call OpenAI.</p><fieldset><label>OpenAI API key <span id="ai-key-state">${data.api_key_configured?'· saved':'· not configured'}</span><input name="api_key" type="password" autocomplete="new-password" placeholder="Enter a new key to replace the saved key" required maxlength="1000"></label><button class="primary" type="submit">Save API key</button></fieldset><p id="ai-key-result" class="help" role="status"></p></form><form class="card" id="ai-settings-form"><h2>2. Model &amp; investigations</h2><p id="ai-saved-model" class="settings-saved">Saved model: ${esc(data.ai_model||'None')}</p><fieldset>${modelPicker(data)}<div class="actions ai-save-actions"><button type="submit" class="primary">Save AI settings</button><button type="submit" id="ai-test">Save and test selected model</button></div><p id="ai-save-result" class="help" role="status"></p><p id="ai-test-result" class="help" role="status"></p><p class="help">Save and test first saves the selected model, then sends one small structured-output request. No server evidence is included. The result identifies the exact model tested. An accessible model may still lack Responses API or JSON-schema support.</p><label class="check"><input name="ai_enabled" type="checkbox" ${data.ai_enabled?'checked':''}>Enable central OpenAI API investigations</label><p class="help">Sends executable paths, SHA-256 hashes, UIDs, and network endpoint metadata. Investigations may request fixed read-only package, executable and service checks. Arguments, environment variables and arbitrary file contents are excluded. Each investigation uses up to two calls. Responses use store: false; your API organization’s data policies still apply.</p>${migration?`<div class="notice"><strong>Admission migration review required.</strong> Existing separate limits remain active until saved. Suggested shared rate: ${esc(data.ai_control_migration.suggested_rate_per_hour)} work starts/hour, no accumulated burst.</div>`:''}<label>Mr Patchy admission mode<select name="ai_control_mode"><option value="legacy" ${data.ai_control_mode==='legacy'?'selected':''}>Legacy separate hourly limits</option><option value="rate" ${data.ai_control_mode==='rate'?'selected':''}>Shared smooth rate throttle</option><option value="daily_cap" ${data.ai_control_mode==='daily_cap'?'selected':''}>Daily spend cap</option><option value="rate_and_daily" ${data.ai_control_mode==='rate_and_daily'?'selected':''}>Rate throttle + daily spend cap</option><option value="unthrottled" ${data.ai_control_mode==='unthrottled'?'selected':''}>Unthrottled by Mr Patchy</option></select></label><label>Shared AI work starts per hour<input name="ai_rate_per_hour" type="number" min="1" max="1000" value="${data.ai_rate_per_hour}" required></label><div class="form-grid"><label>Daily AI cap · USD<input name="ai_daily_cap_usd" type="number" min="0.01" max="1000000" step="0.01" value="${esc(data.ai_daily_cap_usd)}" required></label><label>Budget reset · IANA timezone<input name="ai_budget_timezone" maxlength="64" value="${esc(data.ai_budget_timezone)}" required placeholder="America/New_York"></label></div><div class="notice"><strong>Current budget window</strong><br>Counted $${esc(budget.counted_usd||'0')} · settled $${esc(budget.settled_usd||'0')} · reserved $${esc(budget.reserved_usd||'0')} · uncertain $${esc(budget.uncertain_usd||'0')} · remaining $${esc(budget.remaining_usd||data.ai_daily_cap_usd)}${budget.next_reset?' · resets '+date(budget.next_reset):''}${providerBackoff.blocked?`<br><strong>Provider backoff active</strong> · ${esc(providerBackoff.failures)} consecutive transient failure(s) · next eligible ${date(providerBackoff.next_at)}`:''}</div><p class="help">Capped modes reserve a conservative ceiling before every provider call and reconcile valid usage receipts. Unknown model/tier pricing is blocked, never treated as free. Sent calls without reliable usage retain the full reservation after timeout or restart. Provider Retry-After and transient backoff are shared across workers and purposes. Estimates use a versioned public price catalog and are not provider invoices. Unthrottled removes Mr Patchy rate/spend controls only; finite concurrency, provider limits, global/per-server pause, roles and data sharing still apply.</p><label>Legacy maximum investigations per hour<input name="ai_hourly_limit" type="number" min="1" max="1000" value="${data.ai_hourly_limit}" required></label><label class="check"><input name="ai_updates_enabled" type="checkbox" ${data.ai_updates_enabled?'checked':''}>Automatically score pending updates</label><p class="help">Sends package names, versions, OS release and priority classification. Scores are advisory estimates, not verified CVSS ratings, and never authorize installation.</p><label>Legacy maximum scoring batches per hour · up to 5 updates each<input name="ai_update_hourly_limit" type="number" min="1" max="1000" value="${data.ai_update_hourly_limit}" required></label></fieldset><a class="mint" href="#ai-logs">Inspect AI run logs →</a></form>`;
 const keyForm=$('#ai-key-form'),form=$('#ai-settings-form'),select=$('#ai-model'),manual=$('#ai-model-manual');
 const keyResult=$('#ai-key-result'),saveResult=$('#ai-save-result'),testResult=$('#ai-test-result'),status=$('#ai-model-status'),refresh=$('#ai-model-refresh');
 const alive=()=>currentView(revision,'settings')&&container.isConnected;
 let keyRevision=data.api_key_revision||'',listGeneration=0,busy=false;
 const chosen=()=>select.value==='__manual__'?manual.value.trim():select.value;
 const toggleManual=()=>{const enabled=select.value==='__manual__';$('#ai-manual-label').hidden=!enabled;manual.required=enabled;manual.disabled=!enabled;};
 const markChanged=()=>{saveResult.textContent='Unsaved changes.';testResult.textContent='';toggleManual();};
 form.addEventListener('input',markChanged);form.addEventListener('change',markChanged);toggleManual();
 const setBusy=value=>{busy=value;keyForm.querySelector('fieldset').disabled=value;form.querySelector('fieldset').disabled=value;};
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
   keyResult.textContent='API key saved. Your model selection is unchanged.';saved=true;
  }catch(error){if(alive())keyResult.textContent='API key was not saved. '+error.message;}
  finally{if(alive()){setBusy(false);if(saved)load();}}
 };
 form.onsubmit=async event=>{
  event.preventDefault();if(busy)return;
  if(keyForm.elements.api_key.value){saveResult.textContent='Save the new API key above first, or clear that field to keep using the saved key.';return;}
  const test=event.submitter?.id==='ai-test',f=new FormData(form),model=chosen();
  if(test&&!model){saveResult.textContent='Select or enter a model to test.';return;}
  const body={ai_model:model,ai_enabled:f.has('ai_enabled'),ai_hourly_limit:+f.get('ai_hourly_limit'),ai_updates_enabled:f.has('ai_updates_enabled'),ai_update_hourly_limit:+f.get('ai_update_hourly_limit'),ai_control_mode:f.get('ai_control_mode'),ai_rate_per_hour:+f.get('ai_rate_per_hour'),ai_daily_cap_usd:+f.get('ai_daily_cap_usd'),ai_budget_timezone:f.get('ai_budget_timezone').trim()};
  ++listGeneration;refresh.disabled=false;setBusy(true);saveResult.textContent='Saving AI settings…';testResult.textContent='';
  try{
   const response=await api('/settings/ai','PUT',body);if(!alive())return;
   keyRevision=response.api_key_revision;
   $('#ai-saved-model').textContent='Saved model: '+(response.ai_model||'None');
   saveResult.textContent='AI settings saved. Model: '+(response.ai_model||'None')+'.';
   if(test){
    testResult.textContent='Testing saved model '+response.ai_model+'…';
    try{
     const result=await api('/settings/ai-test','POST',{expected_model:response.ai_model,expected_key_revision:keyRevision});
     if(alive())testResult.textContent=result.detail;
    }catch(error){if(alive())testResult.textContent='Connection test failed. '+error.message+' The AI settings save succeeded.';}
   }
  }catch(error){if(alive())saveResult.textContent='AI settings were not saved. '+error.message;}
  finally{if(alive())setBusy(false);}
 };
 if(data.api_key_configured)load();
}
async function databaseSettings(revision){
 const container=$('#database-settings');
 try{
  const state=await api('/settings/database');
  if(!currentView(revision,'settings')||!container.isConnected)return;
  const active=state.active,target=state.target||{backend:active.backend==='sqlite'?'mysql':'sqlite',host:'',port:3306,database:'mrpatchy',username:'',tls:true,ca_file:'',sqlite_file:'mrpatchy-migrated.db'};
  container.innerHTML=`<h2>Database &amp; offline migration</h2><p><strong>Active: ${esc(active.backend==='sqlite'?'SQLite':'MySQL')}</strong> · ${esc(active.database)}${active.host?' on '+esc(active.host):''}</p><p class="help">Configuration source: ${esc(state.source)}. Destination settings are staged separately; saving does not switch databases.</p><form id="database-form"><label>Migration destination<select name="backend"><option value="mysql" ${target.backend==='mysql'?'selected':''}>MySQL</option><option value="sqlite" ${target.backend==='sqlite'?'selected':''}>SQLite</option></select></label><div id="database-mysql"><div class="form-grid"><label>MySQL host<input name="host" maxlength="253" value="${esc(target.host)}"></label><label>Port<input name="port" type="number" min="1" max="65535" value="${target.port}"></label><label>Database name<input name="database" value="${esc(target.database)}" pattern="[A-Za-z0-9_]{1,64}"></label><label>Username<input name="username" autocomplete="off" value="${esc(target.username)}"></label></div><label>Password ${target.password_configured?'· saved':''}<input name="password" type="password" autocomplete="new-password" placeholder="Blank keeps the staged password for an unchanged destination"></label><label class="check"><input type="checkbox" name="clear_password">Explicitly use no password</label><label class="check"><input type="checkbox" name="tls" ${target.tls?'checked':''}>Verify database TLS certificate and hostname</label><label>CA certificate file · optional<input name="ca_file" value="${esc(target.ca_file)}" placeholder="/data/mysql-ca.pem"></label><p class="help">Create an empty MySQL 8+ database first. The account needs schema creation and data permissions. A CA file must be mounted at this path in both app and worker containers; leave blank to use system trust.</p></div><div id="database-sqlite"><label>New SQLite filename in the app data volume<input name="sqlite_file" value="${esc(target.sqlite_file)}" pattern="[A-Za-z0-9][A-Za-z0-9_.-]{0,119}\\.db"></label><p class="help">Choose a new filename. Existing data is never overwritten.</p></div><button class="primary" type="submit">Save migration destination</button><p id="database-result" class="help" role="status"></p></form><details id="database-migration-steps"><summary>Run an offline migration</summary><p>Finish running jobs, back up the database and persistent volumes, and stop <strong>every app and worker replica</strong>, including any on other hosts. Keep the same app data volume and secret.key. The following commands run from your deployment directory:</p><pre>docker compose stop app worker
# Validate source and destination without copying or switching:
docker compose run --rm --no-deps app python -m app.database_migrate --confirm-offline --dry-run
# Only after a successful dry run, copy, verify and activate:
docker compose run --rm --no-deps app python -m app.database_migrate --confirm-offline --activate
# Only after migration succeeds, restart (retain your worker scale):
docker compose up -d app worker</pre><p class="help">The offline command copies all application tables and verifies row counts and content fingerprints before activation. The original database stays intact. Failed verification leaves the active database unchanged; inspect the destination before retrying. An activated profile overrides DATABASE_URL for both app and workers. Do not restart against the old copy after using the new database.</p></details>`;
  const form=$('#database-form'),result=$('#database-result');
  const toggle=()=>{for(const name of ['mysql','sqlite']){const section=$('#database-'+name),enabled=form.elements.backend.value===name;section.hidden=!enabled;for(const input of section.querySelectorAll('input'))input.disabled=!enabled;}};
  form.elements.backend.onchange=toggle;toggle();
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
    result.textContent='Destination saved. Active database unchanged. Follow the offline migration steps below.';
    $('#database-migration-steps').open=true;
   }catch(error){if(currentView(revision,'settings')&&result.isConnected)result.textContent=error.message;}
   finally{if(button.isConnected)button.disabled=false;}
  };
 }catch(error){if(currentView(revision,'settings')&&container.isConnected)container.textContent='Could not load database settings: '+error.message;}
}
