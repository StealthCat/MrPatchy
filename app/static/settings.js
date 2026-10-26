/* Settings extensions: discover model access and stage an offline database move. */
function modelPicker(cfg){
 return `<label>Model ID<select name="ai_model" id="ai-model"><option value="">Select a model after loading the list</option>${cfg.ai_model?`<option value="${esc(cfg.ai_model)}" selected>${esc(cfg.ai_model)} · saved, not checked</option>`:''}</select></label><button type="button" id="ai-model-refresh">Refresh available models</button><p id="ai-model-status" class="help" role="status">Uses your saved API key. Save a new key first, then refresh. Model access does not guarantee Responses API or structured-output support; save your selection and run the connection test.</p>`;
}
function bindModelPicker(revision){
 const button=$('#ai-model-refresh'),select=$('#ai-model'),status=$('#ai-model-status');
 let generation=0;
 const load=async()=>{
  const ticket=++generation;button.disabled=true;status.textContent='Loading models available to your saved API key…';
  try{
   const response=await api('/settings/ai-models');
   if(!currentView(revision,'settings')||!select.isConnected||ticket!==generation)return;
   const selected=select.value;
   select.replaceChildren(new Option('Select an available model',''));
   if(selected&&!response.models.includes(selected))select.add(new Option(selected+' · unavailable to saved key',selected));
   for(const id of response.models)select.add(new Option(id,id));
   select.value=selected;
   status.textContent=(selected&&!response.models.includes(selected)?'The saved/selected model is unavailable to this API key. Choose another model. ':!response.models.length?'No models were returned for this key. Check project permissions. ':response.models.length+' accessible models loaded. ')+'Save your selection and test Responses API / structured-output compatibility.';
  }catch(error){if(currentView(revision,'settings')&&status.isConnected&&ticket===generation)status.textContent=error.message+' Your selection was preserved.';}
  finally{if(button.isConnected&&ticket===generation)button.disabled=false;}
 };
 button.onclick=load;
 // Return a refresh hook for a successfully saved new API key.
 return load;
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
