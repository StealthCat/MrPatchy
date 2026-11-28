const assert=require('assert/strict');
// Evaluated PostgreSQL commands and libraries render as escaped rows with timing, activity, sources and gaps; start blockers, other parsed files, older agents and unparsed files are explained.
module.exports=async(page,capture)=>{
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const conf='/etc/postgresql/16/main/postgresql.conf';
 const cmd=(setting,command,extra)=>({setting,command,file:conf,line:12,when:'each_completed_wal_segment',conditions:['archive_mode_on','not_while_standby'],active:true,inactive_reason:null,placeholder_error:null,invocation:['/bin/sh','-c',command],...extra});
 const view=extra=>({config_file:conf,data_directory:'/var/lib/postgresql/16/main',auto_conf:'/var/lib/postgresql/16/main/postgresql.auto.conf',server_starts:true,start_blocker:null,errors:[],files:[conf,'/etc/postgresql/16/main/conf.d/10-local.conf'],
  commands:[cmd('archive_command','test ! -f /mnt/arch/%f && cp %p /mnt/arch/%f'),cmd('restore_command','<img src=x onerror=window.__pgInjected=true> %f %p',{when:'archive_recovery_or_standby',conditions:['recovery_or_standby_signal_file_present'],line:14}),
   cmd('ssl_passphrase_command','/usr/local/bin/pass --token=[REDACTED] %p',{when:'server_start_when_ssl_key_has_passphrase',conditions:['ssl_key_file_has_passphrase','start_only'],active:false,inactive_reason:'ssl_off',line:8})],
  libraries:[{setting:'shared_preload_libraries',library:'pg_stat_statements',raw_value:null,file:'/etc/postgresql/16/main/conf.d/10-local.conf',line:1,when:'postmaster_start',active:true,inactive_reason:null},
   {setting:'local_preload_libraries',library:null,raw_value:'unterminated "list',file:conf,line:20,when:'each_session_start',active:false,inactive_reason:'invalid_list_syntax_nothing_loaded'}],
  dynamic_library_path:'$libdir',redacted:true,run_as:'postgres server account',complete:false,
  gaps:[{code:'auto_conf_not_observed',blocking:true,path:'/var/lib/postgresql/16/main/postgresql.auto.conf'}],not_modelled:[],origin:'not_assessed',authorizes_response:false,contract_version:1,...extra});
 const row=(path,extra)=>({path,mechanism:'postgresql',mechanism_label:'PostgreSQL cluster configuration',kind:'regular',uid:0,gid:0,mode:420,sha256:'e'.repeat(64),change:'not_compared',jobs_state:'not_crontab',...extra});
 const respond=items=>({inspection_id:'pg-receipt',created:Date.now()/1000,state:'collected',baseline_state:'not_compared',digest:'pg-digest',items,total:items.length,more:false,cron:{files:0,jobs:0,unparsed:0,truncated:false,not_reported:0},scope:['/etc/postgresql'],
  catalog:[{id:'postgresql',label:'PostgreSQL cluster configuration · 2 parsed files · not reported by this agent version',observed_files:4}],missing_roots:[],skipped:0,gaps:['PostgreSQL gap'],note:'Bounded stored metadata.'});
 let body=respond([row('/etc/postgresql/16/main/conf.d/10-local.conf',{postgresql_state:'parsed',postgresql_statements:3}),row('/etc/postgresql/16/main/environment',{postgresql_state:'not_reported'}),
  row(conf,{postgresql_state:'parsed',postgresql_statements:9,postgresql:view()}),row('/etc/postgresql/16/main/pg_ident.conf',{postgresql_state:'unparsed'})]);
 const handler=route=>route.fulfill({json:body});
 await page.route('**/api/hosts/*/security/startup-inventory?*',handler);
 try{
  await page.goto(new URL('/#servers/'+host+'/startup/files',page.url()).href);await page.locator('#startup-file-items').waitFor();
  await page.getByRole('heading',{name:'PostgreSQL commands and libraries (3 commands · 2 libraries)',exact:true}).waitFor();
  const text=await page.locator('.startup-postgresql-commands').innerText();
  assert.match(text,/test ! -f \/mnt\/arch\/%f && cp %p \/mnt\/arch\/%f/);assert.match(text,/Each completed WAL segment\s+archive_mode_on · not_while_standby/);
  assert.match(text,/<img src=x onerror=window\.__pgInjected=true> %f %p/);assert.match(text,/Archive recovery or standby/);
  assert.match(text,/--token=\[REDACTED\]/);assert.match(text,/No: ssl is off/);assert.match(text,/\/etc\/postgresql\/16\/main\/postgresql\.conf:12/);
  const libs=await page.locator('.startup-postgresql-libraries').innerText();
  assert.match(libs,/pg_stat_statements\s+Server start\s+Yes/);assert.match(libs,/unterminated "list\s+Each new session\s+No: Invalid list: nothing loaded/);
  await page.getByText('Libraries named without a path are looked up in',{exact:false}).waitFor();
  await page.getByText('Evaluated from 2 files starting at',{exact:false}).waitFor();
  await page.getByText('This list is incomplete (1 blocking gap) and is not a safety verdict.',{exact:false}).waitFor();
  await page.locator('.startup-postgresql-gaps summary').click();
  assert.match(await page.locator('.startup-postgresql-gaps').innerText(),/Blocking: postgresql\.auto\.conf \(ALTER SYSTEM\) not collected \/var\/lib\/postgresql\/16\/main\/postgresql\.auto\.conf/);
  await page.getByText('PostgreSQL statements: 3 kept.',{exact:false}).waitFor();
  await page.getByText('PostgreSQL statements: not reported by this agent version.',{exact:false}).waitFor();
  await page.getByText('PostgreSQL statements: the file was not UTF-8 or contained NUL bytes',{exact:false}).waitFor();
  assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.evaluate(()=>window.__pgInjected),undefined);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('startup-postgresql-'+width);}
  body=respond([row(conf,{postgresql_state:'parsed',postgresql_statements:2,postgresql:view({server_starts:false,start_blocker:'configuration_file_contains_errors',commands:[cmd('archive_command','cp %p /a/%f',{active:false,inactive_reason:'configuration_file_contains_errors'})],libraries:[],
   errors:[{reason:'syntax_error',file:conf,line:22},{reason:'could_not_open_file',file:conf,line:23,path:'/etc/postgresql/16/main/local.conf',state:'absent'}]})})]);
  await page.setViewportSize({width:1440,height:1000});await page.reload();await page.locator('#startup-file-items').waitFor();
  await page.getByRole('heading',{name:'PostgreSQL commands and libraries (1 command · 0 libraries)',exact:true}).waitFor();
  await page.getByText('The server would not start: the configuration contains errors',{exact:false}).waitFor();
  assert.match(await page.locator('.startup-postgresql-commands').innerText(),/No: the configuration contains errors, so the server does not start/);
  await page.locator('.startup-postgresql-errors summary').click();
  const errors=await page.locator('.startup-postgresql-errors').innerText();
  assert.match(errors,/PostgreSQL rejects this line \/etc\/postgresql\/16\/main\/postgresql\.conf:22/);assert.match(errors,/Included file cannot be opened \/etc\/postgresql\/16\/main\/postgresql\.conf:23 · \/etc\/postgresql\/16\/main\/local\.conf/);
  await capture('startup-postgresql-refused');
  await page.getByRole('link',{name:'Coverage',exact:true}).click();await page.getByText('PostgreSQL cluster configuration · 2 parsed files · not reported by this agent version',{exact:true}).waitFor();
 }finally{await page.unroute('**/api/hosts/*/security/startup-inventory?*',handler);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
