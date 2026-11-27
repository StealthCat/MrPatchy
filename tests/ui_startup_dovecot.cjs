const assert=require('assert/strict');
// Evaluated Dovecot service programs render as escaped rows with accounts and gaps; refused evaluations, other parsed files, older agents and unparsed files are explained.
module.exports=async(page,capture)=>{
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const svc=(service,extra)=>({service,builtin:false,argv:['/usr/local/bin/run-me','--token=[REDACTED]'],program:'/usr/local/bin/run-me',wrapper:null,exec_account:'root',exec_account_basis:'not_dropped_before_exec',program_account:null,expected_drop_account:null,service_user:'nobody',drop_priv_before_exec:false,protocol:null,enabled:true,starts:'master_start',source:'/etc/dovecot/conf.d/10-master.conf',line:7,...extra});
 const view=(services,extra)=>({services,root_exec:services.map((s,i)=>i).filter(i=>services[i].exec_account==='root'),protocols:['imap','pop3'],files:['/etc/dovecot/dovecot.conf','/etc/dovecot/conf.d/10-master.conf'],config_accepted:null,complete:false,
  gaps:[{code:'passwd_group_not_captured',blocking:true,detail:'/etc/passwd and /etc/group are not captured, so service accounts are shown by name without UID or GID.'},{code:'service_user_not_applied',blocking:false,service:'custom',user:'nobody'}],origin:'not_assessed',authorizes_response:false,contract_version:1,...extra});
 const services=[svc('custom'),svc('<img src=x onerror=window.__dcInjected=true>',{builtin:true,argv:['script','/usr/local/bin/post'],wrapper:'script',exec_account:'nobody',drop_priv_before_exec:true,starts:'on_demand',line:12}),
  svc('imap',{builtin:true,argv:['imap','/usr/local/bin/postlogin'],exec_account:'root',expected_drop_account:'nobody',protocol:'submission',enabled:false,starts:'on_demand',line:18})];
 const row=(path,extra)=>({path,mechanism:'dovecot',mechanism_label:'Dovecot configuration',kind:'regular',uid:0,gid:0,mode:420,sha256:'d'.repeat(64),change:'not_compared',jobs_state:'not_crontab',...extra});
 const respond=(items)=>({inspection_id:'dc-receipt',created:Date.now()/1000,state:'collected',baseline_state:'not_compared',digest:'dc-digest',items,total:items.length,more:false,cron:{files:0,jobs:0,unparsed:0,truncated:false,not_reported:0},scope:['/etc/dovecot'],
  catalog:[{id:'dovecot',label:'Dovecot configuration · 2 parsed files · not reported by this agent version',observed_files:4}],missing_roots:[],skipped:0,gaps:['Dovecot gap'],note:'Bounded stored metadata.'});
 let body=respond([row('/etc/dovecot/conf.d/10-master.conf',{dovecot_state:'parsed',dovecot_statements:42}),row('/etc/dovecot/conf.d/20-old.conf',{dovecot_state:'not_reported'}),
  row('/etc/dovecot/dovecot.conf',{dovecot_state:'parsed',dovecot_statements:9,dovecot:view(services)}),row('/etc/dovecot/private/big.pem',{dovecot_state:'unparsed'})]);
 const handler=route=>route.fulfill({json:body});
 await page.route('**/api/hosts/*/security/startup-inventory?*',handler);
 try{
  await page.goto(new URL('/#servers/'+host+'/startup/files',page.url()).href);await page.locator('#startup-file-items').waitFor();
  await page.getByRole('heading',{name:"Dovecot service programs (3 non-default · 2 exec'd as root)",exact:true}).waitFor();
  const text=await page.locator('.startup-dovecot-services').innerText();
  assert.match(text,/\/usr\/local\/bin\/run-me --token=\[REDACTED\]/);assert.match(text,/At master start/);assert.match(text,/Not a built-in service/);
  assert.match(text,/<img src=x onerror=window\.__dcInjected=true>/);assert.match(text,/nobody \(dropped before exec\)/);assert.match(text,/script wrapper/);
  assert.match(text,/root, expected to drop to nobody \(not verified\)/);assert.match(text,/On first connection\s+Protocol submission not enabled/);assert.match(text,/\/etc\/dovecot\/conf\.d\/10-master\.conf:7/);
  await page.getByText('Evaluated from 2 files; protocols: imap pop3. This list is incomplete (1 blocking gap) and is not a safety verdict.',{exact:false}).waitFor();
  await page.locator('.startup-dovecot-gaps summary').click();
  const gaps=await page.locator('.startup-dovecot-gaps').innerText();
  assert.match(gaps,/Blocking: Accounts not captured/);assert.match(gaps,/Service user not applied before exec service custom/);
  await page.getByText('Dovecot statements: 42 parsed.',{exact:false}).waitFor();
  await page.getByText('Dovecot statements: not reported by this agent version.',{exact:false}).waitFor();
  await page.getByText('Dovecot statements: the file was over 1 MiB or contained NUL bytes',{exact:false}).waitFor();
  assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.evaluate(()=>window.__dcInjected),undefined);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('startup-dovecot-'+width);}
  body=respond([row('/etc/dovecot/dovecot.conf',{dovecot_state:'parsed',dovecot_statements:2,dovecot:view([],{config_accepted:false,files:['/etc/dovecot/dovecot.conf'],gaps:[{code:'unobserved_glob',blocking:true,glob:'/usr/share/dovecot/protocols.d/*.protocol',source:'/etc/dovecot/dovecot.conf',line:24}]})})]);
  await page.setViewportSize({width:1440,height:1000});await page.reload();await page.locator('#startup-file-items').waitFor();
  await page.getByRole('heading',{name:"Dovecot service programs (0 non-default · 0 exec'd as root)",exact:true}).waitFor();
  await page.getByText('The configuration could not be followed to the end',{exact:false}).waitFor();
  assert.equal(await page.locator('.startup-dovecot-services').count(),0);assert.equal(await page.getByText('No service executable differs from the package default.').count(),0);
  await page.locator('.startup-dovecot-gaps summary').click();
  assert.match(await page.locator('.startup-dovecot-gaps').innerText(),/Blocking: Include pattern not observed \/usr\/share\/dovecot\/protocols\.d\/\*\.protocol · \/etc\/dovecot\/dovecot\.conf:24/);
  await capture('startup-dovecot-refused');
  await page.getByRole('link',{name:'Coverage',exact:true}).click();await page.getByText('Dovecot configuration · 2 parsed files · not reported by this agent version',{exact:true}).waitFor();
 }finally{await page.unroute('**/api/hosts/*/security/startup-inventory?*',handler);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
