const assert=require('assert/strict');
// Evaluated strongSwan updown commands render as escaped rows with accounts, discarded connections and gaps; other parsed files, older agents and unparsed files are explained.
module.exports=async(page,capture)=>{
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const cmd=(connection,child,command,extra)=>({connection,child,command,argv:['/bin/sh','-c','2>&1 '+command],program:null,shell_metacharacters:[],uid:0,file:'/etc/swanctl/conf.d/site.conf',line:3,connection_discarded:false,runs:true,...extra});
 const commands=[cmd('site','net','/usr/local/bin/up.sh --password [REDACTED] ; logger $PLUTO_VERB',{shell_metacharacters:['$',';']}),
  cmd('<img src=x onerror=window.__swInjected=true>','a','multi\nline',{connection_discarded:true,runs:false,line:7}),cmd('other','b','',{runs:false,line:9})];
 const view={commands,root_commands:[0],files:['/etc/swanctl/swanctl.conf','/etc/swanctl/conf.d/site.conf'],config_path:'/etc/swanctl/swanctl.conf',config_complete:false,complete:false,
  gaps:[{code:'charon_uid_assumed',blocking:false,detail:'charon is assumed to run as root, as the packaged strongswan service does; its account is not observed.'},{code:'file_not_observed',blocking:true,file:'/etc/swanctl/conf.d/old.conf'}],
  notes:[],origin:'not_assessed',authorizes_response:false,contract_version:1};
 const row=(path,extra)=>({path,mechanism:'strongswan',mechanism_label:'strongSwan swanctl configuration',kind:'regular',uid:0,gid:0,mode:420,sha256:'e'.repeat(64),change:'not_compared',jobs_state:'not_crontab',...extra});
 const body={inspection_id:'sw-receipt',created:Date.now()/1000,state:'collected',baseline_state:'not_compared',digest:'sw-digest',total:4,more:false,cron:{files:0,jobs:0,unparsed:0,truncated:false,not_reported:0},scope:['/etc/swanctl'],
  catalog:[{id:'strongswan',label:'strongSwan swanctl configuration · 2 parsed files · not reported by this agent version',observed_files:4}],missing_roots:[],skipped:0,gaps:['strongSwan gap'],note:'Bounded stored metadata.',
  items:[row('/etc/swanctl/conf.d/old.conf',{strongswan_state:'not_reported'}),row('/etc/swanctl/conf.d/site.conf',{strongswan_state:'parsed',strongswan_statements:12}),
   row('/etc/swanctl/swanctl.conf',{strongswan_state:'parsed',strongswan_statements:4,strongswan:view}),row('/etc/swanctl/conf.d/zz.conf',{strongswan_state:'unparsed'})]};
 const handler=route=>route.fulfill({json:body});
 await page.route('**/api/hosts/*/security/startup-inventory?*',handler);
 try{
  await page.goto(new URL('/#servers/'+host+'/startup/files',page.url()).href);await page.locator('#startup-file-items').waitFor();
  await page.getByRole('heading',{name:'strongSwan updown commands (3 configured · 1 run as root)',exact:true}).waitFor();
  const text=await page.locator('.startup-strongswan-commands').innerText();
  assert.match(text,/\/usr\/local\/bin\/up\.sh --password \[REDACTED\] ; logger \$PLUTO_VERB/);assert.match(text,/Shell syntax: \$ ;/);assert.match(text,/Yes, as root/);
  assert.match(text,/<img src=x onerror=window\.__swInjected=true> · a/);assert.match(text,/No: swanctl discards this connection \(multi-line updown\)/);assert.match(text,/No: empty command/);
  assert.match(text,/\/etc\/swanctl\/conf\.d\/site\.conf:3/);
  await page.getByText('Evaluated from 2 files starting at /etc/swanctl/swanctl.conf.',{exact:false}).waitFor();
  await page.getByText('This list is incomplete (1 blocking gap) and is not a safety verdict.',{exact:false}).waitFor();
  await page.locator('.startup-strongswan-gaps summary').click();
  const gaps=await page.locator('.startup-strongswan-gaps').innerText();
  assert.match(gaps,/charon account assumed/);assert.match(gaps,/Blocking: Included file not observed \/etc\/swanctl\/conf\.d\/old\.conf/);
  await page.getByText('strongSwan statements: 12 parsed.',{exact:false}).waitFor();
  await page.getByText('strongSwan statements: not reported by this agent version.',{exact:false}).waitFor();
  await page.getByText('strongSwan statements: the file was over 1 MiB, was not UTF-8 or contained NUL bytes',{exact:false}).waitFor();
  assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.evaluate(()=>window.__swInjected),undefined);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('startup-strongswan-'+width);}
  await page.setViewportSize({width:1440,height:1000});
  await page.getByRole('link',{name:'Coverage',exact:true}).click();await page.getByText('strongSwan swanctl configuration · 2 parsed files · not reported by this agent version',{exact:true}).waitFor();
 }finally{await page.unroute('**/api/hosts/*/security/startup-inventory?*',handler);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
