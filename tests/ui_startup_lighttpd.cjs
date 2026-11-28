const assert=require('assert/strict');
// Evaluated lighttpd commands render as escaped rows with timing, accounts, conditions and gaps; other parsed files, older agents and unparsed files are explained.
module.exports=async(page,capture)=>{
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const cmd=(kind,command,extra)=>({kind,key:null,extension:null,command,argv:['/bin/sh','-c',command],account:'www-data',uid:null,gid:null,runs:'daemon_start',source:'/etc/lighttpd/lighttpd.conf',line:3,condition:null,starts:true,privileged_at_service_start:true,max_procs:null,...extra});
 const commands=[cmd('include_shell','/usr/share/lighttpd/use-ipv6.pl 80',{account:'invoking_user',runs:'config_parse',line:2}),
  cmd('piped_logger','/usr/bin/logger --password [REDACTED] ; echo $HOME',{key:'accesslog.filename',condition:'$HTTP["host"] == "<img src=x onerror=window.__ltInjected=true>"',line:9}),
  cmd('fastcgi','/usr/bin/php-cgi',{key:'fastcgi.server',extension:'.php',argv:['/usr/bin/php-cgi'],source:'/etc/lighttpd/conf-enabled/15-fastcgi-php.conf',uid:33,privileged_at_service_start:false,line:4})];
 const view={commands,root_commands:[0,1],files:[{path:'/etc/lighttpd/lighttpd.conf'},{path:'/etc/lighttpd/conf-enabled/15-fastcgi-php.conf'}],config_path:'/etc/lighttpd/lighttpd.conf',config_accepted:true,server_user:'www-data',server_uid:null,config_complete:false,complete:false,
  gaps:[{code:'environment_assumed',blocking:false,detail:'lighttpd is assumed to start as root from its packaged service, with SHELL unset (so /bin/sh) in /; its environment is not observed.'},{code:'include_shell_output_not_captured',blocking:true,source:'/etc/lighttpd/lighttpd.conf',line:2,command:'/usr/share/lighttpd/use-ipv6.pl 80'},{code:'passwd_not_captured',blocking:true}],
  notes:[],origin:'not_assessed',authorizes_response:false,contract_version:1};
 const row=(path,extra)=>({path,mechanism:'lighttpd',mechanism_label:'lighttpd configuration',kind:'regular',uid:0,gid:0,mode:420,sha256:'f'.repeat(64),change:'not_compared',jobs_state:'not_crontab',...extra});
 const body={inspection_id:'lt-receipt',created:Date.now()/1000,state:'collected',baseline_state:'not_compared',digest:'lt-digest',total:4,more:false,cron:{files:0,jobs:0,unparsed:0,truncated:false,not_reported:0},scope:['/etc/lighttpd'],
  catalog:[{id:'lighttpd',label:'lighttpd configuration · 2 parsed files · not reported by this agent version',observed_files:4}],missing_roots:[],skipped:0,gaps:['lighttpd gap'],note:'Bounded stored metadata.',
  items:[row('/etc/lighttpd/conf-available/10-ssl.conf',{lighttpd_state:'not_reported'}),row('/etc/lighttpd/conf-available/15-fastcgi-php.conf',{lighttpd_state:'parsed',lighttpd_tokens:41}),
   row('/etc/lighttpd/lighttpd.conf',{lighttpd_state:'parsed',lighttpd_tokens:120,lighttpd:view}),row('/etc/lighttpd/conf-available/zz.conf',{lighttpd_state:'unparsed'})]};
 const handler=route=>route.fulfill({json:body});
 await page.route('**/api/hosts/*/security/startup-inventory?*',handler);
 try{
  await page.goto(new URL('/#servers/'+host+'/startup/files',page.url()).href);await page.locator('#startup-file-items').waitFor();
  await page.getByRole('heading',{name:'lighttpd commands (3 found · 2 may run as root)',exact:true}).waitFor();
  const text=await page.locator('.startup-lighttpd-commands').innerText();
  assert.match(text,/While parsing the configuration, before the privilege drop/);assert.match(text,/Invoking account \(root at service start\)/);
  assert.match(text,/\/usr\/bin\/logger --password \[REDACTED\] ; echo \$HOME/);assert.match(text,/argv: \/bin\/sh · -c · /);
  assert.match(text,/At daemon start \(conditional block\)/);assert.match(text,/<img src=x onerror=window\.__ltInjected=true>/);assert.match(text,/www-data \(UID not observed\)/);
  assert.match(text,/FastCGI backend/);assert.match(text,/fastcgi\.server · \.php/);assert.match(text,/www-data \(UID 33\)/);
  assert.match(text,/\/etc\/lighttpd\/conf-enabled\/15-fastcgi-php\.conf:4/);
  await page.getByText('Evaluated from 2 files starting at /etc/lighttpd/lighttpd.conf.',{exact:false}).waitFor();
  await page.getByText('This list is incomplete (2 blocking gaps) and is not a safety verdict.',{exact:false}).waitFor();
  await page.locator('.startup-lighttpd-gaps summary').click();
  const gaps=await page.locator('.startup-lighttpd-gaps').innerText();
  assert.match(gaps,/Service environment assumed/);assert.match(gaps,/Blocking: include_shell output not captured \/etc\/lighttpd\/lighttpd\.conf:2 · \/usr\/share\/lighttpd\/use-ipv6\.pl 80/);
  assert.match(gaps,/Blocking: \/etc\/passwd not captured/);
  await page.getByText('lighttpd tokens: 41 parsed.',{exact:false}).waitFor();
  await page.getByText('lighttpd tokens: not reported by this agent version.',{exact:false}).waitFor();
  await page.getByText('lighttpd tokens: the file was over 1 MiB, was not UTF-8 or contained NUL bytes',{exact:false}).waitFor();
  assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.evaluate(()=>window.__ltInjected),undefined);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('startup-lighttpd-'+width);}
  await page.setViewportSize({width:1440,height:1000});
  await page.getByRole('link',{name:'Coverage',exact:true}).click();await page.getByText('lighttpd configuration · 2 parsed files · not reported by this agent version',{exact:true}).waitFor();
 }finally{await page.unroute('**/api/hosts/*/security/startup-inventory?*',handler);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
