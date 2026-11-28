const assert=require('assert/strict');
// Evaluated dhcpd execute() programs render as escaped rows with events, scopes, accounts, replacement and gaps; rejected configurations, older agents and unparsed files are explained.
module.exports=async(page,capture)=>{
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const prog=(program,extra)=>({program,path_search:false,truncated_at_nul:false,argv_literal:[program,'commit'],arguments:[{literal:true,value:'commit',expression:'"commit"'}],events:['commit'],scope:['subnet 10.5.5.0 netmask 255.255.255.224'],conditions:[],run_as:['dhcpd'],runs_as_root_at_startup:false,replaced_in_same_scope:false,replaced_events:[],may_be_replaced_by:[],line:12,runs_only_if_config_accepted:false,...extra});
 const programs=[prog('/usr/local/sbin/boot-hook',{events:['startup','config_test','scope_evaluation'],scope:[],run_as:['root','dhcpd'],runs_as_root_at_startup:true,line:7,argv_literal:['/usr/local/sbin/boot-hook']}),
  prog('<img src=x onerror=window.__dhInjected=true>',{argv_literal:null,arguments:[{literal:false,value:null,expression:'binary-to-ascii(10, 8, ".", leased-address)'}],conditions:['if exists host-name'],may_be_replaced_by:[{scope:['host printer'],line:30,events:['commit'],conditional:false}],line:14}),
  prog('notify',{path_search:true,events:['release','expiry'],replaced_in_same_scope:true,replaced_events:['release','expiry'],line:20})];
 const view=extra=>({programs,root_programs:1,process_user:{user:'dhcpd',group:'dhcpd',source:'packaged_unit_default'},rejected_by_parser:false,config_errors:[],
  gaps:[{code:'process_user_unobserved',line:null,detail:'dhcpd command line not observed; the packaged unit runs -user dhcpd -group dhcpd.',blocking:false},{code:'include',line:40,detail:'/etc/dhcp/extra.conf',blocking:true}],
  not_modelled:[],redacted:true,config_path:'/etc/dhcp/dhcpd.conf',complete:false,origin:'not_assessed',authorizes_response:false,contract_version:1,...extra});
 const row=(path,extra)=>({path,mechanism:'dhcpd',mechanism_label:'ISC dhcpd configuration',kind:'regular',uid:0,gid:0,mode:420,sha256:'e'.repeat(64),change:'not_compared',jobs_state:'not_crontab',...extra});
 const respond=items=>({inspection_id:'dh-receipt',created:Date.now()/1000,state:'collected',baseline_state:'not_compared',digest:'dh-digest',items,total:items.length,more:false,cron:{files:0,jobs:0,unparsed:0,truncated:false,not_reported:0},scope:['/etc/dhcp/dhcpd.conf'],
  catalog:[{id:'dhcpd',label:'ISC dhcpd configuration · execute() programs parsed',observed_files:1}],missing_roots:[],skipped:0,gaps:['dhcpd gap'],note:'Bounded stored metadata.'});
 let body=respond([row('/etc/dhcp/dhcpd.conf',{dhcpd_state:'parsed',dhcpd:view()})]);
 const handler=route=>route.fulfill({json:body});
 await page.route('**/api/hosts/*/security/startup-inventory?*',handler);
 // Leave the page first: the same hash does not re-render.
 const open=async()=>{await page.goto(new URL('/#activity',page.url()).href);await page.goto(new URL('/#servers/'+host+'/startup/files',page.url()).href);await page.locator('#startup-file-items').waitFor();};
 try{
  await open();
  await page.getByRole('heading',{name:'dhcpd execute() programs (3 configured · 1 run as root)',exact:true}).waitFor();
  const text=await page.locator('.startup-dhcpd-programs').innerText();
  assert.match(text,/\/usr\/local\/sbin\/boot-hook/);assert.match(text,/Every start · dhcpd -t · Each packet in this scope/);assert.match(text,/Global/);assert.match(text,/root, then dhcpd/);
  assert.match(text,/<img src=x onerror=window\.__dhInjected=true> binary-to-ascii\(10, 8, "\.", leased-address\)/);assert.match(text,/if exists host-name/);assert.match(text,/May be replaced by 1 later or inner on statement/);
  assert.match(text,/notify commit/);assert.match(text,/Replaced by a later on statement in the same scope · Found through PATH/);assert.match(text,/Lease release · Lease expiry/);
  await page.getByText('before dhcpd drops to dhcpd (assumed from the packaged unit)',{exact:false}).waitFor();
  await page.getByText('This list is incomplete (1 blocking gap) and is not a safety verdict.',{exact:false}).waitFor();
  await page.locator('.startup-dhcpd-gaps summary').click();
  const gaps=await page.locator('.startup-dhcpd-gaps').innerText();
  assert.match(gaps,/dhcpd account assumed \(packaged unit\)/);assert.match(gaps,/Blocking: Included file not followed line 40 \/etc\/dhcp\/extra\.conf/);
  assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.evaluate(()=>window.__dhInjected),undefined);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('startup-dhcpd-'+width);}
  await page.setViewportSize({width:1440,height:1000});
  await page.getByRole('link',{name:'Coverage',exact:true}).click();await page.getByText('ISC dhcpd configuration · execute() programs parsed',{exact:true}).waitFor();
  body=respond([row('/etc/dhcp/dhcpd.conf',{dhcpd_state:'parsed',dhcpd:view({rejected_by_parser:true,programs:[],root_programs:0,config_errors:[{file:'/etc/dhcp/dhcpd.conf',line:3,reason:'expecting_quoted_string',detail:'execute() program must be a quoted string'}]})}),
   row('/etc/dhcp/dhcpd6.conf',{mechanism:'dhcpd6',mechanism_label:'ISC dhcpd DHCPv6 configuration'})]);
  await open();
  await page.locator('.startup-dhcpd-refused').waitFor();await page.getByText('No execute() statements found in this file.',{exact:true}).waitFor();
  await page.locator('.startup-dhcpd-errors summary').click();assert.match(await page.locator('.startup-dhcpd-errors').innerText(),/expecting_quoted_string line 3/);
  body=respond([row('/etc/dhcp/dhcpd.conf',{dhcpd_state:'not_reported'})]);await open();
  await page.getByText('dhcpd execute() programs: not reported by this agent version.',{exact:false}).waitFor();
  body=respond([row('/etc/dhcp/dhcpd.conf',{dhcpd_state:'unparsed'})]);await open();
  await page.getByText('dhcpd execute() programs: the file was over 256 KiB, was not UTF-8 or contained NUL bytes',{exact:false}).waitFor();
 }finally{await page.unroute('**/api/hosts/*/security/startup-inventory?*',handler);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
