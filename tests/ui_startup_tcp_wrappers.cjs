const assert=require('assert/strict');
// Parsed hosts.allow/hosts.deny commands render as escaped rows with effect, reachability and notes; older agents and unreadable files are explained.
module.exports=async(page,capture)=>{
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const command=(line,extra)=>({line,option:'spawn',command:'/usr/bin/logger -t tcpd %h',command_truncated:false,redacted:false,daemons:['sshd'],clients:['ALL'],matches_every_request:false,identity_options_ignored:[],after_runtime_checks:[],reachability:'reachable',shadowed_by:null,...extra});
 const allow={parsed:true,entries:3,skipped:1,option_errors:1,error_line:9,unconditional_line:4,aclexec_through_unconditional:false,truncated:false,redacted:true,reachable:2,reachability_unknown:null,
  commands:[command(2,{identity_options_ignored:['user'],after_runtime_checks:['user']}),command(3,{option:'twist',command:'<img src=x onerror=window.__tcpwInjected=true>',daemons:['<b>in.telnetd</b>'],redacted:true,command_truncated:true}),
   command(5,{option:'aclexec',command:'/usr/local/bin/check %a',daemons:['ALL'],reachability:'shadowed',shadowed_by:{path:'/etc/hosts.allow',line:4}})]};
 const deny={parsed:true,entries:1,skipped:0,option_errors:0,error_line:null,unconditional_line:1,aclexec_through_unconditional:false,truncated:true,redacted:false,reachable:0,reachability_unknown:'hosts.allow commands were not reported by this agent version',
  commands:[command(1,{daemons:['ALL'],matches_every_request:true,reachability:'unknown'})]};
 const row=(path,extra)=>({path,mechanism:'tcp_wrappers_allow',mechanism_label:'TCP wrappers allow rules',kind:'regular',uid:0,gid:0,mode:420,sha256:'c'.repeat(64),change:'not_compared',jobs_state:'not_crontab',...extra});
 const handler=route=>route.fulfill({json:{inspection_id:'tcpw-receipt',created:Date.now()/1000,state:'collected',baseline_state:'not_compared',digest:'tcpw-digest',
  items:[row('/etc/hosts.allow',{tcp_wrappers_state:'parsed',tcp_wrappers:allow}),row('/etc/hosts.deny',{mechanism:'tcp_wrappers_deny',mechanism_label:'TCP wrappers deny rules',tcp_wrappers_state:'parsed',tcp_wrappers:deny}),
   row('/etc/hosts.allow.older',{tcp_wrappers_state:'not_reported'}),row('/etc/hosts.allow.binary',{tcp_wrappers_state:'parsed',tcp_wrappers:{parsed:false,entries:0,skipped:0,option_errors:0,error_line:null,unconditional_line:null,aclexec_through_unconditional:false,commands:[],truncated:false,redacted:false,reachable:0,reachability_unknown:null}})],
  total:4,more:false,cron:{files:0,jobs:0,unparsed:0,truncated:false,not_reported:0},scope:['/etc/hosts.allow','/etc/hosts.deny'],catalog:[{id:'tcp_wrappers_allow',label:'TCP wrappers allow rules · 3 parsed commands',observed_files:1}],missing_roots:[],skipped:0,gaps:['TCP wrappers gap'],note:'Bounded stored metadata.'}});
 await page.route('**/api/hosts/*/security/startup-inventory?*',handler);
 try{
  await page.goto(new URL('/#servers/'+host+'/startup/files',page.url()).href);await page.locator('#startup-file-items').waitFor();
  await page.getByRole('heading',{name:'TCP wrappers commands (3 · 2 reachable)',exact:true}).waitFor();
  const text=await page.locator('.startup-tcp-wrappers').first().innerText();
  assert.match(text,/Forked and waited for; output discarded/);assert.match(text,/Replaces the daemon; talks to the client/);assert.match(text,/a non-zero exit unmatches the entry/);
  assert.match(text,/<b>in\.telnetd<\/b>/);assert.match(text,/<img src=x onerror/);assert.match(text,/Credentials redacted · Truncated/);
  assert.match(text,/user option ignored by this libwrap build · Runs only if user succeed first/);assert.match(text,/Shadowed by \/etc\/hosts\.allow line 4/);
  await page.getByText('libwrap stops reading this file at line 9 (missing newline or line too long) · 1 entries without a colon are skipped · 1 entries stop at an invalid option; options before it still run',{exact:true}).waitFor();
  const denied=await page.locator('.startup-tcp-wrappers').nth(1).innerText();assert.match(denied,/Matches every request/);assert.match(denied,/Unknown/);
  await page.getByText('Reachability unknown: hosts.allow commands were not reported by this agent version · Command, daemon or client limit reached; later values omitted',{exact:true}).waitFor();
  await page.getByText('TCP wrappers commands: not reported by this agent version.',{exact:false}).waitFor();
  await page.getByText('The file was too large, not UTF-8 or contained NUL bytes, so no commands are shown',{exact:false}).waitFor();
  assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.locator('#content b').filter({hasText:'in.telnetd'}).count(),0);assert.equal(await page.evaluate(()=>window.__tcpwInjected),undefined);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('startup-tcp-wrappers-'+width);}
  await page.getByRole('link',{name:'Coverage',exact:true}).click();await page.getByText('TCP wrappers allow rules · 3 parsed commands',{exact:true}).waitFor();
 }finally{await page.unroute('**/api/hosts/*/security/startup-inventory?*',handler);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
