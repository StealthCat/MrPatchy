const assert=require('assert/strict');
// Parsed request-key rules render as escaped rows; lookup-wide aborts, skipped drop-ins, older-agent and unreadable files are explained.
module.exports=async(page,capture)=>{
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const rule=(line,extra)=>({line,op:'create',type:'user',description:'*',callout_info:'*',pipe:false,command:'/usr/sbin/handler %k %d %c',command_truncated:false,redacted:false,kernel_upcall:true,requester_controlled:['callout_info','description'],fails_when_selected:null,code_runs:'on_matching_request',...extra});
 const report=(rules,extra)=>({parsed:true,rules,aborts:[],universal_abort_line:null,last_byte_dropped:false,truncated:false,redacted:false,lookups:{universal_aborts:[],complete:true},...extra});
 const conf=report([rule(2),rule(3,{type:'<img src=x onerror=window.__rkInjected=true>',pipe:true,command:'/usr/bin/pipe --password=[REDACTED]',redacted:true,command_truncated:true,requester_controlled:['stdin_callout_info']}),
  rule(4,{op:'negate',kernel_upcall:false,code_runs:'never',requester_controlled:[]}),rule(5,{command:'handler %d',fails_when_selected:'program_without_slash',code_runs:'fails_when_selected',requester_controlled:['description']})],
  {aborts:[{line:6,reason:'syntax_error',scope:['create','logon'],universal:false}],last_byte_dropped:true});
 const aborting=report([rule(1)],{aborts:[{line:2,reason:'syntax_error',scope:['create'],universal:true}],universal_abort_line:2,lookups:{universal_aborts:['/etc/request-key.d/a.conf:2'],complete:false}});
 const row=(path,mechanism,extra)=>({path,mechanism,mechanism_label:mechanism==='request_key'?'keyutils request-key configuration':'keyutils request-key drop-ins',kind:'regular',uid:0,gid:0,mode:420,sha256:'e'.repeat(64),change:'not_compared',jobs_state:'not_crontab',...extra});
 const handler=route=>route.fulfill({json:{inspection_id:'rk-receipt',created:Date.now()/1000,state:'collected',baseline_state:'not_compared',digest:'rk-digest',
  items:[row('/etc/request-key.conf','request_key',{request_key_state:'parsed',request_key:conf}),row('/etc/request-key.d/a.conf','request_key_d',{request_key_state:'parsed',request_key:aborting}),
   row('/etc/request-key.d/b.conf','request_key_d',{request_key_state:'not_reported'}),row('/etc/request-key.d/notes.txt','request_key_d',{request_key_state:'skipped_name'}),
   row('/etc/request-key.d/c.conf','request_key_d',{request_key_state:'parsed',request_key:{...report([]),parsed:false}})],
  total:5,more:false,cron:{files:0,jobs:0,unparsed:0,truncated:false,not_reported:0},scope:['/etc/request-key.conf','/etc/request-key.d'],
  catalog:[{id:'request_key',label:'keyutils request-key configuration · 4 parsed rules',observed_files:1},{id:'request_key_d',label:'keyutils request-key drop-ins · 1 parsed rule · every lookup aborts · not reported by this agent version',observed_files:4}],missing_roots:[],skipped:0,gaps:['request-key gap'],note:'Bounded stored metadata.'}});
 await page.route('**/api/hosts/*/security/startup-inventory?*',handler);
 try{
  await page.goto(new URL('/#servers/'+host+'/startup/files',page.url()).href);await page.locator('#startup-file-items').waitFor();
  await page.getByRole('heading',{name:'request-key rules (4)',exact:true}).waitFor();
  const text=await page.locator('.startup-request-key-rules').first().innerText();
  assert.match(text,/\/usr\/sbin\/handler %k %d %c/);assert.match(text,/Requester controls %c callout information, %d description/);assert.match(text,/As root on a matching request/);
  assert.match(text,/<img src=x onerror=window\.__rkInjected=true>/);assert.match(text,/\| \/usr\/bin\/pipe --password=\[REDACTED\]/);
  assert.match(text,/Piped: reads callout information on standard input and returns the payload · Requester controls callout information on standard input · Credentials redacted · Truncated/);
  assert.match(text,/Never: the kernel upcall uses the create operation/);assert.match(text,/Fails when selected: Program has no slash; request-key crashes/);
  await page.getByText('Line 6: ends before the program · lookups matching create logon',{exact:true}).waitFor();
  await page.getByText('The final line has no newline, so request-key drops its last character, as shown',{exact:false}).waitFor();
  const notice=await page.locator('.startup-request-key-aborts').innerText();
  assert.match(notice,/Every kernel key lookup aborts/);assert.match(notice,/\/etc\/request-key\.d\/a\.conf:2/);
  const second=await page.locator('.startup-request-key-rules').nth(1).innerText();assert.match(second,/Not reached: every lookup aborts/);
  await page.getByText('Line 2: ends before the program · every kernel lookup',{exact:true}).waitFor();
  await page.getByText('Another request-key file was not parsed, so lookups that abort there are not shown',{exact:false}).waitFor();
  await page.getByText('request-key rules: not reported by this agent version.',{exact:false}).waitFor();
  await page.getByText('request-key skips this entry: only names ending in .conf that do not start with a dot are read.',{exact:true}).waitFor();
  await page.getByText('The file was over 64 KiB, was not UTF-8 or contained NUL bytes, so no rules are shown',{exact:false}).waitFor();
  assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.evaluate(()=>window.__rkInjected),undefined);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('startup-request-key-'+width);}
  await page.getByRole('link',{name:'Coverage',exact:true}).click();await page.getByText('keyutils request-key configuration · 4 parsed rules',{exact:true}).waitFor();
 }finally{await page.unroute('**/api/hosts/*/security/startup-inventory?*',handler);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
