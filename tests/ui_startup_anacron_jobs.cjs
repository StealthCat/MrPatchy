const assert=require('assert/strict');
// Parsed /etc/anacrontab jobs render as escaped period/delay/job/command rows with settings; older agents and unreadable tables are explained.
module.exports=async(page,capture)=>{
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const job=(line,extra)=>({line,period_days:1,period_name:null,delay_minutes:5,identifier:'cron.daily',command:'run-parts --report /etc/cron.daily',command_truncated:false,redacted:false,duplicate_of_line:null,...extra});
 const tab={parsed:true,environment:6,unparsed:2,truncated:false,redacted:true,settings:{start_hours_range:{start:3,end:22},random_delay:45},
  jobs:[job(10),job(12,{period_days:30,period_name:'monthly',delay_minutes:15,identifier:'<b>id</b>',command:'<img src=x onerror=window.__anacronInjected=true>'}),
   job(13,{period_days:3,identifier:'backup.sync',command:'/usr/local/bin/sync --password [REDACTED] '+'x'.repeat(480),redacted:true,command_truncated:true}),job(14,{duplicate_of_line:10,command:'/usr/local/bin/second-daily'})]};
 const row=(path,extra)=>({path,mechanism:'anacron',mechanism_label:'anacron table',kind:'regular',uid:0,gid:0,mode:420,sha256:'c'.repeat(64),change:'not_compared',jobs_state:'not_crontab',...extra});
 const handler=route=>route.fulfill({json:{inspection_id:'anacron-receipt',created:Date.now()/1000,state:'collected',baseline_state:'not_compared',digest:'anacron-digest',
  items:[row('/etc/anacrontab',{anacron_state:'parsed',anacron:tab}),row('/etc/anacrontab.older',{anacron_state:'not_reported'}),row('/etc/anacrontab.binary',{anacron_state:'parsed',anacron:{parsed:false,jobs:[],environment:0,unparsed:0,truncated:false,redacted:false,settings:{start_hours_range:null,random_delay:null}}})],
  total:3,more:false,cron:{files:0,jobs:0,unparsed:0,truncated:false,not_reported:0},scope:['/etc/anacrontab'],catalog:[{id:'anacron',label:'anacron table · 4 parsed jobs · not reported by this agent version',observed_files:1}],missing_roots:[],skipped:0,gaps:['anacron gap'],note:'Bounded stored metadata.'}});
 await page.route('**/api/hosts/*/security/startup-inventory?*',handler);
 try{
  await page.goto(new URL('/#servers/'+host+'/startup/files',page.url()).href);await page.locator('#startup-file-items').waitFor();
  await page.getByRole('heading',{name:'anacron jobs (4)',exact:true}).waitFor();
  const settings=await page.locator('.startup-anacron-settings').first().innerText();assert.match(settings,/3:00–22:00/);assert.match(settings,/45 min maximum/);
  const table=page.locator('.startup-anacron-jobs').first();const text=await table.innerText();
  assert.match(text,/@monthly/);assert.match(text,/3 days/);assert.match(text,/1 day\b/);assert.match(text,/15 min/);
  assert.match(text,/<b>id<\/b>/);assert.match(text,/<img src=x onerror/);assert.match(text,/Credentials redacted · Truncated/);assert.match(text,/Shares a timestamp with line 10/);
  await page.getByText('2 unparsed lines · 6 environment assignments (only the two scheduling values are stored)',{exact:true}).waitFor();
  await page.getByText('anacron jobs: not reported by this agent version.',{exact:false}).waitFor();
  await page.getByText('The file was too large, not UTF-8 or contained NUL bytes',{exact:false}).waitFor();
  assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.locator('#content b').filter({hasText:'id'}).count(),0);assert.equal(await page.evaluate(()=>window.__anacronInjected),undefined);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('startup-anacron-jobs-'+width);}
  await page.getByRole('link',{name:'Coverage',exact:true}).click();await page.getByText('anacron table · 4 parsed jobs · not reported by this agent version',{exact:true}).waitFor();
 }finally{await page.unroute('**/api/hosts/*/security/startup-inventory?*',handler);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
