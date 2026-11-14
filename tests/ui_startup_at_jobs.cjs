const assert=require('assert/strict');
// Parsed at jobs render as escaped queue/time/owner facts plus bounded commands; older agents and unrecognized layouts are explained.
module.exports=async(page,capture)=>{
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const scheduled=1763100000;
 const at=(job,extra)=>({queue:'a',job,scheduled_at:scheduled,running:false,uid:1000,gid:1000,account:'alice',commands:['/usr/local/bin/sync --password [REDACTED] /srv','<img src=x onerror=window.__atInjected=true>','x'.repeat(500)],environment:3,parsed:true,truncated:false,redacted:true,...extra});
 const row=(name,extra)=>({path:'/var/spool/cron/atjobs/'+name,mechanism:'at',mechanism_label:'Debian-family at job queue',kind:'regular',uid:1000,gid:1,mode:448,sha256:'b'.repeat(64),change:'not_compared',jobs_state:'not_crontab',...extra});
 const handler=route=>route.fulfill({json:{inspection_id:'at-receipt',created:Date.now()/1000,state:'collected',baseline_state:'not_compared',digest:'at-digest',
  items:[row('a0000301a2b3c4',{at_state:'parsed',at:at(3)}),row('B0000401a2b3c4',{at_state:'parsed',at:at(4,{queue:'b',running:true,parsed:false,commands:[],account:null,environment:0,redacted:false})}),row('a0000501a2b3c4',{at_state:'not_reported'})],
  total:3,more:false,cron:{files:0,jobs:0,unparsed:0,truncated:false,not_reported:0},scope:['/var/spool/cron'],catalog:[{id:'at',label:'Debian-family at job queue · 1 parsed job · 1 not reported by this agent version',observed_files:3}],missing_roots:[],skipped:0,gaps:['at gap'],note:'Bounded stored metadata.'}});
 await page.route('**/api/hosts/*/security/startup-inventory?*',handler);
 try{
  await page.goto(new URL('/#servers/'+host+'/startup/files',page.url()).href);await page.locator('#startup-file-items').waitFor();
  await page.getByRole('heading',{name:'at job 3',exact:true}).waitFor();await page.getByRole('heading',{name:'at job 4 · running',exact:true}).waitFor();
  const facts=page.locator('.startup-at-job').first();assert.match(await facts.innerText(),/alice · UID 1000/);assert.match(await facts.innerText(),new RegExp(new Date(scheduled*1000).toLocaleString().replace(/[.*+?^${}()|[\]\\]/g,'\\$&')));
  assert.match(await page.locator('.startup-at-commands').first().innerText(),/<img src=x onerror/);
  await page.getByText('3 exported environment assignments (values not stored) · Credentials redacted',{exact:true}).waitFor();
  await page.getByText('The job script layout was not recognized',{exact:false}).waitFor();await page.getByText('UID 1000',{exact:true}).waitFor();
  await page.getByText('at job: not reported by this agent version.',{exact:false}).waitFor();
  assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.evaluate(()=>window.__atInjected),undefined);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('startup-at-jobs-'+width);}
  await page.getByRole('link',{name:'Coverage',exact:true}).click();await page.getByText('Debian-family at job queue · 1 parsed job · 1 not reported by this agent version',{exact:true}).waitFor();
 }finally{await page.unroute('**/api/hosts/*/security/startup-inventory?*',handler);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
