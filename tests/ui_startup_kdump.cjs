const assert=require('assert/strict');
// Parsed /etc/kdump.conf hooks render as escaped rows in capture order; refused, older-agent and unreadable files are explained.
module.exports=async(page,capture)=>{
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const hook=(line,source,stage,program,extra)=>({line,source,stage,program,args:[],program_truncated:false,redacted:false,on_failure:'warn',observations:[],...extra});
 const parsed={parsed:true,starts:true,refusals:[],extra_bins:2,truncated:false,redacted:true,hooks:[
  hook(3,'kdump_pre','pre','/opt/has space/pre',{on_failure:'skip_dump_and_run_final_action',observations:['value_has_whitespace','pre_failure_skips_dump']}),
  hook(null,'core_collector','dump','makedumpfile',{args:['-l','--message-level','7','-d','31'],on_failure:'dump_failed',observations:['args_rewritten_at_capture']}),
  hook(5,'kdump_post','post','<img src=x onerror=window.__kdumpInjected=true>',{args:['<dump status>'],redacted:true,program_truncated:true}),
  hook(6,'kdump_emergency','emergency','relative-em',{observations:['relative_path','runs_on_capture_failure']})]};
 const refused={parsed:true,starts:false,hooks:[],extra_bins:0,truncated:true,redacted:false,refusals:[{line:2,option:'<b>bogus</b>',code:'unknown_option'},{line:4,option:'kdump_pre',code:'duplicate_option'}]};
 const row=(path,extra)=>({path,mechanism:'kdump',mechanism_label:'kdump crash-capture configuration',kind:'regular',uid:0,gid:0,mode:420,sha256:'d'.repeat(64),change:'not_compared',jobs_state:'not_crontab',...extra});
 const handler=route=>route.fulfill({json:{inspection_id:'kdump-receipt',created:Date.now()/1000,state:'collected',baseline_state:'not_compared',digest:'kdump-digest',
  items:[row('/etc/kdump.conf',{kdump_state:'parsed',kdump:parsed}),row('/etc/kdump.conf.refused',{kdump_state:'parsed',kdump:refused}),row('/etc/kdump.conf.older',{kdump_state:'not_reported'}),
   row('/etc/kdump.conf.binary',{kdump_state:'parsed',kdump:{parsed:false,starts:null,refusals:[],hooks:[],extra_bins:0,truncated:false,redacted:false}})],
  total:4,more:false,cron:{files:0,jobs:0,unparsed:0,truncated:false,not_reported:0},scope:['/etc/kdump.conf'],catalog:[{id:'kdump',label:'kdump crash-capture configuration · 4 parsed hooks',observed_files:1}],missing_roots:[],skipped:0,gaps:['kdump gap'],note:'Bounded stored metadata.'}});
 await page.route('**/api/hosts/*/security/startup-inventory?*',handler);
 try{
  await page.goto(new URL('/#servers/'+host+'/startup/files',page.url()).href);await page.locator('#startup-file-items').waitFor();
  await page.getByRole('heading',{name:'kdump crash-capture hooks (4)',exact:true}).waitFor();
  const text=await page.locator('.startup-kdump-hooks').innerText();
  assert.match(text,/Before the dump\s+kdump_pre\s+\/opt\/has space\/pre/);assert.match(text,/Runs as one word: a path containing whitespace, with no arguments, so the call fails/);
  assert.match(text,/Skips the dump and runs the final action/);assert.match(text,/makedumpfile -l --message-level 7 -d 31/);
  assert.match(text,/kdump default \(not set in this file\) · The capture script rewrites -F and appends --num-threads/);
  assert.match(text,/<img src=x onerror=window\.__kdumpInjected=true> <dump status>/);assert.match(text,/Credentials redacted · Truncated/);
  assert.match(text,/Only if capture fails\s+kdump_emergency\s+relative-em/);assert.match(text,/Looked up through PATH in the capture environment/);
  const order=[...text.matchAll(/kdump_pre|core_collector|kdump_post|kdump_emergency/g)].map(m=>m[0]);assert.deepEqual(order,['kdump_pre','core_collector','kdump_post','kdump_emergency']);
  await page.getByText('2 extra_bins programs are installed in the capture image but not run by kdump itself · Programs in /etc/kdump/pre.d, post.d and emergency.d are not listed yet, so they are missing from this sequence',{exact:true}).waitFor();
  const notice=await page.locator('.startup-kdump-refused').innerText();
  assert.match(notice,/kdumpctl refuses this configuration/);assert.match(notice,/Line 2: <b>bogus<\/b> · Unknown option/);assert.match(notice,/Line 4: kdump_pre · Repeated option/);assert.match(notice,/Refusal limit reached/);
  await page.getByText('kdump hooks: not reported by this agent version.',{exact:false}).waitFor();
  await page.getByText('The file was over 64 KiB, had 2048 or more lines, was not UTF-8 or contained NUL bytes, so no hooks are shown',{exact:false}).waitFor();
  assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.locator('#content b').filter({hasText:'bogus'}).count(),0);assert.equal(await page.evaluate(()=>window.__kdumpInjected),undefined);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('startup-kdump-'+width);}
  await page.getByRole('link',{name:'Coverage',exact:true}).click();await page.getByText('kdump crash-capture configuration · 4 parsed hooks',{exact:true}).waitFor();
 }finally{await page.unroute('**/api/hosts/*/security/startup-inventory?*',handler);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
