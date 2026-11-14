const assert=require('assert/strict');
// The Investigations page shows the shared AI start-gate snapshot (#727, API from #546).
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let mode='open',requests=0;
 const limitations=['A call-specific conservative price quote can still refuse capped admission.','Provider policy, finite concurrency, per-server pause and lifecycle checks still apply.'];
 const snapshots={
  open:{generated_at:now,mode:'rate',can_start_now:true,next_start_at:null,blockers:[],limitations},
  finite:{generated_at:now,mode:'rate_and_daily',can_start_now:false,next_start_at:now+1800,blockers:[
   {code:'provider_backoff',message:'Shared provider backoff is waiting after a transient failure.',next_at:now+600,recheck_at:null},
   {code:'rate_throttle',message:'The shared smooth-rate throttle is waiting for its next start.',next_at:now+1800,recheck_at:null}],limitations},
  indefinite:{generated_at:now,mode:'daily_cap',can_start_now:false,next_start_at:null,blockers:[
   {code:'disabled',message:'Central AI provider calls are disabled by an administrator.',next_at:null,recheck_at:null},
   {code:'daily_cap',message:'The daily spend cap has no remaining recorded headroom; retained prior windows make the configured reset a recheck boundary only.',next_at:null,recheck_at:now+7200}],limitations},
  legacy:{generated_at:now,mode:'legacy',can_start_now:true,next_start_at:null,blockers:[],limitations,purpose_limits:[
   {purpose:'triage',limit:20,used:20,state:'exhausted',next_at:now+900},
   {purpose:'update_scoring',limit:20,used:3,state:'disabled',next_at:null},
   {purpose:'automatic_plans',limit:10,used:2,state:'available',next_at:null},
   {purpose:'<img src=x onerror=window.__gateInjected=true>',limit:'x',used:-1,state:'exhausted',next_at:'soon'}]},
  malformed:{can_start_now:false,next_start_at:'<b>x</b>',blockers:[{code:'<img src=x onerror=window.__gateInjected=true>',message:'<img src=x onerror=window.__gateInjected=true>',next_at:'soon'}],limitations:['<img src=x onerror=window.__gateInjected=true>']},
 };
 const status={pending:2,active:0,queued:2,reported_capacity:2,ready:2,blocked:0,paused:0,hourly_limit:20,recent_attempts:0,worker_seen:now,enabled:true,reason:'ready',message:'Waiting for shared admission.',retry_at:null,last_error:'',admission:{mode:'rate',rate_per_hour:12}};
 const gates=route=>{requests++;return mode==='error'?route.fulfill({status:500,json:{detail:'boom'}}):route.fulfill({json:snapshots[mode]});};
 const statusRoute=route=>route.fulfill({json:status});const rows=route=>route.fulfill({json:[]});
 await page.route('**/api/settings/ai-control-status',gates);await page.route('**/api/investigation-status',statusRoute);await page.route('**/api/investigations?*',rows);
 try{
  await page.goto(new URL('/#investigations',page.url()).href);await page.reload();
  const card=page.locator('#ai-control-gates');
  await card.getByText('All shared global gates are open now.',{exact:false}).waitFor();
  assert.equal(await card.locator('.badge').innerText(),'open');
  assert.match(await card.innerText(),/finite concurrency, per-server pause and lifecycle checks still apply/);
  // The queue status and investigations list render independently of the snapshot.
  await page.getByRole('heading',{name:'AI worker status',exact:true}).waitFor();

  mode='finite';await page.reload();
  await card.getByText('held by 2 shared gates',{exact:false}).waitFor();
  const finite=await card.innerText();
  assert.match(finite,/Shared provider backoff/);assert.match(finite,/Smooth-rate throttle/);
  assert.match(finite,/Next eligible start:/);
  assert.equal((finite.match(/Next eligible /g)||[]).length,3);
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await card.scrollIntoViewIfNeeded();
   await capture('ai-control-gates-'+width);
  }
  await page.setViewportSize({width:1440,height:1000});

  // Legacy per-purpose allowances (#860) are listed apart from the shared gates.
  mode='legacy';await page.reload();
  await card.getByText('Legacy hourly allowances',{exact:false}).waitFor();
  assert.equal(await card.locator('.badge').innerText(),'open');
  const legacy=await card.locator('[data-ai-purpose-limits]').innerText();
  assert.match(legacy,/Process triage · 20 of 20 in the last hour/);
  assert.match(legacy,/Allowance used up\. Next eligible /);
  assert.match(legacy,/Update scoring · 3 of 20 in the last hour\s+Disabled in Settings/);
  assert.match(legacy,/Automatic incident and startup plans · 2 of 10 in the last hour\s+Allowance available/);
  assert.match(legacy,/Unavailable of Unavailable in the last hour\s+Allowance used up\. No scheduled reopening/);
  assert.equal(await page.locator('#content img[src=x]').count(),0);
  assert.equal(await page.evaluate(()=>window.__gateInjected),undefined);
  for(const width of [320,1440]){
   await page.setViewportSize({width,height:1000});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await card.scrollIntoViewIfNeeded();
   await capture('ai-control-legacy-allowances-'+width);
  }
  await page.setViewportSize({width:1440,height:1000});
  mode='open';await page.reload();
  await card.getByText('All shared global gates are open now.',{exact:false}).waitFor();
  assert.equal(await card.locator('[data-ai-purpose-limits]').count(),0);

  mode='indefinite';await page.reload();
  await card.getByText('No automatic next start.',{exact:false}).waitFor();
  const indefinite=await card.innerText();
  assert.match(indefinite,/Central AI disabled/);assert.match(indefinite,/No scheduled end/);
  assert.match(indefinite,/Recheck at .*not a promised start/);
  assert.doesNotMatch(indefinite,/Next eligible start:/);

  mode='error';await page.reload();
  await card.getByText('Shared AI start gates are unavailable right now.',{exact:false}).waitFor();
  assert.equal(await card.locator('.badge').innerText(),'unavailable');
  await page.getByRole('heading',{name:'AI worker status',exact:true}).waitFor();
  mode='open';const before=requests;
  await card.getByRole('button',{name:'Retry start gates'}).click();
  await card.getByText('All shared global gates are open now.',{exact:false}).waitFor();
  assert.equal(requests,before+1);

  mode='malformed';await page.reload();
  await card.getByText('held by 1 shared gate',{exact:false}).waitFor();
  assert.match(await card.innerText(),/No automatic next start/);
  assert.equal(await page.locator('#content img[src=x]').count(),0);
  assert.equal(await page.evaluate(()=>window.__gateInjected),undefined);

  // Viewers never request the administrator-only snapshot.
  const identity=async route=>{const response=await route.fetch();return route.fulfill({response,json:{...await response.json(),role:'viewer'}});};
  await page.route('**/api/identity',identity);
  try{
   const calls=requests;await page.reload();
   await page.getByText('Oldest pending:',{exact:false}).waitFor();
   assert.equal(await page.locator('#ai-control-gates').count(),0);
   assert.equal(requests,calls);
  }finally{await page.unroute('**/api/identity',identity);}
  await page.reload();await card.getByText('held by 1 shared gate',{exact:false}).waitFor();
 }finally{
  await page.unroute('**/api/settings/ai-control-status',gates);await page.unroute('**/api/investigation-status',statusRoute);await page.unroute('**/api/investigations?*',rows);
 }
};
