const assert=require('assert/strict');
// Activity → Workers shows the fleet-wide shared AI start gates (#930) after the
// registered runtimes and before controllers. Display-only and independently loaded.
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let mode='finite',requests=0,role='admin';
 const limitations=['Provider policy, finite concurrency, per-server pause and lifecycle checks still apply.'];
 const snapshots={
  open:{generated_at:now,mode:'rate',can_start_now:true,next_start_at:null,blockers:[],limitations},
  finite:{generated_at:now,mode:'rate_and_daily',can_start_now:false,next_start_at:now+1800,blockers:[
   {code:'rate_throttle',message:'The shared smooth-rate throttle is waiting for its next start.',next_at:now+1800,recheck_at:null}],limitations},
  malformed:{can_start_now:false,next_start_at:'<b>x</b>',blockers:[{code:'<img src=x onerror=window.__workerGateInjected=true>',message:'<img src=x onerror=window.__workerGateInjected=true>',next_at:'soon'}],limitations:['<img src=x onerror=window.__workerGateInjected=true>']},
 };
 const gates=route=>{requests++;return mode==='error'?route.fulfill({status:500,json:{detail:'boom'}}):route.fulfill({json:snapshots[mode]});};
 const worker={id:'worker-one',boot_id:'a'.repeat(32),role:'worker',deployment_type:'docker',version:'1.0.0',state:'reporting',reason:'Fresh report',heartbeat:now,uptime_seconds:60,coordinator:true,active_jobs:[],job_capacity:4,active_polls:0,poll_capacity:4,pending_polls:0,notification_active:false,active_ai_tasks:0,ai_capacity:4,ai_http_capacity:16,control:{action:'resume',revision:0},control_revision:0,controllable:false,removable:false};
 const workers=route=>{const offset=new URL(route.request().url()).searchParams.get('offset');return route.fulfill({json:{items:offset==='50'?[{...worker,id:'last-worker'}]:[worker],more:offset!=='50',gaps:[],fresh_seconds:90,expected:[],expected_count:0,expectation_source:'registrations'}});};
 const controllers=route=>route.fulfill({json:{items:[],expected:[],gaps:[]}});
 const identity=async route=>{const response=await route.fetch();return route.fulfill({response,json:{...await response.json(),role}});};
 await page.route('**/api/settings/ai-control-status',gates);await page.route('**/api/operations/workers?*',workers);
 await page.route('**/api/operations/controllers*',controllers);await page.route('**/api/identity',identity);
 const card=page.getByRole('region',{name:'Shared AI start gates',exact:true});
 const open=async()=>{await page.goto(new URL('/#activity/workers',page.url()).href);await page.reload();await page.getByRole('heading',{name:'Registered runtimes',exact:true}).waitFor();};
 try{
  await open();
  await card.getByText('held by 1 shared gate',{exact:false}).waitFor();
  const text=await card.innerText();
  assert.match(text,/Smooth-rate throttle/);assert.match(text,/Next eligible start:/);
  assert.match(text,/per-server pause and lifecycle checks still apply/);
  assert.equal(await page.locator('#ai-control-gates').count(),1);
  // After the registered runtimes and before the controllers.
  assert(await page.evaluate(()=>{const gates=document.querySelector('#ai-control-gates'),controllers=document.querySelector('#controller-registrations');
   const runtimes=[...document.querySelectorAll('#content h2')].find(h=>h.textContent==='Registered runtimes').closest('section');
   return !!(runtimes.compareDocumentPosition(gates)&Node.DOCUMENT_POSITION_FOLLOWING)&&!!(gates.compareDocumentPosition(controllers)&Node.DOCUMENT_POSITION_FOLLOWING);}));
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await card.scrollIntoViewIfNeeded();
   await capture('worker-ai-control-gates-'+width);
  }
  await page.setViewportSize({width:1440,height:1000});

  // Refresh re-reads the snapshot in place.
  mode='open';let calls=requests;
  await card.getByRole('button',{name:'Refresh start gates'}).click();
  await card.getByText('All shared global gates are open now.',{exact:false}).waitFor();
  assert.equal(requests,calls+1);

  // Pagination re-renders the page once, with exactly one card.
  await page.locator('#worker-next').click();await page.getByText('last-worker',{exact:true}).waitFor();
  await card.getByText('All shared global gates are open now.',{exact:false}).waitFor();
  assert.equal(await page.locator('#ai-control-gates').count(),1);
  await page.locator('#worker-prev').click();await page.getByText('worker-one',{exact:true}).waitFor();

  // Malformed content is escaped.
  mode='malformed';await page.reload();
  await card.getByText('held by 1 shared gate',{exact:false}).waitFor();
  assert.match(await card.innerText(),/No automatic next start/);
  assert.equal(await page.locator('#content img[src=x]').count(),0);
  assert.equal(await page.evaluate(()=>window.__workerGateInjected),undefined);

  // A failed snapshot shows a retry and never blocks worker or controller sections.
  mode='error';await page.reload();
  await card.getByText('Shared AI start gates are unavailable right now.',{exact:false}).waitFor();
  await page.getByText('worker-one',{exact:true}).waitFor();
  await page.locator('#controller-registrations').waitFor();
  mode='open';calls=requests;
  await card.getByRole('button',{name:'Retry start gates'}).click();
  await card.getByText('All shared global gates are open now.',{exact:false}).waitFor();
  assert.equal(requests,calls+1);

  // A slow snapshot does not delay the worker list, and a late response after
  // leaving the page is discarded.
  let release;const held=new Promise(resolve=>release=resolve);
  const slow=async route=>{await held;return gates(route);};
  await page.unroute('**/api/settings/ai-control-status',gates);await page.route('**/api/settings/ai-control-status',slow);
  try{
   await page.reload();await page.getByText('worker-one',{exact:true}).waitFor();
   await page.locator('#ai-control-gates [role=status]').waitFor();
   await page.getByRole('link',{name:'Operations',exact:true}).click();
   await page.locator('#breadcrumb').getByText('Activity',{exact:false}).waitFor();
   release();await page.waitForTimeout(200);
   assert.equal(await page.locator('#ai-control-gates').count(),0);
   assert.doesNotMatch(await page.locator('#content').innerText(),/shared global gates/);
  }finally{release();await page.unroute('**/api/settings/ai-control-status',slow);await page.route('**/api/settings/ai-control-status',gates);}

  // Viewers see the access-required page and never request the snapshot.
  role='viewer';calls=requests;
  await page.goto(new URL('/#activity/workers',page.url()).href);await page.reload();
  await page.getByRole('heading',{name:'Administrator access required'}).waitFor();
  assert.equal(await page.locator('#ai-control-gates').count(),0);
  assert.equal(requests,calls);
 }finally{
  role='admin';
  await page.unroute('**/api/settings/ai-control-status',gates);await page.unroute('**/api/operations/workers?*',workers);
  await page.unroute('**/api/operations/controllers*',controllers);await page.unroute('**/api/identity',identity);
  await page.goto(new URL('/#overview',page.url()).href);await page.reload();
 }
};
