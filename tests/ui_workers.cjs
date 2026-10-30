const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const sourceVersion=(await(await page.request.get(new URL('/healthz',page.url()).href)).json()).version;
 let expectationError=null,expectationsConfigured=true;const now=Date.now()/1000;let role='admin',empty=false,calls=0,inject=true,desired='resume',revision=0,observed=0,workerState='reporting',conflict=false;const submitted=[];let workerId='worker-one';
 const item=(id,state)=>({id,schema_structure:id===workerId?'verified':state==='stale'?'not_checked':undefined,controller_state:id===workerId?'verified':state==='stale'?'not_checked':undefined,boot_id:'a'.repeat(32),role:'worker',deployment_type:'docker',version:state==='version_mismatch'?'0.8.0':sourceVersion,started:now-3600,heartbeat:now-(state==='stale'?180:15),uptime_seconds:3600,state,reason:state==='stale'?'Heartbeat expired; outcomes unknown.':state==='version_mismatch'?'Worker source version differs from the controller.':state==='draining'?'Worker observed drain; assigned work is finishing. New assignments are blocked.':'Scheduler loop self-report; readiness not assessed.',coordinator:id===workerId&&state==='reporting',active_jobs:state==='stopped'?[]:['fixture-job'],active_polls:state==='stopped'?0:2,pending_polls:0,notification_active:false,control_revision:id===workerId?observed:0,control:{revision:id===workerId?revision:0,action:id===workerId?desired:'resume'},controllable:id===workerId,ai_active:false,job_capacity:2,poll_capacity:8,ai_capacity:1,readiness:'not_assessed'});
 const identity=async route=>{const response=await route.fetch();return route.fulfill({response,json:{...await response.json(),role}});};
 const workers=route=>{calls++;const offset=new URL(route.request().url()).searchParams.get('offset');return route.fulfill({json:{items:empty?[]:offset==='50'?[item('last-worker','stopped')]:[item(workerId,workerState),item(inject?'<img src=x onerror="window.__workerInjected=true">':'worker-two','stale'),item('worker-old-version','version_mismatch')],expected:expectationsConfigured?[{id:inject?'<img src=x onerror=window.__expectedInjected=true>':'worker-expected-east',state:'missing',reason:'No matching registration; inspect deployment and database access.',registered:false,age_seconds:null},{id:'worker-expected-west',state:'stale',reason:'Heartbeat expired; outcomes unknown.',registered:true,age_seconds:180}]:[],expectation_error:expectationError,more:!empty&&offset!=='50',fresh_seconds:120,gaps:['Only self-reported loops; operational readiness is not assessed.','Configured expected worker identities are listed; controllers, endpoint agents and GCP integration nodes remain outside this inventory.']}});};
 const control=route=>{submitted.push(route.request().postDataJSON());if(conflict)return route.fulfill({status:409,json:{detail:'Worker boot changed; refresh before controlling it'}});desired=submitted.at(-1).action;revision++;return route.fulfill({json:{ok:true,revision,action:desired}});};
 await page.route('**/api/operations/workers/control',control);
 await page.route('**/api/identity',identity);await page.route('**/api/operations/workers?*',workers);
 try{
  await page.goto(new URL('/#activity',page.url()).href);
  await page.getByRole('link',{name:'Workers',exact:true}).click();await page.getByRole('heading',{name:'Registered runtimes',exact:true}).waitFor();
  assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.evaluate(()=>window.__workerInjected),undefined);
  assert.equal(await page.locator('.worker-registry-table tbody tr').count(),3);
  await page.getByText('Controller/key startup check: verified at startup.',{exact:false}).waitFor();await page.getByText('Controller/key startup check: not enabled.',{exact:false}).waitFor();await page.getByText('Controller/key startup check: not reported.',{exact:false}).waitFor();
  await page.getByText('Schema structure / receipt protocol: verified at startup.',{exact:false}).waitFor();await page.getByText('Schema structure / receipt protocol: not enabled.',{exact:false}).waitFor();await page.getByText('Schema structure / receipt protocol: not reported.',{exact:false}).waitFor();
  assert.equal(await page.locator('#expected-workers img').count(),0);assert.equal(await page.evaluate(()=>window.__expectedInjected),undefined);
  await page.locator('#worker-next').click();await page.getByText('last-worker',{exact:true}).waitFor();
  await page.locator('#worker-prev').click();await page.getByText('worker-one',{exact:true}).waitFor();
  await page.getByRole('link',{name:'Operations & audit',exact:true}).click();await page.goBack();await page.getByRole('heading',{name:'Registered runtimes',exact:true}).waitFor();
  await page.reload();await page.getByText('worker-one',{exact:true}).waitFor();
  inject=false;await page.locator('#refresh-page').click();await page.getByText('worker-two',{exact:true}).waitFor();
  assert.equal(await page.locator('.worker-control').count(),1,'Stale/mismatched workers have no control');
  await page.getByRole('button',{name:'Drain worker',exact:true}).click();
  await page.locator('#worker-control-form textarea').fill('Planned maintenance window');
  await capture('worker-drain-review-desktop');
  await page.setViewportSize({width:320,height:1000});await capture('worker-drain-review-mobile');
  await page.locator('#worker-control-form button').evaluate(button=>{button.click();button.click();});
  await page.getByRole('button',{name:'Resume admission',exact:true}).waitFor();
  assert.equal(submitted.length,1);assert.equal(submitted[0].boot_id,'a'.repeat(32));assert.equal(submitted[0].worker_id,'worker-one');assert.equal(submitted[0].revision,0);assert.equal(submitted[0].action,'drain');
  await page.getByText('Requested revision 1 · observed 0',{exact:false}).first().waitFor();
  observed=1;workerState='draining';await page.locator('#refresh-page').click();await page.locator('.badge.draining').waitFor();
  conflict=true;await page.getByRole('button',{name:'Resume admission',exact:true}).click();await page.locator('#worker-control-form textarea').fill('Ready to accept work again');await page.getByRole('button',{name:'Request resume',exact:true}).click();
  await page.locator('#modal-message').filter({hasText:'Worker boot changed'}).waitFor();assert.equal(await page.locator('#worker-control-form').count(),1);await page.locator('#close-modal').click();
  conflict=false;await page.getByRole('button',{name:'Resume admission',exact:true}).click();await page.locator('#worker-control-form textarea').fill('Ready to accept work again');await page.getByRole('button',{name:'Request resume',exact:true}).click();await page.getByRole('button',{name:'Drain worker',exact:true}).waitFor();
  assert.equal(submitted.at(-1).revision,1);assert.equal(submitted.at(-1).action,'resume');
  for(const identity of ['.','..','Worker-A','worker-a']){
   workerId=identity;desired='resume';revision=0;observed=0;workerState='reporting';
   await page.locator('#refresh-page').click();await page.locator('.worker-registry-table tbody tr').first().getByText(identity,{exact:true}).waitFor();
   await page.getByRole('button',{name:'Drain worker',exact:true}).click();await page.locator('#worker-control-form textarea').fill('Exact identity control check');await page.getByRole('button',{name:'Request drain',exact:true}).click();await page.getByRole('button',{name:'Resume admission',exact:true}).waitFor();
   assert.equal(submitted.at(-1).worker_id,identity);assert.equal(submitted.at(-1).boot_id,'a'.repeat(32));assert.equal(submitted.at(-1).revision,0);
  }
  workerId='worker-one';desired='resume';revision=2;observed=1;workerState='draining';await page.locator('#refresh-page').click();await page.getByText('worker-one',{exact:true}).waitFor();
  await page.locator('#toast').waitFor({state:'hidden'});
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('worker-registrations-'+width);await capture('expected-workers-'+width);await capture('worker-preflight-'+width);await capture('worker-schema-'+width);}
  expectationError='Expected-worker configuration is invalid.';await page.locator('#refresh-page').click();await page.locator('#expected-workers [role=alert]').filter({hasText:expectationError}).waitFor();expectationError=null;expectationsConfigured=false;await page.locator('#refresh-page').click();await page.getByRole('heading',{name:'Worker expectations not configured',exact:true}).waitFor();
  empty=true;await page.locator('#refresh-page').click();await page.getByRole('heading',{name:'No workers registered yet',exact:true}).waitFor();
  for(const nextRole of ['operator','viewer']){
   role=nextRole;const before=calls;await page.reload();await page.getByRole('heading',{name:'Administrator access required',exact:true}).waitFor();assert.equal(calls,before,'Unauthorized view must not fetch worker records');
  }
 }finally{await page.unroute('**/api/operations/workers/control',control);await page.unroute('**/api/identity',identity);await page.unroute('**/api/operations/workers?*',workers);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
