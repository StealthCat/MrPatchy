const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let role='admin',empty=false,calls=0,inject=true;
 const item=(id,state)=>({id,boot_id:'boot-fixture',role:'worker',deployment_type:'docker',version:state==='version_mismatch'?'0.7.0':'0.8.0',started:now-3600,heartbeat:now-(state==='stale'?180:15),uptime_seconds:3600,state,reason:state==='stale'?'Heartbeat expired; outcomes unknown.':state==='version_mismatch'?'Worker source version differs from the controller.':'Scheduler loop self-report; readiness not assessed.',coordinator:id==='worker-one',active_jobs:state==='stopped'?[]:['fixture-job'],active_polls:state==='stopped'?0:2,ai_active:false,job_capacity:2,poll_capacity:8,ai_capacity:1,readiness:'not_assessed'});
 const identity=async route=>{const response=await route.fetch();return route.fulfill({response,json:{...await response.json(),role}});};
 const workers=route=>{calls++;const offset=new URL(route.request().url()).searchParams.get('offset');return route.fulfill({json:{items:empty?[]:offset==='50'?[item('last-worker','stopped')]:[item('worker-one','reporting'),item(inject?'<img src=x onerror="window.__workerInjected=true">':'worker-two','stale'),item('worker-old-version','version_mismatch')],more:!empty&&offset!=='50',fresh_seconds:120,gaps:['Only self-reported loops; operational readiness is not assessed.','Expected but unregistered nodes remain outside this inventory.']}});};
 await page.route('**/api/identity',identity);await page.route('**/api/operations/workers?*',workers);
 try{
  await page.goto(new URL('/#activity',page.url()).href);
  await page.getByRole('link',{name:'Workers',exact:true}).click();await page.getByRole('heading',{name:'Registered runtimes',exact:true}).waitFor();
  assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.evaluate(()=>window.__workerInjected),undefined);
  assert.equal(await page.locator('.worker-registry-table tbody tr').count(),3);
  await page.locator('#worker-next').click();await page.getByText('last-worker',{exact:true}).waitFor();
  await page.locator('#worker-prev').click();await page.getByText('worker-one',{exact:true}).waitFor();
  await page.getByRole('link',{name:'Operations & audit',exact:true}).click();await page.goBack();await page.getByRole('heading',{name:'Registered runtimes',exact:true}).waitFor();
  await page.reload();await page.getByText('worker-one',{exact:true}).waitFor();
  inject=false;await page.locator('#refresh-page').click();await page.getByText('worker-two',{exact:true}).waitFor();
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('worker-registrations-'+width);}
  empty=true;await page.locator('#refresh-page').click();await page.getByRole('heading',{name:'No workers registered yet',exact:true}).waitFor();
  for(const nextRole of ['operator','viewer']){
   role=nextRole;const before=calls;await page.reload();await page.getByRole('heading',{name:'Administrator access required',exact:true}).waitFor();assert.equal(calls,before,'Unauthorized view must not fetch worker records');
  }
 }finally{await page.unroute('**/api/identity',identity);await page.unroute('**/api/operations/workers?*',workers);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
