const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let injected=true;
 const status=route=>route.fulfill({json:{pending:3,active:2,queued:1,reported_capacity:4,ready:0,blocked:1,paused:1,hourly_limit:20,recent_attempts:2,worker_seen:now,enabled:true,reason:'backoff',message:'Transient or interrupted investigations are waiting for retry eligibility. Configuration failures require review.',retry_at:now+120,last_error:''}});
 const rows=route=>route.fulfill({json:[
  {id:'delayed',host_id:'fixture',evidence:{executable:'/srv/transient-task',uid:1000},verdict:'error',approved:false,last_seen:now,analysis:'OpenAI API HTTP 503. No assessment was accepted.',retry:{state:'deferred',attempts:2,next_at:now+120,reason:'Provider Retry-After is active; existing AI policy limits still apply.'}},
  {id:'blocked',host_id:'fixture',evidence:{executable:'/srv/configuration-review',uid:1000},verdict:'error',approved:false,last_seen:now,analysis:'API authentication failed. Check the saved key.',retry:{state:'blocked',attempts:1,next_at:0,reason:injected?'<img src=x onerror=window.__retryInjected=true> Review configuration; no automatic retry is scheduled.':'Review configuration; no automatic retry is scheduled.'}}
 ]});
 let retries=0;
 const retry=route=>{retries++;return route.fulfill({status:409,json:{detail:'Provider Retry-After is still active; retry after the displayed eligibility time.'}});};
 await page.route('**/api/investigation-status',status);await page.route('**/api/investigations',rows);await page.route('**/api/investigations/delayed/retry',retry);
 try{
  await page.goto(new URL('/#investigations',page.url()).href);
  await page.getByRole('heading',{name:'AI worker status',exact:true}).waitFor();
  await page.getByText('need review',{exact:false}).waitFor();
  await page.getByText('2 active investigations',{exact:false}).waitFor();
  await page.getByText('4 reported AI slots',{exact:false}).waitFor();
  await page.getByText('Retry: deferred',{exact:false}).waitFor();
  assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.evaluate(()=>window.__retryInjected),undefined);
  await page.locator('[data-action="retry-investigation"][data-id="delayed"]').click();
  await page.getByRole('status').filter({hasText:'Provider Retry-After is still active'}).waitFor();assert.equal(retries,1);
  injected=false;await page.reload();await page.getByText('Retry: blocked',{exact:false}).waitFor();
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await capture('ai-parallel-v1220-'+width);
  }
  await page.reload();await page.getByText('Retry: blocked',{exact:false}).waitFor();assert.equal(retries,1);
 }finally{
  await page.setViewportSize({width:1440,height:1000});
  await page.unroute('**/api/investigation-status',status);await page.unroute('**/api/investigations',rows);await page.unroute('**/api/investigations/delayed/retry',retry);
  await page.goto(new URL('/#overview',page.url()).href);
 }
};
