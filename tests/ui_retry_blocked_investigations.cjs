const assert=require('assert/strict');
// Fleet Investigations offers one administrator retry for every investigation
// blocked under the current AI configuration (#934).
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let role='admin',blocked=2,retries=0,reply={retried:2,remaining:0,detail:'2 blocked investigations queued. AI pause, data sharing, shared rate and daily-cap admission still apply.'};
 const status=route=>route.fulfill({json:{pending:2,active:0,queued:0,ready:0,blocked,paused:0,hourly_limit:20,recent_attempts:0,worker_seen:now,enabled:true,reason:'blocked',message:'Investigations need configuration review, explicit retry or server AI resume. No automatic call is eligible.',retry_at:null,last_error:''}});
 const rows=route=>route.fulfill({json:[{id:'blocked-one',host_id:'fixture',evidence:{executable:'/srv/configuration-review',uid:1000},verdict:'error',approved:false,last_seen:now,analysis:'API authentication failed.',retry:{state:'blocked',attempts:1,next_at:0,reason:'Review configuration; no automatic retry is scheduled.'}}]});
 const retry=route=>{retries++;assert.equal(route.request().method(),'POST');blocked=reply.remaining;return route.fulfill({json:reply});};
 const identity=async route=>{const response=await route.fetch();return route.fulfill({response,json:{...await response.json(),role}});};
 await page.route('**/api/identity',identity);await page.route('**/api/investigation-status',status);await page.route('**/api/investigations?*',rows);await page.route('**/api/investigations/blocked/retry',retry);
 try{
  await page.goto(new URL('/#investigations',page.url()).href);
  const button=page.getByRole('button',{name:'Retry blocked investigations',exact:true});
  await button.waitFor();
  assert.match(await page.locator('#retry-blocked-investigations').textContent(),/2 investigations are blocked .*No provider request is sent now/);
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await capture('retry-blocked-investigations-'+width);
  }
  await button.click();
  await page.getByRole('status').filter({hasText:'2 blocked investigations queued'}).waitFor();
  assert.equal(retries,1);
  // The view refreshes: with nothing left blocked the action disappears.
  await page.locator('#retry-blocked-investigations').waitFor({state:'detached'});
  // A partial batch keeps the action and reports the remainder.
  blocked=3;reply={retried:1,remaining:2,detail:'1 blocked investigation queued. 2 still blocked (running, waiting for provider Retry-After, or beyond this batch).'};
  await page.reload();await button.waitFor();
  assert.match(await page.locator('#retry-blocked-investigations').textContent(),/3 investigations are blocked/);
  await button.click();
  await page.getByRole('status').filter({hasText:'2 still blocked'}).waitFor();
  await page.locator('#retry-blocked-investigations',{hasText:'2 investigations are blocked'}).waitFor();
  assert.equal(retries,2);
  // Nothing blocked, or a malformed count, shows no action.
  for(const value of [0,'2',null]){
   blocked=value;await page.reload();await page.getByText('/srv/configuration-review',{exact:true}).waitFor();
   assert.equal(await page.locator('#retry-blocked-investigations').count(),0);
  }
  // Operators see the blocked queue but never the administrator action.
  role='operator';blocked=2;await page.reload();await page.getByText('/srv/configuration-review',{exact:true}).waitFor();
  assert.equal(await page.locator('#retry-blocked-investigations').count(),0);assert.equal(retries,2);
 }finally{
  role='admin';await page.unroute('**/api/identity',identity);
  await page.setViewportSize({width:1440,height:1000});
  await page.unroute('**/api/investigation-status',status);await page.unroute('**/api/investigations?*',rows);await page.unroute('**/api/investigations/blocked/retry',retry);
  await page.goto(new URL('/#overview',page.url()).href);await page.reload();
 }
};
