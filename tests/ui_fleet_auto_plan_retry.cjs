const assert=require('assert/strict');
// Security coverage → Automatic AI plans across the fleet: fleet-wide release of failed automatic attempts (#1251).
module.exports=async(page,capture)=>{
 const now=Math.floor(Date.now()/1000),originalViewport=page.viewportSize();
 let role='admin',failed=3,counts=0,retries=0,statusReads=0,reply={released:2,remaining:1};
 const status=route=>{statusReads++;return route.fulfill({json:{generated_at:now,items:[],truncated:false,totals:{servers:0,ready:0,awaiting:0,awaiting_truncated:false,active_plans:0},pacing:{mode:'rate',limit:null,used:null,remaining:null,next_at:null}}});};
 const count=route=>{counts++;assert.equal(route.request().method(),'GET');
  if(failed==='error')return route.fulfill({status:500,json:{detail:'Internal <script>x</script>'}});return route.fulfill({json:{failed}});};
 const retry=route=>{retries++;assert.equal(route.request().method(),'POST');assert.ok(route.request().headers()['x-csrf-token']);failed=reply.remaining;return route.fulfill({json:reply});};
 const hostRoutes=route=>{throw new Error('the fleet action must not use per-server routes: '+route.request().url());};
 // A navigation can cancel an in-flight identity read; ignore the stale route.
 const identity=async route=>{try{const response=await route.fetch();await route.fulfill({response,json:{...await response.json(),role}});}catch(error){if(!/already handled|closed|cancel/i.test(String(error)))throw error;}};
 await page.route('**/api/identity',identity);await page.route('**/api/security/auto-plan-status',status);
 await page.route('**/api/security/auto-plan-failed',count);await page.route('**/api/security/auto-plan-failed/retry',retry);
 await page.route('**/api/hosts/*/security/auto-plan-failed**',hostRoutes);
 const card=page.locator('#fleet-auto-plans'),box=card.locator('.fleet-auto-plan-retry');
 const open=async()=>{await page.goto(new URL('/#overview',page.url()).href);await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();await page.goto(new URL('/#security',page.url()).href);await page.getByRole('heading',{name:'Security coverage'}).first().waitFor();};
 try{
  await open();
  await box.filter({hasText:'3 open incidents'}).waitFor();
  const text=await box.textContent();
  assert.match(text,/across enabled servers had their automatic AI plan attempt fail and will not be tried again automatically/);
  assert.match(text,/Fix the cause first/);
  assert.match(text,/Retrying sends no provider request now/);
  assert.match(text,/AI pause, response holds and the shared AI start gates still apply/);
  assert.match(text,/Disabled servers are not included/);
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'no horizontal scroll at '+width);
   await box.scrollIntoViewIfNeeded();await capture('fleet-auto-plan-retry-'+width,false);
  }
  await page.setViewportSize(originalViewport);
  // A partial batch says more remain; the count and the status card are both read again.
  const beforeCounts=counts,beforeStatus=statusReads;
  await box.getByRole('button',{name:'Retry failed automatic plans'}).click();
  await page.getByText('Released 2 failed automatic plan attempts for retry; 1 still waiting, run it again',{exact:false}).waitFor();
  await box.filter({hasText:'1 open incident across enabled servers had its automatic AI plan attempt fail'}).waitFor();
  assert.equal(retries,1);assert(counts>beforeCounts,'the count is read again after a release');
  assert(statusReads>beforeStatus,'the automatic plan status is refreshed after a release');
  reply={released:1,remaining:0};
  await box.getByRole('button',{name:'Retry failed automatic plans'}).click();
  await page.getByText('Released 1 failed automatic plan attempt for retry',{exact:false}).waitFor();
  await box.waitFor({state:'hidden'});
  // Nothing released says so and hides the action once the count is zero.
  failed=1;reply={released:0,remaining:0};await open();await box.filter({hasText:'1 open incident'}).waitFor();
  await box.getByRole('button',{name:'Retry failed automatic plans'}).click();
  await page.getByText('Nothing was released; the attempts may have changed',{exact:false}).waitFor();
  await box.waitFor({state:'hidden'});
  // Zero, malformed and failed counts never show the action.
  for(const value of [0,'<img src=x onerror=window.__fleetRetryInjected=true>',-3,2.5,'error']){
   failed=value;const before=counts;await open();
   await card.getByText('No server has automatic AI plans enabled.',{exact:false}).waitFor();
   for(let n=0;n<50&&counts===before;n++)await page.waitForTimeout(20);
   assert(counts>before,'the count was read for '+value);
   await page.waitForTimeout(50);
   assert.equal(await box.isHidden(),true,'hidden for '+value);
  }
  assert.equal(await page.evaluate(()=>window.__fleetRetryInjected),undefined);
  assert.equal(await card.getByText('Internal',{exact:false}).count(),0);
  // Operators never see the fleet card or request the count.
  role='operator';failed=2;const operatorBefore=counts;
  await page.goto(new URL('/#security',page.url()).href);await page.reload();await page.waitForFunction(()=>document.body.dataset.role==='operator');
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(300);
  assert.equal(counts,operatorBefore,'operators never request the fleet failed count');
  assert.equal(await card.count(),0);
 }finally{
  role='admin';
  await page.unroute('**/api/identity',identity);await page.unroute('**/api/security/auto-plan-status',status);
  await page.unroute('**/api/security/auto-plan-failed',count);await page.unroute('**/api/security/auto-plan-failed/retry',retry);
  await page.unroute('**/api/hosts/*/security/auto-plan-failed**',hostRoutes);
  await page.setViewportSize(originalViewport);
  await page.reload();await page.waitForFunction(()=>document.body.dataset.role==='admin');
  await page.goto(new URL('/#overview',page.url()).href);
  await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
 }
};
