const assert=require('assert/strict');
// Server → Security lets administrators release failed automatic AI plan attempts for retry (#1036).
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let role='admin',failed=2,counts=0,retries=0,reply={released:2,remaining:0};
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const status={generated_at:now,enabled:true,state:'ready',awaiting:0,awaiting_truncated:false,oldest_awaiting_since:null,
  active_plan:null,latest_automatic:{state:'failed',created:now-3600},pacing:{mode:'rate',limit:null,used:null,remaining:null,next_at:null}};
 const statusRoute=route=>route.fulfill({json:status});
 const policyRoute=route=>route.request().method()==='GET'?route.fulfill({json:{enabled:true,auto_ai_plan:true,interval_hours:24,paths:['/tmp']}}):route.fallback();
 const count=route=>{counts++;assert.equal(route.request().method(),'GET');
  if(failed==='error')return route.fulfill({status:500,json:{detail:'boom'}});return route.fulfill({json:{failed}});};
 const retry=route=>{retries++;assert.equal(route.request().method(),'POST');assert.ok(route.request().headers()['x-csrf-token']);failed=reply.remaining;return route.fulfill({json:reply});};
 const identity=async route=>{const response=await route.fetch();return route.fulfill({response,json:{...await response.json(),role}});};
 const base='**/api/hosts/'+host+'/security/auto-plan-failed';
 await page.route('**/api/identity',identity);await page.route('**/api/hosts/*/security/auto-plan-status',statusRoute);
 await page.route('**/api/hosts/*/security/policy',policyRoute);await page.route(base,count);await page.route(base+'/retry',retry);
 const box=page.locator('#auto-plan-retry');
 try{
  await page.goto(new URL('/#servers/'+encodeURIComponent(host)+'/security',page.url()).href);await page.reload();
  await box.filter({hasText:'2 open incidents'}).waitFor();
  const text=await box.textContent();
  assert.match(text,/had their automatic AI plan attempt fail and will not be tried again automatically/);
  assert.match(text,/Retrying sends no provider request now/);
  assert.match(text,/AI pause, response holds and the shared AI start gates still apply/);
  // The Save button stays the policy form's first button.
  assert.equal(await page.locator('#security-policy-form button').first().textContent(),'Save scan policy');
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'no horizontal scroll at '+width);
   await box.scrollIntoViewIfNeeded();await capture('auto-plan-retry-'+width,false);
  }
  await page.setViewportSize({width:1440,height:1000});
  // A partial batch says more remain, and the count refreshes after the release.
  reply={released:2,remaining:1};const before=counts;
  await box.getByRole('button',{name:'Retry failed automatic plans'}).click();
  await page.getByText('Released 2 failed automatic plan attempts for retry; 1 still waiting, run it again',{exact:false}).waitFor();
  await box.filter({hasText:'1 open incident on this server had its automatic AI plan attempt fail'}).waitFor();
  assert.equal(retries,1);assert(counts>before,'the count is read again after a release');
  reply={released:1,remaining:0};
  await box.getByRole('button',{name:'Retry failed automatic plans'}).click();
  await page.getByText('Released 1 failed automatic plan attempt for retry',{exact:false}).waitFor();
  await box.waitFor({state:'hidden'});
  // Zero, malformed and failed counts never show the action.
  for(const value of [0,'<img src=x onerror=window.__retryInjected=true>',-3,'error']){
   failed=value;await page.reload();await page.locator('#auto-plan-status').getByText('Latest automatic attempt',{exact:false}).waitFor();
   await page.waitForTimeout(100);assert.equal(await box.isHidden(),true,'hidden for '+value);
  }
  assert.equal(await page.evaluate(()=>window.__retryInjected),undefined);
  // Operators cannot open Security, so they never request the count or see the action.
  role='operator';failed=2;const operatorBefore=counts;await page.reload();
  await page.getByText('Administrator access required',{exact:false}).waitFor();await page.waitForTimeout(300);
  assert.equal(counts,operatorBefore,'operators never request the failed count');
  assert.equal(await box.isVisible(),false);
 }finally{
  role='admin';
  await page.unroute('**/api/identity',identity);await page.unroute('**/api/hosts/*/security/auto-plan-status',statusRoute);
  await page.unroute('**/api/hosts/*/security/policy',policyRoute);await page.unroute(base,count);await page.unroute(base+'/retry',retry);
  await page.setViewportSize({width:1440,height:1000});
  // Restore the administrator shell so the next module does not inherit the operator render.
  await page.reload();await page.waitForFunction(()=>document.body.dataset.role==='admin');
 }
};
