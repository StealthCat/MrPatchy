const assert=require('assert/strict');
// Fleet Security page: automatic AI plan status across opted-in servers (#936). Read-only, admin-only, contained failures.
module.exports=async(page,capture)=>{
 const now=Math.floor(Date.now()/1000),originalViewport=page.viewportSize();
 let mode='fail',reads=0,gateReads=0;
 const gatesRoute=route=>{
  assert.equal(route.request().method(),'GET');
  gateReads++;
  return route.fulfill({json:{mode:'rate_and_daily',can_start_now:false,next_start_at:null,blockers:[
   {code:'daily_cap',message:'Prior windows still carry spend.',recheck_at:now+1800},
   {code:'pricing',message:'The catalog price is missing. <b>fixture tag</b>'},
  ]}});
 };
 const items=[
  {host_id:'auto host/1',host_name:'Alpha <b>bold</b>',enabled:true,state:'ready',awaiting:3,awaiting_truncated:false,oldest_awaiting_since:now-900,active_plan:{state:'queued',created:now-60},latest_automatic:{state:'failed',created:now-7200}},
  {host_id:'auto-host-2',host_name:'Bravo',enabled:true,state:'paused',awaiting:500,awaiting_truncated:true,oldest_awaiting_since:now-86400,active_plan:null,latest_automatic:null},
  {host_id:'auto-host-3',host_name:'Charlie',enabled:true,state:'<img src=x onerror=window.__autoPlanInjected=true>',awaiting:0,awaiting_truncated:false,oldest_awaiting_since:null,active_plan:null,latest_automatic:{state:'<script>x</script>',created:now-30}}];
 const handler=async route=>{
  if(route.request().method()!=='GET')throw new Error('automatic plan status must not write');
  reads++;
  if(mode==='fail')return route.fulfill({status:500,json:{detail:'Internal <script>fixture</script> details'}});
  if(mode==='empty')return route.fulfill({json:{generated_at:now,items:[],truncated:false,totals:{servers:0,ready:0,awaiting:0,awaiting_truncated:false,active_plans:0},pacing:{mode:'rate',limit:null,used:null,remaining:null,next_at:null}}});
  if(mode==='malformed')return route.fulfill({json:{items:'broken'}});
  const legacy=mode==='legacy';
  return route.fulfill({json:{generated_at:now,items,truncated:legacy,totals:{servers:3,ready:1,awaiting:503,awaiting_truncated:true,active_plans:1},
   pacing:legacy?{mode:'legacy',limit:10,used:10,remaining:0,next_at:now+600}:{mode:'rate_and_daily',limit:null,used:null,remaining:null,next_at:null}}});
 };
 await page.route('**/api/security/auto-plan-status',handler);
 await page.route('**/api/settings/ai-control-status',gatesRoute);
 const card=page.locator('#fleet-auto-plans');
 const open=async()=>{await page.goto(new URL('/#overview',page.url()).href);await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();await page.goto(new URL('/#security',page.url()).href);await page.getByRole('heading',{name:'Automatic AI plans across the fleet'}).waitFor();};
 try{
  await open();
  await card.getByRole('alert').filter({hasText:'Automatic AI plan status is unavailable right now. This never means a plan will start'}).waitFor();
  assert.equal(await card.getByText('Internal',{exact:false}).count(),0,'server error details are not shown');
  assert.equal(await page.locator('#coverage-search').isVisible(),true,'the coverage list stays usable');
  mode='populated';await card.getByRole('button',{name:'Retry automatic plan status'}).click();
  await card.getByText('No scheduled shared start.',{exact:false}).waitFor();
  assert.match(await card.innerText(),/Recheck at .+\. This is not a promised start/);
  assert.match(await card.innerText(),/No scheduled end\. An administrator must change this/);
  assert.match(await card.innerText(),/The catalog price is missing\. <b>fixture tag<\/b>/);
  assert.deepEqual(await card.locator('.status-facts span').allTextContents(),['3Servers opted in','1Ready','503+Incidents awaiting an attempt','1Plan jobs queued or running']);
  assert.match(await card.textContent(),/No plan-specific hourly limit; the shared AI start gates/);
  const rows=card.locator('.fleet-auto-plans-list > li');assert.equal(await rows.count(),3);
  const link=rows.nth(0).getByRole('link',{name:'Alpha <b>bold</b>'});
  assert.equal(await link.getAttribute('href'),'#servers/auto%20host%2F1/security');
  assert.match(await rows.nth(0).textContent(),/Ready3 awaiting · oldest updated .+ · Plan queued since .+ · Latest automatic attempt: failed at /);
  assert.match(await rows.nth(1).textContent(),/AI paused500 or more awaiting · oldest updated .+ · No automatic attempt yet/);
  assert.match(await rows.nth(2).textContent(),/UnknownNothing awaiting · Latest automatic attempt: <script>x<\/script> at /);
  assert.equal(await card.locator('img,b,script').count(),0);
  assert.equal(await page.evaluate(()=>window.__autoPlanInjected),undefined);
  assert.match(await card.textContent(),/Plans are proposals for review and never execute automatically/);
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true,'no horizontal scroll at '+width);
   await card.scrollIntoViewIfNeeded();await capture('fleet-auto-plans-'+width);
  }
  await page.setViewportSize(originalViewport);
  mode='legacy';await card.getByRole('button',{name:'Refresh automatic plan status'}).click();
  await card.getByText('Only the first 3 opted-in servers are shown',{exact:false}).waitFor();
  assert.match(await card.textContent(),/Legacy fleet allowance: 10 of 10 plan requests used this hour · next free /);
  assert.equal(await card.locator('[data-auto-plan-gates]').count(),0);
  assert.equal(gateReads,1,'one timing snapshot for all visible servers, none in legacy mode');
  mode='empty';await card.getByRole('button',{name:'Refresh automatic plan status'}).click();
  await card.getByText('No server has automatic AI plans enabled.',{exact:false}).waitFor();
  mode='malformed';await card.getByRole('button',{name:'Refresh automatic plan status'}).click();
  await card.getByText('Automatic AI plan status is unavailable in this response.',{exact:false}).waitFor();
  assert.equal(reads,5,'each load and refresh reads the endpoint once');
 }finally{
  await page.unroute('**/api/security/auto-plan-status',handler);
  await page.unroute('**/api/settings/ai-control-status',gatesRoute);
  await page.setViewportSize(originalViewport);
  await page.goto(new URL('/#overview',page.url()).href);
  await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
 }
};
