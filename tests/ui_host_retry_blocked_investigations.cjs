const assert=require('assert/strict');
// Server → Investigations offers administrators the blocked-investigation retry for that server only (#946).
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let role='admin',blocked=2,counts=0,retries=0,reply={retried:2,remaining:0,detail:'2 blocked investigations queued. AI pause, data sharing, shared rate and daily-cap admission still apply.'};
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const rows=route=>route.fulfill({json:[{id:'host-blocked-one',host_id:host,evidence:{executable:'/srv/host-configuration-review',uid:1000},verdict:'error',approved:false,last_seen:now,analysis:'API authentication failed.',retry:{state:'blocked',attempts:1,next_at:0,reason:'Review configuration; no automatic retry is scheduled.'}}]});
 const count=route=>{counts++;assert.equal(route.request().method(),'GET');return route.fulfill({json:{blocked}});};
 const retry=route=>{retries++;assert.equal(route.request().method(),'POST');assert.ok(route.request().headers()['x-csrf-token']);blocked=reply.remaining;return route.fulfill({json:reply});};
 const fleet=route=>{throw new Error('the server tab must not call the fleet retry');};
 const identity=async route=>{const response=await route.fetch();return route.fulfill({response,json:{...await response.json(),role}});};
 const base='**/api/hosts/'+host+'/investigations/blocked';
 await page.route('**/api/identity',identity);await page.route('**/api/investigations?*',rows);await page.route(base,count);await page.route(base+'/retry',retry);await page.route('**/api/investigations/blocked/retry',fleet);
 const panel=page.locator('#retry-blocked-investigations');
 try{
  await page.goto(new URL('/#servers/'+encodeURIComponent(host)+'/investigations',page.url()).href);await page.reload();
  await panel.filter({hasText:'2 investigations are blocked on this server'}).waitFor();
  assert.match(await panel.textContent(),/No provider request is sent now/);
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await capture('host-retry-blocked-investigations-'+width);
  }
  await page.setViewportSize({width:1440,height:1000});
  await panel.getByRole('button',{name:'Retry blocked investigations',exact:true}).click();
  await page.getByRole('status').filter({hasText:'2 blocked investigations queued'}).waitFor();
  assert.equal(retries,1);
  // The tab refreshes: with nothing left blocked on this server the action disappears.
  await panel.waitFor({state:'detached'});
  // A partial batch keeps the action and reports the remainder.
  blocked=3;reply={retried:1,remaining:2,detail:'1 blocked investigation queued. 2 still blocked (running, waiting for provider Retry-After, or beyond this batch).'};
  await page.reload();await panel.filter({hasText:'3 investigations are blocked on this server'}).waitFor();
  await panel.getByRole('button').click();
  await page.getByRole('status').filter({hasText:'2 still blocked'}).waitFor();
  await panel.filter({hasText:'2 investigations are blocked on this server'}).waitFor();
  assert.equal(retries,2);
  // One blocked investigation uses the singular; zero or a malformed count shows no action.
  blocked=1;await page.reload();await panel.filter({hasText:'1 investigation is blocked on this server'}).waitFor();
  for(const value of [0,'2',null]){
   blocked=value;await page.reload();await page.getByText('/srv/host-configuration-review',{exact:true}).waitFor();
   assert.equal(await panel.count(),0);
  }
  // A failed count read hides the action instead of breaking the tab.
  await page.unroute(base,count);const failing=route=>route.fulfill({status:500,json:{detail:'unavailable'}});await page.route(base,failing);
  await page.reload();await page.getByText('/srv/host-configuration-review',{exact:true}).waitFor();
  assert.equal(await panel.count(),0);
  await page.unroute(base,failing);await page.route(base,count);
  // Operators never request the administrator count or see the action.
  role='operator';blocked=2;const before=counts;await page.reload();await page.getByText('/srv/host-configuration-review',{exact:true}).waitFor();
  assert.equal(await panel.count(),0);assert.equal(counts,before);assert.equal(retries,2);
 }finally{
  role='admin';await page.unroute('**/api/identity',identity);
  await page.setViewportSize({width:1440,height:1000});
  await page.unroute('**/api/investigations?*',rows);await page.unroute(base,count);await page.unroute(base+'/retry',retry);await page.unroute('**/api/investigations/blocked/retry',fleet);
  await page.goto(new URL('/#overview',page.url()).href);await page.reload();
 }
};
