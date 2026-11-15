const assert=require('assert/strict');
// Server → Security shows the read-only automatic AI plan status and mode-correct pacing (#922).
module.exports=async(page,capture)=>{
 const hosts=await page.evaluate(async()=>await(await fetch('/api/hosts')).json());const host=hosts[0];
 const now=Date.now()/1000;let status;
 const base={generated_at:now,enabled:true,state:'ready',awaiting:3,awaiting_truncated:false,oldest_awaiting_since:now-900,
  active_plan:{state:'queued',created:now-60},latest_automatic:{state:'failed',created:now-3600},
  pacing:{mode:'rate',limit:null,used:null,remaining:null,next_at:null}};
 const statusRoute=route=>status==='error'?route.fulfill({status:500,json:{detail:'boom'}}):route.fulfill({json:status});
 const policyRoute=route=>route.request().method()==='GET'?route.fulfill({json:{enabled:true,auto_ai_plan:true,interval_hours:24,paths:['/tmp']}}):route.fallback();
 await page.route('**/api/hosts/*/security/auto-plan-status',statusRoute);
 await page.route('**/api/hosts/*/security/policy',policyRoute);
 try{
  status=base;
  await page.goto(new URL('/#servers/'+host.id+'/security',page.url()).href);
  const notice=page.locator('#auto-plan-status');
  await notice.getByText('awaiting an automatic attempt',{exact:false}).waitFor();
  let text=await notice.innerText();
  assert.match(text,/Automatic plans can be requested for new detections on this server\./);
  assert.match(text,/3 open incidents awaiting an automatic attempt \(oldest updated .+\)/);
  assert.match(text,/A plan has been queued for this server since .+; the next one waits for it/);
  assert.match(text,/Latest automatic attempt: failed at /);
  assert.match(text,/No plan-specific hourly limit; the shared AI start gates/);
  assert.doesNotMatch(text,/ten per hour|Legacy fleet allowance/);
  // The help text no longer claims a fleet hourly cap in every mode.
  const help=await page.locator('#security-policy-form [name=auto_ai_plan]').evaluate(input=>input.closest('label').nextElementSibling.textContent);
  assert.match(help,/Legacy AI control mode also limits plan requests to ten per hour across the fleet; other modes are paced by the shared AI start gates\./);
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await notice.scrollIntoViewIfNeeded();
   await capture('auto-plan-status-'+width,false);
  }
  await page.setViewportSize({width:1440,height:1000});

  status={...base,state:'paused',awaiting:500,awaiting_truncated:true,active_plan:null,latest_automatic:null,
   pacing:{mode:'legacy',limit:10,used:10,remaining:0,next_at:now+600}};
  await page.reload();await notice.getByText('Legacy fleet allowance',{exact:false}).waitFor();
  text=await notice.innerText();
  assert.match(text,/AI is paused for this server, so no automatic plan is requested\./);
  assert.match(text,/500 or more open incidents awaiting/);
  assert.match(text,/Legacy fleet allowance: 10 of 10 plan requests used this hour · next free /);
  assert.doesNotMatch(text,/Latest automatic attempt|A plan has been/);

  status={...base,state:'ready',awaiting:0,oldest_awaiting_since:null,active_plan:null,latest_automatic:null};
  await page.reload();await notice.getByText('No open incidents await',{exact:false}).waitFor();

  // Untrusted values are escaped, never rendered as markup.
  status={...base,awaiting:'<img src=x onerror=window.__planInjected=true>',latest_automatic:{state:'<b>x</b>',created:now}};
  await page.reload();await notice.getByText('Latest automatic attempt',{exact:false}).waitFor();
  assert.equal(await notice.locator('img,b').count(),0);
  assert.equal(await page.evaluate(()=>window.__planInjected),undefined);

  // An unknown state or a failed load never implies that a plan will start.
  for(const value of [{...base,state:'surprise'},'error']){
   status=value;await page.reload();
   await notice.getByText('Status unavailable right now',{exact:false}).waitFor();
   assert.match(await notice.innerText(),/never means a plan will start/);
  }
 }finally{
  await page.unroute('**/api/hosts/*/security/auto-plan-status',statusRoute);
  await page.unroute('**/api/hosts/*/security/policy',policyRoute);
 }
};
