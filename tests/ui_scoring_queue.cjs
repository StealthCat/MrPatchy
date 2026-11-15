const assert=require('assert/strict');
// Settings → AI shows the read-only update-scoring queue summary (#917).
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let queue;
 const base={generated_at:now,scheduler:'enabled',current_updates:9,unscored:7,paused_server_updates:2,
  counts:{eligible:3,retry_wait:1,deferred:1,blocked:1,running:1,complete:2},
  next_eligible_at:now+900,oldest_waiting_since:now-7200,limitations:[]};
 const settingsRoute=async route=>{
  if(route.request().method()!=='GET')return route.continue();
  const response=await route.fetch();const json=await response.json();
  return route.fulfill({response,json:{...json,ai_scoring_queue:queue}});
 };
 await page.route('**/api/settings',settingsRoute);
 try{
  queue=base;
  await page.goto(new URL('/#settings/ai',page.url()).href);await page.reload();
  const notice=page.locator('#scoring-queue');
  await notice.waitFor();
  const text=await notice.innerText();
  assert.match(text,/9 current pending updates: 2 scored · 1 running · 3 eligible now · 1 deferred by shared admission · 1 waiting for the hourly retry · 1 blocked · 2 on AI-paused servers \(not queued\)/);
  assert.match(text,/Oldest unscored since .+ · next timed eligibility /);
  assert.match(text,/Shared start gates, per-server pause and the daily cap still decide when a batch starts\. Scores are advisory\./);
  // The notice sits with the update-scoring toggle, not in the budget notice.
  assert.equal(await page.locator('input[name=ai_updates_enabled]').evaluate(input=>{
   const help=input.closest('label').nextElementSibling;return help.nextElementSibling?.id;}),'scoring-queue');
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await notice.scrollIntoViewIfNeeded();
   await capture('scoring-queue-'+width,false);
  }
  await page.setViewportSize({width:1440,height:1000});

  queue={...base,scheduler:'scoring_disabled',current_updates:1,unscored:0,paused_server_updates:0,
   counts:{eligible:0,retry_wait:0,deferred:0,blocked:0,running:0,complete:1},next_eligible_at:null,oldest_waiting_since:null};
  await page.reload();await notice.waitFor();
  const stopped=await notice.innerText();
  assert.match(stopped,/1 current pending update: 1 scored/);
  assert.doesNotMatch(stopped,/Oldest unscored|AI-paused/);
  assert.match(stopped,/Automatic update scoring is off, so no scoring batch starts\./);

  // Untrusted values are escaped, never rendered as markup.
  queue={...base,current_updates:'<img src=x onerror=window.__queueInjected=true>',counts:{...base.counts,eligible:'<b>x</b>'}};
  await page.reload();await notice.waitFor();
  assert.equal(await notice.locator('img,b').count(),0);
  assert.equal(await page.evaluate(()=>window.__queueInjected),undefined);

  // Without the summary nothing is shown.
  queue=undefined;await page.reload();
  await page.locator('input[name=ai_updates_enabled]').waitFor();
  assert.equal(await page.locator('#scoring-queue').count(),0);
 }finally{await page.unroute('**/api/settings',settingsRoute);}
};
