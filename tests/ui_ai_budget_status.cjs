const assert=require('assert/strict');
// The AI worker status card shows the full daily-cap window (#876): cap, counted,
// settled, reserved, uncertain and remaining spend, calls awaiting reconciliation
// and whether the reset is authoritative.
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let mode='full';
 const base={pending:2,active:1,active_lease_expires_at:now+60,queued:1,reported_capacity:2,ready:1,blocked:0,paused:0,hourly_limit:20,recent_attempts:0,worker_seen:now,enabled:true,reason:'ready',message:'Pending behaviors are eligible; waiting for the next AI worker slot.',retry_at:null,last_error:'',eligible_unclaimed:0,admission:{mode:'daily_cap'}};
 const budget={mode:'daily_cap',enabled:true,timezone:'America/New_York',cap_usd:'10.00',counted_usd:'4.250000',settled_usd:'1.000000',reserved_usd:'0.750000',uncertain_usd:'2.500000',remaining_usd:'5.750000',unreconciled_call_count:2,oldest_unreconciled_reservation_at:now-1800,next_reset:now+7200,next_reset_authoritative:true};
 const payload=()=>mode==='full'?{...base,budget}:
  mode==='recheck'?{...base,budget:{...budget,unreconciled_call_count:0,oldest_unreconciled_reservation_at:null,next_reset_authoritative:false}}:
  mode==='disabled'?{...base,budget:{...budget,enabled:false}}:
  {...base,budget:{...budget,cap_usd:'<img src=x onerror=window.__budgetInjected=true>',reserved_usd:null,remaining_usd:-1,timezone:'<b>zone</b>',unreconciled_call_count:'<i>2</i>',next_reset:'soon'}};
 const status=route=>route.fulfill({json:payload()});
 const rows=route=>route.fulfill({json:[]});
 await page.route('**/api/investigation-status',status);await page.route('**/api/investigations?*',rows);
 try{
  await page.goto(new URL('/#investigations',page.url()).href);await page.reload();
  const card=page.locator('#content .card').filter({has:page.getByRole('heading',{name:'AI worker status',exact:true})});
  const section=card.locator('[data-ai-budget-status]');
  await section.getByRole('heading',{name:'Daily AI spend cap'}).waitFor();
  const facts=await section.locator('.status-facts').innerText();
  for(const expected of [/\$10\.00\s+cap/,/\$4\.250000\s+counted/,/\$1\.000000\s+settled/,/\$0\.750000\s+reserved/,/\$2\.500000\s+uncertain/,/\$5\.750000\s+remaining/])assert.match(facts,expected);
  const text=await section.innerText();
  assert.match(text,/Resets .+ \(America\/New_York\)\./);
  assert.doesNotMatch(text,/recheck boundary/);
  const pending=section.locator('[data-ai-budget-unreconciled]');
  assert.match(await pending.innerText(),/2 transmitted AI calls await reconciliation\. Oldest reservation /);
  assert.match(await pending.innerText(),/stays counted until a usage receipt reconciles them/);
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await capture('ai-budget-status-'+width);
  }
  await page.setViewportSize({width:1440,height:1000});
  mode='recheck';await page.reload();
  await section.getByText('only a recheck boundary',{exact:false}).waitFor();
  assert.equal(await section.locator('[data-ai-budget-unreconciled]').count(),0);
  mode='disabled';await page.reload();
  await card.getByText('2 pending',{exact:false}).waitFor();
  assert.equal(await card.locator('[data-ai-budget-status]').count(),0);
  mode='malformed';await page.reload();
  await section.getByRole('heading',{name:'Daily AI spend cap'}).waitFor();
  const malformed=await section.innerText();
  assert.match(malformed,/Unavailable\s+cap/);
  assert.match(malformed,/Unavailable\s+reserved/);
  assert.match(malformed,/Unavailable\s+remaining/);
  assert.match(malformed,/\$4\.250000\s+counted/);
  assert.match(malformed,/Next reset unavailable\./);
  assert.match(malformed,/Calls awaiting reconciliation: Unavailable\./);
  assert.equal(await section.locator('img, b, i').count(),0);
  assert.equal(await page.evaluate(()=>window.__budgetInjected),undefined);
 }finally{
  await page.unroute('**/api/investigation-status',status);await page.unroute('**/api/investigations?*',rows);
 }
};
