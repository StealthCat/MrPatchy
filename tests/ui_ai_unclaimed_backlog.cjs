const assert=require('assert/strict');
// The AI worker status card renders the eligible-unclaimed backlog (#678).
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let mode='present';
 const base={pending:5,active:1,active_lease_expires_at:now+60,queued:4,reported_capacity:2,ready:3,blocked:0,paused:0,hourly_limit:20,recent_attempts:1,worker_seen:now,enabled:true,reason:'ready',message:'Pending behaviors are eligible; waiting for the next AI worker slot.',retry_at:null,last_error:''};
 const status=route=>route.fulfill({json:mode==='present'?{...base,eligible_unclaimed:3,oldest_eligible_unclaimed_observation_at:now-(2*3600+5*60+10)}:
  mode==='empty'?{...base,eligible_unclaimed:0,oldest_eligible_unclaimed_observation_at:null}:
  {...base,eligible_unclaimed:'<img src=x onerror=window.__unclaimedInjected=true>',oldest_eligible_unclaimed_observation_at:'<b>bad</b>'}});
 const rows=route=>route.fulfill({json:[]});
 await page.route('**/api/investigation-status',status);await page.route('**/api/investigations?*',rows);
 try{
  // A same-hash goto does not re-render; reload so this fixture is what is shown.
  await page.goto(new URL('/#investigations',page.url()).href);await page.reload();
  const card=page.locator('#content .card').filter({has:page.getByRole('heading',{name:'AI worker status',exact:true})});
  await card.getByText('5 pending',{exact:false}).waitFor();
  assert.match(await card.locator('.status-facts').innerText(),/3\s+eligible, unclaimed/);
  const oldest=card.locator('p.help').filter({hasText:'Oldest eligible unclaimed observation:'});
  await oldest.waitFor();
  const text=await oldest.innerText();
  assert.match(text,/about 2h 5m ago/);
  assert.match(text,/observation age, not time since it became eligible/);
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await capture('ai-unclaimed-backlog-'+width);
  }
  await page.setViewportSize({width:1440,height:1000});
  mode='empty';await page.reload();
  await card.getByText('0 eligible, unclaimed',{exact:false}).waitFor();
  assert.match(await card.locator('.status-facts').innerText(),/0\s+eligible, unclaimed/);
  assert.equal(await card.getByText('Oldest eligible unclaimed observation:',{exact:false}).count(),0);
  mode='malformed';await page.reload();
  await card.getByText('Unavailable eligible, unclaimed',{exact:false}).waitFor();
  assert.match(await card.locator('.status-facts').innerText(),/Unavailable\s+eligible, unclaimed/);
  assert.equal(await card.getByText('Oldest eligible unclaimed observation:',{exact:false}).count(),0);
  assert.equal(await page.locator('#content img[src=x]').count(),0);
  assert.equal(await page.evaluate(()=>window.__unclaimedInjected),undefined);
 }finally{
  await page.unroute('**/api/investigation-status',status);await page.unroute('**/api/investigations?*',rows);
 }
};
