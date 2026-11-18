const assert=require('assert/strict');
// Fleet AI activity shows the read-only update-scoring queue summary (#926),
// rendered by the same function as Settings → AI (#917).
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let queue,calls=0,release=null;
 const base={scheduler:'enabled',current_updates:9,unscored:7,paused_server_updates:2,
  counts:{eligible:3,retry_wait:1,deferred:1,blocked:1,running:1,complete:2},
  next_eligible_at:now+900,oldest_waiting_since:now-7200,limitations:[]};
 const pattern='**/api/update-scores/status';
 const handler=async route=>{calls++;
  if(release){await release;}
  return queue==='error'?route.fulfill({status:500,json:{detail:'internal fixture detail'}}):route.fulfill({json:queue});};
 await page.route(pattern,handler);
 const open=async()=>{await page.goto(new URL('/#ai-logs',page.url()).href);await page.reload();};
 const notice=page.locator('#ai-scoring-queue');
 try{
  queue=base;await open();
  await notice.getByText('current pending updates',{exact:false}).waitFor();
  const text=await notice.innerText();
  assert.match(text,/9 current pending updates: 2 scored · 1 running · 3 eligible now · 1 deferred by shared admission · 1 waiting for the hourly retry · 1 blocked · 2 on AI-paused servers \(not queued\)/);
  assert.match(text,/Oldest unscored since .+ · next timed eligibility /);
  assert.match(text,/Shared start gates, per-server pause and the daily cap still decide when a batch starts\. Scores are advisory\./);
  assert.equal(await notice.getAttribute('role'),'status');
  // The page itself (run table) loads independently of the summary.
  await page.locator('#ai-log-table').waitFor();
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await notice.scrollIntoViewIfNeeded();
   await capture('ai-activity-scoring-queue-'+width,false);
  }
  await page.setViewportSize({width:1440,height:1000});

  // Same text as Settings → AI for the same reply (one shared renderer).
  await page.goto(new URL('/#settings/ai',page.url()).href);await page.reload();
  const settings=page.locator('#scoring-queue');
  await settings.getByText('current pending updates',{exact:false}).waitFor();
  assert.equal(await settings.innerText(),text);

  queue={...base,scheduler:'ai_disabled',current_updates:1,unscored:0,paused_server_updates:0,
   counts:{eligible:0,retry_wait:0,deferred:0,blocked:0,running:0,complete:1},next_eligible_at:null,oldest_waiting_since:null};
  await open();await notice.getByText('current pending update',{exact:false}).waitFor();
  const stopped=await notice.innerText();
  assert.match(stopped,/1 current pending update: 1 scored/);
  assert.doesNotMatch(stopped,/Oldest unscored|AI-paused/);
  assert.match(stopped,/Central AI provider calls are disabled, so no scoring batch starts\./);

  // Untrusted values are escaped, never rendered as markup.
  queue={...base,current_updates:'<img src=x onerror=window.__aiQueueInjected=true>',counts:{...base.counts,eligible:'<b>x</b>'}};
  await open();await notice.getByText('eligible now',{exact:false}).waitFor();
  assert.equal(await notice.locator('img,b').count(),0);
  assert.equal(await page.evaluate(()=>window.__aiQueueInjected),undefined);

  // A failed summary says so, hides server detail and never implies scoring may start.
  queue='error';await open();
  await notice.getByText('Unavailable right now',{exact:false}).waitFor();
  assert.match(await notice.innerText(),/never means scoring may start/);
  assert.doesNotMatch(await notice.innerText(),/internal fixture detail/);

  // A reply arriving after navigation away is ignored and never written elsewhere.
  queue=base;let let_go;release=new Promise(r=>let_go=r);
  const before=calls;await open();
  for(let i=0;i<50&&calls===before;i++)await page.waitForTimeout(20);
  assert.equal(await notice.innerText(),'Scoring queue · Loading…');
  await page.locator('[data-nav=overview]').click();
  await page.waitForFunction(()=>location.hash==='#overview'&&!document.querySelector('#ai-scoring-queue'));
  let_go();release=null;await page.waitForTimeout(200);
  assert.equal(await page.locator('#ai-scoring-queue').count(),0);
  assert.equal(await page.getByText('current pending updates',{exact:false}).count(),0);
 }finally{release=null;await page.unroute(pattern,handler);}
};
