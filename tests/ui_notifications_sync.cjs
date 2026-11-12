const assert=require('assert/strict');

// Live-update state and last-synchronized time in the notification panel (#719).
module.exports=async(page,capture)=>{
  let fail=false;
  const count=route=>fail?route.fulfill({status:503,json:{detail:'Temporarily unavailable'}}):route.fulfill({json:{unread:0}});
  const list=route=>fail?route.fulfill({status:503,json:{detail:'Temporarily unavailable'}}):route.fulfill({json:{items:[],offset:0,limit:8,total:0,more:false}});
  await page.route('**/api/notifications/unread-count',count);
  await page.route(/\/api\/notifications\?/,list);
  const sync=page.locator('#notification-sync');
  const text=async()=>(await sync.textContent()).replace(/\s+/g,' ');

  await page.evaluate(()=>{
   window.NotificationShell.reset();window.notificationStreams=[];
   window.EventSource=class{
    constructor(url){this.url=url;this.listeners={};this.closed=false;window.notificationStreams.push(this);}
    addEventListener(name,listener){(this.listeners[name]??=[]).push(listener);}
    emit(name){for(const listener of this.listeners[name]||[])listener({lastEventId:'a'.repeat(64)});}
    close(){this.closed=true;}
   };
  });
  assert.match(await text(),/Live updates: Not started\. Not yet synchronized\./,'reset shows no state and no sync time');

  await page.evaluate(()=>window.NotificationShell.start());
  await page.waitForFunction(()=>window.notificationStreams.length===1);
  await page.waitForFunction(()=>/Last synchronized/.test(document.getElementById('notification-sync').textContent));
  assert.match(await text(),/Live updates: Connecting\./,'stream not yet open is not reported live');
  assert.match(await text(),/not collector, agent or AI health/);
  const stamp=await sync.locator('.notification-sync-time').getAttribute('title');
  assert.ok(Math.abs(Date.parse(stamp)-Date.now())<60000,'last sync time is the authoritative refresh time');

  await page.evaluate(()=>window.notificationStreams[0].onopen());
  assert.match(await text(),/Live updates: Live\./);
  assert.equal(await sync.getAttribute('data-state'),'live');

  await page.evaluate(()=>window.notificationStreams[0].onerror());
  assert.match(await text(),/Live updates: Reconnecting\./);
  assert.match(await text(),/Last synchronized/,'last sync time is retained while reconnecting');

  fail=true;
  await page.evaluate(()=>window.NotificationShell.refresh());
  await page.waitForFunction(()=>document.getElementById('notification-sync').dataset.state==='delayed');
  assert.match(await text(),/Live updates: Delayed \(reconnecting\)\./);
  assert.equal(await sync.locator('.notification-sync-time').getAttribute('title'),stamp,'a failed refresh does not advance the sync time');

  fail=false;
  await page.evaluate(()=>window.notificationStreams[0].emit('notifications'));
  await page.waitForFunction(()=>document.getElementById('notification-sync').dataset.state==='live');
  assert.match(await text(),/Live updates: Live\. Last synchronized/,'a delivered event and successful catch-up restore live state');

  // A refused stream (HTTP 429 at capacity, proxy 502/503) is CLOSED and never retried by the browser.
  await page.evaluate(()=>{const s=window.notificationStreams[0];s.readyState=2;s.onerror();});
  assert.match(await text(),/Live updates: Unavailable, polling only\./,'a permanently failed stream is not reported as reconnecting');
  assert.equal(await sync.getAttribute('data-state'),'unavailable');
  assert.ok(await page.evaluate(()=>window.notificationStreams[0].closed),'the refused stream is released');
  await page.evaluate(()=>window.NotificationShell.refresh());
  await page.waitForFunction(()=>/Last synchronized/.test(document.getElementById('notification-sync').textContent));
  assert.equal(await page.evaluate(()=>window.notificationStreams.length),1,'no immediate reconnect storm before the retry delay');
  assert.match(await text(),/Live updates: Unavailable, polling only\./);
  await page.evaluate(()=>{window.__realNow=Date.now;Date.now=()=>window.__realNow()+31000;});
  await page.evaluate(()=>window.NotificationShell.refresh());
  await page.waitForFunction(()=>window.notificationStreams.length===2);
  await page.evaluate(()=>{Date.now=window.__realNow;});
  assert.match(await text(),/Live updates: Connecting\./,'a successful poll after the retry delay retries the stream once');
  await page.evaluate(()=>window.notificationStreams[1].onopen());
  assert.match(await text(),/Live updates: Live\./,'capacity relief restores live delivery');

  await page.getByRole('button',{name:/Notifications/}).click();
  await sync.waitFor();
  await capture('notification-sync');
  await page.keyboard.press('Escape');

  await page.evaluate(()=>{window.NotificationShell.reset();window.__savedEventSource=window.EventSource;delete window.EventSource;window.NotificationShell.start();});
  await page.waitForFunction(()=>/Last synchronized/.test(document.getElementById('notification-sync').textContent));
  assert.match(await text(),/Live updates: Polling only\./,'no EventSource reports polling-only coverage');

  await page.evaluate(()=>{window.NotificationShell.reset();window.EventSource=window.__savedEventSource;});
  assert.match(await text(),/Live updates: Not started\. Not yet synchronized\./,'logout/reset clears state and sync time');
  await page.unroute('**/api/notifications/unread-count',count);
  await page.unroute(/\/api\/notifications\?/,list);
};
