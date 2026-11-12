const assert=require('assert/strict');

// Two open tabs of one account: each new high/critical revision toasts in only
// one tab, including concurrent refreshes and a tab that catches up later.
module.exports=async(page)=>{
  // Both tabs share one signed-in browser context, cookies and localStorage.
  const origin=new URL(page.url()).origin;
  const context=await page.context().browser().newContext({viewport:{width:1440,height:1000},storageState:await page.context().storageState()});
  const items=[],arrivalLog=[],arrivalKeys=new Set();
  const event=(n,reason,revision=1,severity='critical')=>({id:n.toString(16).padStart(64,'0'),revision,source:'scanner',kind:'finding',subject_type:'scan',subject_id:'tab-'+n,host_id:'',severity,reason,deep_link:'#activity',lifecycle:'active',created:1700900000+n,read:false,dismissed:false});
  const sequence=()=>{for(const item of items){const key=item.id+'@'+item.revision;if(!arrivalKeys.has(key)){arrivalKeys.add(key);arrivalLog.push({id:item.id,revision:item.revision});}}};
  const tabs=[];
  for(let n=0;n<2;n++){
    const tab=await context.newPage();
    await tab.addInitScript(()=>{window.EventSource=class{constructor(){this.listeners={};}addEventListener(){}close(){}};});
    await tab.route('**/api/notifications/unread-count',route=>route.fulfill({json:{unread:items.filter(item=>!item.read).length}}));
    await tab.route(/\/api\/notifications\?/,route=>route.fulfill({json:{items:items.slice(0,8),offset:0,limit:8,total:items.length,more:items.length>8}}));
    await tab.route(/\/api\/notifications\/arrivals(\?|$)/,route=>{
      sequence();
      const url=new URL(route.request().url()),raw=url.searchParams.get('after'),head=arrivalLog.length;
      if(raw===null)return route.fulfill({json:{items:[],cursor:head,more:false,reset:false}});
      const found=[];
      for(let seq=Number(raw)+1;seq<=head;seq++){const entry=arrivalLog[seq-1],item=items.find(candidate=>candidate.id===entry.id);if(item&&item.revision===entry.revision)found.push({...item,arrival:seq});}
      return route.fulfill({json:{items:found,cursor:head,more:false,reset:false}});
    });
    await tab.goto(origin);
    await tab.locator('#shell:not(.hidden)').waitFor();
    await tab.waitForFunction(()=>typeof currentUser!=='undefined'&&!!currentUser);
    tabs.push(tab);
  }
  const [first,second]=tabs;
  const toasts=tab=>tab.locator('.notification-toast');
  const refresh=tab=>tab.evaluate(()=>window.NotificationShell.refresh());
  for(const tab of tabs)await refresh(tab);
  for(const tab of tabs)assert.equal(await toasts(tab).count(),0,'the baseline never toasts in either tab');

  items.unshift(event(1,'Seen first in one tab'));
  await refresh(first);
  await toasts(first).filter({hasText:'Seen first in one tab'}).waitFor();
  await refresh(second);
  assert.equal(await toasts(second).count(),0,'a revision another tab already showed does not toast again');
  assert.match(await second.getByRole('button',{name:/Notifications/}).getAttribute('aria-label'),/1 unread/,'the bell still counts it');

  items.unshift(event(2,'Concurrent arrival'));
  await Promise.all(tabs.map(refresh));
  const counts=await Promise.all(tabs.map(tab=>toasts(tab).filter({hasText:'Concurrent arrival'}).count()));
  assert.equal(counts[0]+counts[1],1,'concurrent refreshes show one toast across tabs');

  const revised=items.find(item=>item.reason==='Seen first in one tab');revised.revision=2;
  await refresh(second);
  await toasts(second).filter({hasText:'Seen first in one tab'}).waitFor();
  await refresh(first);
  assert.equal(await toasts(first).filter({hasText:'Seen first in one tab'}).count(),1,'the earlier revision card remains, and the new revision is not duplicated');
  assert.equal(await first.evaluate(()=>document.querySelectorAll('.notification-toast').length),await toasts(first).count());

  for(let n=0;n<5;n++)items.unshift(event(10+n,'Burst arrival '+n,1,'high'));
  await refresh(first);
  await toasts(first).filter({hasText:'5 new high-severity notifications need attention.'}).waitFor();
  items.unshift(event(20,'Later lone arrival',1,'high'));
  await refresh(second);
  await toasts(second).filter({hasText:'Later lone arrival'}).waitFor();
  assert.equal(await toasts(second).filter({hasText:/new high-severity notifications/}).count(),0,'a catch-up summary counts only revisions this tab claimed');

  const stored=await first.evaluate(()=>localStorage.getItem('mrpatchy-notification-toasts'));
  assert.ok(stored,'claims are shared through same-origin storage');
  assert.doesNotMatch(stored,/arrival|Burst|scanner|activity/,'claims hold no notification text, source or link');
  const parsed=JSON.parse(stored);
  assert.equal(parsed.v,1);assert.ok(parsed.entries.every(entry=>entry.length===3));

  // A different account ignores another account's claims.
  await first.evaluate(()=>{const value=JSON.parse(localStorage.getItem('mrpatchy-notification-toasts'));value.account='someone-else';localStorage.setItem('mrpatchy-notification-toasts',JSON.stringify(value));});
  items.unshift(event(30,'Other account claim ignored'));
  await first.evaluate(id=>{const value=JSON.parse(localStorage.getItem('mrpatchy-notification-toasts'));value.entries.push([id,1,Date.now()]);localStorage.setItem('mrpatchy-notification-toasts',JSON.stringify(value));},items[0].id);
  await refresh(second);
  await toasts(second).filter({hasText:'Other account claim ignored'}).waitFor();

  // Unusable storage fails open to this tab's own toast.
  await first.evaluate(()=>{window.__realStorage=Storage.prototype.getItem;Storage.prototype.getItem=()=>{throw new Error('blocked');};});
  items.unshift(event(31,'Storage blocked still toasts'));
  await refresh(first);
  await toasts(first).filter({hasText:'Storage blocked still toasts'}).waitFor();
  await first.evaluate(()=>{Storage.prototype.getItem=window.__realStorage;});

  await first.evaluate(()=>window.NotificationShell.reset());
  assert.equal(await first.evaluate(()=>localStorage.getItem('mrpatchy-notification-toasts')),null,'reset clears the shared claims');
  await context.close();
};
