const assert=require('assert/strict');

// Issue #1168: the notification center keeps its filters and page in the
// #notifications hash, so reload, copied links and Back/Forward reopen the
// same view. Hash values are checked before use and canonicalised.
module.exports=async(page,capture)=>{
  const id=n=>n.toString(16).padStart(64,'0');
  const hostId='h'.repeat(32);
  const items=Array.from({length:60},(_,n)=>({id:id(n),revision:1,source:n%2?'scanner':'operations',kind:'attention',subject_type:'job',subject_id:`job-${n}`,host_id:n%3?hostId:'',severity:n%2?'high':'medium',reason:`Event ${n} <img src=x onerror="window.deepLinkInjected=1">`,deep_link:'#activity',lifecycle:n%4?'active':'resolved',created:1700000000+n,read:false,dismissed:false}));
  const requests=[];
  const count=route=>route.fulfill({json:{unread:3}});
  const hosts=async route=>{const response=await route.fetch();const list=await response.json();route.fulfill({json:[...list,{id:hostId,name:'Deep link <b>server</b>',address:'192.0.2.90',enabled:true}]});};
  const list=route=>{
    const url=new URL(route.request().url()),q=url.searchParams;requests.push(q);
    const visible=items.filter(item=>(!q.get('severity')||item.severity===q.get('severity'))&&(!q.get('source')||item.source===q.get('source'))&&(!q.get('host_id')||item.host_id===q.get('host_id'))&&(!q.get('lifecycle')||item.lifecycle===q.get('lifecycle')));
    const limit=Number(q.get('limit')||8),offset=Number(q.get('offset')||0);
    return route.fulfill({json:{items:visible.slice(offset,offset+limit).map(item=>({...item})),offset,limit,total:visible.length,more:offset+limit<visible.length}});
  };
  const last=()=>Object.fromEntries([...requests.at(-1).entries()].filter(([key])=>key!=='limit'));
  const hash=()=>page.evaluate(()=>location.hash);
  const heading=()=>page.getByRole('heading',{name:'Your notification history.'}).waitFor();
  const range=async text=>page.waitForFunction(value=>document.querySelector('#notification-center-range')?.textContent===value,text);
  await page.route('**/api/notifications/unread-count',count);
  await page.route('**/api/hosts',hosts);
  await page.route(/\/api\/notifications\?/,list);
  try{
    await page.evaluate(()=>{window.EventSource=class{constructor(){}addEventListener(){}close(){}};window.NotificationShell.start();location.hash='#notifications';});
    await heading();await range('1–25 of 60');
    assert.equal(await hash(),'#notifications','the unfiltered first page keeps the bare address');

    // Apply writes the filters into the hash as a new history entry.
    await page.getByRole('combobox',{name:'Severity'}).selectOption('high');
    await page.getByRole('combobox',{name:'Status'}).selectOption('active');
    await page.getByRole('button',{name:'Apply filters'}).click();
    await page.waitForFunction(()=>location.hash==='#notifications?severity=high&status=active');
    await range('1–25 of 30');
    assert.deepEqual(last(),{offset:'0',severity:'high',lifecycle:'active'});

    // Next and Previous are history entries too.
    await page.getByRole('button',{name:'Clear'}).click();
    await page.waitForFunction(()=>location.hash==='#notifications');await range('1–25 of 60');
    await page.getByRole('button',{name:'Next'}).click();
    await page.waitForFunction(()=>location.hash==='#notifications?page=2');await range('26–50 of 60');
    await page.getByRole('button',{name:'Next'}).click();
    await page.waitForFunction(()=>location.hash==='#notifications?page=3');await range('51–60 of 60');
    assert.deepEqual(last(),{offset:'50'});

    // Back/Forward restore earlier views, including their form state.
    await page.goBack();await page.waitForFunction(()=>location.hash==='#notifications?page=2');await range('26–50 of 60');
    await page.goBack();await page.waitForFunction(()=>location.hash==='#notifications');await range('1–25 of 60');
    await page.goBack();await page.waitForFunction(()=>location.hash==='#notifications?severity=high&status=active');await range('1–25 of 30');
    assert.equal(await page.getByRole('combobox',{name:'Severity'}).inputValue(),'high');
    assert.equal(await page.getByRole('combobox',{name:'Status'}).inputValue(),'active');
    await page.goForward();await page.waitForFunction(()=>location.hash==='#notifications');await range('1–25 of 60');
    assert.equal(await page.getByRole('combobox',{name:'Severity'}).inputValue(),'');

    // A copied link with every filter reopens after reload.
    const full=`#notifications?severity=high&source=scanner&host=${hostId}&status=active&unread=1&dismissed=1`;
    await page.evaluate(address=>{location.hash=address;},full);await heading();
    // Reload starts the live refresh while the center's first request is in flight;
    // the refresh must not discard that page and leave the loading state.
    await page.reload();await heading();
    await page.waitForFunction(()=>document.querySelector('#notification-center-range')?.textContent.endsWith(' of 20'));
    assert.equal(await hash(),full);
    assert.deepEqual(last(),{offset:'0',unread_only:'true',include_dismissed:'true',severity:'high',source:'scanner',host_id:hostId,lifecycle:'active'});
    assert.equal(await page.locator('#notification-filters [name=source]').inputValue(),'scanner');
    assert.equal(await page.locator('#notification-filters [name=host_id]').inputValue(),hostId);
    assert.equal(await page.locator('#notification-filters [name=unread_only]').isChecked(),true);
    assert.equal(await page.locator('#notification-filters [name=include_dismissed]').isChecked(),true);

    // Invalid values are dropped and the address is rewritten, not trusted.
    await page.evaluate(()=>{location.hash='#notifications?severity=urgent&source=%3Cscript%3E&host=unknown-host&status=deleted&unread=yes&page=0&extra=1';});
    await page.waitForFunction(()=>location.hash==='#notifications');await range('1–25 of 60');
    assert.deepEqual(last(),{offset:'0'});
    await page.evaluate(()=>{location.hash='#notifications?page=1e3';});
    await page.waitForFunction(()=>location.hash==='#notifications');
    await page.evaluate(()=>{location.hash='#notifications?source=%22%3E%3Cimg%20src%3Dx%20onerror%3Dwindow.deepLinkInjected%3D1%3E';});
    await page.waitForFunction(()=>location.hash==='#notifications');
    assert.equal(await page.evaluate(()=>window.deepLinkInjected),undefined,'hash and reason text never execute');

    // A page past the end opens the last page instead of an empty list.
    await page.evaluate(()=>{location.hash='#notifications?severity=high&page=9';});
    await page.waitForFunction(()=>location.hash==='#notifications?severity=high&page=2');await range('26–30 of 30');

    for(const viewport of [{width:320,height:700},{width:768,height:1024},{width:1440,height:1000}]){
      await page.setViewportSize(viewport);
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`no horizontal scroll at ${viewport.width}px`);
    }
    await capture('notification-center-deep-link',false);
    await page.evaluate(()=>window.NotificationShell.reset());
    await page.evaluate(()=>{location.hash='#overview';});
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
  }finally{
    await page.unroute('**/api/notifications/unread-count',count);
    await page.unroute('**/api/hosts',hosts);
    await page.unroute(/\/api\/notifications\?/,list);
  }
};
