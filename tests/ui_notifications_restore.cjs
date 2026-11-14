const assert=require('assert/strict');

// Issue #833: Include dismissed shows a dismissed marker and a Restore action.
// Restore sends the shown revision, returns the item to the default history,
// keeps it read and keeps keyboard focus on the same card.
module.exports=async(page,capture)=>{
  const id=n=>String(n).repeat(64);
  const items=[
    {id:id(7),revision:2,source:'operations',kind:'attention',subject_type:'job',subject_id:'job-r',host_id:'',severity:'critical',reason:'Dismissed critical item <b>escaped</b>.',deep_link:'#activity',lifecycle:'active',created:1700000300,read:true,dismissed:true},
    {id:id(8),revision:1,source:'scanner',kind:'finding',subject_type:'scan',subject_id:'scan-r',host_id:'',severity:'low',reason:'Visible read item.',deep_link:'#activity',lifecycle:'active',created:1700000200,read:true,dismissed:false},
  ];
  const restores=[];
  const count=route=>route.fulfill({json:{unread:items.filter(item=>!item.read&&!item.dismissed).length}});
  const list=route=>{const url=new URL(route.request().url());let visible=items;if(url.searchParams.get('include_dismissed')!=='true')visible=visible.filter(item=>!item.dismissed);const offset=Number(url.searchParams.get('offset')||0),limit=Number(url.searchParams.get('limit')||8),total=visible.length;visible=visible.slice(offset,offset+limit).map(item=>({...item}));return route.fulfill({json:{items:visible,offset,limit,total,more:offset+visible.length<total}});};
  const restore=route=>{
    const eventId=new URL(route.request().url()).pathname.split('/').at(-2),body=route.request().postDataJSON();restores.push({id:eventId,...body});
    const item=items.find(candidate=>candidate.id===eventId);
    if(item&&body.revision===item.revision)item.dismissed=false;
    return route.fulfill({json:{id:eventId,revision:body.revision,read_revision:item.revision,dismissed_revision:0}});
  };
  await page.route('**/api/notifications/unread-count',count);
  await page.route(/\/api\/notifications\?/,list);
  await page.route(/\/api\/notifications\/[0-9a-f]{64}\/restore$/,restore);
  try{
    await page.evaluate(()=>{window.notificationStreams=[];window.EventSource=class{constructor(){this.listeners={};window.notificationStreams.push(this);}addEventListener(name,listener){(this.listeners[name]??=[]).push(listener);}close(){}};window.NotificationShell.start();});
    await page.evaluate(()=>{location.hash='#notifications';});
    await page.getByRole('heading',{name:'Your notification history.'}).waitFor();
    const listNode=page.locator('#notification-center-list');
    await listNode.locator('[data-event-id]').first().waitFor();
    assert.equal(await listNode.locator('[data-event-id]').count(),1,'dismissed items stay out of the default history');
    assert.equal(await listNode.getByRole('button',{name:/Restore/}).count(),0);

    await page.locator('#notification-filters [name=include_dismissed]').check();
    await page.locator('#notification-filters').getByRole('button',{name:'Apply filters'}).click();
    const card=listNode.locator(`[data-event-id="${id(7)}"]`);
    await card.waitFor();
    assert.equal(await card.locator('.notification-dismissed').textContent(),'dismissed');
    assert.equal(await card.locator('b').count(),0,'untrusted reason text is escaped');
    assert.equal(await card.getByRole('button',{name:'Dismiss'}).count(),0,'a dismissed item offers Restore instead of Dismiss');
    const restoreButton=card.locator('[data-notification-action=restore]');
    assert.match(await restoreButton.getAttribute('aria-label'),/stays read/);
    await capture('notification-center-restore',false);

    await restoreButton.focus();
    await page.keyboard.press('Enter');
    await page.waitForFunction(id=>{const card=document.querySelector(`#notification-center-list [data-event-id="${id}"]`);return card&&!card.querySelector('.notification-dismissed');},id(7));
    assert.deepEqual(restores,[{id:id(7),revision:2}],'restore sends exactly the shown revision');
    assert.equal(await page.evaluate(()=>document.activeElement?.dataset.notificationAction),'dismiss','focus stays on the restored card');
    assert.equal(await page.evaluate(()=>document.activeElement?.closest('[data-event-id]')?.dataset.eventId),id(7));
    assert.match(await page.locator('#notification-button').getAttribute('aria-label'),/0 unread/,'a restored item stays read');

    await page.locator('#notification-filters-clear').click();
    await page.waitForFunction(id=>!!document.querySelector(`#notification-center-list [data-event-id="${id}"]`)&&document.querySelectorAll('#notification-center-list [data-event-id]').length===2,id(7));
    assert.match(await page.locator('.notification-center-controls .help').textContent(),/Restore returns it to your default history/);
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
    await capture('notification-center-restore-mobile',false);
    await page.setViewportSize({width:1440,height:1000});
    await page.evaluate(()=>window.NotificationShell.reset());
    await page.evaluate(()=>{location.hash='#overview';});
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
  }finally{
    await page.unroute('**/api/notifications/unread-count',count);
    await page.unroute(/\/api\/notifications\?/,list);
    await page.unroute(/\/api\/notifications\/[0-9a-f]{64}\/restore$/,restore);
  }
};
