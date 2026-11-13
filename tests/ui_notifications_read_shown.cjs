const assert=require('assert/strict');

// "Mark shown read" sends exactly the displayed revisions, keeps newer
// revisions unread, refreshes from the authoritative API and stays retryable.
module.exports=async(page,capture)=>{
  const id=n=>String(n).repeat(64);
  const items=[
    {id:id(4),revision:2,source:'operations',kind:'attention',subject_type:'job',subject_id:'job-a',host_id:'',severity:'critical',reason:'Shown critical item.',deep_link:'#activity',lifecycle:'active',created:1700000300,read:false,dismissed:false},
    {id:id(5),revision:1,source:'scanner',kind:'finding',subject_type:'scan',subject_id:'scan-b',host_id:'',severity:'high',reason:'Shown high item.',deep_link:'#activity',lifecycle:'active',created:1700000200,read:false,dismissed:false},
    {id:id(6),revision:1,source:'scanner',kind:'finding',subject_type:'scan',subject_id:'scan-c',host_id:'',severity:'low',reason:'Already read item.',deep_link:'#activity',lifecycle:'active',created:1700000100,read:true,dismissed:false},
  ];
  const batches=[];let failNext=false;
  const unread=()=>items.filter(item=>!item.read&&!item.dismissed).length;
  const count=route=>route.fulfill({json:{unread:unread()}});
  const list=route=>{const url=new URL(route.request().url());let visible=items.filter(item=>!item.dismissed);if(url.searchParams.get('unread_only')==='true')visible=visible.filter(item=>!item.read);const offset=Number(url.searchParams.get('offset')||0),limit=Number(url.searchParams.get('limit')||8),total=visible.length;visible=visible.slice(offset,offset+limit).map(item=>({...item}));return route.fulfill({json:{items:visible,offset,limit,total,more:offset+visible.length<total}});};
  const batch=route=>{
    const body=route.request().postDataJSON();batches.push(body);
    if(failNext){failNext=false;return route.fulfill({status:503,json:{detail:'Notification state is temporarily unavailable'}});}
    let marked=0,unavailable=0;
    for(const pair of body.items){const item=items.find(candidate=>candidate.id===pair.id);if(!item){unavailable++;continue;}if(pair.revision===item.revision&&!item.read){item.read=true;marked++;}}
    return route.fulfill({json:{marked,already_read:body.items.length-marked-unavailable,unavailable}});
  };
  await page.route('**/api/notifications/unread-count',count);
  await page.route(/\/api\/notifications\?/,list);
  await page.route('**/api/notifications/read-batch',batch);
  try{
    await page.evaluate(()=>{window.notificationStreams=[];window.EventSource=class{constructor(){this.listeners={};window.notificationStreams.push(this);}addEventListener(name,listener){(this.listeners[name]??=[]).push(listener);}close(){}};window.NotificationShell.start();});
    const bell=page.locator('#notification-button'),panel=page.getByRole('region',{name:'Recent notifications'});
    await page.waitForFunction(()=>/2 unread/.test(document.querySelector('#notification-button').getAttribute('aria-label')));
    await bell.click();await panel.waitFor();
    const markShown=panel.getByRole('button',{name:'Mark shown read'});
    await page.waitForFunction(()=>!document.querySelector('#notification-read-shown').disabled);

    // The critical item escalates after the panel loaded; that newer revision must stay unread.
    items[0].revision=3;
    failNext=true;
    await markShown.click();
    await page.waitForFunction(()=>/temporarily unavailable/.test(document.querySelector('#notification-status').textContent));
    assert.equal(await markShown.isEnabled(),true,'a failed batch leaves the action retryable');
    assert.equal(await panel.locator('.notification-item.is-read').count(),1,'a failed batch changes nothing locally');

    await markShown.click();
    await page.waitForFunction(()=>/1 shown notification marked read/.test(document.querySelector('#notification-status').textContent));
    assert.equal(batches.length,2);
    assert.deepEqual(batches[1],{items:[{id:id(4),revision:2},{id:id(5),revision:1}]},'only shown unread revisions are sent');
    assert.equal(items[0].read,false,'the escalated revision stays unread');
    await page.waitForFunction(()=>/1 unread/.test(document.querySelector('#notification-button').getAttribute('aria-label')));
    await capture('notifications-read-shown',false);
    assert.equal(await markShown.isEnabled(),true,'the refreshed escalated revision can be marked next');

    // Notification center: page-scoped action preserves filters and focus context.
    await panel.getByRole('link',{name:'View notification center'}).click();
    await page.getByRole('heading',{name:'Your notification history.'}).waitFor();
    const source=page.locator('#notification-filters [name=source]');
    await source.fill('draft filter text');
    const centerMark=page.locator('#notification-center-read-shown');
    await page.waitForFunction(()=>!document.querySelector('#notification-center-read-shown').disabled);
    await centerMark.click();
    await page.waitForFunction(()=>document.querySelector('#notification-center-read-shown').disabled);
    assert.deepEqual(batches.at(-1),{items:[{id:id(4),revision:3}]});
    await page.waitForFunction(()=>/0 unread/.test(document.querySelector('#notification-button').getAttribute('aria-label')));
    assert.equal(await source.inputValue(),'draft filter text','unsubmitted filter text survives the refresh');
    assert.equal(await page.locator('#notification-center-list .notification-center-item.is-read').count(),3);
    assert.match(await page.locator('.notification-center-controls .help').textContent(),/only your account/);
    for(const viewport of [{width:390,height:844}]){
      await page.setViewportSize(viewport);
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
      await capture('notification-center-read-shown-mobile',false);
    }
    await page.setViewportSize({width:1440,height:1000});
    await page.evaluate(()=>window.NotificationShell.reset());
    assert.equal(await page.locator('#notification-read-shown').isDisabled(),true,'reset clears the account-scoped action');
    await page.evaluate(()=>{location.hash='#overview';});
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
  }finally{
    await page.unroute('**/api/notifications/unread-count',count);
    await page.unroute(/\/api\/notifications\?/,list);
    await page.unroute('**/api/notifications/read-batch',batch);
  }
};
