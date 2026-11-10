const assert=require('assert/strict');

module.exports=async(page,capture)=>{
  let unread=2;
  const mutations=[];
  const listRequests=[];
  let holdMutation=false,releaseMutation,mutationStarted;
  const safeId='1'.repeat(64),unsafeId='2'.repeat(64);
  const items=[
    {id:safeId,revision:3,source:'operations',kind:'attention',subject_type:'job',subject_id:'job-7',host_id:'',severity:'critical',reason:'Patch verification needs review.',deep_link:'#activity',lifecycle:'active',created:1700000000,read:false,dismissed:false},
    {id:unsafeId,revision:1,source:'scanner',kind:'finding',subject_type:'scan',subject_id:'scan-9',host_id:'',severity:'high',reason:'<img src=x onerror="window.notificationInjected=true"> Untrusted finding',deep_link:'https://attacker.invalid/',lifecycle:'active',created:1699999000,read:false,dismissed:false},
  ];
  await page.route('**/api/notifications/unread-count',route=>route.fulfill({json:{unread}}));
  await page.route(/\/api\/notifications\?/,route=>{const url=new URL(route.request().url());listRequests.push(url.search);let visible=items.filter(item=>url.searchParams.get('include_dismissed')==='true'||!item.dismissed);if(url.searchParams.get('unread_only')==='true')visible=visible.filter(item=>!item.read);for(const key of ['severity','source']){const value=url.searchParams.get(key);if(value)visible=visible.filter(item=>item[key]===value);}const host=url.searchParams.get('host_id');if(host)visible=visible.filter(item=>item.host_id===host);const offset=Number(url.searchParams.get('offset')||0),limit=Number(url.searchParams.get('limit')||8),total=visible.length;visible=visible.slice(offset,offset+limit);return route.fulfill({json:{items:visible,offset,limit,total,more:offset+visible.length<total}});});
  await page.route(/\/api\/notifications\/[0-9a-f]{64}\/(read|dismiss)$/,route=>{
    const url=route.request().url(),body=route.request().postDataJSON(),id=url.split('/').at(-2),item=items.find(candidate=>candidate.id===id);
    mutations.push({url,body});
    if(item&&!item.read)unread=Math.max(0,unread-1);
    if(item){item.read=true;if(url.endsWith('/dismiss'))item.dismissed=true;}
    if(holdMutation){mutationStarted();return new Promise(resolve=>{releaseMutation=()=>resolve(route.fulfill({json:{id,revision:body.revision,read_revision:body.revision,dismissed_revision:0}}));});}
    return route.fulfill({json:{id,revision:body.revision,read_revision:body.revision,dismissed_revision:url.endsWith('/dismiss')?body.revision:0}});
  });

  await page.evaluate(()=>{
   window.NotificationShell.reset();window.notificationStreams=[];
   window.EventSource=class{
    constructor(url){this.url=url;this.listeners={};this.closed=false;window.notificationStreams.push(this);}
    addEventListener(name,listener){(this.listeners[name]??=[]).push(listener);}
    emit(name,lastEventId='a'.repeat(64)){for(const listener of this.listeners[name]||[])listener({lastEventId});}
    close(){this.closed=true;}
   };
   window.NotificationShell.start();
  });
  await page.waitForFunction(()=>window.notificationStreams.length===1);

  await page.evaluate(()=>window.NotificationShell.refresh());
  const bell=page.getByRole('button',{name:/Notifications/});
  await bell.waitFor();
  assert.match(await bell.getAttribute('aria-label'),/2 unread/);
  const toasts=page.locator('#notification-toasts .notification-toast');
  assert.equal(await toasts.count(),0,'existing events after sign-in/reload are a silent toast baseline');
  await bell.click();
  const panel=page.getByRole('region',{name:'Recent notifications'});
  await panel.waitFor();
  await capture('notifications-desktop',false);
  assert.equal(await panel.getByText('Patch verification needs review.',{exact:true}).count(),1);
  assert.equal(await panel.locator('img[src="x"]').count(),0);
  assert.equal(await page.evaluate(()=>window.notificationInjected),undefined);
  assert.equal(await panel.getByRole('link',{name:'Open'}).count(),1,'only the validated same-origin link is actionable');

  await panel.getByRole('button',{name:'Mark read'}).first().click();
  await panel.locator('.notification-item.is-read').waitFor();
  await panel.getByRole('button',{name:'Dismiss'}).last().click();
  await panel.locator('.notification-item').nth(1).waitFor({state:'detached'});
  await page.waitForFunction(()=>document.querySelector('#notification-button').getAttribute('aria-label').includes('0 unread'));
  assert.equal(mutations.length,2);
  assert.ok(mutations[0].url.endsWith(`/${safeId}/read`));
  assert.deepEqual(mutations[0].body,{revision:3});
  assert.ok(mutations[1].url.endsWith(`/${unsafeId}/dismiss`));
  assert.deepEqual(mutations[1].body,{revision:1});

  await panel.getByRole('link',{name:'View notification center'}).click();
  await page.getByRole('heading',{name:'Your notification history.'}).waitFor();
  assert.equal(await page.locator('#notification-center-list .notification-center-item').count(),1);
  await page.locator('#notification-filters [name=include_dismissed]').check();
  await page.locator('#notification-filters [name=source]').fill('scanner');
  await page.getByRole('button',{name:'Apply filters'}).click();
  const filteredReason=page.locator('#notification-center-list .notification-reason',{hasText:'Untrusted finding'});
  await filteredReason.waitFor();
  assert.equal(await filteredReason.count(),1);
  assert.equal(await page.locator('#notification-center-list img[src="x"]').count(),0);
  assert.ok(listRequests.some(query=>query.includes('include_dismissed=true')&&query.includes('source=scanner')&&query.includes('limit=25')));
  assert.equal(await page.getByRole('link',{name:'Open subject'}).count(),0,'unsafe cross-origin center links remain inert');
  const sourceFilter=page.locator('#notification-filters [name=source]');
  await sourceFilter.focus();
  items.push({id:'3'.repeat(64),revision:1,source:'scanner',kind:'finding',subject_type:'scan',subject_id:'scan-live',host_id:'',severity:'critical',reason:'A live durable event needs review.',deep_link:'#activity',lifecycle:'active',created:1700000100,read:false,dismissed:false});
  unread=1;
  await page.evaluate(()=>window.notificationStreams[0].emit('notifications'));
  await page.locator('#notification-center-list').getByText('A live durable event needs review.',{exact:true}).waitFor();
  assert.equal(await sourceFilter.inputValue(),'scanner','live catch-up preserves filter form state');
  assert.equal(await sourceFilter.evaluate(node=>node===document.activeElement),true,'live catch-up does not steal filter focus');
  assert.match(await bell.getAttribute('aria-label'),/1 unread/);
  const liveToast=toasts.filter({hasText:'A live durable event needs review.'});
  await liveToast.waitFor();
  assert.equal(await liveToast.count(),1,'a new unread revision toasts once');
  assert.equal(await sourceFilter.evaluate(node=>node===document.activeElement),true,'a toast never takes focus');
  assert.equal(await page.locator('#notification-toasts').getAttribute('aria-live'),'polite');
  await page.evaluate(()=>window.notificationStreams[0].emit('notifications'));
  await page.evaluate(()=>window.NotificationShell.refresh());
  assert.equal(await liveToast.count(),1,'re-delivery of the same revision does not toast again');
  await liveToast.getByRole('button',{name:'Close notification toast'}).click();
  await liveToast.waitFor({state:'detached'});
  assert.equal(mutations.length,2,'closing a toast never marks read or dismisses');
  assert.match(await bell.getAttribute('aria-label'),/1 unread/);
  items[2].revision=2;items[2].reason='The live durable event escalated.';
  await page.evaluate(()=>window.NotificationShell.refresh());
  const escalated=toasts.filter({hasText:'The live durable event escalated.'});
  await escalated.waitFor();
  assert.equal(await escalated.getByRole('link',{name:'Open'}).getAttribute('href'),'/#activity');
  assert.equal(await escalated.getAttribute('data-severity'),'critical');
  await page.waitForTimeout(250);
  await capture('notification-toast-desktop',false);
  await escalated.getByRole('button',{name:'Close notification toast'}).click();
  await escalated.waitFor({state:'detached'});
  await capture('notification-center-desktop',false);
  const locationHash=await page.evaluate(()=>location.hash);
  assert.equal(locationHash,'#notifications');
  await page.evaluate(()=>{location.hash='#overview';});
  await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();

  await bell.click();
  await page.getByRole('button',{name:'+ Add server',exact:true}).click();
  const name=page.locator('[name=name]');
  await name.fill('Form state survives notification refresh');
  await name.focus();
  unread=5;
  for(let n=0;n<5;n++)items.unshift({id:String(4+n).repeat(64),revision:1,source:'operations',kind:'attention',subject_type:'job',subject_id:'burst-'+n,host_id:'',severity:'low',reason:n===4?'<img src=x onerror="window.toastInjected=true"> Burst toast '+n:'Burst toast '+n,deep_link:n===4?'javascript:alert(1)':'#activity',lifecycle:'active',created:1700000200+n,read:false,dismissed:false});
  await page.evaluate(()=>window.NotificationShell.refresh());
  assert.equal(await name.inputValue(),'Form state survives notification refresh');
  assert.equal(await name.evaluate(node=>node===document.activeElement),true);
  assert.match(await bell.getAttribute('aria-label'),/5 unread/);
  await page.locator('#close-modal').click();
  assert.equal(await toasts.count(),4,'a burst shows at most three event toasts plus one summary');
  await toasts.filter({hasText:'2 more new notifications arrived.'}).getByRole('link',{name:'View notification center'}).waitFor();
  const injected=toasts.filter({hasText:'Burst toast 4'});
  assert.equal(await injected.count(),1);
  assert.equal(await injected.locator('img').count(),0,'toast reason text is escaped');
  assert.equal(await page.evaluate(()=>window.toastInjected),undefined);
  assert.equal(await injected.getByRole('link').count(),0,'an unsafe toast link is omitted');
  await injected.waitFor({state:'detached',timeout:15000});
  assert.equal(await toasts.count(),0,'low-severity toasts expire on their own');
  items.unshift({id:'9'.repeat(64),revision:1,source:'scanner',kind:'finding',subject_type:'scan',subject_id:'scan-sticky',host_id:'',severity:'high',reason:'A sticky high-severity event stays visible.',deep_link:'#activity',lifecycle:'active',created:1700000300,read:false,dismissed:false});
  await page.evaluate(()=>window.NotificationShell.refresh());
  const sticky=toasts.filter({hasText:'A sticky high-severity event stays visible.'});
  await sticky.waitFor();

  for(const viewport of [{width:768,height:1024},{width:390,height:844}]){
   await page.setViewportSize(viewport);
   await bell.click();
   await panel.waitFor();
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
   const box=await panel.boundingBox();
   assert.ok(box.x>=0&&box.x+box.width<=viewport.width&&box.y>=0&&box.y+box.height<=viewport.height);
   await capture(viewport.width===390?'notifications-mobile':'notifications-tablet',false);
   assert.equal(await sticky.isVisible(),false,'the open panel hides the toast stack');
   await page.keyboard.press('Escape');
   await panel.waitFor({state:'hidden'});
   await sticky.waitFor();
   const toastBox=await sticky.boundingBox();
   assert.ok(toastBox.x>=0&&toastBox.x+toastBox.width<=viewport.width,'the toast fits the viewport width');
   await capture(viewport.width===390?'notification-toast-mobile':'notification-toast-tablet',false);
   assert.equal(await bell.evaluate(node=>node===document.activeElement),true);
  }
  await page.setViewportSize({width:1440,height:1000});

  items.find(item=>item.id===safeId).read=false;
  unread=1;
  await page.evaluate(()=>window.NotificationShell.refresh());
  await bell.click();
  holdMutation=true;
  const started=new Promise(resolve=>{mutationStarted=resolve;});
  await panel.locator('.notification-item').filter({hasText:'Patch verification needs review.'}).getByRole('button',{name:'Mark read'}).click();
  await started;
  await page.evaluate(()=>window.NotificationShell.reset());
  assert.equal(await page.evaluate(()=>window.notificationStreams[0].closed),true,'logout/reset closes the account stream');
  releaseMutation();
  await page.waitForTimeout(50);
  assert.equal(await page.locator('#notification-list').textContent(),'','a late mutation response cannot restore account-scoped content after reset');
  assert.equal(await page.locator('#notification-status').textContent(),'','a late mutation response cannot restore account-scoped status after reset');
  assert.equal(await page.locator('#notification-badge').isHidden(),true);
  assert.equal(await page.locator('#notification-toasts').evaluate(node=>node.children.length),0,'logout/reset clears account-scoped toasts');
};
