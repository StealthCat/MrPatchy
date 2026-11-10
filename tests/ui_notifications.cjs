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
  await page.route(/\/api\/notifications\?/,route=>{const url=new URL(route.request().url());listRequests.push(url.search);let visible=items.filter(item=>url.searchParams.get('include_dismissed')==='true'||!item.dismissed);if(url.searchParams.get('unread_only')==='true')visible=visible.filter(item=>!item.read);for(const key of ['severity','source']){const value=url.searchParams.get(key);if(value)visible=visible.filter(item=>item[key]===value);}const host=url.searchParams.get('host_id');if(host)visible=visible.filter(item=>item.host_id===host);if(url.searchParams.get('severity'))visible=[...visible].sort((a,b)=>b.created-a.created||(a.id<b.id?-1:1));const offset=Number(url.searchParams.get('offset')||0),limit=Number(url.searchParams.get('limit')||8),total=visible.length;visible=visible.slice(offset,offset+limit);return route.fulfill({json:{items:visible,offset,limit,total,more:offset+visible.length<total}});});
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
  await page.evaluate(()=>window.NotificationShell.refresh());
  assert.equal(await name.inputValue(),'Form state survives notification refresh');
  assert.equal(await name.evaluate(node=>node===document.activeElement),true);
  assert.match(await bell.getAttribute('aria-label'),/5 unread/);
  await page.locator('#close-modal').click();

  for(const viewport of [{width:768,height:1024},{width:390,height:844}]){
   await page.setViewportSize(viewport);
   await bell.click();
   await panel.waitFor();
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
   const box=await panel.boundingBox();
   assert.ok(box.x>=0&&box.x+box.width<=viewport.width&&box.y>=0&&box.y+box.height<=viewport.height);
   await capture(viewport.width===390?'notifications-mobile':'notifications-tablet',false);
   await page.keyboard.press('Escape');
   await panel.waitFor({state:'hidden'});
   assert.equal(await bell.evaluate(node=>node===document.activeElement),true);
  }
  await page.setViewportSize({width:1440,height:1000});

  items[0].read=false;
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

  // Live toasts: the initial set never toasts; new or re-revised unread
  // high/critical events do, bounded, without focus theft or read side effects.
  for(const item of items){item.read=false;item.dismissed=false;}
  unread=items.length;
  const toasts=page.locator('.notification-toast');
  await page.evaluate(()=>window.NotificationShell.start());
  await page.evaluate(()=>window.NotificationShell.refresh());
  assert.match(await bell.getAttribute('aria-label'),/3 unread/);
  assert.equal(await toasts.count(),0,'events present at sign-in or reload do not toast');

  await page.getByRole('button',{name:'+ Add server',exact:true}).click();
  const toastName=page.locator('[name=name]');
  await toastName.fill('Toast keeps this draft');
  await toastName.focus();
  const mutationCount=mutations.length;
  items.unshift({id:'4'.repeat(64),revision:1,source:'scanner',kind:'finding',subject_type:'scan',subject_id:'scan-new',host_id:'',severity:'critical',reason:'<img src=x onerror="window.toastInjected=true"> New critical finding',deep_link:'#activity',lifecycle:'active',created:1700000200,read:false,dismissed:false});
  unread++;
  await page.evaluate(()=>window.notificationStreams.at(-1).emit('notifications'));
  const newToast=toasts.filter({hasText:'New critical finding'});
  await newToast.waitFor();
  assert.equal(await toasts.count(),1);
  assert.equal(await newToast.locator('img').count(),0);
  assert.equal(await page.evaluate(()=>window.toastInjected),undefined);
  assert.equal(await page.evaluate(()=>document.getElementById('notification-toasts').parentElement.id),'modal','the toast mounts inside the open modal so it is not inert');
  assert.equal(await toastName.inputValue(),'Toast keeps this draft');
  assert.equal(await toastName.evaluate(node=>node===document.activeElement),true,'a toast never steals focus');
  assert.equal(await newToast.getByRole('link',{name:'Open'}).getAttribute('href'),'/#activity');
  await capture('notification-toast-dialog',false);
  await newToast.getByRole('button',{name:/Hide this toast/}).click();
  await newToast.waitFor({state:'detached'});
  assert.equal(mutations.length,mutationCount,'hiding a toast does not mark the notification read or dismissed');
  assert.equal(items[0].read,false);
  await page.evaluate(()=>window.NotificationShell.refresh());
  assert.equal(await toasts.count(),0,'an unchanged revision does not toast again');
  await page.locator('#close-modal').click();

  items.unshift({id:'5'.repeat(64),revision:1,source:'operations',kind:'attention',subject_type:'job',subject_id:'job-medium',host_id:'',severity:'medium',reason:'Medium notice stays in the bell.',deep_link:'#activity',lifecycle:'active',created:1700000300,read:false,dismissed:false});
  await page.evaluate(()=>window.NotificationShell.refresh());
  assert.equal(await toasts.count(),0,'medium and lower severities do not toast');

  const revised=items.find(item=>item.id===safeId);revised.revision++;
  await page.evaluate(()=>window.NotificationShell.refresh());
  await toasts.filter({hasText:'Patch verification needs review.'}).waitFor();
  assert.equal(await page.evaluate(()=>document.getElementById('notification-toasts').parentElement===document.body),true);
  assert.equal(await toasts.count(),1,'a reopened or escalated revision toasts again');
  await capture('notification-toast-desktop',false);

  for(let n=0;n<4;n++)items.unshift({id:String(6+n).repeat(64),revision:1,source:'scanner',kind:'finding',subject_type:'scan',subject_id:'burst-'+n,host_id:'',severity:'high',reason:'Burst finding '+n,deep_link:'#activity',lifecycle:'active',created:1700000400+n,read:false,dismissed:false});
  await page.evaluate(()=>window.NotificationShell.refresh());
  const summary=toasts.filter({hasText:'4 new high-severity notifications need attention.'});
  await summary.waitFor();
  assert.equal(await toasts.count(),1,'a burst collapses into one summary toast');
  assert.equal(await summary.getByRole('link',{name:'Open notification center'}).getAttribute('href'),'#notifications');
  await page.setViewportSize({width:390,height:844});
  const toastBox=await summary.boundingBox();
  assert.ok(toastBox.x>=0&&toastBox.x+toastBox.width<=390&&toastBox.y+toastBox.height<=844);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.waitForTimeout(300);
  await capture('notification-toast-mobile',false);
  await page.setViewportSize({width:1440,height:1000});

  await page.evaluate(()=>window.NotificationShell.reset());
  assert.equal(await toasts.count(),0,'logout/reset clears toasts');

  // Toast admission is independent of the bell's eight-item recent window.
  const critical=(n,created,reason)=>({id:n.toString(16).padStart(64,'0'),revision:1,source:'scanner',kind:'finding',subject_type:'scan',subject_id:'window-'+n,host_id:'',severity:'critical',reason,deep_link:'#activity',lifecycle:'active',created,read:false,dismissed:false});
  items.splice(0,items.length);
  for(let n=1;n<=9;n++)items.unshift(critical(0x100+n,1700100000+n,'Pre-existing critical '+n));
  unread=9;
  await page.evaluate(()=>window.NotificationShell.start());
  await page.evaluate(()=>window.NotificationShell.refresh());
  assert.equal(await toasts.count(),0,'nine pre-existing urgent events stay a silent baseline');
  items[0].dismissed=true;items[0].read=true;unread=8;
  await page.evaluate(()=>window.NotificationShell.refresh());
  assert.equal(await toasts.count(),0,'an unchanged event sliding into the bell window after another session dismisses one does not toast');
  for(let n=1;n<=8;n++)items.unshift({...critical(0x200+n,1700200000+n,'Informational '+n),severity:'info'});
  items.push(critical(0x300,1690000000,'Lagging producer critical'));unread=17;
  await page.evaluate(()=>window.NotificationShell.refresh());
  assert.equal((await page.evaluate(()=>[...document.querySelectorAll('#notification-list .notification-reason')].map(node=>node.textContent))).includes('Lagging producer critical'),false,'the new critical event is outside the bell window');
  await toasts.filter({hasText:'Lagging producer critical'}).waitFor();
  assert.equal(await toasts.count(),1,'a genuinely new urgent event outside the bell window toasts; informational events do not');

  // A full admission window: events entering from below it are not new.
  await page.evaluate(()=>window.NotificationShell.reset());
  items.splice(0,items.length);
  for(let n=1;n<=105;n++)items.unshift(critical(0x1000+n,1700300000+n,'Large backlog '+n));
  unread=105;
  await page.evaluate(()=>window.NotificationShell.start());
  await page.evaluate(()=>window.NotificationShell.refresh());
  assert.equal(await toasts.count(),0);
  for(let n=0;n<5;n++){items[n].dismissed=true;items[n].read=true;}
  await page.evaluate(()=>window.NotificationShell.refresh());
  assert.equal(await toasts.count(),0,'events below a full admission window that slide into it do not toast');
  items.unshift(critical(0x2000,1700400000,'Newest backlog critical'));
  await page.evaluate(()=>window.NotificationShell.refresh());
  await toasts.filter({hasText:'Newest backlog critical'}).waitFor();
  assert.equal(await toasts.count(),1);
  await page.evaluate(()=>window.NotificationShell.reset());

  // Seen-revision eviction never forgets an event still in a complete urgent window.
  items.splice(0,items.length);
  items.push({...critical(0x3000,1700500000,'Long-lived high notice'),severity:'high'});
  unread=1;
  await page.evaluate(()=>window.NotificationShell.start());
  await page.evaluate(()=>window.NotificationShell.refresh());
  assert.equal(await toasts.count(),0);
  const longLived=toasts.filter({hasText:'Long-lived high notice'});
  for(let burst=0;burst<5;burst++){
   for(const item of items)if(item.severity==='critical')item.read=true;
   for(let n=1;n<=100;n++)items.unshift(critical(0x4000+burst*0x100+n,1700600000+burst*1000+n,'Burst '+burst+' critical '+n));
   await page.evaluate(()=>window.NotificationShell.refresh());
   assert.equal(await longLived.count(),0);
  }
  for(const item of items)if(item.severity==='critical')item.read=true;
  await page.evaluate(()=>window.NotificationShell.refresh());
  await page.evaluate(()=>window.NotificationShell.refresh());
  assert.equal(await longLived.count(),0,'an unchanged high event that stayed in its complete window does not toast after 500 other revisions were seen');
  await page.evaluate(()=>window.NotificationShell.reset());
};
