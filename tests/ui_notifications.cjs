const assert=require('assert/strict');

module.exports=async(page,capture)=>{
  let unread=2;
  const mutations=[];
  const safeId='1'.repeat(64),unsafeId='2'.repeat(64);
  const items=[
    {id:safeId,revision:3,source:'operations',kind:'attention',subject_type:'job',subject_id:'job-7',host_id:'',severity:'critical',reason:'Patch verification needs review.',deep_link:'#activity',lifecycle:'active',created:1700000000,read:false,dismissed:false},
    {id:unsafeId,revision:1,source:'scanner',kind:'finding',subject_type:'scan',subject_id:'scan-9',host_id:'',severity:'high',reason:'<img src=x onerror="window.notificationInjected=true"> Untrusted finding',deep_link:'https://attacker.invalid/',lifecycle:'active',created:1699999000,read:false,dismissed:false},
  ];
  await page.route('**/api/notifications/unread-count',route=>route.fulfill({json:{unread}}));
  await page.route(/\/api\/notifications\?/,route=>{const visible=items.filter(item=>!item.dismissed);return route.fulfill({json:{items:visible,offset:0,limit:8,total:visible.length,more:false}});});
  await page.route(/\/api\/notifications\/[0-9a-f]{64}\/(read|dismiss)$/,route=>{
    const url=route.request().url(),body=route.request().postDataJSON(),id=url.split('/').at(-2),item=items.find(candidate=>candidate.id===id);
    mutations.push({url,body});
    if(item&&!item.read)unread=Math.max(0,unread-1);
    if(item){item.read=true;if(url.endsWith('/dismiss'))item.dismissed=true;}
    return route.fulfill({json:{id,revision:body.revision,read_revision:body.revision,dismissed_revision:url.endsWith('/dismiss')?body.revision:0}});
  });

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
};
