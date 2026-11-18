const assert=require('assert/strict');

// Issue #835: the notification center's Status filter sends the lifecycle
// query value, is restored on re-render and reset by Clear.
module.exports=async(page,capture)=>{
  const id=n=>String(n).repeat(64);
  const items=[
    {id:id(7),revision:1,source:'operations',kind:'attention',subject_type:'job',subject_id:'job-open',host_id:'',severity:'high',reason:'Still needs attention.',deep_link:'#activity',lifecycle:'active',created:1700000300,read:false,dismissed:false},
    {id:id(8),revision:2,source:'scanner',kind:'finding',subject_type:'scan',subject_id:'scan-done',host_id:'',severity:'medium',reason:'Recovered <b>fixture</b>.',deep_link:'#activity',lifecycle:'resolved',created:1700000200,read:false,dismissed:false},
  ];
  const requests=[];
  const count=route=>route.fulfill({json:{unread:2}});
  const list=route=>{
    const url=new URL(route.request().url());requests.push(url.searchParams.get('lifecycle'));
    const lifecycle=url.searchParams.get('lifecycle');
    const visible=items.filter(item=>!lifecycle||item.lifecycle===lifecycle).map(item=>({...item}));
    return route.fulfill({json:{items:visible,offset:0,limit:Number(url.searchParams.get('limit')||8),total:visible.length,more:false}});
  };
  await page.route('**/api/notifications/unread-count',count);
  await page.route(/\/api\/notifications\?/,list);
  try{
    await page.evaluate(()=>{window.EventSource=class{constructor(){}addEventListener(){}close(){}};window.NotificationShell.start();location.hash='#notifications';});
    await page.getByRole('heading',{name:'Your notification history.'}).waitFor();
    const status=page.getByRole('combobox',{name:'Status'});
    assert.equal(await status.inputValue(),'','the default shows all statuses');
    assert.deepEqual(await status.locator('option').allTextContents(),['All statuses','Active','Resolved']);
    const listed=()=>page.locator('#notification-center-list .notification-center-item').count();
    await page.waitForFunction(()=>document.querySelectorAll('#notification-center-list .notification-center-item').length===2);
    assert.equal(requests.at(-1),null,'no lifecycle parameter is sent by default');

    await status.selectOption('resolved');
    await page.getByRole('button',{name:'Apply filters'}).click();
    await page.waitForFunction(()=>document.querySelectorAll('#notification-center-list .notification-center-item').length===1);
    assert.equal(requests.at(-1),'resolved');
    assert.equal(await page.getByRole('combobox',{name:'Status'}).inputValue(),'resolved','the selection survives the re-render');
    const shown=page.locator('#notification-center-list .notification-center-item');
    assert.match(await shown.textContent(),/Recovered <b>fixture<\/b>\./,'untrusted reason text stays escaped');
    assert.equal(await shown.locator('b').count(),0);
    assert.equal(await shown.locator('.notification-resolved').count(),1);
    for(const viewport of [{width:390,height:844}]){
      await page.setViewportSize(viewport);
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
      await capture('notification-center-status-filter-mobile',false);
    }
    await page.setViewportSize({width:1440,height:1000});
    await capture('notification-center-status-filter',false);

    await page.getByRole('combobox',{name:'Status'}).selectOption('active');
    await page.getByRole('button',{name:'Apply filters'}).click();
    await page.waitForFunction(()=>/Still needs attention/.test(document.querySelector('#notification-center-list').textContent));
    assert.equal(requests.at(-1),'active');assert.equal(await listed(),1);

    await page.locator('#notification-filters-clear').click();
    await page.waitForFunction(()=>document.querySelectorAll('#notification-center-list .notification-center-item').length===2);
    assert.equal(requests.at(-1),null,'Clear removes the status filter');
    assert.equal(await page.getByRole('combobox',{name:'Status'}).inputValue(),'');
    await page.evaluate(()=>window.NotificationShell.reset());
    await page.evaluate(()=>{location.hash='#overview';});
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
  }finally{
    await page.unroute('**/api/notifications/unread-count',count);
    await page.unroute(/\/api\/notifications\?/,list);
  }
};
