const assert=require('assert/strict');

module.exports=async(page,capture)=>{
  const pattern='**/api/ai/triage/timings';
  const originalViewport=page.viewportSize();
  let calls=0,release,requestStarted;
  const held=new Promise(resolve=>release=resolve),started=new Promise(resolve=>requestStarted=resolve);
  const populated={sampled_runs:3,runs_without_samples:1,discarded_events:2,events_truncated:true,event_limit:2048,stages:{
    provider:{samples:3,errors:1,p50_ms:0,p95_ms:12.345},
    ssh_evidence:{samples:0,errors:0,p50_ms:null,p95_ms:null}
  }};
  const routeHandler=async route=>{
    switch(++calls){
      case 1:return route.fulfill({status:503,json:{detail:'Internal fixture details'}});
      case 2:return route.fulfill({json:{...populated,sampled_runs:0,runs_without_samples:0,discarded_events:0,events_truncated:false,stages:{}}});
      case 3:return route.fulfill({json:populated});
      default:requestStarted();await held;return route.fulfill({json:populated});
    }
  };
  await page.route(pattern,routeHandler);
  try{
    await page.locator('[data-nav=ai-logs]').click();
    const panel=page.getByRole('region',{name:'Process triage timings',exact:true});
    await panel.getByRole('button',{name:'Load timing summary'}).click();
    await panel.getByRole('status').filter({hasText:'Timing summary is unavailable'}).waitFor();
    assert.equal(await panel.getByText('Internal fixture details').count(),0);
    assert.equal(await page.locator('#ai-log-table').isVisible(),true);
    await panel.getByRole('button',{name:'Retry timing summary'}).click();
    await panel.getByRole('status').filter({hasText:'No retained timing samples'}).waitFor();
    assert.equal(await panel.getByRole('table').isVisible(),false);
    await panel.getByRole('button',{name:'Refresh timing summary'}).click();
    await panel.getByRole('row',{name:/provider/}).waitFor();
    assert.deepEqual(await panel.getByRole('row',{name:/provider/}).getByRole('cell').allTextContents(),['3','1','0','12.345']);
    assert.deepEqual(await panel.getByRole('row',{name:/ssh evidence/}).getByRole('cell').allTextContents(),['0','0','—','—']);
    assert.match(await panel.getByRole('status').textContent(),/3 runs sampled.*1 without valid samples.*2 malformed events discarded.*2,048 timing events/);
    for(const width of [320,768,1440]){
      await page.setViewportSize({width,height:900});
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
      await capture('ai-triage-timings-'+width);
    }
    await panel.getByRole('button',{name:'Refresh timing summary'}).click();await started;
    const response=page.waitForResponse('**/api/ai/triage/timings');
    await page.locator('[data-nav=overview]').click();
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
    release();await response;
    assert.equal(await panel.count(),0);
  }finally{
    release();await page.unroute(pattern,routeHandler);await page.setViewportSize(originalViewport);
  }
};
