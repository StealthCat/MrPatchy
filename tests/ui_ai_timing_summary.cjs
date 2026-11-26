const assert=require('assert/strict');

module.exports=async(page,capture)=>{
  const pattern=url=>url.pathname==='/api/ai/triage/timings';
  const originalViewport=page.viewportSize();
  let calls=0,release,requestStarted;const purposes=[];
  const held=new Promise(resolve=>release=resolve),started=new Promise(resolve=>requestStarted=resolve);
  const populated={purpose:'triage',sampled_runs:3,runs_without_samples:1,discarded_events:2,events_truncated:true,event_limit:2048,stages:{
    claim_lock:{samples:2,errors:0,p50_ms:1,p95_ms:2},
    claim_lock_hold:{samples:2,errors:0,p50_ms:3,p95_ms:4},
    provider:{samples:3,errors:1,p50_ms:0,p95_ms:12.345},
    ssh_evidence:{samples:0,errors:0,p50_ms:null,p95_ms:null}
  }};
  const scoring={...populated,purpose:'update_scoring',sampled_runs:2,runs_without_samples:0,discarded_events:0,events_truncated:false,stages:{
    provider:{samples:2,errors:0,p50_ms:4,p95_ms:9},
    result_persistence:{samples:2,errors:0,p50_ms:1.5,p95_ms:2},
    oldest_update_age:{samples:1,errors:0,p50_ms:42,p95_ms:42}
  }};
  const routeHandler=async route=>{
    const purpose=new URL(route.request().url()).searchParams.get('purpose');purposes.push(purpose);
    if(purpose==='update_scoring')return route.fulfill({json:scoring});
    switch(++calls){
      case 1:return route.fulfill({status:503,json:{detail:'Internal fixture details'}});
      case 2:return route.fulfill({json:{...populated,sampled_runs:0,runs_without_samples:0,discarded_events:0,events_truncated:false,stages:{}}});
      case 3:case 4:return route.fulfill({json:populated});
      default:requestStarted();await held;return route.fulfill({json:populated});
    }
  };
  await page.route(pattern,routeHandler);
  try{
    await page.locator('[data-nav=ai-logs]').click();
    const panel=page.getByRole('region',{name:'AI stage timings',exact:true});
    const activity=panel.getByRole('combobox',{name:'Activity'});
    assert.equal(await activity.inputValue(),'triage');
    await panel.getByRole('button',{name:'Load timing summary'}).click();
    await panel.getByRole('status').filter({hasText:'Process triage timing summary is unavailable'}).waitFor();
    assert.equal(await panel.getByText('Internal fixture details').count(),0);
    assert.equal(await page.locator('#ai-log-table').isVisible(),true);
    await panel.getByRole('button',{name:'Retry timing summary'}).click();
    await panel.getByRole('status').filter({hasText:'No retained timing samples'}).waitFor();
    assert.equal(await panel.getByRole('table').isVisible(),false);
    await panel.getByRole('button',{name:'Refresh timing summary'}).click();
    await panel.getByRole('row',{name:/provider/}).waitFor();
    for(const [name,expected] of [['claim lock',['2','0','1','2']],['claim lock hold',['2','0','3','4']]]){
      const row=panel.getByRole('row').filter({has:page.getByRole('rowheader',{name,exact:true})});
      assert.deepEqual(await row.getByRole('cell').allTextContents(),expected);
    }
    assert.deepEqual(await panel.getByRole('row',{name:/provider/}).getByRole('cell').allTextContents(),['3','1','0','12.345']);
    assert.deepEqual(await panel.getByRole('row',{name:/ssh evidence/}).getByRole('cell').allTextContents(),['0','0','—','—']);
    assert.match(await panel.getByRole('status').textContent(),/3 runs sampled.*1 without valid samples.*2 malformed events discarded.*2,048 timing events/);
    await activity.selectOption('update_scoring');
    assert.equal(await panel.getByRole('table').count(),0);
    assert.equal(await panel.getByRole('status').textContent(),'');
    await panel.getByRole('button',{name:'Load timing summary'}).click();
    await panel.getByRole('row',{name:/result persistence/}).waitFor();
    assert.deepEqual(await panel.getByRole('row',{name:/provider/}).getByRole('cell').allTextContents(),['2','0','4','9']);
    assert.match(await panel.getByRole('status').textContent(),/^Update importance: 2 runs sampled/);
    assert.match(await panel.getByRole('status').textContent(),/from first observed pending availability to batch selection/);
    assert.deepEqual(await panel.getByRole('row',{name:/oldest update age/}).getByRole('cell').allTextContents(),['1','0','42','42']);
    assert.equal(await panel.getByRole('table').getByText('Update importance').count(),1);
    assert.equal(purposes.at(-1),'update_scoring');
    for(const width of [320,768,1440]){
      await page.setViewportSize({width,height:900});
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
      await capture('ai-scoring-timings-'+width);
    }
    await page.setViewportSize(originalViewport);
    await activity.selectOption('triage');
    await panel.getByRole('button',{name:'Load timing summary'}).click();
    await panel.getByRole('row',{name:/ssh evidence/}).waitFor();
    assert.equal(await panel.getByRole('row',{name:/oldest update age/}).count(),0);
    assert.doesNotMatch(await panel.getByRole('status').textContent(),/Oldest update age/);
    for(const width of [320,768,1440]){
      await page.setViewportSize({width,height:900});
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
      await capture('ai-triage-timings-'+width);
    }
    await panel.getByRole('button',{name:'Refresh timing summary'}).click();await started;
    const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/ai/triage/timings');
    await page.locator('[data-nav=overview]').click();
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
    release();await response;
    assert.equal(await panel.count(),0);
    assert.ok(purposes.every(p=>p==='triage'||p==='update_scoring'));
  }finally{
    release();await page.unroute(pattern,routeHandler);await page.setViewportSize(originalViewport);
  }
};
