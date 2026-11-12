const assert=require('assert/strict');

module.exports=async(page,capture)=>{
  const pattern='**/api/ai/known-good/summary';
  const originalViewport=page.viewportSize();
  let calls=0,release,requestStarted;
  const held=new Promise(resolve=>release=resolve),started=new Promise(resolve=>requestStarted=resolve);
  const populated={active_entries:1234,revoked_entries:2,retained_reuse_assessments:57,reuse_assessments_on_revoked_entries:3};
  const routeHandler=async route=>{
    switch(++calls){
      case 1:return route.fulfill({status:503,json:{detail:'Internal fixture details'}});
      case 2:return route.fulfill({json:{active_entries:-1,revoked_entries:'7',retained_reuse_assessments:null,reuse_assessments_on_revoked_entries:0}});
      case 3:return route.fulfill({json:populated});
      default:requestStarted();await held;return route.fulfill({json:populated});
    }
  };
  await page.route(pattern,routeHandler);
  try{
    await page.locator('[data-nav=ai-logs]').click();
    const panel=page.getByRole('region',{name:'Fleet known-good cache',exact:true});
    await panel.waitFor();
    assert.equal(calls,0,'summary must load only on demand');
    await panel.getByRole('button',{name:'Load cache summary'}).click();
    await panel.getByRole('status').filter({hasText:'Cache summary is unavailable'}).waitFor();
    assert.equal(await panel.getByText('Internal fixture details').count(),0);
    assert.equal(await page.locator('#ai-log-table').isVisible(),true);
    await panel.getByRole('button',{name:'Retry cache summary'}).click();
    await panel.getByRole('status').filter({hasText:'Summary of retained records'}).waitFor();
    const facts=panel.locator('.status-facts span');
    assert.deepEqual(await facts.allTextContents(),['Unavailable active safe candidates','Unavailable revoked candidates','Unavailable retained reuse assessments','0 reuse assessments on revoked candidates']);
    assert.equal(await panel.locator('.known-good-review').isVisible(),false);
    await panel.getByRole('button',{name:'Refresh cache summary'}).click();
    await panel.getByText('1,234 active safe candidates').waitFor();
    assert.deepEqual(await facts.allTextContents(),['1,234 active safe candidates','2 revoked candidates','57 retained reuse assessments','3 reuse assessments on revoked candidates']);
    assert.match(await panel.locator('.known-good-review').textContent(),/^3 retained reuse assessment\(s\) are linked to revoked candidates and need review\./);
    assert.match(await panel.textContent(),/grants no approval and authorizes no response/);
    for(const width of [320,768,1440]){
      await page.setViewportSize({width,height:900});
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
      await capture('ai-known-good-summary-'+width);
    }
    await panel.getByRole('button',{name:'Refresh cache summary'}).click();await started;
    const response=page.waitForResponse(pattern);
    await page.locator('[data-nav=overview]').click();
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
    release();await response;
    assert.equal(await panel.count(),0);
    const before=calls;
    const identity=async route=>{const response=await route.fetch();route.fulfill({response,json:{...await response.json(),role:'viewer'}});};
    await page.route('**/api/identity',identity);
    try{
      await page.goto(new URL('/#ai-logs',page.url()).href);
      await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
      assert.equal(await page.getByRole('region',{name:'Fleet known-good cache',exact:true}).count(),0);
      assert.equal(calls,before,'viewers must not request the known-good summary');
    }finally{
      await page.unroute('**/api/identity',identity);
      await page.goto(new URL('/#overview',page.url()).href);
      await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
    }
  }finally{
    release();await page.unroute(pattern,routeHandler);await page.setViewportSize(originalViewport);
  }
};
