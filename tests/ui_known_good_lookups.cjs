const assert=require('assert/strict');

module.exports=async(page,capture)=>{
  const pattern='**/api/ai/known-good/lookups';
  const originalViewport=page.viewportSize();
  let calls=0;
  const misses={no_candidate:12,context_ineligible:3,candidate_revoked:0,candidate_unverified:1,bypassed_refresh:2,bypassed_changed:0,miss_unclassified:0};
  const populated={window_days:30,since_day:'2026-10-15',timezone:'UTC',counted_since_day:'2026-11-01',hits:1234,misses,total_misses:18,scope:'process_triage'};
  const routeHandler=async route=>{
    switch(++calls){
      case 1:return route.fulfill({status:503,json:{detail:'Internal fixture details'}});
      case 2:return route.fulfill({json:{hits:-1,total_misses:'7',misses:{no_candidate:'<img src=x>'},counted_since_day:'<img src=x>'}});
      default:return route.fulfill({json:populated});
    }
  };
  await page.route(pattern,routeHandler);
  try{
    await page.locator('[data-nav=ai-logs]').click();
    const panel=page.getByRole('region',{name:'Cache lookup outcomes',exact:true});
    await panel.waitFor();
    assert.equal(calls,0,'lookup outcomes must load only on demand');
    await panel.getByRole('button',{name:'Load lookup outcomes'}).click();
    await panel.getByRole('status').filter({hasText:'Lookup outcomes are unavailable'}).waitFor();
    assert.equal(await panel.getByText('Internal fixture details').count(),0);
    await panel.getByRole('button',{name:'Retry lookup outcomes'}).click();
    await panel.getByRole('status').filter({hasText:'No lookups have been counted yet.'}).waitFor();
    const facts=panel.locator('.status-facts span');
    assert.deepEqual(await facts.allTextContents(),['Unavailable cache hits','Unavailable cache misses']);
    assert.equal(await panel.locator('.known-good-misses').isVisible(),false);
    assert.equal(await panel.locator('img').count(),0);
    await panel.getByRole('button',{name:'Refresh lookup outcomes'}).click();
    await panel.getByText('1,234 cache hits').waitFor();
    assert.deepEqual(await facts.allTextContents(),['1,234 cache hits','18 cache misses']);
    assert.deepEqual(await panel.locator('.known-good-misses li').allTextContents(),['12 no candidate for the exact fingerprint','3 exact verified context incomplete','1 candidate not reusable at lookup time','2 bypassed by administrator Re-triage']);
    assert.equal(await panel.getByRole('status').textContent(),'Last 30 UTC days of process triage. Counted since 2026-11-01 (UTC).');
    assert.match(await panel.textContent(),/grants no approval and authorizes no response/);
    for(const width of [320,768,1440]){
      await page.setViewportSize({width,height:900});
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
      await capture('ai-known-good-lookups-'+width);
    }
    const before=calls;
    const identity=async route=>{const response=await route.fetch();route.fulfill({response,json:{...await response.json(),role:'viewer'}});};
    await page.route('**/api/identity',identity);
    try{
      await page.goto(new URL('/#ai-logs',page.url()).href);
      await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
      assert.equal(await page.getByRole('region',{name:'Cache lookup outcomes',exact:true}).count(),0);
      assert.equal(calls,before,'viewers must not request lookup outcomes');
    }finally{
      await page.unroute('**/api/identity',identity);
      await page.goto(new URL('/#overview',page.url()).href);
      await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
    }
  }finally{
    await page.unroute(pattern,routeHandler);await page.setViewportSize(originalViewport);
  }
};
