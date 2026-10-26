const assert=require('assert/strict');
module.exports=async(page)=>{
  let calls=0,release,started;
  const waiting=new Promise(resolve=>release=resolve),start=new Promise(resolve=>started=resolve);
  const routeHandler=async route=>{
    calls++;
    if(calls===1)return route.fulfill({status:502,json:{detail:'OpenAI API HTTP 429 (insufficient_quota); request ID: req_fixture. Check API credits and project limits.'}});
    if(calls===2)return route.fulfill({json:{ok:true,detail:'OpenAI connection and structured-output test passed using saved settings.'}});
    started();await waiting;await route.fulfill({json:{ok:true,detail:'Late response must not overwrite another page'}});
  };
  await page.route('**/api/settings/ai-test',routeHandler);
  try{
    await page.locator('#ai-test').click();
    await page.locator('#ai-test-result').filter({hasText:'HTTP 429 (insufficient_quota)'}).waitFor();
    assert.equal(await page.locator('#ai-test').isDisabled(),false);
    await page.locator('#ai-test').click();
    await page.locator('#ai-test-result').filter({hasText:'test passed'}).waitFor();
    await page.locator('#ai-test').click();await start;
    assert.equal(await page.locator('#ai-test').isDisabled(),true);
    await page.locator('[data-nav=overview]').click();
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
    release();await page.waitForTimeout(100);
    assert.equal(await page.getByText('Late response must not overwrite another page').count(),0);
    assert.equal(calls,3);
    await page.locator('[data-nav=settings]').click();
    await page.getByRole('heading',{name:'Set your own rhythm.'}).waitFor();
    await page.locator('[href="#settings/ai"]').first().click();
    await page.locator('#ai-settings-form').waitFor();
    assert.equal(await page.locator('#ai-test-result').textContent(),'');
  }finally{release();await page.unroute('**/api/settings/ai-test',routeHandler);}
};
