const assert=require('assert/strict');
module.exports=async(page,capture)=>{
  // Every top-level workflow stays usable at phone, tablet and desktop widths.
  for(const width of [320,768,1440]){
    await page.setViewportSize({width,height:1000});
    for(const view of ['overview','servers','packages','repositories','investigations','schedules','activity','history','ai-logs','users','settings']){
      await page.locator('[data-nav='+view+']').click();
      await page.waitForFunction(view=>document.querySelector('[data-nav='+view+']')?.getAttribute('aria-current')==='page',view);
      await page.locator('#page-title').waitFor();
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,view+' overflows at '+width);
      assert.equal(await page.locator('#retry-view').count(),0,view+' failed to load');
      if(width===1440&&['servers','packages','investigations','activity'].includes(view))await capture(view);
    }
  }
  // Keyboard skip must focus content without replacing the SPA route.
  await page.locator('.skip-link').focus();
  await page.keyboard.press('Enter');
  assert.equal(await page.evaluate(()=>document.activeElement.id),'page-title');
  assert.equal(new URL(page.url()).hash,'#settings');
  // Assets are local, load correctly and carry explicit alt text (empty for decoration).
  const assets=await page.evaluate(async()=>{
    await Promise.all([...document.images].map(i=>i.decode()));
    return [...document.images].every(i=>i.naturalWidth>0&&i.hasAttribute('alt')&&new URL(i.src).origin===location.origin);
  });
  assert.equal(assets,true);
  // Loading failures must be actionable and provider text must never become markup.
  const failure=route=>route.fulfill({status:503,json:{detail:'Temporary <img src=x onerror=alert(1)> failure'}});
  await page.route('**/api/dashboard',failure);
  await page.locator('[data-nav=overview]').click();
  await page.locator('#retry-view').waitFor();
  assert.equal(await page.locator('#content img[src=x]').count(),0);
  await page.unroute('**/api/dashboard',failure);
  await page.locator('#retry-view').click();
  await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
  // Reduced motion disables the only animated ornament.
  await page.emulateMedia({reducedMotion:'reduce'});
  let release,started;
  const start=new Promise(r=>started=r),wait=new Promise(r=>release=r);
  const delayed=async route=>{started();await wait;await route.fallback();};
  await page.route('**/api/dashboard',delayed);
  await page.locator('#refresh-page').click();await start;
  assert.equal(await page.locator('.loading-dots').evaluate(x=>getComputedStyle(x).animationName),'none');
  release();await page.unroute('**/api/dashboard',delayed);
  await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
  await page.emulateMedia({reducedMotion:'no-preference'});
  // Mobile sign-in retains all credentials and the account/session controls.
  await page.locator('#logout').click();
  await page.setViewportSize({width:320,height:844});
  await page.locator('#login').waitFor();
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  await page.locator('.skip-link').focus();await page.keyboard.press('Enter');
  assert.equal(await page.evaluate(()=>document.activeElement.name),'username');
  await capture('login-mobile');
};
