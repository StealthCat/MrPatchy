const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 await page.locator('[href="#settings/database"]').first().click();
 await page.locator('#database-form').waitFor();
 await page.locator('#database-form [name=host]').fill('mysql.example.test');
 await page.locator('#database-form [name=username]').fill('patchy');
 await page.locator('#database-form [name=password]').fill('fixture-secret-only');
 await page.getByRole('button',{name:'Save migration destination',exact:true}).click();
 await page.locator('#database-result').filter({hasText:'Destination saved'}).waitFor();
 assert.equal(await page.locator('#database-form [name=password]').inputValue(),'');
 await page.locator('[data-nav=overview]').click();
 await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
 await page.locator('[data-nav=settings]').click();
 await page.locator('[href="#settings/database"]').first().click();
 await page.locator('#database-form [name=host]').waitFor();
 assert.equal(await page.locator('#database-form [name=host]').inputValue(),'mysql.example.test');
 assert.equal(await page.locator('#database-form [name=password]').inputValue(),'');
 assert.match(await page.locator('#database-settings').textContent(),/Active: SQLite/);
 await capture('database-settings');
 // Test connection: button is separate from Save, reports an aria-live result and discards stale results on edit.
 let tested=0,releaseTest,releaseFailure;
 const testWait=new Promise(resolve=>releaseTest=resolve),failureWait=new Promise(resolve=>releaseFailure=resolve);
 const testHandler=async route=>{
  tested++;
  if(tested===1)await testWait;
  if(tested===2){await failureWait;return route.fulfill({status:503,json:{detail:'Synthetic delayed failure'}});}
  await route.fulfill({json:{ok:true,elapsed_ms:12,detail:'Connected and ran a read-only query.',scope:'Checked from this controller only.'}});
 };
 await page.route('**/api/settings/database/test',testHandler);
 try{
  const testButton=page.getByRole('button',{name:'Test connection',exact:true});
  const status=page.getByRole('status').and(page.locator('#database-test-result'));
  await testButton.focus();
  await page.keyboard.press('Enter');
  await status.filter({hasText:'Testing connection'}).waitFor();
  assert.equal(await testButton.getAttribute('aria-disabled'),'true');
  assert.equal(await page.evaluate(()=>document.activeElement.id),'database-test');
  await page.keyboard.press('Enter');
  releaseTest();
  await status.filter({hasText:'Success (12 ms)'}).waitFor();
  assert.equal(await status.getAttribute('aria-live'),'polite');
  assert.equal(await page.evaluate(()=>document.activeElement.id),'database-test');
  assert.equal(tested,1);
  await capture('database-settings-test-desktop');
  await page.keyboard.press('Enter');
  await status.filter({hasText:'Testing connection'}).waitFor();
  await page.locator('#database-form [name=host]').fill('other.example.test');
  releaseFailure();
  await page.locator('#database-test:not([aria-disabled])').waitFor();
  assert.equal(await status.textContent(),'');
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false);
  await testButton.click();
  await page.locator('#database-test-result').filter({hasText:'Success'}).waitFor();
  await capture('database-settings-test-mobile');
  await page.setViewportSize({width:1440,height:1000});
  await page.locator('#database-form [name=host]').fill('mysql.example.test');
 }finally{releaseTest();releaseFailure();await page.unroute('**/api/settings/database/test',testHandler);}
 await page.setViewportSize({width:390,height:844});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false);
 await page.setViewportSize({width:1440,height:1000});
 await page.locator('#database-form [name=backend]').selectOption('sqlite');
 await page.locator('#database-form [name=sqlite_file]').fill('migrated.db');
 await page.getByRole('button',{name:'Save migration destination',exact:true}).click();
 await page.locator('#database-result').filter({hasText:'Destination saved'}).waitFor();
 assert.equal(await page.locator('#database-form [name=host]').isDisabled(),true);
 // A slow stage response must not write into a newly navigated page.
 let release,started;const waiting=new Promise(r=>release=r),start=new Promise(r=>started=r);
 const handler=async route=>{if(route.request().method()!=='PUT')return route.continue();started();await waiting;await route.fulfill({json:{ok:true}});};
 await page.route('**/api/settings/database',handler);
 try{
  await page.getByRole('button',{name:'Save migration destination',exact:true}).click();await start;
  await page.locator('[data-nav=overview]').click();
  await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
  release();await page.waitForTimeout(100);
  assert.equal(await page.locator('#database-result').count(),0);
 }finally{release();await page.unroute('**/api/settings/database',handler);}
 await page.locator('[data-nav=settings]').click();
 await page.getByRole('heading',{name:'Set your own rhythm.'}).waitFor();
};
