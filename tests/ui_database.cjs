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
