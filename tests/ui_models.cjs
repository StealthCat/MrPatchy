const assert=require('assert/strict');
module.exports=async(page)=>{
 let calls=0,release,started;const waiting=new Promise(r=>release=r),start=new Promise(r=>started=r);
 const handler=async route=>{
  calls++;
  if(calls===1)return route.fulfill({json:{models:['available-model','ft:private:model'],selected:'',selected_available:false}});
  if(calls===2)return route.fulfill({json:{models:['different-model'],selected:'available-model',selected_available:false}});
  if(calls===3)return route.fulfill({status:502,json:{detail:'Model discovery unavailable'}});
  started();await waiting;await route.fulfill({json:{models:['late-model']}});
 };
 await page.route('**/api/settings/ai-models',handler);
 try{
  assert.equal(await page.locator('[name=ai_model]').evaluate(e=>e.tagName),'SELECT');
  await page.locator('#ai-model-refresh').click();
  await page.locator('#ai-model-status').filter({hasText:'2 accessible models'}).waitFor();
  await page.locator('#ai-model').selectOption('available-model');
  await page.getByRole('button',{name:'Save monitoring settings'}).click();
  await page.getByRole('status').filter({hasText:'Monitoring settings saved'}).waitFor();
  await page.locator('#ai-model-refresh').click();
  await page.locator('#ai-model-status').filter({hasText:'model is unavailable'}).waitFor();
  assert.equal(await page.locator('#ai-model').inputValue(),'available-model');
  await page.locator('#ai-model-refresh').click();
  await page.locator('#ai-model-status').filter({hasText:'Model discovery unavailable'}).waitFor();
  assert.equal(await page.locator('#ai-model').inputValue(),'available-model');
  await page.locator('#ai-model-refresh').click();await start;
  await page.locator('[data-nav=overview]').click();
  await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
  release();await page.waitForTimeout(100);
  assert.equal(await page.getByText('late-model').count(),0);
 }finally{release();await page.unroute('**/api/settings/ai-models',handler);}
 await page.locator('[data-nav=settings]').click();
 await page.getByRole('heading',{name:'Set your own rhythm.'}).waitFor();
};
