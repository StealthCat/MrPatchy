const assert=require('assert/strict');
module.exports=async page=>{
 let action='quarantine-apply',state='queued',writes=0;
 const jobs=route=>route.fulfill({json:[{id:'cancel-response-fixture',host_id:'fixture-host',action,state,created:Date.now()/1000,output:''}]});
 const cancel=route=>{assert.equal(route.request().method(),'POST');assert.equal(state,'queued');writes++;state='cancelled';return route.fulfill({json:{ok:true}});};
 await page.route('**/api/jobs?*',jobs);
 await page.route('**/api/operations/jobs/cancel-response-fixture/cancel',cancel);
 try{
  for(const next of ['quarantine-apply','quarantine-restore','process-suspend','process-resume']){
   action=next;state='queued';
   await page.goto(new URL('/?response-cancel='+next+'#activity',page.url()).href);
   const button=page.locator('.cancel-job[data-id="cancel-response-fixture"]');
   await button.locator('..').locator('summary').click();await button.click();
   await page.getByRole('button',{name:'Cancel operation',exact:true}).click();
   await page.getByRole('status').filter({hasText:'Operation cancelled'}).waitFor();
   assert.equal(await page.locator('.cancel-job[data-id="cancel-response-fixture"]').count(),0);
   assert.match(await page.locator('#content details.source summary').innerText(),/cancelled/);
   assert.equal(await page.locator('#modal').evaluate(x=>x.open),false);
  }
  assert.equal(writes,4);
 }finally{
  await page.unroute('**/api/jobs?*',jobs);
  await page.unroute('**/api/operations/jobs/cancel-response-fixture/cancel',cancel);
 }
};
