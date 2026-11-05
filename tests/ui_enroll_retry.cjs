const assert=require('assert/strict');
// Add-server step 1 (#438): a rejected request must leave the form retryable and must not claim the server may exist.
module.exports=async(page)=>{
 let mode=422;const calls=[];
 const handler=route=>{
  if(route.request().method()!=='POST')return route.fallback();
  calls.push(mode);
  return route.fulfill({status:mode,json:{detail:mode===422?'Invalid address.':'Database unavailable.'}});
 };
 await page.route('**/api/hosts',handler);
 try{
  await page.getByRole('button',{name:'+ Add server',exact:true}).click();
  const address=page.locator('#host-form [name=address]');
  assert.equal(await address.getAttribute('pattern'),'[A-Za-z0-9:.\\-]+');
  await page.locator('#host-form [name=name]').fill('Retry NAS');
  await address.fill('192.0.2.77');
  const button=page.locator('#host-form button');
  await button.click();
  await page.locator('#modal-message').filter({hasText:'Invalid address.'}).waitFor();
  assert.equal(await button.isDisabled(),false);
  assert.doesNotMatch(await page.locator('#modal-message').textContent(),/may already have been created/);
  mode=500;await button.click();
  await page.locator('#modal-message').filter({hasText:'may already have been created'}).waitFor();
  assert.equal(await button.isDisabled(),true);
  assert.deepEqual(calls,[422,500]);
 }finally{
  await page.unroute('**/api/hosts',handler);
  await page.keyboard.press('Escape');
 }
};
