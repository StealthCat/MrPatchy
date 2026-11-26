const assert=require('assert/strict');
// Administrator-confirmed AI price catalog (#1487): review, stale-revision refusal and confirmation.
module.exports=async(page,capture)=>{
 await page.locator('[href="#settings/ai"]').first().click();await page.locator('#ai-settings-form').waitFor();
 assert.match(await page.locator('#ai-settings-form').textContent(),/bundled with this release/);
 await page.getByRole('button',{name:'Review and confirm prices'}).click();
 const form=page.locator('#price-catalog-form');await form.waitFor();
 const astra=page.getByLabel('gpt-6-astra Input USD per million tokens');
 assert.equal(await astra.inputValue(),'10');
 // Older models have no verified cache-write price and offer no input for one.
 assert.equal(await page.locator('[name="gpt-4.1:cache_write"]').count(),0);
 await capture?.('settings-price-catalog');
 // A confirmation made elsewhere after the dialog opened is refused, not overwritten.
 let stale=true;
 await page.route('**/api/settings/ai-price-catalog',async route=>{
  if(route.request().method()==='POST'&&stale){stale=false;await route.fulfill({status:409,json:{detail:'The price catalog changed after you opened it. Review the current rates and confirm again.'}});}
  else await route.fallback();
 });
 await page.locator('[name=days]').fill('14');
 await form.getByRole('checkbox').check();
 await page.locator('[name=confirmation]').fill('CONFIRM PRICES');
 await form.getByRole('button',{name:'Confirm prices'}).click();
 await page.locator('#modal-message').filter({hasText:'changed after you opened it'}).waitFor();
 assert.ok(await page.locator('#modal').evaluate(dialog=>dialog.open),'a refused confirmation keeps the dialog open');
 await form.getByRole('button',{name:'Confirm prices'}).click();
 await page.locator('#toast').filter({hasText:'Prices confirmed until'}).waitFor();
 await page.unroute('**/api/settings/ai-price-catalog');
 assert.equal(await page.locator('#modal').evaluate(dialog=>dialog.open),false);
 await page.locator('#ai-settings-form').filter({hasText:'confirmed by admin'}).waitFor();
 const catalog=await (await page.request.get(new URL('/api/settings/ai-price-catalog',page.url()).href)).json();
 assert.equal(catalog.origin,'administrator');assert.match(catalog.version,/^admin-/);
 assert.equal(catalog.expires_at-catalog.verified_at,14*86400);
 assert.deepEqual(catalog.rates,catalog.bundled_rates);
};
