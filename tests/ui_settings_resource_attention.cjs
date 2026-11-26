const assert=require('assert/strict');
// Settings -> Patch policy: the low-resource notice threshold round-trips and stays responsive (#1297).
module.exports=async(page,capture)=>{
 const settings=async()=>(await page.request.get(new URL('/api/settings',page.url()).href)).json();
 await page.locator('[data-nav=settings]').click();
 await page.getByRole('heading',{name:'Set your own rhythm.'}).waitFor();
 // The settings finder lists Patch policy for the new control.
 await page.locator('#settings-search').fill('low-resource');
 await page.locator('#settings-hub [href="#settings/patching"]').waitFor();
 await page.locator('#settings-hub [href="#settings/patching"]').click();
 await page.locator('#patch-settings-form').waitFor();
 const field=page.getByLabel('Low-resource notice at · % available');
 const before=(await settings()).resource_attention_percent;
 assert.equal(await field.inputValue(),String(before));
 assert.match(await page.locator('#patch-settings-form').textContent(),/free disk space, free inodes or available memory.*rises 5 points above it/s);
 // Browser validation keeps out-of-range values from being sent.
 let saves=0;const counter=request=>{if(request.method()==='PUT'&&request.url().endsWith('/api/settings/patching'))saves++;};
 page.on('request',counter);
 await field.fill('51');
 await page.getByRole('button',{name:'Save patch policy'}).click();
 assert.equal(await field.evaluate(input=>input.validity.rangeOverflow),true);
 assert.equal(saves,0);
 await field.fill('25');
 await capture?.('settings-patching-resource');
 await page.getByRole('button',{name:'Save patch policy'}).click();
 await page.locator('#section-save-result').filter({hasText:'Patch policy saved'}).waitFor();
 page.off('request',counter);
 assert.equal(saves,1);
 assert.equal((await settings()).resource_attention_percent,25);
 await page.reload();await page.locator('#patch-settings-form').waitFor();
 assert.equal(await page.getByLabel('Low-resource notice at · % available').inputValue(),'25');
 for(const width of [320,768,1440]){
  await page.setViewportSize({width,height:1000});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'patch policy overflows at '+width);
 }
 // Restore the value other modules expect.
 await page.getByLabel('Low-resource notice at · % available').fill(String(before));
 await page.getByRole('button',{name:'Save patch policy'}).click();
 await page.locator('#section-save-result').filter({hasText:'Patch policy saved'}).waitFor();
 assert.equal((await settings()).resource_attention_percent,before);
};
