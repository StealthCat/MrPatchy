const assert=require('assert/strict');
// Settings -> Patch policy: the hash-sweep stall notice threshold round-trips and stays responsive (#1265).
module.exports=async(page,capture)=>{
 const settings=async()=>(await page.request.get(new URL('/api/settings',page.url()).href)).json();
 await page.locator('[data-nav=settings]').click();
 await page.getByRole('heading',{name:'Set your own rhythm.'}).waitFor();
 // The settings finder lists Patch policy for the new control.
 await page.locator('#settings-search').fill('hash sweep');
 await page.locator('#settings-hub [href="#settings/patching"]').waitFor();
 await page.locator('#settings-hub [href="#settings/patching"]').click();
 await page.locator('#patch-settings-form').waitFor();
 const field=page.getByLabel('Hash-sweep stall notice after · minutes');
 const before=(await settings()).integrity_sweep_stalled_minutes;
 assert.equal(await field.inputValue(),String(before));
 assert.match(await page.locator('#patch-settings-form').textContent(),/hash sweep has not completed for this long.*about six minutes/s);
 // Browser validation keeps out-of-range values from being sent.
 let saves=0;const counter=request=>{if(request.method()==='PUT'&&request.url().endsWith('/api/settings/patching'))saves++;};
 page.on('request',counter);
 await field.fill('9');
 await page.getByRole('button',{name:'Save patch policy'}).click();
 assert.equal(await field.evaluate(input=>input.validity.rangeUnderflow),true);
 assert.equal(saves,0);
 await field.fill('45');
 await capture?.('settings-patching-hash-sweep');
 await page.getByRole('button',{name:'Save patch policy'}).click();
 await page.locator('#section-save-result').filter({hasText:'Patch policy saved'}).waitFor();
 page.off('request',counter);
 assert.equal(saves,1);
 assert.equal((await settings()).integrity_sweep_stalled_minutes,45);
 await page.reload();await page.locator('#patch-settings-form').waitFor();
 assert.equal(await page.getByLabel('Hash-sweep stall notice after · minutes').inputValue(),'45');
 for(const width of [320,768,1440]){
  await page.setViewportSize({width,height:1000});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'patch policy overflows at '+width);
 }
 // Restore the value other modules expect.
 await page.getByLabel('Hash-sweep stall notice after · minutes').fill(String(before));
 await page.getByRole('button',{name:'Save patch policy'}).click();
 await page.locator('#section-save-result').filter({hasText:'Patch policy saved'}).waitFor();
 assert.equal((await settings()).integrity_sweep_stalled_minutes,before);
};
