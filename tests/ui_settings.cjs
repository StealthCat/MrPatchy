const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 assert.equal(await page.locator('#ai-settings-form').count(),0,'settings hub must not contain all forms');
 await page.locator('[href="#settings/patching"]').first().click();
 await page.locator('#patch-settings-form').waitFor();
 assert.equal(await page.locator('#ai-model').count(),0);
 await page.locator('[name=repo_minutes]').fill('35');
 await page.getByRole('button',{name:'Save patch policy'}).click();
 await page.locator('#section-save-result').filter({hasText:'Patch policy saved'}).waitFor();
 await page.locator('[href="#settings/history"]').first().click();
 await page.locator('[name=history_days]').fill('45');
 await page.getByRole('button',{name:'Save history retention'}).click();
 await page.locator('#section-save-result').filter({hasText:'History retention saved'}).waitFor();
 const data=await (await page.request.get(new URL('/api/settings',page.url()).href)).json();
 assert.equal(data.repo_minutes,35);assert.equal(data.history_days,45);
 // Deep links, reload, and browser back retain the section route.
 await page.reload();await page.locator('#history-settings-form').waitFor();
 assert.equal(await page.locator('[name=history_days]').inputValue(),'45');
 await page.locator('[href="#settings/patching"]').first().click();await page.locator('#patch-settings-form').waitFor();
 assert.equal(await page.locator('[name=repo_minutes]').inputValue(),'35');
 await page.goBack();await page.locator('#history-settings-form').waitFor();
 for(const width of [320,390,1440]){
  await page.setViewportSize({width,height:1000});
  for(const section of ['ai','patching','database','https','history']){
   await page.locator('[href="#settings/'+section+'"]').first().click();
   await page.waitForFunction(section=>document.querySelector('.settings-nav [aria-current=page]')?.getAttribute('href')==='#settings/'+section,section);
   if(section==='database')await page.locator('#database-form').waitFor();
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,section+' overflows at '+width);
  }
 }
 await page.locator('[data-nav=settings]').click();
 await page.getByRole('heading',{name:'Set your own rhythm.'}).waitFor();
 await capture('settings-sections');
};
