const assert=require('assert/strict');
// Settings forms ask before an in-app navigation, Back/Forward or refresh discards edits.
module.exports=async page=>{
 const dialog=page.locator('#modal');
 const prompt=async()=>{
  await page.locator('#modal-title').filter({hasText:'Leave without saving?'}).waitFor();
  assert.equal(await dialog.evaluate(d=>d.open),true);
 };
 const noPrompt=async()=>assert.equal(await dialog.evaluate(d=>d.open),false,'unexpected unsaved-changes prompt');
 const hash=()=>page.evaluate(()=>location.hash);
 const unloadBlocked=()=>page.evaluate(()=>{const e=new Event('beforeunload',{cancelable:true});dispatchEvent(e);return e.defaultPrevented;});

 await page.locator('[href="#settings/history"]').first().click();
 const history=page.locator('[name=history_days]');await history.waitFor();
 const original=await history.inputValue();
 assert.equal(await unloadBlocked(),false,'untouched forms must not block unload');

 // A section tab with an edited form keeps the page, URL and value until the user chooses.
 await history.fill(String(+original+1));
 assert.equal(await unloadBlocked(),true,'edited forms must request the native leave prompt');
 await page.locator('.settings-nav [href="#settings/patching"]').click();
 await prompt();
 assert.equal(await hash(),'#settings/history');
 assert.equal(await history.inputValue(),String(+original+1));
 await page.locator('#unsaved-stay').click();
 await dialog.waitFor({state:'hidden'});
 assert.equal(await hash(),'#settings/history');
 assert.equal(await history.inputValue(),String(+original+1));

 // Any shell link is held the same way; Discard changes continues to the requested page.
 await page.locator('[data-nav=overview]').click();
 await prompt();
 assert.equal(await hash(),'#settings/history');
 await page.keyboard.press('Escape');
 await dialog.waitFor({state:'hidden'});
 assert.equal(await history.inputValue(),String(+original+1),'Escape must keep the edits');
 await page.locator('.settings-nav [href="#settings/patching"]').click();
 await prompt();
 await page.locator('#unsaved-discard').click();
 const repo=page.locator('[name=repo_minutes]');await repo.waitFor();
 assert.equal(await hash(),'#settings/patching');
 assert.equal(await unloadBlocked(),false);

 // Browser Back with edits restores the current address and asks.
 const minutes=await repo.inputValue();
 await repo.fill(String(+minutes+5));
 await page.goBack();
 await prompt();
 assert.equal(await hash(),'#settings/patching');
 assert.equal(await repo.inputValue(),String(+minutes+5));
 await page.locator('#unsaved-discard').click();
 await history.waitFor();
 assert.equal(await hash(),'#settings/history');
 assert.equal(await history.inputValue(),original,'discarded edits were not saved');

 // Reverting an edit, or saving it, clears the warning.
 await history.fill(String(+original+2));await history.fill(original);
 await page.locator('.settings-nav [href="#settings/patching"]').click();
 await repo.waitFor();await noPrompt();
 await page.locator('.settings-nav [href="#settings/history"]').click();await history.waitFor();
 await history.fill(String(+original+3));
 await page.getByRole('button',{name:'Save history retention'}).click();
 await page.locator('#section-save-result').filter({hasText:'History retention saved'}).waitFor();
 assert.equal(await unloadBlocked(),false,'saved forms must not block unload');
 await page.locator('.settings-nav [href="#settings/patching"]').click();
 await repo.waitFor();await noPrompt();
 await page.locator('.settings-nav [href="#settings/history"]').click();await history.waitFor();
 assert.equal(await history.inputValue(),String(+original+3));
 await history.fill(original);
 await page.getByRole('button',{name:'Save history retention'}).click();
 await page.locator('#section-save-result').filter({hasText:'History retention saved'}).waitFor();

 // The page Refresh control asks too; Stay keeps an unsaved API key entry.
 await page.locator('.settings-nav [href="#settings/ai"]').click();
 const key=page.locator('#ai-key-form [name=api_key]');await key.waitFor();
 await key.fill('sk-unsaved-entry');
 await page.locator('#refresh-page').click();
 await prompt();
 await page.locator('#unsaved-stay').click();
 assert.equal(await key.inputValue(),'sk-unsaved-entry');
 await key.fill('');
 await page.locator('.settings-nav [href="#settings/database"]').click();
 await page.locator('#database-form').waitFor();await noPrompt();

 // View filters are not settings and never ask.
 await page.locator('.settings-nav [href="#settings"]').click();
 await page.locator('#settings-search').fill('retention');
 await page.locator('#settings-hub [href="#settings/history"]').click();
 await history.waitFor();await noPrompt();
 await page.locator('.settings-nav [href="#settings/ai"]').click();
 await page.locator('#ai-spend-history-days').selectOption('7');
 await page.locator('.settings-nav [href="#settings/patching"]').click();
 await repo.waitFor();await noPrompt();
};
