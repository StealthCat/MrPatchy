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
 // A held move is undone through session history, which settles asynchronously.
 const expectHash=async(expected,message)=>{await page.waitForFunction(h=>location.hash===h,expected,{timeout:3000}).catch(()=>{});assert.equal(await hash(),expected,message);};
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
 await expectHash('#settings/history');
 assert.equal(await history.inputValue(),String(+original+1));
 await page.locator('#unsaved-stay').click();
 await dialog.waitFor({state:'hidden'});
 await expectHash('#settings/history');
 assert.equal(await history.inputValue(),String(+original+1));

 // Any shell link is held the same way; Discard changes continues to the requested page.
 await page.locator('[data-nav=overview]').click();
 await prompt();
 await expectHash('#settings/history');
 await page.keyboard.press('Escape');
 await dialog.waitFor({state:'hidden'});
 assert.equal(await history.inputValue(),String(+original+1),'Escape must keep the edits');
 await page.locator('.settings-nav [href="#settings/patching"]').click();
 await prompt();
 await page.locator('#unsaved-discard').click();
 const repo=page.locator('[name=repo_minutes]');await repo.waitFor();
 await expectHash('#settings/patching');
 assert.equal(await unloadBlocked(),false);

 // Browser Back → Stay keeps the page without rewriting history: once the edit
 // is reverted, Back reaches the original previous page and Forward returns.
 const minutes=await repo.inputValue();
 await repo.fill(String(+minutes+5));
 await page.goBack();
 await prompt();
 await page.locator('#unsaved-stay').click();
 await dialog.waitFor({state:'hidden'});
 await expectHash('#settings/patching');
 assert.equal(await repo.inputValue(),String(+minutes+5),'Stay must keep the edits');
 await repo.fill(minutes);
 await page.goBack();
 await history.waitFor();
 await expectHash('#settings/history','Back after Stay must reach the previous page, not a rewritten copy');
 await noPrompt();
 await page.goForward();
 await repo.waitFor();
 await expectHash('#settings/patching');

 // Browser Back with edits restores the current address and asks.
 await repo.fill(String(+minutes+5));
 await page.goBack();
 await prompt();
 await expectHash('#settings/patching');
 assert.equal(await repo.inputValue(),String(+minutes+5));
 await page.locator('#unsaved-discard').click();
 await history.waitFor();
 await expectHash('#settings/history');
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

 // A clean Back onto an entry that shares the settled position still renders. Other
 // scripts' pushState and coalesced hash changes can leave two entries with one index;
 // only the guard's own undo may be swallowed.
 await page.evaluate(()=>history.pushState(history.state,'','#settings/history'));
 await page.evaluate(()=>{location.hash='#settings/database';});
 await page.locator('#database-form').waitFor();
 await page.evaluate(()=>history.back());await history.waitFor();
 await page.evaluate(()=>history.back());
 await expectHash('#settings/patching','clean Back must reach the earlier entry');
 await repo.waitFor({timeout:5000});
 assert.equal(await history.count(),0,'clean Back onto a shared position must render the page it reaches');
 await noPrompt();
};
