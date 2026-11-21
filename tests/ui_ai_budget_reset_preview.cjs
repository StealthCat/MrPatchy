const assert=require('assert/strict');
// Settings → AI shows the concrete budget-window boundaries before and after a capped
// timezone or mode change, in the live effects panel and the expansion dialog (#1267).
module.exports=async(page,capture)=>{
 const confirmedSave=async controls=>page.evaluate(async controls=>{const current=await api('/settings');const preview=await api('/settings/ai/preview','POST',controls);return api('/settings/ai','PUT',{...controls,expected_ai_controls_revision:current.ai_controls_revision,...(preview.expansion_confirmation?{confirm_ai_expansion:preview.expansion_confirmation}:{})});},controls);
 const saved=async()=>page.evaluate(async()=>(await api('/settings')));
 const original=await saved();
 const restore=()=>confirmedSave({ai_control_mode:original.ai_control_mode,ai_rate_per_hour:original.ai_rate_per_hour,ai_budget_timezone:original.ai_budget_timezone});
 try{
  await confirmedSave({ai_control_mode:'rate',ai_rate_per_hour:20,ai_budget_timezone:'UTC'});
  await page.goto(new URL('/#settings/ai',page.url()).href);await page.reload();
  const form=page.locator('#ai-settings-form'),panel=page.locator('#ai-control-effects');
  const mode=form.locator('[name=ai_control_mode]'),zone=form.locator('[name=ai_budget_timezone]');
  await mode.waitFor();
  // Entering a capped mode discloses the window the new cap applies to; there is no current window.
  await mode.selectOption('daily_cap');
  const entering=panel.locator('.ai-budget-reset');
  await entering.waitFor();
  const enteringText=await entering.innerText();
  assert.match(enteringText,/Current window · no daily cap/);
  assert.match(enteringText,/Proposed window · UTC · started .* · resets .* · in \d+ h \d+ min/);
  assert.match(enteringText,/Calls made while uncapped are not recorded against a daily cap/);
  // Back to the stored mode: nothing to disclose.
  await mode.selectOption('rate');
  await panel.getByText('No change to Mr Patchy admission or spend ceilings',{exact:false}).waitFor();
  assert.equal(await panel.locator('.ai-budget-reset').count(),0);
  // A stored capped mode with a changed reset timezone shows both windows.
  await confirmedSave({ai_control_mode:'daily_cap',ai_rate_per_hour:20,ai_budget_timezone:'UTC'});
  await page.reload();await zone.waitFor();
  await zone.fill('Pacific/Kiritimati');
  const moving=panel.locator('.ai-budget-reset');
  await panel.getByText('Proposed window · Pacific/Kiritimati',{exact:false}).waitFor();
  const movingText=await moving.innerText();
  assert.match(movingText,/Current window · UTC · started .* · resets /);
  assert.match(movingText,/keeps counting until the reset of the budget window it was admitted under/);
  const server=await page.evaluate(async()=>(await api('/settings/ai/preview','POST',{ai_control_mode:'daily_cap',ai_budget_timezone:'Pacific/Kiritimati'})).budget_reset);
  assert.equal(await moving.getAttribute('data-resets-sooner'),String(server.resets_sooner));
  assert.equal(/resets before the current one/.test(movingText),server.resets_sooner);
  await capture('settings-ai-budget-reset');
  // The expansion dialog repeats the disclosure; cancelling saves nothing.
  await form.getByRole('button',{name:'Save AI settings'}).click();
  const dialog=page.locator('#modal');
  await dialog.getByRole('heading',{name:'Confirm expanded AI admission or spend'}).waitFor();
  assert.match(await page.locator('#ai-expansion-list').innerText(),/reset timezone changes from UTC to Pacific\/Kiritimati/);
  assert.match(await dialog.locator('.ai-budget-reset').innerText(),/Proposed window · Pacific\/Kiritimati/);
  await capture('settings-ai-budget-reset-confirm',false);
  await page.locator('#ai-expansion-cancel').click();
  await page.locator('#ai-save-result').getByText('Save cancelled',{exact:false}).waitFor();
  assert.equal((await saved()).ai_budget_timezone,'UTC');
 }finally{await restore();}
};
