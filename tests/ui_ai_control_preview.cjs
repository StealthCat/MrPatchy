const assert=require('assert/strict');
// Settings → AI previews admission/spend effects and confirms expansions before saving (#871).
module.exports=async(page,capture)=>{
 const saved=async()=>page.evaluate(async()=>(await api('/settings')));
 const original=await saved();
 const restore=async()=>page.evaluate(async values=>{const current=await api('/settings');await api('/settings/ai','PUT',{ai_control_mode:values.ai_control_mode,ai_rate_per_hour:values.ai_rate_per_hour,expected_ai_controls_revision:current.ai_controls_revision});},original);
 try{
  await page.evaluate(async()=>{const current=await api('/settings');await api('/settings/ai','PUT',{ai_control_mode:'rate',ai_rate_per_hour:20,expected_ai_controls_revision:current.ai_controls_revision});});
  await page.goto(new URL('/#settings/ai',page.url()).href);await page.reload();
  const form=page.locator('#ai-settings-form'),panel=page.locator('#ai-control-effects'),rate=form.locator('[name=ai_rate_per_hour]');
  await rate.waitFor();assert.equal(await panel.isHidden(),true);
  // Lowering the rate is reported as a restriction and saves without a confirmation.
  await rate.fill('5');
  await panel.getByText('Combined AI work start ceiling changes from 20/hour to 5/hour',{exact:false}).waitFor();
  assert.equal(await panel.locator('li.expands').count(),0);
  // Raising it is flagged as an expansion in the live panel.
  await rate.fill('60');
  await panel.getByText('from 20/hour to 60/hour',{exact:false}).first().waitFor();
  assert.ok(await panel.locator('li.expands').count()>=1);
  await capture('settings-ai-effects');
  // Save asks for confirmation; Cancel saves nothing and keeps the entry.
  await form.getByRole('button',{name:'Save AI settings'}).click();
  const dialog=page.locator('#modal');
  await dialog.getByRole('heading',{name:'Confirm expanded AI admission or spend'}).waitFor();
  assert.match(await page.locator('#ai-expansion-list').innerText(),/20\/hour to 60\/hour/);
  await capture('settings-ai-expansion-confirm',false);
  await page.locator('#ai-expansion-cancel').click();
  await page.locator('#ai-save-result').getByText('Save cancelled. Nothing was saved',{exact:false}).waitFor();
  assert.equal(await dialog.evaluate(d=>d.open),false);
  assert.equal(await rate.inputValue(),'60');
  assert.equal((await saved()).ai_rate_per_hour,20);
  // Escape/close also cancels.
  await form.getByRole('button',{name:'Save AI settings'}).click();
  await page.locator('#ai-expansion-confirm').waitFor();
  await page.keyboard.press('Escape');
  await page.locator('#ai-save-result').getByText('Save cancelled',{exact:false}).waitFor();
  assert.equal((await saved()).ai_rate_per_hour,20);
  // Confirming saves, and the audit names the expansion.
  await form.getByRole('button',{name:'Save AI settings'}).click();
  await page.locator('#ai-expansion-confirm').click();
  await page.locator('#ai-save-result').getByText('AI settings saved.',{exact:false}).waitFor();
  assert.equal((await saved()).ai_rate_per_hour,60);
  assert.equal(await panel.isHidden(),true);
  const audit=await page.evaluate(async()=>(await api('/audit?limit=20')).find(row=>row.action==='update ai settings'));
  assert.match(audit.detail,/expands AI admission or spend: .*20\/hour to 60\/hour/);
  // A restriction saves immediately without a dialog.
  await rate.fill('10');
  await panel.getByText('from 60/hour to 10/hour',{exact:false}).first().waitFor();
  await form.getByRole('button',{name:'Save AI settings'}).click();
  await page.locator('#ai-save-result').getByText('AI settings saved.',{exact:false}).waitFor();
  assert.equal(await dialog.evaluate(d=>d.open),false);
  assert.equal((await saved()).ai_rate_per_hour,10);
 }finally{await restore();}
};
