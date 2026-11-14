const assert=require('assert/strict');
// Settings → AI previews admission/spend effects and confirms expansions before saving (#871);
// the server refuses an expanding save that lacks the preview's confirmation (#881).
module.exports=async(page,capture)=>{
 // Direct API save as an administrator who reviewed the preview: resend with its confirmation.
 const confirmedSave=async body=>page.evaluate(async body=>{const current=await api('/settings');const controls={ai_control_mode:body.ai_control_mode,ai_rate_per_hour:body.ai_rate_per_hour};const preview=await api('/settings/ai/preview','POST',controls);return api('/settings/ai','PUT',{...controls,expected_ai_controls_revision:current.ai_controls_revision,...(preview.expansion_confirmation?{confirm_ai_expansion:preview.expansion_confirmation}:{})});},body);
 const saved=async()=>page.evaluate(async()=>(await api('/settings')));
 const original=await saved();
 const restore=async()=>confirmedSave({ai_control_mode:original.ai_control_mode,ai_rate_per_hour:original.ai_rate_per_hour});
 try{
  await confirmedSave({ai_control_mode:'rate',ai_rate_per_hour:20});
  // An API save that expands admission without the preview's confirmation is refused and writes nothing (#881).
  const refused=await page.evaluate(async()=>{const r=await fetch('/api/settings/ai',{method:'PUT',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({ai_rate_per_hour:60})});return {status:r.status,detail:(await r.json()).detail};});
  assert.equal(refused.status,409);assert.match(refused.detail,/were not confirmed: .*20\/hour to 60\/hour/);
  assert.equal((await saved()).ai_rate_per_hour,20);
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
