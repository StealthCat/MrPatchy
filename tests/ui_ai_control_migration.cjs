const assert=require('assert/strict');
// Settings → AI fills a non-expanding legacy-to-shared-rate proposal without saving (#879, #878).
module.exports=async(page,capture)=>{
 const saved=async()=>page.evaluate(async()=>(await api('/settings')));
 const original=await saved();
 // Fixture setup and restore act as an administrator who reviewed the preview: they resend with its
 // confirmation, which #881 requires for any expanding save.
 const put=values=>page.evaluate(async values=>{const current=await api('/settings');const preview=await api('/settings/ai/preview','POST',values);await api('/settings/ai','PUT',{...values,expected_ai_controls_revision:current.ai_controls_revision,...(preview.expansion_confirmation?{confirm_ai_expansion:preview.expansion_confirmation}:{})});},values);
 const keys=['ai_control_mode','ai_rate_per_hour','ai_hourly_limit','ai_update_hourly_limit','ai_updates_enabled'];
 try{
  await put({ai_control_mode:'legacy',ai_hourly_limit:20,ai_update_hourly_limit:20,ai_updates_enabled:true});
  await page.goto(new URL('/#settings/ai',page.url()).href);await page.reload();
  const form=page.locator('#ai-settings-form'),notice=page.locator('#ai-migration'),panel=page.locator('#ai-control-effects');
  await notice.waitFor();
  const text=await notice.innerText();
  assert.match(text,/Suggested shared rate: 10 work starts\/hour/);
  assert.match(text,/process triage 20\/hour · update scoring 20\/hour · automatic incident\/startup plans 10\/hour/);
  assert.match(text,/no purpose can start more work per hour than it does now/);
  await notice.getByRole('button',{name:'Use suggested shared rate'}).click();
  assert.equal(await form.locator('[name=ai_control_mode]').inputValue(),'rate');
  assert.equal(await form.locator('[name=ai_rate_per_hour]').inputValue(),'10');
  await panel.getByText('Combined AI work start ceiling changes from 50/hour to 10/hour',{exact:false}).waitFor();
  assert.equal(await panel.locator('li.expands').count(),0);
  await capture('settings-ai-migration');
  // Filling the form saved nothing: the installation stays on legacy until the administrator saves.
  assert.equal((await saved()).ai_control_mode,'legacy');
  // Saving the proposal needs no expansion confirmation and leaves legacy mode.
  await form.getByRole('button',{name:'Save AI settings'}).click();
  await page.locator('#ai-save-result').getByText('AI settings saved.',{exact:false}).waitFor();
  assert.equal(await page.locator('#modal').evaluate(d=>d.open),false);
  const after=await saved();
  assert.equal(after.ai_control_mode,'rate');assert.equal(after.ai_rate_per_hour,10);
  assert.equal(after.ai_control_migration.required,false);
 }finally{await put(Object.fromEntries(keys.map(key=>[key,original[key]])));}
};
