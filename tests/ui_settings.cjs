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
 const providerRevision='a'.repeat(64);let providerActive=true,clearRequest=null;
 const settingsHandler=async route=>{
  const response=await route.fetch(),json=await response.json();
  json.ai_provider_backoff=providerActive?{blocked:true,next_at:1793491200,failures:2,
   reason:'Transient provider or transport failure; bounded exponential backoff is active.',
   updated_at:1793404800,revision:providerRevision}:{blocked:false,next_at:null,failures:0,reason:'',updated_at:null,revision:''};
  await route.fulfill({response,json});
 };
 const clearHandler=async route=>{clearRequest=route.request().postDataJSON();providerActive=false;await route.fulfill({json:{cleared:true}});};
 await page.route('**/api/settings',settingsHandler);
 await page.route('**/api/ai/provider-backoff/clear',clearHandler);
 const spendReads=[];
 await page.route('**/api/settings/ai-spend-history?*',route=>{
  const params=new URL(route.request().url()).searchParams;
  const days=Number(params.get('days')),timezone=params.get('timezone');
  spendReads.push({days,timezone});
  if(days===90)return route.fulfill({status:503,json:{detail:'History fixture temporarily unavailable.'}});
  const windows=days===7?[]:[{timezone:timezone||'UTC<img src=x onerror=window.__spendInjected=true>',window_start:1793404800,reset_at:1793491200,call_count:3,settled_usd:'0.01',reserved_usd:'0.02',sent_usd:'0.03',uncertain_usd:'0.04',other_usd:'0.05',counted_usd:'0.15'}];
  return route.fulfill({json:{days,generated_at:1793404800,cutoff:1793404800-days*86400,max_windows:days*4,truncated:false,windows}});
 });
 await page.locator('[href="#settings/ai"]').first().click();await page.locator('#ai-settings-form').waitFor();
 await page.locator('#ai-spend-history table').waitFor();
 assert.match(await page.locator('#ai-settings-form').textContent(),/Provider backoff active.*2 consecutive.*recorded.*next eligible/s);
 await page.getByRole('button',{name:'Review and clear provider backoff'}).click();
 const clearForm=page.locator('#provider-backoff-clear-form');await clearForm.waitFor();
 assert.match(await page.locator('#modal-body').textContent(),/newer or expired floor will be preserved.*sends no provider or target request/s);
 await clearForm.getByLabel('Reason').fill('Reviewed provider status and current quota.');
 await clearForm.getByLabel('Type CLEAR BACKOFF').fill('CLEAR BACKOFF');
 await clearForm.getByRole('button',{name:'Clear reviewed provider backoff'}).click();
 await page.getByText('Reviewed provider backoff cleared.').waitFor();
 await page.locator('#ai-settings-form').waitFor();
 assert.deepEqual(clearRequest,{expected_revision:providerRevision,reason:'Reviewed provider status and current quota.',confirmation:'CLEAR BACKOFF'});
 // The success toast precedes the asynchronous Settings reload, and the old
 // #ai-settings-form also satisfies the wait above, so wait for the old button
 // to detach instead of counting it immediately.
 await page.locator('#provider-backoff-clear').waitFor({state:'detached'});
 assert.match(await page.locator('#ai-spend-history').textContent(),/local public-price estimates.*not provider invoices/s);
 assert.equal(await page.locator('#ai-spend-history img[src=x]').count(),0);assert.equal(await page.evaluate(()=>window.__spendInjected),undefined);
 await page.locator('#ai-spend-history-days').selectOption('7');await page.getByRole('status').filter({hasText:'No retained billable AI calls'}).waitFor();
 await page.locator('#ai-spend-history-days').selectOption('90');await page.getByRole('alert').filter({hasText:'History fixture temporarily unavailable'}).waitFor();
 assert.match(await page.locator('#ai-spend-history .error-state img').getAttribute('src'),/mr-patchy-error\.webp$/);
 await page.locator('#ai-spend-history-days').selectOption('30');await page.locator('#ai-spend-history table').waitFor();
 assert.deepEqual(spendReads.slice(-4),[30,7,90,30].map(days=>({days,timezone:null})));
 const timezoneFilter=page.locator('#ai-spend-history-timezone');
 const budgetTimezone=page.locator('[name=ai_budget_timezone]');
 const savedTimezone=await budgetTimezone.inputValue();
 await budgetTimezone.fill('Europe/London');
 await timezoneFilter.fill('America/New_York');
 await timezoneFilter.press('Enter');
 await page.locator('#ai-spend-history table').getByText('America/New_York',{exact:false}).waitFor();
 assert.deepEqual(spendReads.at(-1),{days:30,timezone:'America/New_York'});
 assert.equal(await budgetTimezone.inputValue(),'Europe/London');
 await timezoneFilter.fill('');
 await page.getByRole('button',{name:'Apply timezone filter'}).click();
 await page.locator('#ai-spend-history table').getByText('UTC<img',{exact:false}).waitFor();
 assert.deepEqual(spendReads.at(-1),{days:30,timezone:null});
 await budgetTimezone.fill(savedTimezone);
 // Exercise the omitted-cap API default and its real rendered budget summary.
 const defaultCap=await page.evaluate(async()=>{
  const response=await fetch('/api/settings/ai',{method:'PUT',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({ai_control_mode:'daily_cap'})});
  return response.status;
 });
 assert.equal(defaultCap,200);
 await page.reload();await page.locator('#ai-settings-form').waitFor();
 assert.equal(await page.locator('[name=ai_daily_cap_usd]').inputValue(),'10');
 assert.match(await page.locator('#ai-settings-form').textContent(),/remaining \$10(?:\s|$)/);
 await page.getByText('No transmitted AI calls await reconciliation.',{exact:true}).waitFor();
 assert.match(await page.locator('#ai-settings-form').textContent(),/Price catalog current.*2026-10-26.*expires/s);
 await page.locator('[name=ai_control_mode]').selectOption('rate_and_daily');
 await page.locator('[name=ai_daily_cap_usd]').fill('12.50');
 await page.locator('[name=ai_budget_timezone]').fill('America/New_York');
 await page.getByRole('button',{name:'Save AI settings',exact:true}).click();
 // Raising the cap and moving its reset timezone expand spend, so the save asks first (#871).
 assert.match(await page.locator('#ai-expansion-list').innerText(),/\$10\.00\/day to \$12\.50\/day[\s\S]*America\/New_York/);
 await page.locator('#ai-expansion-confirm').click();
 await page.locator('#ai-save-result').filter({hasText:'AI settings saved'}).waitFor();
 const aiState=await (await page.request.get(new URL('/api/settings',page.url()).href)).json();
 assert.equal(aiState.ai_control_mode,'rate_and_daily');assert.equal(aiState.ai_daily_cap_usd,12.5);
 assert.equal(aiState.ai_budget_timezone,'America/New_York');
 // A concurrent control change makes this open form stale: saving it must be refused, not overwrite (#709).
 const concurrent=await page.evaluate(async()=>(await fetch('/api/settings/ai',{method:'PUT',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({ai_daily_cap_usd:20})})).status);
 assert.equal(concurrent,200);
 await page.locator('[name=ai_daily_cap_usd]').fill('15');
 await page.getByRole('button',{name:'Save AI settings',exact:true}).click();
 await page.locator('#ai-save-result').filter({hasText:'reload Settings'}).waitFor();
 assert.equal(await page.locator('[name=ai_daily_cap_usd]').inputValue(),'15');
 assert.equal((await (await page.request.get(new URL('/api/settings',page.url()).href)).json()).ai_daily_cap_usd,20);
 await page.reload();await page.locator('#ai-settings-form').waitFor();
 assert.equal(await page.locator('[name=ai_daily_cap_usd]').inputValue(),'20');
 assert.match(await page.locator('#ai-settings-form').textContent(),/uncertain.*remaining/s);
 assert.match(await page.locator('#ai-settings-form').textContent(),/Provider Retry-After.*shared across workers/s);
 for(const width of [320,390,1440]){
  await page.setViewportSize({width,height:1000});
  for(const section of ['ai','patching','database','https','history']){
   await page.locator('[href="#settings/'+section+'"]').first().click();
   await page.waitForFunction(section=>document.querySelector('.settings-nav [aria-current=page]')?.getAttribute('href')==='#settings/'+section,section);
   if(section==='database')await page.locator('#database-form').waitFor();
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,section+' overflows at '+width);
  }
 }
 const budgetFixture=route=>route.fulfill({json:{...aiState,ai_budget:{
  ...aiState.ai_budget,unreconciled_call_count:2,oldest_unreconciled_reservation_at:1793404800,
 }}});
 await page.route('**/api/settings',budgetFixture);
 try{
  await page.locator('[href="#settings/ai"]').first().click();
  await page.getByText('2 transmitted AI calls await reconciliation · Oldest reservation',{exact:false}).waitFor();
 }finally{await page.unroute('**/api/settings',budgetFixture);}
 await page.locator('[data-nav=settings]').click();
 await page.getByRole('heading',{name:'Set your own rhythm.'}).waitFor();
 await page.unroute('**/api/settings',settingsHandler);
 await page.unroute('**/api/ai/provider-backoff/clear',clearHandler);
 await capture('settings-sections');
};
