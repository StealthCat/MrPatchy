const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;
 const fixture=[
  {name:'openssl:amd64',installed:'3.0.1',candidate:'3.0.2',held:false,dpkg_state:'install ok installed',priority:'high',priority_manual:false,due:now+86400,assessment:{state:'complete',score:72,confidence:'low',model:'fixture-model',explanation:'Security repository classification merits timely review.',limitations:'Metadata-only estimate; no verified CVE or changelog.',completed:now},installation:{state:'scheduled',at:now+7200,schedule:'Evening maintenance',reason:'Expected start after repository refresh.'}},
  {name:'curl:amd64',installed:'1',candidate:'2',held:false,dpkg_state:'install ok installed',priority:'normal',due:now+86400,assessment:{state:'deferred',next_at:now+1200,explanation:'Queued until shared AI eligibility; no evidence was discarded.'},installation:{state:'unscheduled',at:null,reason:'No matching schedule.'}},
  {name:'held:amd64',installed:'1',candidate:'2',held:true,dpkg_state:'hold ok installed',priority:'normal',installation:{state:'blocked',at:null,reason:'Held by target policy.'}},
  {name:'broken:amd64',installed:'1',candidate:'2',held:false,dpkg_state:'install ok unpacked',priority:'normal'},
  {name:'installed:amd64',installed:'2',candidate:'',held:false,dpkg_state:'install ok installed',priority:'normal',assessment:{state:'complete',score:67,historical:true,from_version:'1',to_version:'2',explanation:'Saved installation assessment',completed:now}},
  {name:'queued:amd64',installed:'1',candidate:'2',held:false,dpkg_state:'install ok installed',priority:'normal',installation:{state:'waiting',job_id:'queued-job',at:null,reason:'Waiting for a canary job.'}},
 ];
 const packages=route=>route.fulfill({json:fixture});
 await page.route('**/api/hosts/*/packages?*',packages);
 try{
  await page.locator('[data-nav=packages]').click();await page.locator('.pkg-check').first().waitFor();
  await page.locator('#select-all-updates').click();assert.equal(await page.locator('.pkg-check:checked').count(),2);
  await page.locator('#clear-updates').click();assert.equal(await page.locator('.pkg-check:checked').count(),0);
  await page.locator('.package-assessment summary').first().click();await page.getByText('Security repository classification merits timely review.').waitFor();
  await page.locator('.package-assessment summary').nth(1).click();await page.getByText('Next eligible scoring attempt:',{exact:false}).waitFor();
  await page.getByText('Not scheduled',{exact:true}).waitFor();
  await page.getByText('Historical AI score',{exact:true}).click();await page.getByText('Saved installation assessment',{exact:true}).waitFor();
  await capture('update-importance');
  await page.locator('#select-all-updates').click();await page.locator('#patch-selected').click();await page.locator('#confirm-patch').waitFor();
  assert.match(await page.locator('#confirm-patch').innerText(),/2 selected updates/);
  assert.equal(await page.locator('#modal-body pre').innerText(),'openssl:amd64\ncurl:amd64');await page.keyboard.press('Escape');
 }finally{await page.unroute('**/api/hosts/*/packages?*',packages);}
 const status=route=>route.fulfill({json:{pending:4,ready:0,hourly_limit:20,recent_attempts:2,worker_seen:now,reason:'backoff',message:'Failed investigations are waiting for the retry interval.',retry_at:now+1200,scoring_deferred:1,scoring_next_at:now+1200,last_error:'OpenAI API HTTP 429 (insufficient_quota)'}});
 const runs=route=>route.fulfill({json:{items:[{id:'fixture-run',purpose:'triage',state:'error',stage:'failed',started:now,model:'fixture-model',calls:1,message:'OpenAI API HTTP 429 (insufficient_quota); request ID req_fixture'}],more:false}});
 const run=route=>route.fulfill({json:{id:'fixture-run',purpose:'triage',state:'error',model:'fixture-model',calls:1,events:[{stage:'api_request',created:now,message:'Sending structured request.'},{stage:'api_response',created:now,message:'OpenAI HTTP 429; request ID req_fixture'},{stage:'failed',created:now,message:'Check API billing and limits.'}]}});
 await page.route('**/api/investigation-status',status);await page.route('**/api/ai/runs?*',runs);await page.route('**/api/ai/runs/fixture-run',run);
 try{
  await page.locator('[data-nav=ai-logs]').click();await page.getByText('1 scoring deferred',{exact:false}).waitFor();await page.getByRole('link',{name:'Inspect run',exact:true}).click();await page.getByRole('link',{name:'Timeline',exact:true}).click();await page.getByText('Check API billing and limits.',{exact:true}).waitFor();await capture('ai-run-detail');await page.getByRole('link',{name:'← AI activity',exact:true}).click();await page.locator('#ai-log-table').waitFor();await capture('ai-run-logs');
 }finally{await page.unroute('**/api/investigation-status',status);await page.unroute('**/api/ai/runs?*',runs);await page.unroute('**/api/ai/runs/fixture-run',run);}
 const history=route=>route.fulfill({json:{items:[{id:1,host_id:'fixture-host',name:'openssl:amd64',action:'version_changed',before:['3.0.1'],after:['3.0.2'],state_before:'install ok installed',state_after:'install ok installed',observed:now,recorded:now,source:'job_observation',actor:'operator',job_id:'',assessment:{state:'complete',score:72,historical:true,from_version:'3.0.1',to_version:'3.0.2',explanation:'Original patch importance',completed:now}}],more:false}});
 await page.route('**/api/package-history?*',history);
 try{await page.locator('[data-nav=history]').click();await page.getByText('3.0.1 → 3.0.2',{exact:true}).waitFor();await page.getByText('Historical AI score',{exact:true}).click();await page.getByText('Original patch importance',{exact:true}).waitFor();await capture('package-history');}finally{await page.unroute('**/api/package-history?*',history);}
 // User creation and their own password change use real APIs on the disposable DB.
 await page.locator('[data-nav=users]').click();await page.locator('#new-user').click();
 await page.locator('#user-form [name=username]').fill('new-teammate');await page.locator('#user-form [name=password]').fill('temporary-password-long');await page.locator('#user-form [name=confirm_password]').fill('temporary-password-long');await page.getByRole('button',{name:'Save user',exact:true}).click();await page.getByText('new-teammate',{exact:true}).waitFor();await capture('users');
 // A delayed save from a dismissed user form must not close a newer dialog.
 let releaseSave,saveStarted;
 const saveGate=new Promise(resolve=>releaseSave=resolve),started=new Promise(resolve=>saveStarted=resolve);
 const delayedSave=async route=>{if(route.request().method()!=='PUT')return route.continue();saveStarted();await saveGate;await route.fulfill({json:{ok:true}});};
 await page.route('**/api/users',delayedSave);
 try{
  await page.locator('[data-edit-user="new-teammate"]').click();await page.getByRole('button',{name:'Save user',exact:true}).click();await started;
  await page.keyboard.press('Escape');await page.getByRole('button',{name:'Account',exact:true}).click();await page.locator('#account-form').waitFor();
  const title=await page.locator('#modal-title').innerText();const response=page.waitForResponse(r=>r.url().endsWith('/api/users')&&r.request().method()==='PUT');releaseSave();await response;
  await page.waitForTimeout(150);assert.equal(await page.locator('#modal').evaluate(e=>e.open),true);assert.equal(await page.locator('#modal-title').innerText(),title);await page.keyboard.press('Escape');
 }finally{releaseSave();await page.unroute('**/api/users',delayedSave);}
 await page.locator('#logout').click();await page.locator('#login-form [name=username]').fill('new-teammate');await page.locator('#login-form [name=password]').fill('temporary-password-long');await page.getByRole('button',{name:'Open your workspace'}).click();await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
 assert.equal(await page.locator('[data-nav=users]').isVisible(),false);assert.equal(await page.locator('[data-nav=ai-logs]').isVisible(),false);
 await page.getByRole('button',{name:'Account',exact:true}).click();await page.locator('#account-form [name=password]').fill('temporary-password-long');await page.locator('#account-form [name=new_password]').fill('my-own-password-long');await page.locator('#account-form [name=confirm_password]').fill('wrong-password-long');await page.locator('#change-password').click();await page.getByText('New passwords do not match',{exact:true}).waitFor();
 await page.locator('#account-form [name=confirm_password]').fill('my-own-password-long');await page.locator('#change-password').click();await page.locator('#login').waitFor();
 await page.locator('#login-form [name=username]').fill('new-teammate');await page.locator('#login-form [name=password]').fill('my-own-password-long');await page.getByRole('button',{name:'Open your workspace'}).click();await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
 await page.locator('#logout').click();await page.locator('#login-form [name=username]').fill('admin');await page.locator('#login-form [name=password]').fill('ui-test-password-long');await page.getByRole('button',{name:'Open your workspace'}).click();await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
};
