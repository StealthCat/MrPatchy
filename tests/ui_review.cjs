// Regression checks for the interactive security/usability review.
const assert=require('assert/strict');
module.exports=async function reviewUI(page,ids,capture){
  const api=async(path,method='GET',body)=>page.evaluate(async({path,method,body})=>{
    const session=await (await fetch('/api/session')).json();
    const response=await fetch('/api'+path,{method,headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrf},body:body===undefined?undefined:JSON.stringify(body)});
    return {status:response.status,body:await response.json()};
  },{path,method,body});
  const operations=async()=>{
    await page.getByRole('button',{name:'Account',exact:true}).click();
    await page.getByRole('button',{name:'Operations',exact:true}).click();
    await page.locator('#window-form button').waitFor();
  };
  const windowsA=[{days:[0,2],start:60,end:120}],windowsB=[{days:[5],start:600,end:720}];
  for(const [id,windows] of [[ids.a,windowsA],[ids.b,windowsB]])assert.equal((await api('/operations/'+id+'/window','PUT',{windows})).status,200);
  await operations();
  for(const [id,windows] of [[ids.a,windowsA],[ids.b,windowsB]]){
    await page.locator('#window-form [name=host]').selectOption(id);
    await page.waitForFunction(expected=>document.querySelector('#window-form [name=windows]').value===JSON.stringify(expected,null,2),windows);
    assert.equal(await page.locator('#window-form button').isDisabled(),false);
  }
  // A slow previous host must not overwrite the selected host's maintenance policy.
  let releaseWindow,windowStarted;const startWindow=new Promise(r=>windowStarted=r);
  const windowRoute='**/api/operations/'+ids.a+'/window';
  await page.route(windowRoute,async route=>{windowStarted();await new Promise(r=>releaseWindow=r);await route.fulfill({json:{windows:windowsA}});});
  await page.locator('#window-form [name=host]').selectOption(ids.a);await startWindow;
  assert.equal(await page.locator('#window-form button').isDisabled(),true);
  await page.locator('#window-form [name=host]').selectOption(ids.b);
  await page.waitForFunction(expected=>document.querySelector('#window-form [name=windows]').value===JSON.stringify(expected,null,2),windowsB);
  releaseWindow();await page.waitForTimeout(100);
  assert.deepEqual(JSON.parse(await page.locator('#window-form [name=windows]').inputValue()),windowsB);
  await page.unroute(windowRoute);
  await capture('operations');
  await page.keyboard.press('Escape');assert.equal(await page.locator('#modal').evaluate(x=>x.open),false);

  // Editing saved notification metadata must not erase or expose its password.
  const smtp={host:'mail.example.test',port:587,mode:'starttls',sender:'patchy@example.test',recipients:['ops@example.test'],username:'patchy',password:'fixture-only-secret',enabled:false};
  assert.equal((await api('/operations/smtp','PUT',smtp)).status,200);
  await operations();await page.getByRole('button',{name:'SSO, SMTP & target policies',exact:true}).click();
  await page.locator('#smtp-form').waitFor();
  assert.equal(await page.locator('#smtp-form [name=host]').inputValue(),smtp.host);
  assert.equal(await page.locator('#smtp-form [name=password]').inputValue(),'');
  assert.equal(await page.locator('#modal-body').innerText().then(x=>x.includes(smtp.password)),false);
  await page.getByRole('button',{name:'Save SMTP configuration',exact:true}).click();
  await page.locator('#modal-message').filter({hasText:'SMTP settings saved'}).waitFor();
  assert.equal((await api('/operations/notifications')).body.password_configured,true);
  await page.locator('#close-modal').click();
  await page.getByRole('button',{name:'Account',exact:true}).click();
  await page.locator('#account-form [name=password]').fill('incorrect');
  await page.locator('#account-form [name=new_password]').fill('replacement-password-long');
  await page.getByRole('button',{name:'Change password',exact:true}).click();
  await page.locator('#modal-message').filter({hasText:'Invalid credentials'}).waitFor();
  assert.equal((await api('/identity')).status,200);
  let releaseMfa,mfaStarted;const startMfa=new Promise(r=>mfaStarted=r);
  await page.route('**/api/identity/mfa',async route=>{mfaStarted();await new Promise(r=>releaseMfa=r);await route.fulfill({json:{secret:'fixture-only-secret'}});});
  await page.getByRole('button',{name:'Set up authenticator MFA',exact:true}).click();await startMfa;
  assert.equal(await page.locator('#mfa-setup').isDisabled(),true);
  await page.locator('#close-modal').click();
  releaseMfa();await page.waitForTimeout(100);
  assert.equal(await page.locator('#modal').evaluate(x=>x.open),false);
  await page.unroute('**/api/identity/mfa');

  // Late dashboard responses cannot replace a different page selected meanwhile.
  let releaseDashboard,dashboardStarted;const startDashboard=new Promise(r=>dashboardStarted=r);
  await page.route('**/api/dashboard',async route=>{dashboardStarted();await new Promise(r=>releaseDashboard=r);await route.continue();});
  await page.locator('[data-nav=overview]').click();await startDashboard;
  await page.locator('[data-nav=servers]').click();await page.getByRole('heading',{name:'Your Linux fleet.'}).waitFor();
  releaseDashboard();await page.waitForTimeout(150);
  assert.equal(await page.locator('#content h1').innerText(),'Your Linux fleet.');
  await page.unroute('**/api/dashboard');

  // A debounced search must not dereference fields removed by navigation.
  await page.locator('[data-nav=packages]').click();await page.locator('.pkg-check').first().waitFor();
  await page.locator('#package-search').fill('pending-search');
  await page.locator('[data-nav=servers]').click();await page.getByRole('heading',{name:'Your Linux fleet.'}).waitFor();
  await page.waitForTimeout(300);
  assert.doesNotMatch(await page.locator('#toast').innerText(),/Cannot read properties/);

  const queued=await api('/hosts/'+ids.a+'/actions/refresh','POST');assert.equal(queued.status,200);
  await page.locator('[data-nav=activity]').click();
  const cancel=page.locator('.cancel-job[data-id="'+queued.body.job_id+'"]');
  await cancel.locator('..').locator('summary').click();await cancel.click();
  await page.getByRole('button',{name:'Cancel operation',exact:true}).click();
  await page.getByRole('status').filter({hasText:'Operation cancelled'}).waitFor();
  assert.equal((await api('/jobs/'+queued.body.job_id)).body.state,'cancelled');

  // Closed dialogs and signed-out sessions must not be repopulated by old requests.
  await page.locator('[data-nav=servers]').click();await page.getByRole('button',{name:'Manage ↗'}).first().click();
  let releaseHistory,historyStarted;const startHistory=new Promise(r=>historyStarted=r);
  await page.route('**/api/hosts/*/history?*',async route=>{historyStarted();await new Promise(r=>releaseHistory=r);await route.fulfill({json:[]});});
  await page.locator('#host-history').click();await startHistory;await page.keyboard.press('Escape');
  releaseHistory();await page.waitForTimeout(100);assert.equal(await page.locator('#modal').evaluate(x=>x.open),false);
  await page.unroute('**/api/hosts/*/history?*');
  for(const role of ['viewer','operator'])assert.equal((await api('/users','PUT',{username:role,role,password:'role-test-password-long'})).status,200);
  let releaseSettings,settingsStarted;const startSettings=new Promise(r=>settingsStarted=r);
  await page.route('**/api/settings',async route=>{settingsStarted();const response=await route.fetch();await new Promise(r=>releaseSettings=r);await route.fulfill({response});});
  await page.locator('[data-nav=settings]').click();await startSettings;
  await page.locator('#logout').click();await page.locator('#login').waitFor();releaseSettings();await page.waitForTimeout(100);
  assert.equal(await page.locator('#content').innerHTML(),'');assert.equal(await page.locator('#modal-body').innerHTML(),'');
  await page.unroute('**/api/settings');
  for(const role of ['viewer','operator']){
    await page.locator('#login-form [name=username]').fill(role);await page.locator('#login-form [name=password]').fill('role-test-password-long');
    await page.getByRole('button',{name:'Open your workspace'}).click();
    await page.waitForFunction(role=>document.body.dataset.role===role,role);
    await page.locator('[data-nav=overview]').click();
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
    assert.equal(await page.locator('[data-nav=settings]').isVisible(),false);
    assert.equal(await page.locator('[data-nav=repositories]').isVisible(),false);
    await page.locator('[data-nav=packages]').click();await page.locator('.priority-select').first().waitFor();
    assert.equal(await page.locator('.priority-select').first().isDisabled(),true);
    assert.equal(await page.locator('.pkg-check').first().isDisabled(),role==='viewer');
    assert.equal(await page.locator('#patch-selected').isVisible(),role==='operator');
    await page.locator('[data-nav=activity]').click();await page.getByRole('heading',{name:'A record of the work.'}).waitFor();
    assert.equal(await page.getByRole('heading',{name:'Audit trail',exact:true}).count(),0);
    assert.equal(await page.locator('.cancel-job').count(),0);
    await page.locator('#logout').click();await page.locator('#login').waitFor();
  }
  await page.locator('#login-form [name=username]').fill('admin');await page.locator('#login-form [name=password]').fill('ui-test-password-long');
  await page.getByRole('button',{name:'Open your workspace'}).click();await page.getByRole('heading',{name:'A record of the work.'}).waitFor();
  for(const width of [320,390]){
    await page.setViewportSize({width,height:844});
    assert.equal(await page.getByRole('button',{name:'Account',exact:true}).isVisible(),true);
    assert.equal(await page.locator('#logout').isVisible(),true);
    for(const nav of ['packages','repositories','settings']){
      await page.locator('[data-nav='+nav+']').click();
      await page.waitForFunction(nav=>document.querySelector('[data-nav='+nav+']').getAttribute('aria-current')==='page',nav);
      await page.locator('#content h1').waitFor();
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,nav+' overflows '+width+'px');
    }
    await operations();await page.locator('#window-form [name=windows]').waitFor();
    assert.equal(await page.locator('#modal').evaluate(x=>x.scrollWidth>x.clientWidth),false);
    await page.keyboard.press('Escape');
  }
  await page.setViewportSize({width:1440,height:1000});
};
