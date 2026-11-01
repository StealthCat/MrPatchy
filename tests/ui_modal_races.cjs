const assert=require('assert/strict');

module.exports=async function modalRaces(page){
  const openAccount=async()=>{
    await page.getByRole('button',{name:'Account',exact:true}).click();
    await page.locator('#account-form').waitFor();
    return page.locator('#modal-title').innerText();
  };
  const replaceDialog=async()=>{
    await page.locator('#close-modal').click();
    const title=await openAccount();
    assert.match(title,/^Account/);
    return title;
  };
  const assertAccountUnaffected=async title=>{
    assert.equal(await page.locator('#modal').evaluate(dialog=>dialog.open),true);
    assert.equal(await page.locator('#modal-title').innerText(),title);
    assert.equal(await page.locator('#modal-message').isVisible(),false);
  };

  // A completed repository write belongs to the dialog that submitted it. A
  // newer Account dialog must survive, while the global toast remains useful.
  let sourcePosts=0,releaseSource,sourceStarted;
  const sourceWait=new Promise(resolve=>releaseSource=resolve);
  const sourceStart=new Promise(resolve=>sourceStarted=resolve);
  const source=async route=>{sourcePosts++;sourceStarted();await sourceWait;await route.fulfill({json:{job_id:'source-race'}});};
  await page.route('**/api/hosts/modal-race/repositories',source);
  try{
    await page.evaluate(()=>saveSource('/etc/apt/sources.list.d/race.sources','Types: deb','modal-race'));
    await page.locator('#confirm-source').evaluate(button=>{button.click();button.click();});
    await sourceStart;
    const accountTitle=await replaceDialog();
    releaseSource();
    await page.locator('#toast').filter({hasText:'Repository change queued'}).waitFor({state:'visible'});
    await assertAccountUnaffected(accountTitle);
    assert.equal(sourcePosts,1);
    await page.locator('#close-modal').click();
  }finally{releaseSource();await page.unroute('**/api/hosts/modal-race/repositories',source);}

  // Errors from an obsolete trust dialog are still reported, but never inside
  // the unrelated replacement dialog.
  let trustPuts=0,releaseTrust,trustStarted;
  const trustWait=new Promise(resolve=>releaseTrust=resolve);
  const trustStart=new Promise(resolve=>trustStarted=resolve);
  const investigations=route=>route.fulfill({json:[{id:'modal-race-trust',host_id:'modal-race',evidence:{executable:'/usr/bin/race',uid:1000},last_seen:Date.now()/1000,verdict:'unknown',approved:false,analysis:'Review this fixture.'}]});
  const trust=async route=>{trustPuts++;trustStarted();await trustWait;await route.fulfill({status:409,json:{detail:'Trust decision became stale'}});};
  await page.route('**/api/investigations?*',investigations);
  await page.route('**/api/investigations/modal-race-trust',trust);
  try{
    await page.locator('[data-nav=investigations]').click();
    await page.getByRole('button',{name:'Review & approve',exact:true}).click();
    await page.locator('#confirm-trust').evaluate(button=>{button.click();button.click();});
    await trustStart;
    const accountTitle=await replaceDialog();
    releaseTrust();
    await page.locator('#toast').filter({hasText:'Trust decision became stale'}).waitFor({state:'visible'});
    await assertAccountUnaffected(accountTitle);
    assert.equal(trustPuts,1);
    await page.locator('#close-modal').click();
  }finally{releaseTrust();await page.unroute('**/api/investigations/modal-race-trust',trust);await page.unroute('**/api/investigations?*',investigations);}

  // Session changes suppress feedback and UI mutations from the obsolete
  // operation. The intercepted write never reaches a target.
  let releaseSignedOut,signedOutStarted;
  const signedOutWait=new Promise(resolve=>releaseSignedOut=resolve);
  const signedOutStart=new Promise(resolve=>signedOutStarted=resolve);
  const signedOut=async route=>{signedOutStarted();await signedOutWait;await route.fulfill({json:{job_id:'signed-out'}});};
  await page.route('**/api/hosts/modal-signout/repositories',signedOut);
  try{
    await page.evaluate(()=>saveSource('/tmp/signed-out.sources','Types: deb','modal-signout'));
    await page.locator('#confirm-source').click();
    await signedOutStart;
    await page.evaluate(()=>document.querySelector('#logout').click());
    await page.getByRole('button',{name:'Open your workspace'}).waitFor();
    releaseSignedOut();
    await page.waitForTimeout(100);
    assert.equal(await page.locator('#toast').isVisible(),false);
    await page.locator('[name=password]').fill('ui-test-password-long');
    await page.getByRole('button',{name:'Open your workspace'}).click();
    await page.locator('#shell').waitFor({state:'visible'});
    await page.locator('[data-nav=overview]').click();
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
  }finally{releaseSignedOut();await page.unroute('**/api/hosts/modal-signout/repositories',signedOut);}

  // Schedule deletion has the same close-after-await contract and keeps its
  // submit button one-shot while the request is pending.
  const schedule={id:'modal-race-schedule',revision:'r1',name:'Race schedule',enabled:false,approved:false,all_hosts:true,host_ids:[],timezone:'UTC',frequency:'daily',days:[0],month_day:1,minute:120,window_minutes:120,priorities:['normal'],critical:{enabled:false,after_minutes:0,bypass_window:false},high:{enabled:false,after_minutes:60,bypass_window:false},recovery:{reboot:false,rollback:false}};
  let scheduleDeletes=0,releaseSchedule,scheduleStarted;
  const scheduleWait=new Promise(resolve=>releaseSchedule=resolve);
  const scheduleStart=new Promise(resolve=>scheduleStarted=resolve);
  const scheduleList=route=>route.fulfill({json:{schedules:[schedule],runs:[],host_policies:{}}});
  const scheduleCalendar=route=>route.fulfill({json:{events:[]}});
  const scheduleDelete=async route=>{scheduleDeletes++;scheduleStarted();await scheduleWait;return route.fulfill({json:{}});};
  await page.route('**/api/schedules',scheduleList);
  await page.route('**/api/schedules/calendar?*',scheduleCalendar);
  await page.route('**/api/schedules/modal-race-schedule',scheduleDelete);
  try{
    await page.locator('[data-nav=schedules]').click();
    await page.getByRole('heading',{name:'Patching, on your calendar.'}).waitFor();
    await page.locator('.schedule-item h3').filter({hasText:'Race schedule'}).waitFor();
    await page.locator('[data-delete-schedule]').click();
    await page.locator('#confirm-delete-schedule').evaluate(button=>{button.click();button.click();});
    await scheduleStart;
    const accountTitle=await replaceDialog();
    releaseSchedule();
    await page.locator('#toast').filter({hasText:'Schedule deleted'}).waitFor({state:'visible'});
    await assertAccountUnaffected(accountTitle);
    assert.equal(scheduleDeletes,1);
    await page.locator('#close-modal').click();
  }finally{
    releaseSchedule();
    await page.unroute('**/api/schedules/modal-race-schedule',scheduleDelete);
    await page.unroute('**/api/schedules/calendar?*',scheduleCalendar);
    await page.unroute('**/api/schedules',scheduleList);
  }

  // A delayed patch confirmation reports through the global toast for its own
  // session and never closes or annotates a newer dialog; failures behave alike.
  const patchFixture=[{name:'race-pkg:amd64',installed:'1',candidate:'2',held:false,dpkg_state:'install ok installed',priority:'normal',installation:{state:'unscheduled',at:null,reason:'No matching schedule.'}}];
  const patchList=route=>route.fulfill({json:patchFixture});
  const patchPolicy=route=>route.fulfill({json:{reboot:false,rollback:false}});
  for(const outcome of ['success','error']){
    let patchPosts=0,releasePatch,patchStarted;
    const patchWait=new Promise(resolve=>releasePatch=resolve);
    const patchStart=new Promise(resolve=>patchStarted=resolve);
    const patchWrite=async route=>{patchPosts++;patchStarted();await patchWait;await route.fulfill(outcome==='success'?{json:{job_id:'patch-race'}}:{status:409,json:{detail:'Patch request became stale'}});};
    await page.route('**/api/hosts/*/packages?*',patchList);
    await page.route('**/api/hosts/*/patch-policy',patchPolicy);
    await page.route('**/api/hosts/*/patch',patchWrite);
    try{
      await page.locator('[data-nav=packages]').click();
      await page.locator('.pkg-check').first().waitFor();
      await page.locator('#select-all-updates').click();
      await page.locator('#patch-selected').click();
      await page.locator('#confirm-patch').waitFor();
      await page.locator('#confirm-patch').evaluate(button=>{button.click();button.click();});
      await patchStart;
      const accountTitle=await replaceDialog();
      releasePatch();
      await page.locator('#toast').filter({hasText:outcome==='success'?'Installation queued':'Patch request became stale'}).waitFor({state:'visible'});
      await assertAccountUnaffected(accountTitle);
      assert.equal(patchPosts,1);
      await page.locator('#close-modal').click();
      await page.locator('[data-nav=overview]').click();
      await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
    }finally{releasePatch();await page.unroute('**/api/hosts/*/patch',patchWrite);await page.unroute('**/api/hosts/*/patch-policy',patchPolicy);await page.unroute('**/api/hosts/*/packages?*',patchList);}
  }

  // Navigation invalidates the submitting dialog but not the authenticated
  // session. Delayed patch outcomes remain truthful in the global toast and
  // must not replace or redirect the newly rendered view.
  for(const outcome of ['success','error']){
    let patchPosts=0,releasePatch,patchStarted;
    const patchWait=new Promise(resolve=>releasePatch=resolve);
    const patchStart=new Promise(resolve=>patchStarted=resolve);
    const patchWrite=async route=>{patchPosts++;patchStarted();await patchWait;await route.fulfill(outcome==='success'?{json:{job_id:'patch-navigation-race'}}:{status:409,json:{detail:'Patch request became stale'}});};
    await page.route('**/api/hosts/*/packages?*',patchList);
    await page.route('**/api/hosts/*/patch-policy',patchPolicy);
    await page.route('**/api/hosts/*/patch',patchWrite);
    try{
      await page.locator('[data-nav=packages]').click();
      await page.locator('.pkg-check').first().waitFor();
      await page.locator('#select-all-updates').click();
      await page.locator('#patch-selected').click();
      await page.locator('#confirm-patch').click();
      await patchStart;
      await page.evaluate(()=>document.querySelector('[data-nav=overview]').click());
      await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
      releasePatch();
      await page.locator('#toast').filter({hasText:outcome==='success'?'Installation queued':'Patch request became stale'}).waitFor({state:'visible'});
      assert.equal(await page.locator('#modal').evaluate(dialog=>dialog.open),false);
      assert.equal(await page.getByRole('heading',{name:'A healthier fleet starts here.'}).isVisible(),true);
      assert.equal(patchPosts,1);
    }finally{releasePatch();await page.unroute('**/api/hosts/*/patch',patchWrite);await page.unroute('**/api/hosts/*/patch-policy',patchPolicy);await page.unroute('**/api/hosts/*/packages?*',patchList);}
  }

  // Sign-out changes the session. Neither successful nor failed work from the
  // obsolete session may display feedback, mutate the login view, or re-open
  // the submitting dialog after the response arrives.
  for(const outcome of ['success','error']){
    let patchPosts=0,releasePatch,patchStarted;
    const patchWait=new Promise(resolve=>releasePatch=resolve);
    const patchStart=new Promise(resolve=>patchStarted=resolve);
    const patchWrite=async route=>{patchPosts++;patchStarted();await patchWait;await route.fulfill(outcome==='success'?{json:{job_id:'patch-signout-race'}}:{status:409,json:{detail:'Patch request became stale'}});};
    await page.route('**/api/hosts/*/packages?*',patchList);
    await page.route('**/api/hosts/*/patch-policy',patchPolicy);
    await page.route('**/api/hosts/*/patch',patchWrite);
    try{
      await page.locator('[data-nav=packages]').click();
      await page.locator('.pkg-check').first().waitFor();
      await page.locator('#select-all-updates').click();
      await page.locator('#patch-selected').click();
      await page.locator('#confirm-patch').click();
      await patchStart;
      await page.evaluate(()=>document.querySelector('#logout').click());
      await page.getByRole('button',{name:'Open your workspace'}).waitFor();
      const patchResponse=page.waitForResponse(response=>response.request().method()==='POST'&&new URL(response.url()).pathname.endsWith('/patch'));
      releasePatch();
      await patchResponse;
      assert.equal(await page.locator('#toast').isVisible(),false);
      assert.equal(await page.locator('#modal').evaluate(dialog=>dialog.open),false);
      assert.equal(await page.getByRole('button',{name:'Open your workspace'}).isVisible(),true);
      assert.equal(patchPosts,1);
      await page.locator('[name=username]').fill('admin');
      await page.locator('[name=password]').fill('ui-test-password-long');
      const loginResponse=page.waitForResponse(response=>response.request().method()==='POST'&&new URL(response.url()).pathname==='/api/login');
      await page.getByRole('button',{name:'Open your workspace'}).click();
      assert.equal((await loginResponse).status(),200);
      await page.locator('#shell').waitFor({state:'visible'});
      await page.locator('[data-nav=overview]').click();
      await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
    }finally{releasePatch();await page.unroute('**/api/hosts/*/patch',patchWrite);await page.unroute('**/api/hosts/*/patch-policy',patchPolicy);await page.unroute('**/api/hosts/*/packages?*',patchList);}
  }
};
