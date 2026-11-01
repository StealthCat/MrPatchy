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
};
