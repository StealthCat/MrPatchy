const {chromium}=require('playwright');
const {spawn}=require('child_process');
const fs=require('fs');
const os=require('os');
const path=require('path');
const assert=require('assert/strict');
(async()=>{
  const data=fs.mkdtempSync(path.join(os.tmpdir(),'mrpatchy-ui-'));
  const server=spawn(process.env.PYTHON||'python',['-m','uvicorn','app.main:app','--host','127.0.0.1','--port','8097','--no-access-log'],{
    cwd:path.resolve(__dirname,'..'),env:{...process.env,DATA_DIR:data,TLS_DIR:path.join(data,'tls'),COOKIE_SECURE:'false',ADMIN_PASSWORD:'ui-test-password-long',DISABLE_SCHEDULER:'1'},stdio:'ignore'});
  let browser;
  try{
    for(let n=0;n<100;n++){try{await fetch('http://127.0.0.1:8097/healthz');break;}catch{await new Promise(r=>setTimeout(r,100));}}
    browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_EXECUTABLE_PATH?{executablePath:process.env.PLAYWRIGHT_EXECUTABLE_PATH,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote']}: {})});
    const page=await browser.newPage({viewport:{width:1440,height:1000}});
    const shots=process.env.SCREENSHOT_DIR;
    if(shots)fs.mkdirSync(shots,{recursive:true});
    const capture=async(name,fullPage=true)=>{if(shots){await page.evaluate(async()=>{window.scrollTo(0,0);await Promise.all([...document.images].map(img=>img.decode().catch(()=>{})));});await page.screenshot({path:path.join(shots,name+'.jpg'),type:'jpeg',quality:88,fullPage});}};
    const errors=[];page.on('pageerror',e=>errors.push(String(e)));
    await page.goto('http://127.0.0.1:8097');
    await page.getByRole('button',{name:'Open your workspace'}).waitFor();
    await capture('login');
    await page.locator('[name=password]').fill('ui-test-password-long');
    await page.getByRole('button',{name:'Open your workspace'}).click();
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
    await page.getByRole('button',{name:'+ Add server',exact:true}).click();
    await page.locator('[name=name]').fill('Test Ubuntu');
    await page.locator('[name=address]').fill('192.0.2.15');
    await page.getByRole('button',{name:'Continue to preparation'}).click();
    await page.getByRole('heading',{name:'Prepare Test Ubuntu · Step 2 of 3'}).waitFor();
    assert.equal(await page.locator('#install-mode').inputValue(),'offline');
    await capture('enrollment');
    const download=page.locator('#install-delivery a');
    const installerPath=await download.getAttribute('href');
    const installer=await page.request.get(new URL(installerPath,page.url()).href);
    assert.equal(installer.status(),200);assert.match(await installer.text(),/useradd --system/);
    await page.locator('#install-mode').selectOption('curl');
    await page.locator('#install-delivery pre').filter({hasText:'curl -fsSL'}).waitFor();
    await require('./ui_enrollment.cjs')(page,installerPath.replace(/\/installer$/,''),capture);
    await page.getByRole('button',{name:'I ran the script · Proceed to step 3'}).click();
    await page.getByRole('heading',{name:'Connect and verify · Step 3 of 3'}).waitFor();
    await page.locator('[name=fingerprint]').fill('SHA256:'+'a'.repeat(43));
    await page.route('**/api/hosts/*/actions/deploy',route=>route.fulfill({json:{job_id:'verified-fixture'}}));
    await page.route('**/api/jobs/verified-fixture',route=>route.fulfill({json:{state:'complete',output:'Verified fixture'}}));
    await page.getByRole('button',{name:'Finish and verify installation',exact:true}).click();
    await page.locator('#enrollment-result').filter({hasText:'Installation verified'}).waitFor();
    await page.locator('#close-modal').click();
    await page.locator('[data-nav=servers]').click();
    await page.getByRole('button',{name:'Manage ↗'}).click();
    assert.equal(await page.locator('#modal-body a[download]').count(),1);
    await page.locator('#close-modal').click();
    await require('./ui_schedules.cjs')(page,capture);
    await page.locator('[data-nav=settings]').click();
    await page.getByRole('heading',{name:'Set your own rhythm.'}).waitFor();
    await capture('settings');
    await page.getByRole('button',{name:'Save monitoring settings'}).click();
    await page.getByRole('status').filter({hasText:'Monitoring settings saved'}).waitFor();
    await require('./ui_ai.cjs')(page);
    await require('./ui_tls.cjs')(page,capture);
    await page.locator('[data-nav=repositories]').click();
    await page.getByRole('button',{name:'Repository access',exact:true}).click();
    await page.locator('#access-form [name=default_release]').fill('stable');
    await page.locator('#access-form [name=mirrors]').fill('{"file:/srv/repo":"https://mirror.example.test/repo"}');
    await page.getByRole('button',{name:'Save repository access',exact:true}).click();
    await page.getByRole('status').filter({hasText:'Repository access saved'}).waitFor();
    await page.getByRole('button',{name:'Repository access',exact:true}).click();
    assert.equal(await page.locator('#access-form [name=default_release]').inputValue(),'stable');
    await page.locator('#close-modal').click();
    // Reproduce a delayed A response arriving after switching the selector to B.
    const ids=await page.evaluate(async()=>{
      const session=await (await fetch('/api/session')).json();
      const hosts=await (await fetch('/api/hosts')).json();
      const created=await (await fetch('/api/hosts',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrf},body:JSON.stringify({name:'Second target',address:'192.0.2.16'})})).json();
      return {a:hosts[0].id,b:created.id};
    });
    let releaseA;let markStarted;const started=new Promise(resolve=>markStarted=resolve);
    const delayed=new Promise(resolve=>releaseA=resolve);
    const row=(name,version)=>({name,installed:'1',candidate:version,held:false,priority:'normal',priority_manual:false,due:0});
    await page.route('**/api/hosts/*/packages?*',async route=>{
      const isA=route.request().url().includes(ids.a);
      if(isA){markStarted();await delayed;}
      await route.fulfill({json:[row(isA?'package-from-a:amd64':'package-from-b:amd64',isA?'2':'3')]});
    });
    await page.locator('[data-nav=packages]').click();
    await started;
    await page.locator('#server-select').selectOption(ids.b);
    await page.getByText('package-from-b:amd64',{exact:true}).waitFor();
    releaseA();await page.waitForTimeout(100);
    assert.equal(await page.getByText('package-from-a:amd64',{exact:true}).count(),0);
    const submitted=[];
    await page.route('**/api/hosts/*/patch-policy',route=>route.fulfill({json:{reboot:route.request().url().includes(ids.b),rollback:route.request().url().includes(ids.b)}}));
    await page.route('**/api/hosts/*/patch',async route=>{
      submitted.push({url:route.request().url(),body:route.request().postDataJSON()});
      await route.fulfill({json:{job_id:'ui-intercept-only'}});
    });
    await page.locator('.pkg-check').check();
    await page.getByRole('button',{name:'Install selected updates',exact:true}).click();
    await page.getByText('enabled — services may be interrupted',{exact:true}).waitFor();
    await capture('patch-review');
    // Rapid repeated clicks must queue only one approved transaction.
    await page.locator('#confirm-patch').evaluate(button=>{button.click();button.click();});
    await page.getByRole('status').filter({hasText:'Installation queued'}).waitFor();
    assert.equal(submitted.length,1);assert.ok(submitted[0].url.includes(ids.b));
    assert.deepEqual(submitted[0].body.expected_versions,{'package-from-b:amd64':'3'});
    assert.deepEqual(submitted[0].body.expected_recovery_policy,{reboot:true,rollback:true});
    await page.getByRole('button',{name:'Account',exact:true}).click();
    await page.getByRole('button',{name:'Operations',exact:true}).click();
    await page.getByRole('button',{name:'SSO, SMTP & target policies',exact:true}).click();
    await page.locator('#advanced-host').selectOption(ids.b);
    await page.waitForFunction(()=>document.querySelector('#recovery-policy [name=reboot]').checked);
    assert.equal(await page.locator('#recovery-policy [name=rollback]').isChecked(),true);
    await page.locator('#advanced-host').selectOption(ids.a);
    await page.waitForFunction(()=>!document.querySelector('#recovery-policy [name=reboot]').checked);
    assert.equal(await page.locator('#recovery-policy [name=rollback]').isChecked(),false);
    await page.locator('#close-modal').click();
    // Release-plan review authorizes exactly one immutable plan, never an arbitrary command.
    const releaseId='f'.repeat(36),releaseDigest='a'.repeat(64),releaseDecisions=[];
    let releaseState='ready';
    await page.route('**/api/hosts/*/releases',route=>route.fulfill({json:[{id:releaseId,state:releaseState,created:Date.now()/1000,job_id:''}]}));
    await page.route('**/api/hosts/*/releases/'+releaseId,route=>route.fulfill({json:{id:releaseId,state:releaseState,digest:releaseDigest,job_id:'',plan:{target:{distribution:'Debian',from_version:'12',version:'13'},expires:Date.now()/1000+3600,blockers:[],warnings:['A tested snapshot and reboot are included in this approval.'],authorization:'GO authorizes this release transition, reviewed configuration edits, reboot and one snapshot rollback.',transaction:[{action:'install',package:'nginx',version:'1.26.3'}],reviews:[{path:'/etc/nginx/nginx.conf',reason:'Preserve local settings while updating the package configuration.',changed:true}],edits:[{path:'/etc/nginx/nginx.conf',diff:'--- current\n+++ planned\n-    listen 443 ssl http2;\n+    listen 443 ssl;\n+    http2 on;'}],sources:{'/etc/apt/sources.list':'deb https://deb.debian.org/debian trixie main'}}}}));
    await page.route('**/api/hosts/*/releases/'+releaseId+'/decision',route=>{releaseDecisions.push(route.request().postDataJSON());releaseState='complete';return route.fulfill({json:{state:'approved',job_id:'fixture'}});});
    await page.locator('[data-nav=servers]').click();
    await page.getByRole('button',{name:'Manage ↗'}).first().click();
    await page.getByRole('button',{name:'Plan distribution upgrade',exact:true}).click();
    await page.getByRole('button',{name:'Review plan',exact:true}).click();
    await page.getByRole('heading',{name:'Debian 12 → 13'}).waitFor();
    await page.locator('summary').filter({hasText:'/etc/nginx/nginx.conf'}).click();
    await capture('release-upgrade');
    await page.getByRole('button',{name:'GO · Execute approved plan',exact:true}).click();
    await page.getByRole('heading',{name:'Debian 12 → 13'}).waitFor();
    assert.deepEqual(releaseDecisions,[{decision:'go',digest:releaseDigest}]);
    await page.locator('#close-modal').click();
    // A delayed progress response must never rebind a newer plan's GO button.
    const oldId='b'.repeat(36),newId='c'.repeat(36),newDigest='c'.repeat(64);
    let resolveJob,jobStarted;const delayedJob=new Promise(resolve=>resolveJob=resolve),jobStart=new Promise(resolve=>jobStarted=resolve);
    await page.route('**/api/jobs/delayed-release-job',async route=>{jobStarted();await delayedJob;await route.fulfill({json:{state:'complete',output:'old plan preparation'}});});
    for(const [id,digest,job_id] of [[oldId,'b'.repeat(64),'delayed-release-job'],[newId,newDigest,'']]){
      await page.route('**/api/hosts/*/releases/'+id,route=>route.fulfill({json:{id,state:'ready',digest,job_id,plan:{target:{distribution:'Debian',from_version:'12',version:'13'},authorization:'Illustrative plan '+id}}}));
    }
    await page.evaluate(({host,id})=>{reviewRelease(host,id);},{host:ids.a,id:oldId});
    await jobStart;
    await page.evaluate(({host,id})=>reviewRelease(host,id),{host:ids.a,id:newId});
    resolveJob();await page.waitForTimeout(100);
    const raceDecisions=[];
    await page.route('**/api/hosts/*/releases/*/decision',route=>{raceDecisions.push({url:route.request().url(),body:route.request().postDataJSON()});return route.fulfill({json:{state:'approved'}});});
    await page.getByRole('button',{name:'GO · Execute approved plan',exact:true}).click();
    await page.waitForFunction(()=>!document.querySelector('#approve-release').disabled);
    assert.equal(raceDecisions.length,1);assert.ok(raceDecisions[0].url.includes(newId));
    assert.deepEqual(raceDecisions[0].body,{decision:'go',digest:newDigest});
    // Closing a dialog also invalidates an in-flight plan fetch.
    const slowId='d'.repeat(36);let resolvePlan,planStarted;
    const delayedPlan=new Promise(resolve=>resolvePlan=resolve),planStart=new Promise(resolve=>planStarted=resolve);
    await page.route('**/api/hosts/*/releases/'+slowId,async route=>{planStarted();await delayedPlan;await route.fulfill({json:{id:slowId,state:'ready',digest:newDigest,plan:{}}});});
    await page.evaluate(({host,id})=>{reviewRelease(host,id);},{host:ids.a,id:slowId});
    await planStart;await page.locator('#close-modal').click();resolvePlan();await page.waitForTimeout(100);
    assert.equal(await page.locator('#modal').evaluate(node=>node.open),false);
    await require('./ui_review.cjs')(page,ids,capture);
    {
      // Illustrative fixture responses also exercise populated mobile tables in CI.
      const demoHosts=await (await page.request.get('http://127.0.0.1:8097/api/hosts')).json();
      const now=Date.now()/1000;
      demoHosts.forEach((h,i)=>Object.assign(h,{name:i?'Raspberry Pi lab':'Ubuntu services',state:i?'attention':'online',last_seen:now,architecture:i?'arm64':'amd64',integrity:i?[{path:'repository',issue:'Review required'}]:[]}));
      await page.route('**/api/hosts',route=>route.fulfill({json:demoHosts}));
      await page.route('**/api/dashboard',route=>route.fulfill({json:{servers:2,online:1,packages:874,updates:9,overdue:2,integrity_alerts:1,investigations:5,repo_minutes:60}}));
      await page.locator('[data-nav=overview]').click();
      await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
      await page.getByText('Ubuntu services',{exact:true}).waitFor();
      await page.locator('#toast').waitFor({state:'hidden'});
      await capture('overview');
      await require('./ui_rpm.cjs')(page,demoHosts,capture);
    }
    await page.setViewportSize({width:390,height:844});
    await page.locator('[data-nav=overview]').click();
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
    await capture('mobile');
    await page.setViewportSize({width:1440,height:1000});
    await require('./ui_fleet.cjs')(page,capture);
    await require('./ui_design.cjs')(page,capture);
    assert.deepEqual(errors,[]);
    console.log('Desktop/mobile UI smoke checks passed');
  }finally{if(browser)await browser.close();server.kill();fs.rmSync(data,{recursive:true,force:true});}
})().catch(e=>{console.error(e);process.exitCode=1;});
