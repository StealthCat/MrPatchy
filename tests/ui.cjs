const {chromium}=require('playwright');
const {spawn}=require('child_process');
const fs=require('fs');
const os=require('os');
const path=require('path');
const assert=require('assert/strict');
(async()=>{
  const data=fs.mkdtempSync(path.join(os.tmpdir(),'mrpatchy-ui-'));
  const server=spawn(process.env.PYTHON||'python',['-m','uvicorn','app.main:app','--host','127.0.0.1','--port','8097','--no-access-log'],{
    cwd:path.resolve(__dirname,'..'),env:{...process.env,DATA_DIR:data,COOKIE_SECURE:'false',ADMIN_PASSWORD:'ui-test-password-long',DISABLE_SCHEDULER:'1'},stdio:'ignore'});
  let browser;
  try{
    for(let n=0;n<100;n++){try{await fetch('http://127.0.0.1:8097/healthz');break;}catch{await new Promise(r=>setTimeout(r,100));}}
    browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_EXECUTABLE_PATH?{executablePath:process.env.PLAYWRIGHT_EXECUTABLE_PATH,args:['--no-sandbox','--disable-dev-shm-usage','--single-process','--no-zygote']}: {})});
    const page=await browser.newPage({viewport:{width:1440,height:1000}});
    const errors=[];page.on('pageerror',e=>errors.push(String(e)));
    await page.goto('http://127.0.0.1:8097');
    await page.locator('[name=password]').fill('ui-test-password-long');
    await page.getByRole('button',{name:'Open your workspace'}).click();
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
    await page.getByRole('button',{name:'+ Add server',exact:true}).click();
    await page.locator('[name=name]').fill('Test Ubuntu');
    await page.locator('[name=address]').fill('192.0.2.15');
    await page.getByRole('button',{name:'Continue to preparation'}).click();
    await page.getByRole('heading',{name:'Prepare Test Ubuntu · Step 2 of 3'}).waitFor();
    assert.equal(await page.locator('#install-mode').inputValue(),'offline');
    const download=page.locator('#install-delivery a');
    const installer=await page.request.get(new URL(await download.getAttribute('href'),page.url()).href);
    assert.equal(installer.status(),200);assert.match(await installer.text(),/useradd --system/);
    await page.locator('#install-mode').selectOption('curl');
    await page.locator('#install-delivery pre').filter({hasText:'curl -fsSL'}).waitFor();
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
    await page.locator('[data-nav=settings]').click();
    await page.getByRole('heading',{name:'Set your own rhythm.'}).waitFor();
    await page.getByRole('button',{name:'Save monitoring settings'}).click();
    await page.getByRole('status').filter({hasText:'Monitoring settings saved'}).waitFor();
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
    await page.route('**/api/hosts/*/patch',async route=>{
      submitted.push({url:route.request().url(),body:route.request().postDataJSON()});
      await route.fulfill({json:{job_id:'ui-intercept-only'}});
    });
    await page.locator('.pkg-check').check();
    await page.getByRole('button',{name:'Install selected updates',exact:true}).click();
    await page.getByRole('button',{name:'Install 1 selected updates',exact:true}).click();
    await page.getByRole('status').filter({hasText:'Installation queued'}).waitFor();
    assert.equal(submitted.length,1);assert.ok(submitted[0].url.includes(ids.b));
    assert.deepEqual(submitted[0].body.expected_versions,{'package-from-b:amd64':'3'});
    await page.setViewportSize({width:390,height:844});
    await page.locator('[data-nav=overview]').click();
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
    assert.deepEqual(errors,[]);
    console.log('Desktop/mobile UI smoke checks passed');
  }finally{if(browser)await browser.close();server.kill();fs.rmSync(data,{recursive:true,force:true});}
})().catch(e=>{console.error(e);process.exitCode=1;});
