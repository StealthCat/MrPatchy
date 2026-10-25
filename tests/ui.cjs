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
    browser=await chromium.launch({headless:true});
    const page=await browser.newPage({viewport:{width:1440,height:1000}});
    const errors=[];page.on('pageerror',e=>errors.push(String(e)));
    await page.goto('http://127.0.0.1:8097');
    await page.locator('[name=password]').fill('ui-test-password-long');
    await page.getByRole('button',{name:'Open your workspace'}).click();
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
    await page.getByRole('button',{name:'+ Add server',exact:true}).click();
    await page.locator('[name=name]').fill('Test Ubuntu');
    await page.locator('[name=address]').fill('192.0.2.15');
    await page.getByRole('button',{name:'Create enrollment'}).click();
    await page.getByRole('heading',{name:'Test Ubuntu'}).waitFor();
    await page.getByRole('button',{name:'Get curl command'}).click();
    await page.locator('#curl-output pre').waitFor();
    assert.match(await page.locator('#curl-output pre').textContent(),/curl -fsSL/);
    await page.locator('#close-modal').click();
    await page.locator('[data-nav=settings]').click();
    await page.getByRole('heading',{name:'Set your own rhythm.'}).waitFor();
    await page.getByRole('button',{name:'Save monitoring settings'}).click();
    await page.getByRole('status').filter({hasText:'Monitoring settings saved'}).waitFor();
    await page.setViewportSize({width:390,height:844});
    await page.locator('[data-nav=overview]').click();
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
    assert.deepEqual(errors,[]);
    console.log('Desktop/mobile UI smoke checks passed');
  }finally{if(browser)await browser.close();server.kill();fs.rmSync(data,{recursive:true,force:true});}
})().catch(e=>{console.error(e);process.exitCode=1;});
