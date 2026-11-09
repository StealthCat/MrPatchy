// Standalone fixture browser check: node tests/ui_error_mascot.cjs
const {chromium}=require('playwright');
const fs=require('node:fs');
const path=require('node:path');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.PLAYWRIGHT_EXECUTABLE_PATH?{executablePath:process.env.PLAYWRIGHT_EXECUTABLE_PATH}:{})});
 try{
  const page=await browser.newPage();
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  let attempts=0;
  await page.route('http://patchy.test/**',route=>{
   const url=new URL(route.request().url());
   if(url.pathname.startsWith('/api/')){
    if(url.pathname==='/api/identity')attempts++;
    return route.fulfill({status:url.pathname==='/api/session'?401:503,json:{detail:'Temporary failure <script>unsafe()</script>'}});
   }
   const relative=url.pathname==='/'?'index.html':url.pathname.replace(/^\/static\//,'');
   const file=path.resolve(__dirname,'../app/static',relative);
   assert.ok(file.startsWith(path.resolve(__dirname,'../app/static')+path.sep));
   return route.fulfill({body:fs.readFileSync(file),contentType:relative.endsWith('.js')?'application/javascript':relative.endsWith('.css')?'text/css':relative.endsWith('.png')?'image/png':relative.endsWith('.webp')?'image/webp':'text/html'});
  });
  await page.goto('http://patchy.test/');
  await page.locator('#login:not(.hidden)').waitFor();
  assert.equal(await page.locator('#login-error-mascot').isVisible(),false);
  await page.locator('[name=password]').fill('invalid-password');
  await page.locator('#login-form button').click();
  await page.locator('#login-error-mascot:visible').waitFor();
  assert.match(await page.locator('#login-error').innerText(),/<script>/);
  assert.equal(await page.locator('#login-error script').count(),0);
  await page.evaluate(()=>loginError(''));
  assert.equal(await page.locator('#login-error-mascot').isVisible(),false);
  await page.evaluate(()=>{showShell();return render();});
  await page.locator('#retry-view').waitFor();
  const previous=attempts;
  await page.locator('#retry-view').click();
  await page.waitForFunction(()=>document.querySelector('#retry-view')&&!document.querySelector('#content .loading-state'));
  assert.ok(attempts>previous,'Retry must request the view again');
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   const image=page.locator('#content .error-state img');
   assert.match(await image.getAttribute('src'),/mr-patchy-error.webp$/);
   await image.evaluate(img=>img.decode());
   assert.equal(await image.evaluate(img=>img.naturalWidth>0),true);
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
   if(process.env.SCREENSHOT_DIR){fs.mkdirSync(process.env.SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:path.join(process.env.SCREENSHOT_DIR,`error-${width}.png`),fullPage:true});}
  }
  await page.evaluate(()=>{document.querySelector('#content').innerHTML=PatchyUI.empty('No records','Nothing here yet.');});
  assert.match(await page.locator('#content img').getAttribute('src'),/mr-patchy-welcome.png$/);
  await page.evaluate(()=>{document.querySelector('#content').innerHTML=PatchyUI.error('Unable to load history',PatchyUI.esc('<img src=x onerror=unsafe()>'),'<button>Retry history</button>');});
  assert.equal(await page.locator('#content img').count(),1);
  assert.equal(await page.getByRole('button',{name:'Retry history'}).isVisible(),true);
  for(const status of [300,301,302,303,307,308,403,404,500,501,502,503,504]){
   await page.goto(`http://patchy.test/static/errors/${status}.html`);
   assert.match(await page.title(),new RegExp(String(status)));
   await page.locator('.error-mascot').evaluate(img=>img.decode());
   const pose=status<400?'redirect':({403:'forbidden',404:'not-found',500:'error',501:'not-implemented',502:'bad-gateway',503:'maintenance',504:'timeout'})[status];
   assert.equal(await page.locator('.error-mascot').getAttribute('src'),`/static/mascot/mr-patchy-${pose}.webp`);
   assert.equal(await page.getByRole('link',{name:'Return to workspace'}).getAttribute('href'),'/');
   assert.equal(await page.locator('script').count(),0,'HTTP pages must not depend on JavaScript');
   for(const width of [320,768,1440]){
    await page.setViewportSize({width,height:1000});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    if(process.env.SCREENSHOT_DIR&&[300,403,404,500,503].includes(status)&&width!==768){await page.screenshot({path:path.join(process.env.SCREENSHOT_DIR,`http-${status}-${width}.png`),fullPage:true});}
   }
  }
  if(process.env.SCREENSHOT_DIR){
   await page.setViewportSize({width:1440,height:1000});
   await page.setContent(`<html><head><style>body{margin:0;padding:28px;background:#0a141c;color:#eef6f6;font-family:system-ui}h1{font-size:26px;margin:0 0 22px}main{display:grid;grid-template-columns:repeat(4,1fr);gap:18px}section{background:#14252f;border:1px solid #adcddd29;border-radius:20px;text-align:center;padding:20px}img{width:240px;height:300px;object-fit:contain}h2{font-size:17px;margin:12px 0 0;color:#9ee8d1}</style></head><body><h1>Mr Patchy · A helping paw for every detour</h1><main>${[['3xx · Redirect','redirect'],['403 · Forbidden','forbidden'],['404 · Not found','not-found'],['500 · Server error','error'],['501 · Not implemented','not-implemented'],['502 · Bad gateway','bad-gateway'],['503 · Maintenance','maintenance'],['504 · Timeout','timeout']].map(([label,pose])=>`<section><img src="http://patchy.test/static/mascot/mr-patchy-${pose}.webp"><h2>${label}</h2></section>`).join('')}</main></body></html>`);
   await page.evaluate(()=>Promise.all([...document.images].map(img=>img.decode())));
   await page.screenshot({path:path.join(process.env.SCREENSHOT_DIR,'themed-error-pages.png'),fullPage:true});
  }
  assert.deepEqual(errors,[]);
  console.log('Error mascot: sign-in feedback, view failure, retry, escaping and 320/768/1440 layouts passed.');
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
