const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const handlers=[];const handler=async route=>{
  const url=new URL(route.request().url());if(url.pathname!='/api/security/coverage')return route.fallback();
  assert.equal(route.request().method(),'GET');handlers.push(url.searchParams.get('q'));
  const scan={state:'incomplete',created:Date.now()/1000,signatures:'unknown',overdue:false,scanned:0,findings:0,roots:['/srv'],gaps:['Scanner missing'],last_attempt:null};
  return route.fulfill({json:{summary:{servers:1,disabled:0,open_incidents:2},items:[{id:'coverage-host',name:'Coverage fixture',enabled:true,last_seen:Date.now()/1000,open_incidents:2,expected_hours:24,engines:{ClamAV:scan,YARA:{...scan,state:'never_scanned'}}}],more:false}});
 };
 await page.route('**/api/**',handler);
 try{
  await page.goto(new URL('/#security',page.url()).href);
  await page.getByRole('heading',{name:'Coverage fixture',exact:true}).waitFor();
  await page.getByRole('heading',{name:'ClamAV · incomplete',exact:true}).waitFor();
  await page.getByRole('heading',{name:'YARA · never_scanned',exact:true}).waitFor();
  assert.equal(await page.getByRole('link',{name:'Review server security'}).getAttribute('href'),'#servers/coverage-host/security');
  await page.locator('#coverage-search input').fill('fixture');await Promise.all([page.waitForResponse(r=>r.url().includes('/security/coverage?')&&r.url().includes('q=fixture')),page.getByRole('button',{name:'Find servers',exact:true}).click()]);
  assert.equal(handlers.at(-1),'fixture');
  if(capture)await capture('security-coverage-desktop');
  await page.setViewportSize({width:390,height:844});
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'Coverage page must fit the mobile viewport');
  if(capture)await capture('security-coverage-mobile');
  await page.setViewportSize({width:1440,height:1000});
 }finally{await page.unroute('**/api/**',handler);}
};
