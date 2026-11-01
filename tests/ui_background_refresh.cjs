const assert=require('assert/strict');
// The 30 s background refresh must not show the loading placeholder, jump scroll or drop focus (#153).
module.exports=async(page)=>{
 const now=Date.now()/1000;let release=null,placeholder=false;
 const rows=Array.from({length:40},(_,i)=>({id:'bg-'+i,name:'Background '+String(i+1).padStart(2,'0'),address:'192.0.2.'+(i+1),architecture:'amd64',state:'online',enabled:true,last_seen:0,integrity:[],error:''}));
 const hosts=route=>route.fulfill({json:rows});
 const dashboard=async route=>{if(release)await release;await route.fallback();};
 await page.route('**/api/hosts',hosts);
 try{
  await page.goto(new URL('/?background-refresh=1#overview/attention',page.url()).href);
  await page.locator('[data-fleet-section=attention]').waitFor();
  await page.setViewportSize({width:1440,height:600});
  const link=page.locator('.fleet-observation a.button').nth(8);
  await link.scrollIntoViewIfNeeded();await link.focus();
  const before=await page.evaluate(()=>({y:scrollY,href:document.activeElement.getAttribute('href')}));
  assert.ok(before.y>0&&before.href);
  await page.route('**/api/dashboard',dashboard);
  let open;release=new Promise(resolve=>open=resolve);
  await page.evaluate(()=>{window.__bgDone=refreshInBackground();new MutationObserver(()=>{if(document.querySelector('#content .loading-state'))window.__bgPlaceholder=true;}).observe(document.querySelector('#content'),{childList:true,subtree:true});});
  await page.waitForTimeout(100);
  assert.ok(await page.locator('.fleet-observation').count()>0,'old view stays while the refresh is fetching');
  open();release=null;await page.evaluate(()=>window.__bgDone);
  const after=await page.evaluate(()=>({y:scrollY,href:document.activeElement.getAttribute('href'),tag:document.activeElement.tagName,placeholder:!!window.__bgPlaceholder}));
  assert.equal(after.y,before.y);assert.equal(after.href,before.href);assert.equal(after.tag,'A');assert.equal(after.placeholder,false);
 }finally{await page.unroute('**/api/hosts',hosts);await page.unroute('**/api/dashboard',dashboard).catch(()=>{});await page.setViewportSize({width:1440,height:1000});}
};
