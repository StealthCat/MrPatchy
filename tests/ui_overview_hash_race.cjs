const assert=require('assert/strict');
// An address that changes while the Overview dashboard is loading must not be rewritten to #overview.
// Reloading right after a hash navigation can resolve the dashboard before the new hash renders;
// rewriting then replaced the new history entry, so the reload landed on Overview instead.
module.exports=async page=>{
 const base=new URL('/',page.url()).href;
 let release;const held=new Promise(r=>{release=r;});let started;const waiting=new Promise(r=>{started=r;});
 const hold=async route=>{started();await held;await route.continue();};
 await page.route('**/api/dashboard',hold);
 try{
  await page.goto(base+'#overview/unknown-section');
  await waiting;
  // Move the address without a hashchange render, as a reload racing a goto does.
  await page.evaluate(()=>history.pushState(history.state,'','#investigations'));
  release();
  await page.waitForResponse(r=>r.url().endsWith('/api/dashboard'));
  await page.waitForTimeout(300);
  assert.equal(await page.evaluate(()=>location.hash),'#investigations','a late Overview load must not rewrite a newer address');
 }finally{release();await page.unroute('**/api/dashboard',hold);}
 // Without a competing navigation, unknown Overview sections are still normalized to #overview.
 await page.goto(base+'#overview/unknown-section');
 await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
 await page.waitForFunction(()=>location.hash==='#overview',null,{timeout:3000});
};
