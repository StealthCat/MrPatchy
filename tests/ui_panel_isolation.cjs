const assert=require('assert/strict');
module.exports=async(page)=>{
 const hosts=await (await page.request.get(new URL('/api/hosts',page.url()).href)).json(),host=hosts[0];
 const prefix='/api/hosts/'+host.id+'/security/';
 const failing={archive:true,monitor:true,policy:true};const log=[];
 let releasePolicy;const policyWait=new Promise(resolve=>releasePolicy=resolve);let holdPolicy=true;
 const handler=async route=>{
  const url=new URL(route.request().url());
  if(!url.pathname.startsWith(prefix))return route.fallback();
  log.push(url.pathname.slice(prefix.length));
  if(url.pathname===prefix+'policy'){
   if(holdPolicy)await policyWait;
   if(failing.policy)return route.fulfill({status:503,json:{detail:'Scheduled scan policy unavailable'}});
  }
  if(url.pathname===prefix+'evidence-archives'&&failing.archive)return route.fulfill({status:503,json:{detail:'Evidence archive storage temporarily unavailable'}});
  if(url.pathname===prefix+'persistence-monitor'&&failing.monitor)return route.fulfill({status:503,json:{detail:'Monitor policy unavailable'}});
  return route.fallback();
 };
 await page.route('**/api/**',handler);
 try{
  await page.goto(new URL('/#servers/'+host.id+'/overview',page.url()).href);
  await page.goto(new URL('/#servers/'+host.id+'/security',page.url()).href);
  const panel=page.locator('#server-tab-body section.card').filter({hasText:'Evidence archive storage temporarily unavailable'});
  await panel.waitFor();
  // Unrelated panels and scan handlers must be usable while policy is unresolved.
  assert.ok(log.includes('evidence-archives'));
  assert.equal(await page.locator('#security-scan-form').evaluate(form=>typeof form.onsubmit),'function');
  await page.locator('#security-scan-form textarea').fill('/tmp/unsaved-security-scope');
  await page.locator('#yara-scan-form [name=bundle_id]').fill('unsaved-bundle');
  await page.evaluate(()=>{window.__savedScanForm=document.querySelector('#security-scan-form');window.__savedScanHistory=document.querySelector('#security-history');});
  holdPolicy=false;releasePolicy();
  const policy=page.locator('#security-policy-form');
  await policy.getByText('Scheduled scan policy unavailable').waitFor();
  failing.policy=false;await policy.getByRole('button',{name:'Retry'}).click();
  await policy.locator('button').filter({hasText:'Save scan policy'}).waitFor();
  await page.waitForFunction(()=>!document.querySelector('#security-policy-form button').disabled);
  assert.equal(await page.locator('#security-scan-form textarea').inputValue(),'/tmp/unsaved-security-scope');
  assert.equal(await page.locator('#yara-scan-form [name=bundle_id]').inputValue(),'unsaved-bundle');
  assert.ok(await page.evaluate(()=>window.__savedScanForm===document.querySelector('#security-scan-form')&&window.__savedScanHistory===document.querySelector('#security-history')));
  assert.equal(await page.getByText('Unable to load this server tab').count(),0);
  assert.equal(await page.locator('#security-scan-form').count(),1);
  assert.equal(await page.locator('#yara-scan-form').count(),1);
  await page.locator('#execution-scan-form').waitFor();
  await page.getByRole('heading',{name:'Quarantines'}).first().waitFor().catch(()=>{});
  assert.ok(await page.locator('#repair-publication-panel,#publication-panel').count()>=1);
  failing.archive=false;
  await panel.getByRole('button',{name:'Retry'}).click();
  await page.locator('#server-tab-body').getByText('Evidence archive storage temporarily unavailable').waitFor({state:'detached'});
  // File integrity: monitor failure keeps inspection forms and incidents usable.
  await page.goto(new URL('/#servers/'+host.id+'/integrity',page.url()).href);
  const monitor=page.locator('#persistence-monitor').filter({hasText:'Monitor policy unavailable'});
  await monitor.waitFor();
  assert.equal(await page.locator('#security-inspection-form').count(),1);
  assert.equal(await page.getByText('Unable to load this server tab').count(),0);
  await page.locator('#persistence-incidents').getByRole('heading',{name:'Startup-change incidents'}).waitFor();
  failing.monitor=false;await monitor.getByRole('button',{name:'Retry'}).click();
  await page.locator('#persistence-monitor-form').waitFor();
 }finally{releasePolicy();await page.unroute('**/api/**',handler);}
};
