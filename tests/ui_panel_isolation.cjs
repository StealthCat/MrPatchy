const assert=require('assert/strict');
module.exports=async(page)=>{
 const hosts=await (await page.request.get(new URL('/api/hosts',page.url()).href)).json(),host=hosts[0];
 const prefix='/api/hosts/'+host.id+'/security/';
 const failing={archive:true,monitor:true,policy:true};const log=[];
 let releasePolicy;const policyWait=new Promise(resolve=>releasePolicy=resolve);let holdPolicy=true;
 let releaseMonitor;const monitorWait=new Promise(resolve=>releaseMonitor=resolve);let holdMonitor=false;const incidentRequests=[];
 // Out-of-order gates: hold the next matching GET, then fail it only after a newer request has succeeded.
 const gate=()=>{let release,arrived;const wait=new Promise(resolve=>release=resolve),seen=new Promise(resolve=>arrived=resolve);return {wait,seen,release,arrived};};
 const held={latest:null,inspections:null};const gates=[];
 const hold=async(route,key,detail)=>{const g=held[key];held[key]=null;g.arrived();await g.wait;return route.fulfill({status:503,json:{detail}});};
 const handler=async route=>{
  const url=new URL(route.request().url());
  if(url.pathname===prefix.slice(0,-1)&&route.request().method()==='GET'&&held.latest)return hold(route,'latest','Stale latest scan failure');
  if(!url.pathname.startsWith(prefix))return route.fallback();
  if(url.pathname===prefix+'inspections'&&route.request().method()==='GET'&&held.inspections)return hold(route,'inspections','Stale inspection failure');
  log.push(url.pathname.slice(prefix.length));
  if(url.pathname===prefix+'policy'){
   if(holdPolicy)await policyWait;
   if(failing.policy)return route.fulfill({status:503,json:{detail:'Scheduled scan policy unavailable'}});
  }
  if(url.pathname===prefix+'evidence-archives'&&failing.archive)return route.fulfill({status:503,json:{detail:'Evidence archive storage temporarily unavailable'}});
  if(url.pathname===prefix+'persistence-incidents'){incidentRequests.push(url.searchParams.get('offset'));return route.fulfill({json:{items:[],more:true}});}
  if(url.pathname===prefix+'persistence-monitor'&&route.request().method()==='GET'&&holdMonitor)await monitorWait;
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
  const settle=()=>page.evaluate(()=>new Promise(resolve=>setTimeout(resolve,100)));
  const staleFailure=async(key,path,tab,refresh,target,fresh,detail)=>{
   const g=gate();gates.push(g);held[key]=g;
   await page.goto(new URL('/#servers/'+host.id+'/overview',page.url()).href);
   await page.goto(new URL('/#servers/'+host.id+'/'+tab,page.url()).href);
   await g.seen;
   const succeeded=page.waitForResponse(response=>new URL(response.url()).pathname===path&&response.status()===200);
   await page.locator(refresh).click();await succeeded;await settle();
   if(fresh)await page.locator(target).getByText(fresh).first().waitFor();
   const failed=page.waitForResponse(response=>new URL(response.url()).pathname===path&&response.status()===503);
   g.release();await failed;await settle();
   assert.equal(await page.locator(target+' .panel-retry').count(),0,'a stale initial failure must not replace a newer successful '+key+' refresh');
   assert.equal(await page.locator(target).getByText(detail).count(),0);
   if(fresh)assert.ok(await page.locator(target).getByText(fresh).count()>=1);
  };
  // Security: hold the initial latest-scan request, let Refresh succeed, then fail the held request.
  await staleFailure('latest',prefix.slice(0,-1),'security','#security-refresh','#security-latest','Latest scan coverage','Stale latest scan failure');
  // File integrity: a held, then failed, monitor policy never blocks incidents or inspection forms,
  // and policy Retry reloads only the policy panel without resetting the incident page.
  holdMonitor=true;
  await page.goto(new URL('/#servers/'+host.id+'/integrity',page.url()).href);
  const incidents=page.locator('#persistence-incidents');
  await incidents.getByRole('heading',{name:'Startup-change incidents'}).waitFor();
  assert.equal(await page.locator('#persistence-monitor-form').count(),0);
  assert.equal(await page.locator('#persistence-monitor').getByText('Monitor policy unavailable').count(),0);
  assert.equal(await page.locator('#security-inspection-form').count(),1);
  await incidents.locator('#startup-next').click();
  await page.waitForFunction(()=>{const prev=document.querySelector('#startup-prev');return prev&&!prev.disabled;});
  assert.equal(incidentRequests.at(-1),'10');
  holdMonitor=false;releaseMonitor();
  const monitor=page.locator('#persistence-monitor').filter({hasText:'Monitor policy unavailable'});
  await monitor.waitFor();
  assert.equal(await page.getByText('Unable to load this server tab').count(),0);
  const incidentCount=incidentRequests.length;
  failing.monitor=false;await monitor.getByRole('button',{name:'Retry'}).click();
  await page.locator('#persistence-monitor-form').waitFor();
  assert.equal(incidentRequests.length,incidentCount,'policy retry must not reload startup incidents');
  assert.equal(await incidents.locator('#startup-prev').isDisabled(),false,'policy retry must keep the incident page');
  // File integrity: the same ownership rule applies to the initial inspection receipts load.
  await staleFailure('inspections',prefix+'inspections','integrity','#inspection-refresh','#inspection-reports','','Stale inspection failure');
 }finally{releasePolicy();releaseMonitor();for(const g of gates)g.release();await page.unroute('**/api/**',handler);}
};
