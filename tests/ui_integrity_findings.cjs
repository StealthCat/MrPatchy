const assert=require('assert/strict');

module.exports=async function integrityFindingsUI(page,capture){
 const now=Math.floor(Date.now()/1000);
 const findings=Array.from({length:51},(_,index)=>({path:'/etc/finding-'+index,issue:'Changed'}));
 findings[50].issue='<img src=x onerror="window.integrityInjected=true">';
 const hosts=[
  {id:'integrity-a',name:'Integrity A',enabled:true,last_seen:now,integrity:findings},
  {id:'integrity-b',name:'Integrity B',enabled:true,last_seen:now,integrity:[]},
  {id:'integrity-c',name:'Integrity C',enabled:false,last_seen:now,integrity:[{path:'/etc/disabled',issue:'Changed'}]},
 ].map(host=>({address:'192.0.2.15',port:22,state:'online',...host}));
 let role='admin',inspectionReads=0;
 const pkg={package:'example',state:'different',findings:[{path:'/etc/example',status:'modified',checks:'digest'}]};
 const routes=[
  ['**/api/hosts',route=>route.fulfill({json:hosts})],
  ['**/api/identity',async route=>{const response=await route.fetch();await route.fulfill({response,json:{...await response.json(),role}});}],
  ['**/api/hosts/*/summary',route=>{
   const host=hosts.find(item=>route.request().url().includes('/'+item.id+'/'));
   return host?route.fulfill({json:{host,counts:{packages:1,updates:0,held:0,overdue:0,unapproved:0,pending_ai:0},system:{},collector:{},jobs:{}}}):route.fallback();
  }],
  ['**/api/hosts/*/integrity-findings',route=>{
   const host=hosts.find(item=>route.request().url().includes('/'+item.id+'/'));
   const resolved_alert={opened_at:now-600,complete:true,items:[{path:'/etc/retained',issue:'Missing'}]};
   return route.fulfill({json:{items:host.integrity,hashed_at:host.integrity.length?now-600:null,last_seen:host.last_seen,inactive:!host.enabled,...(role==='admin'?{resolved_alert}:{})}});
  }],
  ['**/api/hosts/*/security/inspections?offset=*',route=>{
   inspectionReads++;
   const first=new URL(route.request().url()).searchParams.get('offset')==='0';
   const packageResult=first?pkg:{...pkg,package:'older package'};
   return route.fulfill({json:{items:[{created:now,report:{state:'different',packages:[packageResult]}}],more:first}});
  }],
 ];
 const open=hash=>page.goto(new URL('/?integrity-ui=1'+hash,page.url()).href);
 const tab=page.locator('#server-tab-body');
 for(const [pattern,handler] of routes)await page.route(pattern,handler);
 try{
  await open('#overview');
  await page.getByRole('link',{name:'51 stored integrity findings across enabled servers'}).click();
  await page.locator('#fleet-integrity-page').filter({hasText:'Page 1 of 2'}).waitFor();
  assert.equal(await page.locator('#fleet-integrity-rows tr').count(),50);
  await page.locator('#fleet-integrity-next').click();
  await page.locator('#fleet-integrity-page').filter({hasText:'Page 2 of 2'}).waitFor();
  assert.equal(await page.locator('#fleet-integrity-rows tr').count(),1);
  assert.equal(await page.getByText('/etc/disabled',{exact:true}).count(),0);
  await page.locator('#fleet-integrity-rows').getByRole('link',{name:'Integrity A'}).click();
  await tab.getByText('/etc/retained',{exact:true}).waitFor();
  await tab.locator('.server-facts dd').filter({hasText:'stale'}).waitFor();
  assert.equal(new URL(page.url()).hash,'#servers/integrity-a/findings');
  assert.equal(await tab.locator('img[src=x]').count(),0);
  assert.equal(await page.evaluate(()=>window.integrityInjected),undefined);
  await tab.locator('summary').filter({hasText:'1 discrepancies'}).click();
  await tab.getByText('/etc/example',{exact:true}).waitFor();
  await tab.getByRole('button',{name:'Next',exact:true}).click();
  await tab.getByText('older package · different · 1 discrepancies',{exact:true}).waitFor();
  await tab.getByRole('button',{name:'Previous',exact:true}).click();
  await tab.getByText('example · different · 1 discrepancies',{exact:true}).waitFor();
  await page.goBack();
  await page.locator('#fleet-integrity-page').filter({hasText:'Page 2 of 2'}).waitFor();
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
   assert.equal(await page.locator('#fleet-integrity-findings .table-wrap').evaluate(table=>table.scrollWidth>table.clientWidth),false);
   await capture('fleet-integrity-'+width);
  }
  await open('#servers/integrity-a/overview');
  const count=page.locator('a.stat').filter({hasText:'Integrity findings'});
  assert.equal(await count.locator('strong').innerText(),'51');
  await count.click();
  await tab.getByText('/etc/finding-0',{exact:true}).waitFor();
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
   await capture('server-integrity-'+width,false);
  }
  await page.reload();
  await tab.getByText('/etc/finding-0',{exact:true}).waitFor();
  await page.getByRole('combobox',{name:'Switch server'}).selectOption('integrity-b');
  await tab.getByText('No findings in the latest stored snapshot.',{exact:false}).waitFor();
  await tab.locator('.server-facts dd').filter({hasText:'Not reported'}).first().waitFor();
  await page.getByRole('link',{name:'Overview',exact:true}).and(page.locator('.server-tabs a')).click();
  assert.equal(await count.locator('strong').innerText(),'0');
  await count.press('Enter');
  await tab.getByText('No findings in the latest stored snapshot.',{exact:false}).waitFor();
  const adminReads=inspectionReads;
  role='viewer';
  await open('#servers/integrity-c/overview');
  await page.locator('.server-tabs').getByRole('link',{name:'Integrity findings'}).click();
  await tab.getByText('/etc/disabled',{exact:true}).waitFor();
  await tab.getByText('Management is inactive. This is retained telemetry.').waitFor();
  assert.equal(await tab.getByRole('heading',{name:'Recorded inspection findings'}).count(),0);
  assert.equal(inspectionReads,adminReads);
 }finally{
  for(const [pattern,handler] of routes)await page.unroute(pattern,handler);
  await page.setViewportSize({width:1440,height:1000});
  await page.goto(new URL('/#overview',page.url()).href);
 }
};
