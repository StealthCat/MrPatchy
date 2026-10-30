const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let role='admin',writes=0,failed=false;
 let rows=Array.from({length:27},(_,i)=>({id:'fleet-'+i,name:'Fleet '+String(i+1).padStart(2,'0'),address:'192.0.2.'+(i+1),architecture:'amd64',state:'online',enabled:true,last_seen:now-300,integrity:[],error:''}));
 Object.assign(rows[0],{name:'Atlas <img src=x onerror="window.__fleetInjected=true">',last_seen:0});
 Object.assign(rows[1],{name:'Borealis · Build',last_seen:now+300});
 Object.assign(rows[2],{name:'Cygnus · Database',last_seen:now,enabled:false});
 Object.assign(rows[3],{name:'Delta · Services',last_seen:now,integrity:[{issue:'stored'}],error:'Diagnostic <svg onload="window.__fleetInjected=true">'});
 Object.assign(rows[4],{name:'Echo · Lab',last_seen:now});
 const hosts=route=>route.fulfill({json:rows});
 const dashboard=route=>route.fulfill(failed?{status:503,json:{detail:'Unavailable <img src=x onerror=window.__fleetInjected=true>'}}:{json:{servers:26,online:2,packages:874,updates:9,overdue:2,integrity_alerts:1,investigations:5,repo_minutes:60}});
 const identity=async route=>{const response=await route.fetch();return route.fulfill({response,json:{...await response.json(),role}});};
 const refresh=async()=>{const old=await page.locator('[data-fleet-section]').elementHandle();await page.locator('#refresh-page').click();await page.waitForFunction(node=>!node.isConnected,old);if(!failed)await page.locator('[data-fleet-section]').waitFor();};
 const observe=request=>{if(new URL(request.url()).pathname.startsWith('/api/')&&!['GET','HEAD'].includes(request.method()))writes++;};page.on('request',observe);
 await page.route('**/api/hosts',hosts);await page.route('**/api/dashboard',dashboard);await page.route('**/api/identity',identity);
 try{
  await page.goto(new URL('/?fleet-review=1#overview',page.url()).href);await page.locator('[data-fleet-section=summary]').waitFor();
  assert.equal(await page.locator('#content img[src=x]').count(),0);
  assert.equal(await page.locator('.stat').filter({hasText:'Recent contact'}).locator('strong').innerText(),'1');
  assert.equal(await page.locator('.stat').filter({hasText:'Servers to review'}).locator('strong').innerText(),'25');
  await page.getByRole('link',{name:'Server attention',exact:true}).click();await page.locator('[data-fleet-section=attention]').waitFor();
  assert.equal(await page.locator('.fleet-observation').count(),12);
  await page.getByText('No contact recorded',{exact:true}).waitFor();await page.getByText('Future contact timestamp',{exact:true}).waitFor();
  assert.equal(await page.locator('#content svg[onload],#content img[src=x]').count(),0);
  await page.locator('#fleet-review-next').click();await page.locator('#fleet-review-page').filter({hasText:'Page 2 of 3'}).waitFor();
  await page.getByRole('link',{name:'Monitoring',exact:true}).click();await page.locator('[data-fleet-section=monitoring]').waitFor();
  await page.goBack();await page.locator('#fleet-review-page').filter({hasText:'Page 2 of 3'}).waitFor();
  await refresh();await page.locator('#fleet-review-page').filter({hasText:'Page 2 of 3'}).waitFor();
  await page.locator('#fleet-review-filter').selectOption('unknown');assert.equal(await page.locator('.fleet-observation').count(),2);
  await page.locator('#fleet-review-search').fill('192.0.2.2');assert.equal(await page.locator('.fleet-observation').count(),1);
  await page.getByRole('link',{name:'Summary',exact:true}).click();await page.locator('[data-fleet-section=summary]').waitFor();await page.getByRole('link',{name:'Server attention',exact:true}).click();
  await page.locator('#fleet-review-search').waitFor();assert.equal(await page.locator('#fleet-review-search').inputValue(),'192.0.2.2');assert.equal(await page.locator('#fleet-review-filter').inputValue(),'unknown');
  await page.reload();await page.locator('#fleet-review-search').waitFor();assert.equal(await page.locator('#fleet-review-search').inputValue(),'');assert.equal(await page.locator('#fleet-review-filter').inputValue(),'attention');
  await page.locator('#fleet-review-filter').selectOption('disabled');await page.locator('.fleet-observation strong').filter({hasText:'Management disabled'}).waitFor();
  await page.locator('#fleet-review-filter').selectOption('recent');await page.getByRole('heading',{name:'Echo · Lab',exact:true}).waitFor();
  assert.equal(await page.locator('.fleet-observation .button').getAttribute('href'),'#servers/fleet-4/overview');
  await page.locator('#fleet-review-search').fill('no matching server');await page.getByRole('heading',{name:'No servers in this view',exact:true}).waitFor();
  await page.locator('#fleet-review-reset').click();
  // Clamp a remembered page after the next snapshot shrinks.
  await page.locator('#fleet-review-next').click();rows=rows.slice(0,5);rows[0].name='Atlas · Production';rows[3].error='Repository check needs review. Open the server for its recorded diagnostic.';
  await refresh();await page.locator('#fleet-review-page').filter({hasText:'Page 1 of 1'}).waitFor();
  for(const section of ['summary','attention','monitoring']){
   await page.evaluate(key=>location.hash=key==='summary'?'#overview':'#overview/'+key,section);await page.locator('[data-fleet-section='+section+']').waitFor();
   for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('fleet-'+section+'-'+width);}
  }
  for(const nextRole of ['operator','viewer']){
   role=nextRole;await page.goto(new URL('/?fleet-role='+nextRole+'#overview/monitoring',page.url()).href);await page.locator('[data-fleet-section=monitoring]').waitFor();
   assert.equal(await page.getByRole('link',{name:'Inspect worker reports',exact:false}).count(),0);assert.equal(await page.getByRole('button',{name:'+ Add server',exact:true}).isVisible(),false);
   await page.getByRole('link',{name:'Server attention',exact:true}).click();await page.locator('.fleet-observation').first().waitFor();
  }
  // A delayed Summary response must not replace a newer Monitoring page.
  let release,started;const wait=new Promise(resolve=>release=resolve),start=new Promise(resolve=>started=resolve);let first=true;
  const delayed=async route=>{if(first){first=false;started();await wait;}await route.fallback();};
  await page.route('**/api/dashboard',delayed);await page.evaluate(()=>location.hash='#overview');await start;
  await page.evaluate(()=>location.hash='#overview/monitoring');await page.locator('[data-fleet-section=monitoring]').waitFor();
  release();await page.waitForTimeout(100);assert.equal(await page.locator('[data-fleet-section=summary]').count(),0);await page.unroute('**/api/dashboard',delayed);
  // Invalid and exact-boundary timestamps remain uncertain; disabled wins over contact.
  assert.deepEqual(await page.evaluate(()=>[0,null,NaN,Infinity,-1].map(last_seen=>fleetObservation({last_seen,enabled:true},1000).kind)),['unknown','unknown','unknown','unknown','unknown']);
  assert.equal(await page.evaluate(()=>fleetObservation({last_seen:880,enabled:true},1000).kind),'stale');
  assert.equal(await page.evaluate(()=>fleetObservation({last_seen:1001,enabled:false},1000).kind),'disabled');
  role='admin';await page.goto(new URL('/#overview/unknown',page.url()).href);await page.locator('[data-fleet-section=summary]').waitFor();assert.equal(new URL(page.url()).hash,'#overview');
  failed=true;await refresh();await page.getByRole('button',{name:'Retry loading',exact:true}).waitFor();assert.equal(await page.locator('#content img[src=x]').count(),0);
  failed=false;await page.getByRole('button',{name:'Retry loading',exact:true}).click();await page.locator('[data-fleet-section=summary]').waitFor();
  rows=[];await page.evaluate(()=>location.hash='#overview/attention');await page.getByRole('heading',{name:'No servers enrolled yet',exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>window.__fleetInjected),undefined);assert.equal(writes,0,'Fleet browsing must not mutate or contact targets/providers');
 }finally{page.off('request',observe);await page.unroute('**/api/hosts',hosts);await page.unroute('**/api/dashboard',dashboard);await page.unroute('**/api/identity',identity);await page.evaluate(()=>Object.assign(fleetReviewContext,{q:'',filter:'attention',offset:0}));await page.setViewportSize({width:1440,height:1000});}
};
