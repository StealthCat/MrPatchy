const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let mode='review',writes=0;
 const host=(id,name)=>({id,name,address:'192.0.2.9',state:'online',enabled:true,last_seen:now,integrity:[],error:'',architecture:'amd64'});
 const body=()=>mode==='quiet'?{counts:{total:2,ok:2,warning:0,critical:0,stale:0,unavailable:0},loss:{dropped_batches:0,lost_observations:0,servers_with_loss:0},servers:[],more:0}
  :{counts:{total:5,ok:1,warning:1,critical:1,stale:1,unavailable:1},loss:{dropped_batches:6,lost_observations:20,servers_with_loss:2},more:3,
    servers:[{host_id:'s1',name:'Crit <img src=x onerror="window.__spoolInjected=true">',status:'fresh',pressure:'critical',utilization_percent:95,dropped_batches:5,lost_observations:19},{host_id:'s2',name:'Old',status:'stale',pressure:'ok',utilization_percent:10,dropped_batches:1,lost_observations:1}]};
 const spool=route=>mode==='fail'?route.fulfill({status:500,json:{detail:'boom'}}):route.fulfill({json:body()});
 const observe=request=>{if(new URL(request.url()).pathname.startsWith('/api/')&&!['GET','HEAD'].includes(request.method()))writes++;};page.on('request',observe);
 const hosts=route=>route.fulfill({json:[host('s1','Crit'),host('s2','Old')]});
 await page.route('**/api/spool-health',spool);await page.route('**/api/hosts',hosts);
 try{
  const open=async()=>{await page.goto(new URL('/?fleet-spool='+mode+'#overview',page.url()).href);await page.locator('[data-fleet-section=summary]').waitFor();};
  await open();
  const card=page.locator('[data-fleet-spool]');
  assert.equal(await card.getAttribute('data-fleet-spool'),'review');
  const text=await card.innerText();
  assert.match(text,/Critical \(≥90%\)\s*1/);assert.match(text,/Cumulative lost observations\s*20/);assert.match(text,/95% used/);assert.match(text,/stale telemetry/);assert.match(text,/3 more server/);
  assert.equal(await card.locator('a[href="#servers/s1/overview"]').count(),1);
  assert.equal(await page.locator('#content img[src=x]').count(),0);
  for(const width of [320,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);}
  await capture('fleet-spool-review');
  mode='quiet';await open();assert.equal(await card.getAttribute('data-fleet-spool'),'ok');await card.getByText('No enabled server reports spool pressure',{exact:false}).waitFor();
  mode='fail';await open();assert.equal(await card.getAttribute('data-fleet-spool'),'unavailable');await card.getByText('could not be loaded',{exact:false}).waitFor();
  assert.equal(await page.evaluate(()=>window.__spoolInjected),undefined);assert.equal(writes,0);
 }finally{page.off('request',observe);await page.unroute('**/api/spool-health',spool);await page.unroute('**/api/hosts',hosts);await page.setViewportSize({width:1440,height:1000});}
};
