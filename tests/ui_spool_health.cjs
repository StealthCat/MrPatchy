const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const id='spool-ui-host',now=Date.now()/1000;let mode='warning';
 const host={id,name:'Spool UI server',address:'192.0.2.77',port:22,state:'online',enabled:true,deleted_at:0,integrity:[],last_seen:now,error:'',repo_error:'',package_manager:'apt',architecture:'amd64'};
 const health=()=>{
  if(mode==='fail')return null;
  if(mode==='unavailable')return {host_id:id,status:'unavailable',pressure:'unavailable',reason:'No spool counters have been collected from this server.',collected:null};
  const queue=mode==='ok'?{pending_batches:2,queued_bytes:100,capacity_bytes:1000,utilization_percent:10}:{pending_batches:9,queued_bytes:950,capacity_bytes:1000,utilization_percent:95};
  return {host_id:id,status:mode==='stale'?'stale':'fresh',pressure:mode==='ok'?'ok':mode==='stale'?'ok':'critical',collected:now,queue,
   loss:mode==='ok'?{dropped_batches:0,lost_observations:0,by_reason:{oversize:{batches:0,observations:0},capacity:{batches:0,observations:0}},unclassified_batches:0}:{dropped_batches:3,lost_observations:12,by_reason:{oversize:{batches:1,observations:4},capacity:{batches:2,observations:8}},unclassified_batches:null}};
 };
 const handler=async route=>{
  const url=new URL(route.request().url()),p=url.pathname;
  if(p==='/api/hosts')return route.fulfill({json:[host]});
  if(p==='/api/hosts/'+id+'/spool-health'){const body=health();return body?route.fulfill({json:body}):route.fulfill({status:500,json:{detail:'boom'}});}
  if(p==='/api/hosts/'+id+'/summary')return route.fulfill({json:{host,system:{os:'Fixture OS',architecture:'amd64'},collector:{processes:0,managed_files:0},counts:{packages:0,updates:0,held:0,overdue:0,unapproved:0,pending_ai:0},jobs:{},last_patch:null}});
  if(p.endsWith('/security/ai-policy'))return route.fulfill({json:{paused:false,state:'eligible',global_enabled:true,revision:'',reason:''}});
  return route.fallback();
 };
 await page.route('**/api/**',handler);
 try{
  const open=async()=>{await page.goto(new URL('/#servers',page.url()).href);await page.goto(new URL('/#servers/'+id+'/overview',page.url()).href);await page.reload();};
  await open();
  const card=page.locator('[data-spool-health]');
  await card.waitFor();
  assert.equal(await card.getAttribute('data-spool-health'),'fresh');
  assert.equal(await card.getAttribute('data-spool-pressure'),'critical');
  const text=await card.innerText();
  assert.match(text,/95% of capacity used/);assert.match(text,/Lost observations \(cumulative\)\s*12/);
  assert.match(text,/oversize: 1 batches, 4 observations/);
  assert.equal(await card.locator('[role=alert]').count(),1);
  await capture('spool-health-critical');
  mode='ok';await page.reload();await card.waitFor();
  assert.equal(await card.getAttribute('data-spool-pressure'),'ok');
  assert.equal(await card.locator('[role=alert],[role=status].notice').count(),0);
  mode='stale';await page.reload();await card.waitFor();
  assert.equal(await card.getAttribute('data-spool-health'),'stale');assert.match(await card.innerText(),/stale/);
  mode='unavailable';await page.reload();await card.waitFor();
  assert.equal(await card.getAttribute('data-spool-health'),'unavailable');assert.match(await card.innerText(),/No spool counters/);
  mode='fail';await page.reload();await card.waitFor();
  assert.equal(await card.getAttribute('data-spool-health'),'unavailable');assert.match(await card.innerText(),/could not be loaded/);
  await page.getByRole('heading',{name:'Integrity findings'}).waitFor();
 }finally{await page.unroute('**/api/**',handler);}
};
