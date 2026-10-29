const assert=require('assert/strict');
module.exports=async(page)=>{
 const hosts=await (await page.request.get(new URL('/api/hosts',page.url()).href)).json(),host=hosts[0];
 const endpoint='/api/hosts/'+host.id+'/security/execution-scans';
 let policy={enabled:false,paths:['/srv/app'],debounce_seconds:30,cooldown_minutes:15,max_per_hour:4,revision:'',activated:0};const writes=[];
 const handler=async route=>{
  const request=route.request(),url=new URL(request.url());
  if(url.pathname!==endpoint)return route.fallback();
  if(request.method()==='PUT'){
   const body=request.postDataJSON();assert.equal(body.expected_revision,policy.revision);assert.ok(body.reason.length>=10);writes.push(body);policy={...body,revision:'revision-'+writes.length,activated:Date.now()/1000};return route.fulfill({json:policy});
  }
  return route.fulfill({json:{policy,state:policy.enabled?'limited':'disabled',limited:policy.enabled,counts:{pending:1},coverage:{dropped_observations:2},last_seen:Date.now()/1000,collector_issues:[],items:[{id:'trigger-fixture',evidence:{executable:'/srv/app/fixture'},state:'pending',created:Date.now()/1000,detail:'Verified execution is a scheduling hint only.'}],more:false}});
 };
 await page.route('**/api/**',handler);
 try{
  await page.goto(new URL('/#servers/'+host.id+'/security',page.url()).href);
  await page.getByRole('heading',{name:'Execution-triggered scans',exact:true}).waitFor();
  const form=page.locator('#execution-scan-form');await form.waitFor();
  assert.equal(writes.length,0);assert.equal(await form.locator('[name=enabled]').isChecked(),false);
  await form.locator('[name=enabled]').check();await form.locator('[name=paths]').fill('/srv/app');await form.locator('[name=reason]').fill('Review bounded automatic scanning from verified execution metadata.');
  await form.getByRole('button',{name:'Save execution scan policy',exact:true}).click();
  await page.locator('#execution-scan-panel .badge').filter({hasText:'limited'}).waitFor();assert.equal(writes.length,1);
  await page.locator('#execution-scan-history').filter({hasText:'/srv/app/fixture'}).waitFor();
  await form.locator('[name=enabled]').uncheck();await form.locator('[name=reason]').fill('Disable future automatic execution scans after review.');
  await form.getByRole('button',{name:'Save execution scan policy',exact:true}).click();
  await page.locator('#execution-scan-panel .badge').filter({hasText:'disabled'}).waitFor();assert.equal(writes.length,2);assert.equal(writes[1].enabled,false);
 }finally{await page.unroute('**/api/**',handler);}
};
