const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 let role='admin',fail=false,mismatch=false,inject=true,writes=0;const reads=[];
 const now=Date.now()/1000;
 const identity=async route=>{const r=await route.fetch();return route.fulfill({response:r,json:{...await r.json(),role}});};
 const audit=route=>{reads.push(route.request().url());if(fail)return route.fulfill({status:404,json:{detail:'Expired <img src=x onerror=window.__activityInjected=true>'}});const u=new URL(route.request().url()),id=u.pathname.split('/entries/')[1],offset=Number(u.searchParams.get('offset')||0);return route.fulfill({json:id?{id:Number(id),created:now,action:inject?'Review <img src=x onerror=window.__activityInjected=true>':'Administrator review',detail:inject?'Recorded event <svg onload=window.__activityInjected=true>':'Worker drain requested for planned maintenance. Review the worker report for acknowledgement.'}:Array.from({length:offset?1:50},(_,i)=>({id:offset+i+1,created:now,action:'Fixture review '+i,detail:'stored event'}))});};
 const job=route=>{reads.push(route.request().url());return route.fulfill(fail?{status:404,json:{detail:'Missing operation'}}:{json:{id:mismatch?'other':'fixture-operation',host_id:'fixture-host',action:'security-plan',created:now,state:'queued',next_at:now+120,payload:{_ai_deferred:true},output:inject?'Untrusted <img src=x onerror=window.__activityInjected=true> output':'AI planning remains queued until the saved shared eligibility time.'}});};
 const observe=r=>{if(new URL(r.url()).pathname.startsWith('/api/')&&r.method()!=='GET')writes++;};page.on('request',observe);
 await page.route('**/api/identity',identity);await page.route('**/api/audit?*',audit);await page.route('**/api/audit/entries/*',audit);await page.route('**/api/jobs/fixture-operation*',job);
 try{
  await page.goto(new URL('/?activity-pages=1#activity/audit',page.url()).href);await page.getByRole('link',{name:'Open entry 1',exact:true}).waitFor();
  await page.locator('#audit-workspace').getByRole('button',{name:'Next',exact:true}).click();await page.getByRole('link',{name:'Open entry 51',exact:true}).click();await page.getByRole('heading',{name:'Audit entry',exact:true}).waitFor();
  assert.equal(await page.locator('#content img[src=x],#content svg[onload]').count(),0);
  await page.goBack();await page.getByRole('link',{name:'Open entry 51',exact:true}).waitFor();await page.reload();await page.getByRole('link',{name:'Open entry 1',exact:true}).waitFor();
  inject=false;await page.getByRole('link',{name:'Open entry 1',exact:true}).click();await page.getByRole('heading',{name:'Audit entry',exact:true}).waitFor();
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('audit-entry-'+width);}
  fail=true;await page.reload();await page.getByRole('heading',{name:'Audit entry unavailable',exact:true}).waitFor();fail=false;await page.getByRole('button',{name:'Retry entry',exact:true}).click();await page.getByRole('heading',{name:'Audit entry',exact:true}).waitFor();
  await page.goto(new URL('/#activity/jobs/fixture-operation',page.url()).href);await page.getByRole('heading',{name:'Operation detail',exact:true}).waitFor();await page.getByText('AI eligibility',{exact:true}).waitFor();assert.equal(await page.locator('#content .cancel-job,#content .reconcile-job').count(),0);assert.equal(await page.locator('#content img[src=x]').count(),0);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('operation-detail-'+width);}
  const fixtureHost=route=>route.fulfill({json:[{id:'fixture-host',name:'Activity target',address:'192.0.2.90',port:22,state:'online',integrity:[],enabled:true}]});await page.route('**/api/hosts',fixtureHost);
  await page.goto(new URL('/#servers/fixture-host/patching/jobs/fixture-operation',page.url()).href);await page.locator('#server-tab-body .activity-detail').waitFor();assert.equal(new URL(reads.at(-1)).searchParams.get('host_id'),'fixture-host');await page.unroute('**/api/hosts',fixtureHost);
  await page.goto(new URL('/#activity/jobs/fixture-operation',page.url()).href);await page.getByRole('heading',{name:'Operation detail',exact:true}).waitFor();
  mismatch=true;await page.reload();await page.getByRole('heading',{name:'Operation unavailable',exact:true}).waitFor();mismatch=false;
  role='viewer';const count=reads.length;await page.goto(new URL('/#activity/audit',page.url()).href);await page.getByRole('heading',{name:'Administrator access required',exact:true}).waitFor();assert.equal(reads.length,count);
  await page.goto(new URL('/#activity/jobs/fixture-operation',page.url()).href);await page.getByRole('heading',{name:'Operation detail',exact:true}).waitFor();assert.equal(writes,0);assert.equal(await page.evaluate(()=>window.__activityInjected),undefined);
 }finally{page.off('request',observe);await page.unroute('**/api/identity',identity);await page.unroute('**/api/audit?*',audit);await page.unroute('**/api/audit/entries/*',audit);await page.unroute('**/api/jobs/fixture-operation*',job);await page.setViewportSize({width:1440,height:1000});}
};
