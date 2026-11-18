const assert=require('assert/strict');
// Linked-servers section on an assessment that published, reused or revoked a
// fleet known-good candidate: lazy load, escaping, roles, paging, errors,
// stale-response isolation and responsive layout.
module.exports=async(page,capture)=>{
 const now=Date.now()/1000,id='d'.repeat(64),record='44444444-4444-4444-4444-444444444444',fingerprint='f'.repeat(64),revision='b'.repeat(64);
 const host=await page.evaluate(async()=>{let list=await(await fetch('/api/hosts')).json();if(list.length)return list[0].id;const session=await(await fetch('/api/session')).json();return(await(await fetch('/api/hosts',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrf},body:JSON.stringify({name:'Linked fixture',address:'192.0.2.91'})})).json()).id;});
 let mode='published',failures=1;const reads=[];let hold=null;
 const current={id,host_id:host,executable:'/usr/bin/linked',verdict:'low',analysis:'Advisory',approved:false,revision,can_retriage:true,refresh:{}};
 const history=route=>route.fulfill({json:{current,items:[{id:record,source:'ai',created:now,risk:'low',model:'fixture-model',run_id:''}],more:false}});
 const detail=route=>route.fulfill({json:{id:record,source:'ai',subject:id,host_id:host,created:now,model:'fixture-model',policy_hash:'c'.repeat(64),run_id:'',result:{risk:'low',explanation:'Saved explanation',recommended_checks:'None'},snapshot:{},inputs:[],
  known_good:mode==='ineligible'?{version:1,eligible:false,reasons:[]}:{version:1,eligible:true,fingerprint,published:mode==='published',active:mode==='published',review_required:mode==='revoked',linked_assessments:23,revoked_at:mode==='revoked'?now:0,revoked_by:'admin',revoked_reason:'Fleet review'}}});
 const item=(n,extra={})=>({assessment_id:`00000000-0000-0000-0000-${String(n).padStart(12,'0')}`,subject:'e'.repeat(64),created:now-n,role:n===22?'origin':n%2?'reuse':'linked',host_id:'host-'+n,host_name:'Server '+n,host_active:true,...extra});
 const links=async route=>{const url=new URL(route.request().url());reads.push(url);if(hold)await hold;if(failures>0){failures--;return route.fulfill({status:503,json:{detail:'Fixture outage'}});}
  const offset=Number(url.searchParams.get('offset'));const items=offset?[item(21),item(22)]:Array.from({length:20},(_,i)=>i?item(i+1):item(1,{host_name:'<img src=x onerror=window.__linkInjected=true>',host_active:false}));
  return route.fulfill({json:{fingerprint,version:1,active:mode!=='revoked',revoked_at:mode==='revoked'?now:0,origin_assessment_id:item(22).assessment_id,origin:{host_id:'host-22',host_name:'Server 22',host_active:true},total:22,offset,items,more:!offset}});};
 const base='**/api/investigations/'+id+'/history';
 await page.route(base+'?*',history);await page.route(base,history);await page.route(base+'/'+record+'*',detail);await page.route('**/api/ai/known-good/*/observations*',links);
 const open=async()=>{await page.goto(new URL('/#investigations/item/'+id+'/history/'+record,page.url()).href);await page.reload();await page.getByRole('heading',{name:'Recorded AI assessment',exact:true}).waitFor();};
 const section=page.locator('#known-good-links');
 try{
  await open();
  await section.getByRole('alert').filter({hasText:'Unable to load linked assessments'}).waitFor();
  assert.match(reads.at(-1).pathname,new RegExp('/api/ai/known-good/'+fingerprint+'/observations$'));
  assert.equal(reads.at(-1).searchParams.get('offset'),'0');assert.equal(reads.at(-1).searchParams.get('limit'),'20');
  await section.getByRole('button',{name:'Retry',exact:true}).click();
  await section.getByText('22 retained assessment(s) on the fleet are bound to fingerprint v1.',{exact:false}).waitFor();
  assert.match(await section.textContent(),/grants no approval and authorizes no response/);
  assert.equal(await section.locator('tbody tr').count(),20);
  assert.equal(await section.locator('img[src=x]').count(),0);assert.equal(await page.evaluate(()=>window.__linkInjected),undefined);
  await section.getByText('<img src=x onerror=window.__linkInjected=true>',{exact:false}).waitFor();
  await section.getByText('Inactive server',{exact:true}).waitFor();
  await section.getByText('Exact-match reuse · no provider call',{exact:true}).first().waitFor();
  await section.getByText('Independent AI assessment · same fingerprint',{exact:true}).first().waitFor();
  assert.equal(await section.getByRole('link',{name:'Review assessment'}).first().getAttribute('href'),`#investigations/item/${'e'.repeat(64)}/history/${item(1).assessment_id}`);
  assert.equal(await section.getByRole('button',{name:'Previous linked',exact:true}).isDisabled(),true);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'no horizontal page scroll at '+width);await capture('known-good-links-'+width);}
  await page.setViewportSize({width:1440,height:1000});
  await section.getByRole('button',{name:'Next linked',exact:true}).click();
  await section.getByText('Published this candidate',{exact:true}).waitFor();
  assert.equal(reads.at(-1).searchParams.get('offset'),'20');
  assert.equal(await section.locator('tbody tr').count(),2);
  assert.equal(await section.getByRole('button',{name:'Next linked',exact:true}).isDisabled(),true);
  await section.getByRole('button',{name:'Previous linked',exact:true}).click();
  await section.locator('tbody tr').nth(19).waitFor();assert.equal(reads.at(-1).searchParams.get('offset'),'0');
  mode='revoked';await open();await section.getByText('(revoked: each needs review)',{exact:false}).waitFor();
  mode='ineligible';const before=reads.length;await open();await page.getByRole('heading',{name:'Fleet match unavailable',exact:true}).waitFor();assert.equal(reads.length,before);assert.equal(await section.count(),0);
  // A response that arrives after the administrator navigated away is discarded.
  mode='published';let release;hold=new Promise(resolve=>release=resolve);const pending=reads.length;
  await page.goto(new URL('/#investigations/item/'+id+'/history/'+record,page.url()).href);await page.reload();
  while(reads.length===pending)await page.waitForTimeout(20);
  await page.locator('[data-nav=overview]').click();await page.locator('#content').getByRole('heading').first().waitFor();
  release();hold=null;await page.waitForTimeout(200);assert.equal(await section.count(),0);
 }finally{
  hold=null;await page.setViewportSize({width:1440,height:1000});
  await page.unroute(base+'?*',history);await page.unroute(base,history);await page.unroute(base+'/'+record+'*',detail);await page.unroute('**/api/ai/known-good/*/observations*',links);
  await page.goto(new URL('/#overview',page.url()).href);
 }
};
