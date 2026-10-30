const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let detailCalls=0,scopeHost='';
 const pricing={estimated_usd:'0.0001665',version:'2026-10-26',per_million:{input:'0.1',cached_input:'0.01',output:'0.5',cache_write:'0.125'},cache_ttl:'30m'};
 const call={number:1,requested_model:'gpt-6-luna',response_model:'gpt-6-luna',service_tier:'default',status:'estimated',pricing,usage:{input_tokens:1000,cached_tokens:400,cache_write_tokens:100,output_tokens:200,reasoning_tokens:100}};
 const cost={status:'estimated',estimated_usd:'0.000333',priced_calls:2,total_calls:2,in_progress:false};
 const complete={id:'cost-complete',purpose:'triage',state:'complete',model:'gpt-6-luna',calls:2,started:now-60,finished:now-1,message:'<img src=x onerror=window.__aiInjected=true> Structured result validated.',cost,api_calls:[call,{...call,number:2}],events:[{stage:'validated',created:now,message:'Saved structured result; no target action executed.'},{stage:'timing_provider',created:now,message:'provider: 125.500 ms; outcome=complete'},{stage:'timing_run',created:now,message:'run: 300.250 ms; outcome=complete'}]};
 const partial={...complete,id:'cost-partial',state:'error',message:'Follow-up API request timed out.',cost:{...cost,status:'partial',priced_calls:1,estimated_usd:'0.0001665'},api_calls:[call,{...call,number:2,status:'unavailable',usage:{},pricing:{},reason:'No usage receipt was received. The call may still have incurred a charge.'}]};
 const unknown={...complete,id:'cost-unknown',purpose:'connection_test',calls:1,state:'error',model:'fixture-model',message:'OpenAI API HTTP 404 (model_not_found)',cost:{status:'unavailable',estimated_usd:null},api_calls:[]};
 const legacy={...complete,id:'cost-legacy',started:now-86400,cost:{status:'unavailable',estimated_usd:null},api_calls:[],message:'Historical run without token receipts.'};
 const rows=[complete,partial,unknown,legacy];
 const runs=route=>{const next=new URL(route.request().url()).searchParams.get('offset')==='50';return route.fulfill({json:{items:next?[legacy]:rows,more:!next}});};
 const details=route=>{detailCalls++;const url=new URL(route.request().url());if(url.searchParams.has('host_id'))assert.equal(url.searchParams.get('host_id'),scopeHost);return route.fulfill({json:rows.find(r=>url.pathname.endsWith('/'+r.id))});};
 await page.route('**/api/ai/runs?*',runs);await page.route('**/api/ai/runs/cost-*',details);
 try{
  await page.locator('[data-nav=ai-logs]').click();
  await page.getByRole('columnheader',{name:'Est. API cost (USD)',exact:true}).waitFor();
  const table=page.locator('#ai-log-table');
  await table.getByText('$0.000333',{exact:true}).waitFor();
  assert.equal(await table.getByText('Partial · 1 of 2 calls',{exact:true}).count(),1);
  assert.equal(await table.getByText('Unavailable',{exact:true}).count(),2);
  assert.equal(await table.getByText('$0.000000',{exact:true}).count(),0);
  await capture('ai-action-costs');
  await page.locator('[data-ai-run="cost-complete"]').click();
  const modal=page.locator('#content');
  await page.getByRole('link',{name:'Cost',exact:true}).click();
  await modal.getByRole('heading',{name:'Estimated API cost (USD)',exact:true}).waitFor();
  assert.equal(await modal.getByText('Reasoning (included in output)',{exact:false}).count(),2);
  await modal.getByText('Rates used · 2026-10-26',{exact:true}).first().click();
  await modal.getByText('Rates are saved with this call.',{exact:false}).first().waitFor();
  await capture('ai-action-cost-detail');await page.getByRole('link',{name:'← AI activity',exact:true}).click();
  await page.locator('[data-ai-run="cost-partial"]').click();await page.getByRole('link',{name:'Cost',exact:true}).click();
  await modal.getByRole('heading',{name:'API call 2 · Cost unavailable',exact:true}).waitFor();
  await modal.getByText('The call may still have incurred a charge.',{exact:false}).waitFor();
  await page.getByRole('link',{name:'← AI activity',exact:true}).click();
  await page.locator('[data-ai-run="cost-legacy"]').click();await page.getByRole('link',{name:'Cost',exact:true}).click();
  await modal.getByText('Historical costs cannot be reconstructed.',{exact:false}).waitFor();
  await page.getByRole('link',{name:'← AI activity',exact:true}).click();
  await page.locator('#ai-log-next').click();await page.locator('[data-ai-run="cost-legacy"]').waitFor();await page.locator('[data-ai-run="cost-legacy"]').click();await page.getByRole('heading',{name:'Saved run',exact:true}).waitFor();await page.goBack();await page.locator('#ai-log-table').waitFor();assert.equal(await page.locator('[data-ai-run="cost-complete"]').count(),0);await page.locator('#ai-log-prev').click();await page.locator('[data-ai-run="cost-complete"]').waitFor();
  await page.locator('#ai-log-purpose').selectOption('triage');
  await page.locator('[data-ai-run="cost-complete"]').click();await page.getByRole('heading',{name:'Saved run',exact:true}).waitFor();assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.evaluate(()=>window.__aiInjected),undefined);complete.message='Structured result validated and processing completed.';
  await page.getByRole('link',{name:'Timeline',exact:true}).click();await page.getByRole('heading',{name:'Run timeline',exact:true}).waitFor();await page.getByRole('heading',{name:'Timing · provider',exact:true}).waitFor();await page.getByText('provider: 125.500 ms; outcome=complete',{exact:true}).waitFor();for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await capture('ai-run-timing-'+width);}await capture('ai-run-timeline');
  await page.reload();await page.getByRole('heading',{name:'Run timeline',exact:true}).waitFor();
  await page.goBack();await page.getByRole('heading',{name:'Saved run',exact:true}).waitFor();
  await page.getByRole('link',{name:'← AI activity',exact:true}).click();
  // Reload clears context; subsequent in-memory Back/refresh retains it.
  await page.locator('#ai-log-purpose').selectOption('triage');await page.locator('[data-ai-run="cost-complete"]').click();await page.goBack();await page.locator('#ai-log-purpose').waitFor();assert.equal(await page.locator('#ai-log-purpose').inputValue(),'triage');
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});await page.locator('[data-ai-run="cost-complete"]').click();await page.getByRole('heading',{name:'Saved run',exact:true}).waitFor();assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await capture('ai-run-summary-'+width);await page.getByRole('link',{name:'← AI activity',exact:true}).click();}
  for(const width of [320,390]){
   await page.setViewportSize({width,height:844});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await page.locator('[data-ai-run="cost-complete"]').click();await page.getByRole('link',{name:'Cost',exact:true}).click();
   await modal.getByRole('heading',{name:'API call 2 · $0.000167',exact:true}).waitFor();
   assert(await modal.evaluate(el=>el.scrollWidth<=el.clientWidth+1));
   await page.getByRole('link',{name:'← AI activity',exact:true}).click();
   await page.locator('#ai-log-table').waitFor();
  }
  let release,started,finished;const pending=new Promise(resolve=>release=resolve),seen=new Promise(resolve=>started=resolve),done=new Promise(resolve=>finished=resolve);
  const delayed=async route=>{started();await pending;await route.fulfill({json:{...complete,id:'cost-delay'}}).catch(()=>{});finished();};await page.route('**/api/ai/runs/cost-delay',delayed);
  await page.evaluate(()=>location.hash='#ai-logs/run/cost-delay/summary');await seen;await page.evaluate(()=>location.hash='#ai-logs');await page.locator('#ai-log-table').waitFor();release();await done;await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));assert.equal(await page.getByRole('heading',{name:'Saved run',exact:true}).count(),0);await page.unroute('**/api/ai/runs/cost-delay',delayed);
  const host=await page.evaluate(async()=>{let hosts=await(await fetch('/api/hosts')).json();if(!hosts.length){const session=await(await fetch('/api/session')).json();const created=await(await fetch('/api/hosts',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrf},body:JSON.stringify({name:'Run history fixture',address:'192.0.2.90'})})).json();return created.id;}return hosts[0].id;});
  complete.shared_batch=true;scopeHost=host;await page.goto(new URL('/#servers/'+host+'/ai/run/cost-complete/cost',page.url()).href);await page.getByRole('heading',{name:'Estimated API cost (USD)',exact:true}).waitFor();await page.getByText('Shared batch: displayed cost covers the whole run',{exact:false}).waitFor();
  await page.getByRole('link',{name:'← AI activity',exact:true}).click();await page.locator('#ai-log-table').waitFor();assert(page.url().endsWith('/ai'));
  await page.goto(new URL('/#ai-logs/run/missing-run/summary',page.url()).href);await page.getByRole('heading',{name:'Unable to open AI run',exact:true}).waitFor();await page.getByRole('link',{name:'← AI activity',exact:true}).click();await page.locator('#ai-log-table').waitFor();
  const identity=async route=>{const response=await route.fetch();return route.fulfill({response,json:{...await response.json(),role:'viewer'}});};
  await page.route('**/api/identity',identity);const before=detailCalls;await page.goto(new URL('/#ai-logs/run/cost-complete/summary',page.url()).href);await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();assert.equal(detailCalls,before);await page.unroute('**/api/identity',identity);
 }finally{
  await page.setViewportSize({width:1440,height:1000});
  await page.unroute('**/api/ai/runs?*',runs);await page.unroute('**/api/ai/runs/cost-*',details);await page.goto(new URL('/#activity',page.url()).href);
 }
};
