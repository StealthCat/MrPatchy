const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;
 const pricing={estimated_usd:'0.0001665',version:'2026-10-26',per_million:{input:'0.1',cached_input:'0.01',output:'0.5',cache_write:'0.125'},cache_ttl:'30m'};
 const call={number:1,requested_model:'gpt-6-luna',response_model:'gpt-6-luna',service_tier:'default',status:'estimated',pricing,usage:{input_tokens:1000,cached_tokens:400,cache_write_tokens:100,output_tokens:200,reasoning_tokens:100}};
 const cost={status:'estimated',estimated_usd:'0.000333',priced_calls:2,total_calls:2,in_progress:false};
 const complete={id:'cost-complete',purpose:'triage',state:'complete',model:'gpt-6-luna',calls:2,started:now,message:'Structured result validated and processing completed.',cost,api_calls:[call,{...call,number:2}],events:[]};
 const partial={...complete,id:'cost-partial',state:'error',message:'Follow-up API request timed out.',cost:{...cost,status:'partial',priced_calls:1,estimated_usd:'0.0001665'},api_calls:[call,{...call,number:2,status:'unavailable',usage:{},pricing:{},reason:'No usage receipt was received. The call may still have incurred a charge.'}]};
 const unknown={...complete,id:'cost-unknown',purpose:'connection_test',calls:1,state:'error',model:'fixture-model',message:'OpenAI API HTTP 404 (model_not_found)',cost:{status:'unavailable',estimated_usd:null},api_calls:[]};
 const legacy={...complete,id:'cost-legacy',started:now-86400,cost:{status:'unavailable',estimated_usd:null},api_calls:[],message:'Historical run without token receipts.'};
 const rows=[complete,partial,unknown,legacy];
 const runs=route=>route.fulfill({json:{items:rows,more:false}});
 const details=route=>route.fulfill({json:rows.find(r=>route.request().url().endsWith('/'+r.id))});
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
  const modal=page.locator('#modal');
  await modal.getByRole('heading',{name:'Estimated API cost (USD)',exact:true}).waitFor();
  assert.equal(await modal.getByText('Reasoning (included in output)',{exact:false}).count(),2);
  await modal.getByText('Rates used · 2026-10-26',{exact:true}).first().click();
  await modal.getByText('Rates are saved with this call.',{exact:false}).first().waitFor();
  await capture('ai-action-cost-detail');await page.keyboard.press('Escape');
  await page.locator('[data-ai-run="cost-partial"]').click();
  await modal.getByRole('heading',{name:'API call 2 · Cost unavailable',exact:true}).waitFor();
  await modal.getByText('The call may still have incurred a charge.',{exact:false}).waitFor();
  await page.keyboard.press('Escape');
  await page.locator('[data-ai-run="cost-legacy"]').click();
  await modal.getByText('Historical costs cannot be reconstructed.',{exact:false}).waitFor();
  await page.keyboard.press('Escape');
  for(const width of [320,390]){
   await page.setViewportSize({width,height:844});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await page.locator('[data-ai-run="cost-complete"]').click();
   await modal.getByRole('heading',{name:'API call 2 · $0.000167',exact:true}).waitFor();
   assert(await modal.evaluate(el=>el.scrollWidth<=el.clientWidth+1));
   await page.keyboard.press('Escape');
   await modal.waitFor({state:'hidden'});
  }
 }finally{
  await page.setViewportSize({width:1440,height:1000});
  await page.unroute('**/api/ai/runs?*',runs);await page.unroute('**/api/ai/runs/cost-*',details);
 }
};
