const assert=require('assert/strict');
// Fleet known-good candidate list in the AI activity cache panel: on-demand load,
// state filter, escaping, origin links, paging, errors, stale responses and layout.
module.exports=async(page,capture)=>{
 const pattern='**/api/ai/known-good/candidates*';
 const now=Date.now()/1000,reads=[];let failures=1,hold=null;
 const item=(n,extra={})=>({fingerprint:n.toString(16).padStart(64,'a'),version:1,created:now-n,classification_source:'ai',model:'fixture-model',origin_assessment_id:`00000000-0000-0000-0000-${String(n).padStart(12,'0')}`,origin_subject:'e'.repeat(64),origin:{host_id:'host-'+n,host_name:'Server '+n,host_active:true},active:true,revoked_at:0,revoked_by:'',revoked_reason:'',linked:n+1,reused:n,...extra});
 const handler=async route=>{
  const url=new URL(route.request().url());reads.push(url);
  if(hold)await hold;
  if(failures>0){failures--;return route.fulfill({status:503,json:{detail:'Internal fixture details'}});}
  const state=url.searchParams.get('state'),offset=Number(url.searchParams.get('offset'));
  if(state==='revoked')return route.fulfill({json:{state,offset,more:false,items:[item(30,{active:false,revoked_at:now,revoked_by:'admin<b>',revoked_reason:'<img src=x onerror=window.__kgInjected=true>',origin_subject:'',origin:{host_id:'host-30',host_name:'',host_active:false}})]}});
  if(state==='all')return route.fulfill({json:{state,offset,more:false,items:[]}});
  const items=offset?[item(21)]:Array.from({length:20},(_,i)=>i?item(i+1):item(1,{origin:{host_id:'host-1',host_name:'<img src=x onerror=window.__kgInjected=true>',host_active:false}}));
  return route.fulfill({json:{state,offset,more:!offset,items}});
 };
 await page.route(pattern,handler);
 try{
  await page.goto(new URL('/#ai-logs',page.url()).href);
  const panel=page.getByRole('region',{name:'Fleet known-good cache',exact:true});
  const section=panel.getByRole('region',{name:'Candidates',exact:true});
  await section.waitFor();
  assert.equal(reads.length,0,'candidates must load only on demand');
  assert.match(await section.textContent(),/grants no approval and authorizes no response/);
  await section.getByRole('button',{name:'Load candidates',exact:true}).click();
  await section.getByRole('status').filter({hasText:'Candidates are unavailable'}).waitFor();
  assert.equal(await section.getByText('Internal fixture details').count(),0);
  assert.equal(await page.locator('#ai-log-table').isVisible(),true,'AI runs stay usable after a failure');
  await section.getByRole('button',{name:'Retry candidates',exact:true}).click();
  await section.getByRole('status').filter({hasText:'Showing active candidates 1–20.'}).waitFor();
  const last=reads.at(-1);
  assert.equal(last.pathname,'/api/ai/known-good/candidates');
  assert.deepEqual([last.searchParams.get('state'),last.searchParams.get('offset'),last.searchParams.get('limit')],['active','0','20']);
  assert.equal(await section.locator('tbody tr').count(),20);
  assert.equal(await section.locator('img').count(),0);assert.equal(await page.evaluate(()=>window.__kgInjected),undefined);
  await section.getByText('<img src=x onerror=window.__kgInjected=true>',{exact:false}).waitFor();
  await section.getByText('Inactive server',{exact:true}).first().waitFor();
  assert.equal(await section.getByRole('link',{name:'Origin assessment'}).first().getAttribute('href'),`#investigations/item/${'e'.repeat(64)}/history/${item(1).origin_assessment_id}`);
  assert.match(await section.locator('tbody tr').nth(1).textContent(),/3 linked2 exact-match reuse\(s\)/);
  assert.equal(await section.getByRole('button',{name:'Previous candidates'}).isDisabled(),true);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1),'no horizontal page scroll at '+width);await capture('known-good-candidates-'+width);}
  await page.setViewportSize({width:1440,height:1000});
  await section.getByRole('button',{name:'Next candidates'}).click();
  await section.getByRole('status').filter({hasText:'Showing active candidates 21–21.'}).waitFor();
  assert.equal(reads.at(-1).searchParams.get('offset'),'20');
  assert.equal(await section.getByRole('button',{name:'Next candidates'}).isDisabled(),true);
  await section.getByLabel('Show').selectOption('revoked');
  await section.getByRole('status').filter({hasText:'Showing revoked candidates 1–1.'}).waitFor();
  assert.equal(reads.at(-1).searchParams.get('offset'),'0','changing the filter restarts paging');
  const revoked=section.locator('tbody tr');
  assert.match(await revoked.textContent(),/revoked/);
  await section.getByText('admin<b>',{exact:false}).waitFor();
  await section.getByText('Origin assessment not retained',{exact:true}).waitFor();
  await section.getByText('host-30',{exact:false}).waitFor();
  assert.equal(await section.locator('img,b').count(),0);
  assert.equal(await section.locator('.actions').isHidden(),true);
  await section.getByLabel('Show').selectOption('all');
  await section.getByText('No candidates on this page.',{exact:false}).first().waitFor();
  // A response that arrives after leaving AI activity is discarded.
  let release;hold=new Promise(resolve=>release=resolve);const pending=reads.length;
  await section.getByRole('button',{name:'Refresh candidates'}).click();
  while(reads.length===pending)await page.waitForTimeout(20);
  await page.locator('[data-nav=overview]').click();await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
  release();hold=null;await page.waitForTimeout(200);
  assert.equal(await page.locator('.known-good-candidates').count(),0);
  // Viewers never see or request the list.
  const before=reads.length;
  const identity=async route=>{const response=await route.fetch();route.fulfill({response,json:{...await response.json(),role:'viewer'}});};
  await page.route('**/api/identity',identity);
  try{
   await page.goto(new URL('/#ai-logs',page.url()).href);
   await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
   assert.equal(await page.locator('.known-good-candidates').count(),0);
   assert.equal(reads.length,before,'viewers must not request candidates');
  }finally{await page.unroute('**/api/identity',identity);await page.goto(new URL('/#overview',page.url()).href);await page.reload();}
 }finally{
  hold=null;await page.setViewportSize({width:1440,height:1000});
  await page.unroute(pattern,handler);
 }
};
