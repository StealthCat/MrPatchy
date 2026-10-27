const assert=require('assert/strict');
module.exports=async(page)=>{
 const hosts=await page.evaluate(async()=>await(await fetch('/api/hosts')).json());const host=hosts[0];
 const prefix='/api/hosts/'+host.id+'/security',writes=[];let incidentState='open';
 const report={state:'incomplete',scanned:2,skipped:1,findings:[],gaps:['Encrypted content'],signatures:{state:'stale',built_at:Date.now()/1000-10*86400}};
 const plan={id:'plan-fixture',state:'draft',created:Date.now()/1000,evidence_digest:'a'.repeat(64),content:{summary:'Review fixture detection',uncertainty:'Signature alone does not establish compromise',steps:[{action:'preserve_evidence',reason:'Preserve fixture',impact:'Storage',verification:'Digest matches',evidence_ids:['incident-fixture','scan-fixture']}]}};
 const handler=async route=>{
  const request=route.request(),url=new URL(request.url());
  if(url.pathname.startsWith('/api/security/indicators/'))return route.fulfill({json:{items:[{host_id:host.id,path:'/tmp/security-fixture',state:incidentState,updated:Date.now()/1000}],more:false}});
  if(!url.pathname.startsWith(prefix))return route.fallback();
  if(['POST','PUT'].includes(request.method())){writes.push(url.pathname);if(url.pathname.endsWith('/policy'))assert.equal(request.postDataJSON().auto_ai_plan,true);if(url.pathname.endsWith('/incidents/incident-fixture'))incidentState=request.postDataJSON().state;if(url.pathname.endsWith('/approve'))plan.state='approved';return route.fulfill({json:{ok:true,job_id:'job-fixture',execution:'manual_only'}});}
  if(url.pathname.endsWith('/policy'))return route.fulfill({json:{enabled:false,interval_hours:24,paths:['/tmp']}});
  if(url.pathname===prefix)return route.fulfill({json:report});
  if(url.pathname.endsWith('/timeline'))return route.fulfill({json:{items:[{kind:'review',actor:'admin',created:Date.now()/1000,details:{reason:'Fixture reviewed'}}],more:false}});
  if(url.pathname.endsWith('/history'))return route.fulfill({json:{items:[{id:'scan-fixture',created:Date.now()/1000,report}],more:false}});
  if(url.pathname.endsWith('/incidents'))return route.fulfill({json:{items:[{id:'incident-fixture',state:incidentState,updated:Date.now()/1000,evidence:{path:'/tmp/security-fixture',sha256:'b'.repeat(64)},plans:[plan]}],more:false}});
  return route.fallback();
 };
 await page.route('**/api/**',handler);
 try{
  await page.goto(new URL('/#servers/'+host.id+'/security',page.url()).href);
  await page.getByText('Review fixture detection',{exact:true}).waitFor();
  await page.getByText('Signature freshness: Stale',{exact:true}).waitFor();
  assert.equal(writes.length,0);
  await page.locator('#security-policy-form [name=enabled]').check();
  await page.locator('#security-policy-form [name=auto_ai_plan]').check();
  await page.getByRole('button',{name:'Save scan policy',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Scan policy saved'));
  assert.equal(writes.pop(),prefix+'/policy');
  await page.getByRole('button',{name:'Review approval',exact:true}).click();
  assert.equal(writes.length,0,'Opening review must not approve');
  await page.getByRole('button',{name:'Approve for manual response',exact:true}).click();
  await page.locator('#security-incidents .badge').filter({hasText:'approved'}).waitFor();
  assert.equal(writes.at(-1),prefix+'/plans/plan-fixture/approve');
  await page.getByRole('button',{name:'Generate AI response plan',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('AI plan queued'));
  assert.equal(writes.at(-1),prefix+'/incidents/incident-fixture/plan');
  await page.getByRole('button',{name:'Incident timeline',exact:true}).click();
  await page.locator('#incident-records pre').filter({hasText:'Fixture reviewed'}).waitFor();await page.locator('#close-modal').click();
  await page.getByRole('button',{name:'Find hash across fleet',exact:true}).click();
  await page.locator('#incident-records a').waitFor();await page.locator('#close-modal').click();
  await page.getByRole('button',{name:'Review incident',exact:true}).click();
  await page.locator('#incident-review-form [name=state]').selectOption('false_positive');
  await page.locator('#incident-review-form [name=reason]').fill('Confirmed this is an approved test fixture.');
  await page.getByRole('button',{name:'Save incident review',exact:true}).click();
  await page.locator('#security-incidents .badge').filter({hasText:'false_positive'}).waitFor();
  assert.equal(writes.at(-1),prefix+'/incidents/incident-fixture');
  for(const width of [320,390,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);}
 }finally{await page.unroute('**/api/**',handler);await page.setViewportSize({width:1440,height:1000});}
};
