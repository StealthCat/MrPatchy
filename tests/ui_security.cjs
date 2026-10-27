const assert=require('assert/strict');
module.exports=async(page)=>{
 const hosts=await page.evaluate(async()=>await(await fetch('/api/hosts')).json());const host=hosts[0];
 const prefix='/api/hosts/'+host.id+'/security',writes=[];let incidentState='open';
 const report={state:'incomplete',scanned:2,skipped:1,findings:[],gaps:['Encrypted content'],signatures:{state:'stale',built_at:Date.now()/1000-10*86400}};
 const plan={id:'plan-fixture',state:'draft',created:Date.now()/1000,evidence_digest:'a'.repeat(64),content:{summary:'Review fixture detection',uncertainty:'Signature alone does not establish compromise',steps:[{action:'preserve_evidence',reason:'Preserve fixture',impact:'Storage',verification:'Digest matches',evidence_ids:['incident-fixture','scan-fixture']}]}};
 const startupPlan={id:'startup-plan',state:'draft',evidence_digest:'d'.repeat(64),content:{summary:'Investigate startup change',uncertainty:'Administrative change remains possible',steps:[]}};
 const handler=async route=>{
  const request=route.request(),url=new URL(request.url());
  if(url.pathname.startsWith('/api/security/indicators/'))return route.fulfill({json:{items:[{host_id:host.id,path:'/tmp/security-fixture',state:incidentState,updated:Date.now()/1000}],more:false}});
  if(!url.pathname.startsWith(prefix))return route.fallback();
  if(url.pathname.endsWith('/agent')&&request.method()==='GET')return route.fulfill({json:{policy:{auto_upgrade:false,auto_repair:false},status:{state:'drifted',checked:Date.now()/1000,stale:false,issues:[{path:'/usr/local/lib/mrpatchy/agent.py',kind:'unexpected_content_or_missing'}],report:{}},enrolled_outdated:false}});
  if(url.pathname.endsWith('/agent')&&request.method()==='PUT'){writes.push(url.pathname);assert.equal(request.postDataJSON().auto_upgrade,true);return route.fulfill({json:{auto_upgrade:true,auto_repair:false}});}
  if(url.pathname.endsWith('/persistence-monitor')){if(request.method()==='PUT'){writes.push(url.pathname);assert.equal(request.postDataJSON().enabled,true);return route.fulfill({json:{...request.postDataJSON(),revision:'monitor-version'}});}return route.fulfill({json:{enabled:false,interval_hours:12,link_incidents:false,revision:''}});}
  if(url.pathname.endsWith('/persistence-incidents/startup-fixture/plans/startup-plan/approve')){writes.push(url.pathname);startupPlan.state='approved';return route.fulfill({json:{execution:'manual_only'}});}
  if(url.pathname.endsWith('/persistence-incidents'))return route.fulfill({json:{items:[{id:'startup-fixture',state:'open',updated:1,baseline_id:'baseline-fixture',evidence:{changes:[{path:'/etc/cron.d/task',kind:'added'}]},plans:[startupPlan]}],more:false}});
  if(url.pathname.endsWith('/persistence-incidents/startup-fixture/history'))return route.fulfill({json:{detections:[{inspection_id:'inspection-job'}],reviews:[],more:false}});
  if(url.pathname.endsWith('/baseline')&&request.method()==='GET')return route.fulfill({json:{state:'not_configured',baseline:null,eligible:true,latest:{id:'inspection-job',created:Date.now()/1000,digest:'c'.repeat(64),inventory:{scope:['/etc/cron.d'],entries:[],missing_roots:[]}},comparison:{state:'unavailable',changes:[]}}});
  if(url.pathname.endsWith('/baseline')&&request.method()==='POST'){writes.push(url.pathname);assert.equal(request.postDataJSON().expected,'');assert.equal(request.postDataJSON().inspection_id,'inspection-job');return route.fulfill({json:{id:'baseline-fixture'}});}
  if(url.pathname.endsWith('/comparison'))return route.fulfill({json:{state:'compared',previous_created:Date.now()/1000-3600,note:'Observed changes, not a malware verdict.',changes:[{path:'/etc/cron.d/review-me',kind:'added'}]}});
  if(url.pathname.endsWith('/vendor-inspections')){assert.deepEqual(request.postDataJSON(),{bundle_id:'vendor-fixture'});writes.push(url.pathname);return route.fulfill({json:{job_id:'vendor-job'}});}
  if(url.pathname.endsWith('/inspections')){
   if(request.method()==='POST'){writes.push(url.pathname);assert.deepEqual(request.postDataJSON(),{packages:['openssh-server'],persistence:true});return route.fulfill({json:{job_id:'inspection-job'}});}
   return route.fulfill({json:{items:[{id:'inspection-job',created:Date.now()/1000,report:{state:'collected',packages:[{package:'openssh-server',state:'differences',installed_identity:'installed 1',gaps:[],findings:[{path:'/etc/ssh/sshd_config',status:'metadata_or_content_changed',checks:'??5??????',configuration_file:true}]}],persistence:{state:'collected',entries:[{path:'/etc/systemd/system/example.service',kind:'regular',sha256:'a'.repeat(64)}]}}}],more:false}});
  }
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
  await page.goto(new URL('/#servers/'+host.id+'/integrity',page.url()).href);
  await page.locator('#security-inspection-form').waitFor();
  await page.getByText('Trust basis: local package database',{exact:true}).waitFor();
  await page.locator('#security-inspection-form [name=packages]').fill('openssh-server');
  await page.getByRole('button',{name:'Queue inspection',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Inspection queued'));
  assert.equal(writes.at(-1),prefix+'/inspections');
  await page.locator('#vendor-inspection-form [name=bundle_id]').fill('vendor-fixture');
  await page.getByRole('button',{name:'Queue vendor verification',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Vendor verification queued'));
  assert.equal(writes.at(-1),prefix+'/vendor-inspections');
  await page.locator('#inspection-reports summary').filter({hasText:'openssh-server'}).click();
  await page.getByText('/etc/ssh/sshd_config',{exact:true}).waitFor();
  await page.getByRole('button',{name:'Compare startup inventory',exact:true}).click();
  await page.locator('.inspection-comparison pre').filter({hasText:'/etc/cron.d/review-me'}).waitFor();
  await page.getByRole('button',{name:'Review latest as baseline',exact:true}).click();
  await page.locator('#startup-baseline-approval textarea').fill('Verified the startup entries against approved configuration.');
  await page.getByRole('button',{name:'Approve startup baseline',exact:true}).click();
  await page.locator('#modal').waitFor({state:'hidden'});
  assert.equal(writes.at(-1),prefix+'/baseline');

  await page.locator('#persistence-monitor-form [name=enabled]').check();
  await page.locator('#persistence-monitor-form [name=link_incidents]').check();
  await page.getByRole('button',{name:'Save startup monitoring',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Startup monitoring saved'));
  const beforeStartupRequest=writes.length;
  await page.getByRole('button',{name:'Request startup AI plan',exact:true}).click();
  assert.equal(writes.length,beforeStartupRequest);
  await page.getByRole('button',{name:'Send metadata and request plan',exact:true}).click();
  await page.locator('#modal').waitFor({state:'hidden'});
  assert.equal(writes.at(-1),prefix+'/persistence-incidents/startup-fixture/plan');
  await page.getByRole('button',{name:'Review startup plan approval',exact:true}).click();
  await page.getByRole('button',{name:'Approve for manual startup response',exact:true}).click();
  await page.locator('#modal').waitFor({state:'hidden'});
  assert.equal(writes.at(-1),prefix+'/persistence-incidents/startup-fixture/plans/startup-plan/approve');
  await page.getByRole('button',{name:'Linked inspections and reviews',exact:true}).click();
  await page.locator('#startup-evidence').filter({hasText:'inspection-job'}).waitFor();await page.locator('#close-modal').click();
  await page.getByRole('button',{name:'Review startup incident',exact:true}).click();
  await page.locator('#startup-review-form [name=state]').selectOption('acknowledged');
  await page.locator('#startup-review-form [name=reason]').fill('Investigating the new startup entry.');
  await page.getByRole('button',{name:'Save startup review',exact:true}).click();
  await page.locator('#modal').waitFor({state:'hidden'});
  await page.goto(new URL('/#servers/'+host.id+'/agent',page.url()).href);
  await page.locator('#agent-policy').waitFor();
  await page.locator('#agent-policy [name=auto_upgrade]').check();
  await page.getByRole('button',{name:'Save agent policy',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Agent policy saved'));
  assert.equal(writes.at(-1),prefix+'/agent');
  await page.getByRole('button',{name:'Check agent now',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Agent check queued'));
  assert.equal(writes.at(-1),prefix+'/agent/check');
  for(const width of [320,390,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);}
 }finally{await page.unroute('**/api/**',handler);await page.setViewportSize({width:1440,height:1000});}
};
