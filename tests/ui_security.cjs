const assert=require('assert/strict');
module.exports=async(page)=>{
 const hosts=await page.evaluate(async()=>await(await fetch('/api/hosts')).json());const host=hosts[0];
 const prefix='/api/hosts/'+host.id+'/security',writes=[];let incidentState='open',copyState='prepared',responseState='prepared',responseHold=false,watchEnabled=true;let processState='prepared',processHold=false,repairQueued=false,stagingCreated=false;let responsePolicy={enabled:false,interval_minutes:15,pause_on_problem:false,revision:''};
 const report={state:'incomplete',scanned:2,skipped:1,findings:[],gaps:['Encrypted content'],signatures:{state:'stale',built_at:Date.now()/1000-10*86400}};
 const plan={id:'plan-fixture',state:'draft',created:Date.now()/1000,evidence_digest:'a'.repeat(64),content:{summary:'Review fixture detection',uncertainty:'Signature alone does not establish compromise',steps:[{action:'preserve_evidence',reason:'Preserve fixture',impact:'Storage',verification:'Digest matches',evidence_ids:['incident-fixture','scan-fixture']}]}};
 const startupPlan={id:'startup-plan',state:'draft',evidence_digest:'d'.repeat(64),content:{summary:'Investigate startup change',uncertainty:'Administrative change remains possible',steps:[]}};
 const handler=async route=>{
  const request=route.request(),url=new URL(request.url());
  if(url.pathname.startsWith('/api/security/indicators/'))return route.fulfill({json:{items:[{host_id:host.id,path:'/tmp/security-fixture',state:incidentState,updated:Date.now()/1000}],more:false}});
  if(!url.pathname.startsWith(prefix))return route.fallback();
  if(url.pathname.endsWith('/agent')&&request.method()==='GET')return route.fulfill({json:{policy:{auto_upgrade:false,auto_repair:false},status:{state:'drifted',checked:Date.now()/1000,stale:false,issues:[{path:'/usr/local/lib/mrpatchy/agent.py',kind:'unexpected_content_or_missing'}],report:{}},enrolled_outdated:false}});
  if(url.pathname.endsWith('/agent')&&request.method()==='PUT'){writes.push(url.pathname);assert.equal(request.postDataJSON().auto_upgrade,true);return route.fulfill({json:{auto_upgrade:true,auto_repair:false}});}
  if(url.pathname.endsWith('/persistence-monitor')){if(request.method()==='PUT'){writes.push(url.pathname);assert.equal(request.postDataJSON().enabled,true);assert.deepEqual(request.postDataJSON().custom_paths,['/srv/myapp/config.json']);return route.fulfill({json:{...request.postDataJSON(),revision:'monitor-version'}});}return route.fulfill({json:{enabled:false,interval_hours:12,link_incidents:false,revision:''}});}
  if(url.pathname.endsWith('/persistence-incidents/startup-fixture/plans/startup-plan/approve')){writes.push(url.pathname);startupPlan.state='approved';return route.fulfill({json:{execution:'manual_only'}});}
  if(url.pathname.endsWith('/persistence-incidents'))return route.fulfill({json:{items:[{id:'startup-fixture',state:'open',updated:1,baseline_id:'baseline-fixture',evidence:{changes:[{path:'/etc/cron.d/task',kind:'added'}]},plans:[startupPlan]}],more:false}});
  if(url.pathname.endsWith('/persistence-incidents/startup-fixture/history'))return route.fulfill({json:{detections:[{inspection_id:'inspection-job'}],reviews:[],more:false}});
  if(url.pathname.endsWith('/baseline')&&request.method()==='GET')return route.fulfill({json:{state:'not_configured',baseline:null,eligible:true,latest:{id:'inspection-job',created:Date.now()/1000,digest:'c'.repeat(64),inventory:{scope:['/etc/cron.d'],entries:[],missing_roots:[]}},comparison:{state:'unavailable',changes:[]}}});
  if(url.pathname.endsWith('/baseline')&&request.method()==='POST'){writes.push(url.pathname);assert.equal(request.postDataJSON().expected,'');assert.equal(request.postDataJSON().inspection_id,'inspection-job');return route.fulfill({json:{id:'baseline-fixture'}});}
  if(url.pathname.endsWith('/comparison'))return route.fulfill({json:{state:'compared',previous_created:Date.now()/1000-3600,note:'Observed changes, not a malware verdict.',changes:[{path:'/etc/cron.d/review-me',kind:'added'}]}});
  if(url.pathname.endsWith('/evidence-copies'))return route.fulfill({json:{items:[{id:'copy-fixture',state:copyState,created:Date.now()/1000,snapshot:{path:'/tmp/security-fixture',sha256:'b'.repeat(64)},snapshot_digest:'e'.repeat(64)}],more:false}});
  if(url.pathname.endsWith('/evidence-copies/copy-fixture/execute')){assert.equal(request.postDataJSON().confirmation,'PRESERVE');assert.equal(request.postDataJSON().snapshot_digest,'e'.repeat(64));copyState='preserved';writes.push(url.pathname);return route.fulfill({json:{job_id:'copy-job'}});}
  if(url.pathname.endsWith('/evidence-copies/copy-fixture/acquire')){assert.equal(request.postDataJSON().confirmation,'ACQUIRE');assert.equal(request.postDataJSON().snapshot_digest,'e'.repeat(64));writes.push(url.pathname);return route.fulfill({json:{job_id:'acquire-job'}});}
  if(url.pathname.endsWith('/response-monitor')){if(request.method()==='PUT'){writes.push(url.pathname);const body=request.postDataJSON();assert.equal(body.enabled,true);assert.equal(body.interval_minutes,5);assert.equal(body.pause_on_problem,true);responsePolicy={...body,revision:'policy-version'};return route.fulfill({json:responsePolicy});}return route.fulfill({json:{policy:responsePolicy,watched:1,problem_count:0,overdue_count:0,rotation_minutes:responsePolicy.interval_minutes,scope_limited:false,pending:null}});}
  if(url.pathname.endsWith('/quarantines/response-fixture/watch')){const body=request.postDataJSON();assert.equal(body.enabled,false);assert.equal(body.plan_digest,'f'.repeat(64));watchEnabled=false;writes.push(url.pathname);return route.fulfill({json:{enabled:false,revision:'watch-version'}});}
  if(url.pathname===prefix+'/repair-preparations')return route.fulfill({json:{items:repairQueued?[{id:'repair-fixture',report_digest:'9'.repeat(64),stage_id:stagingCreated?'stage-fixture':null,state:'ready',path:'/srv/security-fixture',bundle_id:'vendor-fixture',actor:'admin',finished:Date.now()/1000,report:{scope_current:true,manifest:{entries:[{path:'/srv/security-fixture',sha256:'b'.repeat(64),size:10}]},read_only:true,publication:'not_implemented',authentication:{artifact_sha256:'b'.repeat(64),signers:['publisher-fixture']},target:{replacement_mode:420,gaps:[],facts:{retained_verified:true,destination_empty:true,package_matches:true,owner_matches:true}}}}]:[],more:false}});
  if(url.pathname===prefix+'/repair-preparations/repair-fixture/stage'){const body=request.postDataJSON();assert.equal(body.confirmation,'STAGE');assert.equal(body.report_digest,'9'.repeat(64));stagingCreated=true;writes.push(url.pathname);return route.fulfill({json:{stage_id:'stage-fixture',job_id:'stage-job',publication:'not_authorized'}});}
  if(url.pathname===prefix+'/repair-stages')return route.fulfill({json:{items:stagingCreated?[{id:'stage-fixture',state:'staged',actor:'admin',reason:'Reviewed private staging.',created:Date.now()/1000,expires:Date.now()/1000+300,observed:Date.now()/1000,plan:{manifest:{entries:[{path:'/srv/security-fixture',size:10}]}},report:{scope_current:true,trust_current:true,target:{received:10,facts:{payload_verified:true}}}}]:[],more:false}});
  if(url.pathname===prefix+'/repair-stages/stage-fixture/status'){writes.push(url.pathname);return route.fulfill({json:{job_id:'stage-status-job'}});}
  if(url.pathname===prefix+'/repair-stages/stage-fixture/history')return route.fulfill({json:{items:[{kind:'approved',actor:'admin',report:{reason:'Reviewed private staging.'}},{kind:'observed_staged',actor:'admin'}],more:false}});
  if(url.pathname.endsWith('/quarantines/response-fixture/repair-preparations')){assert.deepEqual(request.postDataJSON(),{bundle_id:'vendor-fixture',plan_digest:'f'.repeat(64)});repairQueued=true;writes.push(url.pathname);return route.fulfill({json:{job_id:'repair-job',read_only:true,publication:'not_implemented'}});}
  if(url.pathname.endsWith('/process-responses'))return route.fulfill({json:{items:[{id:'process-response-fixture',state:processState,hold:processHold,created:Date.now()/1000,observed:Date.now()/1000,plan:{process:{pid:41,start_ticks:100,pid_namespace:123,proc_device:7,proc_inode:8}},plan_digest:'c'.repeat(64),receipt_digest:'d'.repeat(64),receipt:{resume_ready:processState==='suspended',resume_attempted:processState==='resumed'}}],more:false}});
  if(url.pathname.endsWith('/process-responses/process-response-fixture/actions/suspend')){assert.equal(request.postDataJSON().confirmation,'SUSPEND');assert.equal(request.postDataJSON().plan_digest,'c'.repeat(64));processState='suspended';processHold=true;writes.push(url.pathname);return route.fulfill({json:{job_id:'suspend-job'}});}
  if(url.pathname.endsWith('/process-responses/process-response-fixture/actions/resume')){assert.equal(request.postDataJSON().confirmation,'RESUME');assert.equal(request.postDataJSON().receipt_digest,'d'.repeat(64));processState='resumed';processHold=false;writes.push(url.pathname);return route.fulfill({json:{job_id:'resume-job'}});}
  if(url.pathname.endsWith('/process-responses/process-response-fixture/history'))return route.fulfill({json:{events:[{kind:'suspend_approved',actor:'admin'}],approvals:[{action:'suspend',actor:'admin'}],more:false}});
  if(url.pathname.endsWith('/quarantines/response-fixture/process-preparations')){assert.deepEqual(request.postDataJSON(),{observation_id:'process-job',pid:41,plan_digest:'f'.repeat(64)});writes.push(url.pathname);return route.fulfill({json:{job_id:'process-prepare-job'}});}
  if(url.pathname.endsWith('/quarantines/response-fixture/processes')){
   if(request.method()==='POST'){assert.deepEqual(request.postDataJSON(),{plan_digest:'f'.repeat(64)});writes.push(url.pathname);return route.fulfill({json:{job_id:'process-job'}});}
   return route.fulfill({json:{items:[{id:'process-job',state:'references_found',actor:'admin',created:Date.now()/1000,report:{scope_current:true,observation:{processes_examined:12,entries_examined:80,matches:[{pid:41,start_ticks:100,references:{descriptor:1,executable:1}}],gaps:{memory_map_unavailable:2}}}}],more:false}});
  }
  if(url.pathname.endsWith('/quarantines/response-fixture/checks'))return route.fulfill({json:{items:[{state:'verified',report:{facts:{held_verified:true}}}],more:false}});
  if(url.pathname.endsWith('/quarantines'))return route.fulfill({json:{items:[{id:'response-fixture',state:responseState,hold:responseHold,created:Date.now()/1000,observed:Date.now()/1000,plan:{file:{path:'/srv/security-fixture'}},plan_digest:'f'.repeat(64),receipt_digest:'a'.repeat(64),receipt:{restore_ready:responseState==='quarantined',restore_attempted:responseState==='restored'},monitor:{watch:{enabled:watchEnabled,revision:watchEnabled?'':'watch-version'},eligible:responseState==='quarantined',last_check:{state:'verified',created:Date.now()/1000}}}],more:false}});
  if(url.pathname.endsWith('/quarantines/response-fixture/history'))return route.fulfill({json:{events:[{kind:'quarantine_approved',actor:'admin'}],approvals:[{action:'quarantine',actor:'admin'}],more:false}});
  if(url.pathname.endsWith('/quarantines/response-fixture/execute')){assert.equal(request.postDataJSON().confirmation,'QUARANTINE');assert.equal(request.postDataJSON().plan_digest,'f'.repeat(64));responseState='quarantined';responseHold=true;writes.push(url.pathname);return route.fulfill({json:{job_id:'quarantine-job'}});}
  if(url.pathname.endsWith('/quarantines/response-fixture/restore')){assert.equal(request.postDataJSON().confirmation,'RESTORE');assert.equal(request.postDataJSON().receipt_digest,'a'.repeat(64));responseState='restored';responseHold=false;writes.push(url.pathname);return route.fulfill({json:{job_id:'restore-job'}});}
  if(url.pathname.endsWith('/quarantines/response-fixture/release')){assert.equal(request.postDataJSON().confirmation,'KEEP QUARANTINED');responseHold=false;writes.push(url.pathname);return route.fulfill({json:{state:'quarantined',server_changes_paused:false}});}
  if(url.pathname.endsWith('/evidence-archives'))return route.fulfill({json:{items:[{id:'archive-fixture',state:'verified',created:Date.now()/1000,snapshot:{path:'/tmp/security-fixture',sha256:'b'.repeat(64)},actor:'admin',reason:'Retain independent evidence.'}],more:false}});
  if(url.pathname.endsWith('/evidence-archives/archive-fixture/history'))return route.fulfill({json:{items:[{state:'approved',actor:'admin'},{state:'verified',actor:'admin'}],more:false}});
  if(url.pathname.endsWith('/yara')){assert.deepEqual(request.postDataJSON(),{bundle_id:'rules-fixture',paths:['/tmp']});writes.push(url.pathname);return route.fulfill({json:{job_id:'yara-job'}});}
  if(url.pathname.endsWith('/vendor-inspections')){assert.deepEqual(request.postDataJSON(),{bundle_id:'vendor-fixture'});writes.push(url.pathname);return route.fulfill({json:{job_id:'vendor-job'}});}
  if(url.pathname.endsWith('/inspections')){
   if(request.method()==='POST'){writes.push(url.pathname);assert.deepEqual(request.postDataJSON(),{packages:['openssh-server'],persistence:true,custom_paths:['/srv/myapp/config.json']});return route.fulfill({json:{job_id:'inspection-job'}});}
   return route.fulfill({json:{items:[{id:'inspection-job',created:Date.now()/1000,report:{state:'collected',packages:[{package:'openssh-server',state:'differences',installed_identity:'installed 1',gaps:[],findings:[{path:'/etc/ssh/sshd_config',status:'metadata_or_content_changed',checks:'??5??????',configuration_file:true}]}],persistence:{state:'collected',entries:[{path:'/etc/systemd/system/example.service',kind:'regular',sha256:'a'.repeat(64)}]}}},{id:'rpm-vendor-job',created:Date.now()/1000,report:{state:'collected',trust_basis:'controller_authenticated_rpm_artifact',packages:[],persistence:null,vendor_verification:{state:'matches_artifact_bytes',package:'Patchy_test',version:'2:1.0-1',architecture:'x86_64',examined:1,findings:[],gaps:[]},vendor_authentication:{signature_key_ids:['0123456789abcdef']}}}],more:false}});
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
  await page.locator('#yara-scan-form [name=bundle_id]').fill('rules-fixture');
  await page.getByRole('button',{name:'Queue YARA scan',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('YARA scan queued'));
  assert.equal(writes.at(-1),prefix+'/yara');
  await page.getByRole('button',{name:'Prepare evidence copy',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Evidence preparation queued'));
  assert.equal(writes.at(-1),prefix+'/incidents/incident-fixture/preservation');
  const beforePreserve=writes.length;await page.getByRole('button',{name:'Review preservation approval',exact:true}).click();assert.equal(writes.length,beforePreserve);
  await page.locator('#copy-approval [name=reason]').fill('Preserve this fixture for investigation.');
  await page.locator('#copy-approval [name=confirmation]').fill('PRESERVE');
  await page.getByRole('button',{name:'Execute approved evidence copy',exact:true}).click();
  await page.locator('#modal').waitFor({state:'hidden'});assert.equal(writes.at(-1),prefix+'/evidence-copies/copy-fixture/execute');
  const beforeAcquire=writes.length;await page.getByRole('button',{name:'Review controller acquisition',exact:true}).click();assert.equal(writes.length,beforeAcquire);
  await page.locator('#archive-approval [name=reason]').fill('Retain independent evidence for investigation.');
  await page.locator('#archive-approval [name=confirmation]').fill('ACQUIRE');
  await page.getByRole('button',{name:'Acquire evidence to controller',exact:true}).click();
  await page.locator('#modal').waitFor({state:'hidden'});assert.equal(writes.at(-1),prefix+'/evidence-copies/copy-fixture/acquire');
  await page.getByRole('button',{name:'Verify controller copy',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Controller evidence verification queued'));
  assert.equal(writes.at(-1),prefix+'/evidence-archives/archive-fixture/status');
  await page.getByRole('button',{name:'Acquisition custody history',exact:true}).click();
  await page.locator('#archive-history').filter({hasText:'verified'}).waitFor();await page.locator('#close-modal').click();
  await page.getByRole('button',{name:'Prepare file quarantine',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Read-only quarantine preparation queued'));
  assert.equal(writes.at(-1),prefix+'/evidence-archives/archive-fixture/quarantine');
  await page.locator('#response-monitor-policy [name=enabled]').check();
  await page.locator('#response-monitor-policy [name=interval_minutes]').fill('5');
  await page.locator('#response-monitor-policy [name=pause_on_problem]').check();
  await page.getByRole('button',{name:'Save response monitoring',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Response monitoring saved'));
  assert.equal(writes.at(-1),prefix+'/response-monitor');
  const beforeQuarantine=writes.length;await page.getByRole('button',{name:'Review quarantine approval',exact:true}).click();assert.equal(writes.length,beforeQuarantine);
  await page.locator('#response-approval [name=reason]').fill('Reviewed this file and the affected service.');
  await page.locator('#response-approval [name=confirmation]').fill('QUARANTINE');
  await page.getByRole('button',{name:'Quarantine approved file',exact:true}).click();
  await page.locator('#modal').waitFor({state:'hidden'});assert.equal(writes.at(-1),prefix+'/quarantines/response-fixture/execute');
  await page.getByRole('button',{name:'File response history',exact:true}).click();
  await page.locator('#response-history').filter({hasText:'quarantine_approved'}).waitFor();await page.locator('#close-modal').click();
  await page.getByRole('button',{name:'Verify file response',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Read-only file response verification queued'));
  await page.getByRole('button',{name:'Inspect process references',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Read-only process reference inspection queued'));
  assert.equal(writes.at(-1),prefix+'/quarantines/response-fixture/processes');
  await page.getByRole('button',{name:'Process reference history',exact:true}).click();
  await page.locator('#response-process-history').filter({hasText:'PID 41'}).waitFor();
  await page.getByText('Inspection gaps: memory map unavailable: 2',{exact:true}).waitFor();
  assert.equal(await page.locator('#response-process-next').isDisabled(),true);
  for(const width of [320,390,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'Process observations must fit the viewport');}
  await page.getByRole('button',{name:'Prepare process suspension',exact:true}).click();
  await page.locator('#modal').waitFor({state:'hidden'});assert.equal(writes.at(-1),prefix+'/quarantines/response-fixture/process-preparations');
  const beforeSuspend=writes.length;await page.getByRole('button',{name:'Review process suspension',exact:true}).click();assert.equal(writes.length,beforeSuspend);
  await page.locator('#process-approval [name=reason]').fill('Reviewed exact process identity and service impact.');
  await page.locator('#process-approval [name=confirmation]').fill('SUSPEND');
  await page.getByRole('button',{name:'Suspend approved process',exact:true}).click();
  await page.locator('#modal').waitFor({state:'hidden'});assert.equal(writes.at(-1),prefix+'/process-responses/process-response-fixture/actions/suspend');
  await page.getByRole('button',{name:'Verify process response',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Read-only process response verification queued'));
  await page.getByRole('button',{name:'Process response history',exact:true}).click();
  await page.locator('#process-response-history').filter({hasText:'suspend_approved'}).waitFor();
  for(const width of [320,390,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'Process response history must fit the viewport');}
  await page.locator('#close-modal').click();
  const beforeResume=writes.length;await page.getByRole('button',{name:'Review process recovery',exact:true}).click();assert.equal(writes.length,beforeResume);
  await page.locator('#process-approval [name=reason]').fill('Reviewed recovery and the risk of resuming the process.');
  await page.locator('#process-approval [name=confirmation]').fill('RESUME');
  await page.getByRole('button',{name:'Resume approved process',exact:true}).click();
  await page.locator('#modal').waitFor({state:'hidden'});assert.equal(writes.at(-1),prefix+'/process-responses/process-response-fixture/actions/resume');
  const beforeRepair=writes.length;await page.getByRole('button',{name:'Prepare trusted replacement',exact:true}).click();assert.equal(writes.length,beforeRepair);
  await page.locator('#trusted-repair-request [name=bundle_id]').fill('vendor-fixture');
  await page.getByRole('button',{name:'Queue trusted replacement preparation',exact:true}).click();
  await page.locator('#modal').waitFor({state:'hidden'});assert.equal(writes.at(-1),prefix+'/quarantines/response-fixture/repair-preparations');
  await page.getByRole('button',{name:'Refresh repair preparations',exact:true}).click();
  await page.getByText('Readiness gaps: None recorded',{exact:true}).waitFor();
  await page.getByText('Review replacement authentication and readiness receipt',{exact:true}).click();
  await page.locator('#repair-preparation-panel pre').filter({hasText:'publisher-fixture'}).waitFor();
  const beforeStaging=writes.length;
  await page.getByRole('button',{name:'Review replacement staging',exact:true}).click();assert.equal(writes.length,beforeStaging);
  await page.locator('#replacement-stage-approval [name=reason]').fill('Reviewed private staging; publication needs a separate approval.');
  await page.locator('#replacement-stage-approval [name=confirmation]').fill('STAGE');
  await page.getByRole('button',{name:'Stage approved replacement',exact:true}).click();
  await page.locator('#modal').waitFor({state:'hidden'});assert.equal(writes.at(-1),prefix+'/repair-preparations/repair-fixture/stage');
  await page.getByRole('button',{name:'Refresh replacement staging',exact:true}).click();
  await page.getByText('Retained transfer progress: 10 bytes · Payload verified: Yes',{exact:true}).waitFor();
  await page.getByRole('button',{name:'Verify staged replacement',exact:true}).click();
  await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Read-only staging verification queued'));
  assert.equal(writes.at(-1),prefix+'/repair-stages/stage-fixture/status');
  await page.getByRole('button',{name:'Replacement staging history',exact:true}).click();
  await page.locator('#repair-stage-history').filter({hasText:'observed_staged'}).waitFor();
  for(const width of [320,390,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'Replacement staging history must fit the viewport');}
  await page.locator('#close-modal').click();
  assert.equal(await page.getByRole('button',{name:/Publish replacement/i}).count(),0,'Staging must not expose live-file publication');
  for(const width of [320,390,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'Trusted replacement preparation must fit the viewport');}
  await page.getByRole('button',{name:'Review server pause',exact:true}).click();
  await page.locator('#response-release [name=reason]').fill('Verified service health and accepted quarantine impact.');
  await page.locator('#response-release [name=typed]').fill('KEEP QUARANTINED');
  await page.getByRole('button',{name:'Release reviewed server pause',exact:true}).click();
  await page.locator('#modal').waitFor({state:'hidden'});assert.equal(writes.at(-1),prefix+'/quarantines/response-fixture/release');
  const beforeWatch=writes.length;await page.getByRole('button',{name:'Review automatic watch',exact:true}).click();assert.equal(writes.length,beforeWatch);
  await page.locator('#response-watch-review [name=enabled]').uncheck();
  await page.locator('#response-watch-review [name=reason]').fill('Reviewed and retired this retained response watch.');
  await page.getByRole('button',{name:'Save watch review',exact:true}).click();
  await page.locator('#modal').waitFor({state:'hidden'});assert.equal(writes.at(-1),prefix+'/quarantines/response-fixture/watch');
  await page.getByRole('button',{name:'Verification check history',exact:true}).click();
  await page.locator('#response-check-history').filter({hasText:'held_verified'}).waitFor();await page.locator('#close-modal').click();
  const beforeRestore=writes.length;await page.getByRole('button',{name:'Review restoration approval',exact:true}).click();assert.equal(writes.length,beforeRestore);
  await page.locator('#response-approval [name=reason]').fill('Reviewed the original and approved recovery.');
  await page.locator('#response-approval [name=confirmation]').fill('RESTORE');
  await page.getByRole('button',{name:'Restore approved original file',exact:true}).click();
  await page.locator('#modal').waitFor({state:'hidden'});assert.equal(writes.at(-1),prefix+'/quarantines/response-fixture/restore');
  for(const width of [320,390,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'File response view must fit the viewport');}
  await page.goto(new URL('/#servers/'+host.id+'/integrity',page.url()).href);
  await page.locator('#security-inspection-form').waitFor();
  await page.getByText('Trust basis: local package database',{exact:true}).waitFor();
  await page.getByText('Trust basis: controller-authenticated RPM artifact',{exact:true}).waitFor();
  await page.locator('#inspection-reports pre').filter({hasText:'Patchy_test'}).first().waitFor();
  await page.locator('#security-inspection-form [name=packages]').fill('openssh-server');
  await page.locator('#security-inspection-form [name=custom_paths]').fill('/srv/myapp/config.json');
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

  await page.locator('#persistence-monitor-form [name=enabled]').check();await page.locator('#persistence-monitor-form [name=custom_paths]').fill('/srv/myapp/config.json');
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
