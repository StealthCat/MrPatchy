const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const now=Date.now()/1000,alpha='workspace-alpha',beta='workspace-beta';let role='admin',lateRelease,lateStarted,recoveryCount=0;
 const hosts=[{id:alpha,name:'Atlas · Production',address:'192.0.2.41',port:22,architecture:'amd64',package_manager:'apt',state:'online',integrity:[],last_seen:now,last_repo:now,fingerprint:'SHA256:fixture',error:'',repo_error:''},{id:beta,name:'Borealis · Build',address:'192.0.2.42',port:22,architecture:'x86_64',package_manager:'rpm',state:'online',integrity:[],last_seen:now,last_repo:now,fingerprint:'SHA256:fixture',error:'',repo_error:''}];
 const scope=id=>id===alpha?'Atlas':'Borealis';
 const packageRow=id=>({id:id+':openssl',name:scope(id)+'-openssl:amd64',installed:'3.0.1',candidate:'3.0.2',priority:'high',priority_manual:false,held:false,dpkg_state:'install ok installed',due:now+86400,installation:{state:'scheduled',at:now+3600,reason:'Next approved maintenance window',schedule:'Nightly patching'},assessment:{state:'complete',score:75,explanation:'Security maintenance',confidence:'low',model:'fixture',completed:now}});
 const requests=[],writes=[];
 const handler=async route=>{
  const request=route.request(),url=new URL(request.url()),p=url.pathname;requests.push(url.pathname+url.search);
  if(p==='/api/identity'){const response=await route.fetch();return route.fulfill({response,json:{...await response.json(),role}});}
  if(p==='/api/hosts')return route.fulfill({json:hosts});
  const id=hosts.find(h=>p.startsWith('/api/hosts/'+h.id+'/')||p.startsWith('/api/operations/'+h.id+'/'))?.id;
  if(id&&p.endsWith('/connection')){
   if(request.method()==='PUT'){writes.push({path:p,body:request.postDataJSON()});return route.fulfill({json:request.postDataJSON().connection});}
   return route.fulfill({json:{address:hosts.find(h=>h.id===id).address,port:22,transport:'direct',project:'',zone:'',instance:''}});
  }
  if(id&&p.endsWith('/connection/test'))return route.fulfill({json:{ok:true,message:'Pinned SSH identity and bridge response verified.'}});
  if(request.method()!=='GET'&&(id||p.startsWith('/api/investigations/'))){writes.push({path:p,body:request.postDataJSON()});return route.fulfill({json:{ok:true,detail:'Queued'}});}
  if(id&&p.endsWith('/summary')){
   if(id===alpha&&lateStarted){const started=lateStarted;lateStarted=null;started();await new Promise(resolve=>lateRelease=resolve);}
   return route.fulfill({json:{host:hosts.find(h=>h.id===id),system:{os:'PRETTY_NAME="Debian GNU/Linux 13"',architecture:'amd64',package_manager:id===alpha?'apt':'rpm',machine_id:scope(id)+'-machine',collected:now},collector:{collected:now,hashed_at:now,processes:143,managed_files:8},counts:{packages:1432,updates:1,held:2,overdue:0,unapproved:1,pending_ai:1,investigations:1},jobs:{queued:1,recovery_required:recoveryCount},last_patch:{state:'complete',created:now-86400}}});
  }
  if(id&&p.endsWith('/security/ai-policy'))return route.fulfill({json:{paused:false,state:'eligible',global_enabled:true,revision:'',reason:''}});
  if(id&&p.endsWith('/packages'))return route.fulfill({json:[packageRow(id)]});
  if(id&&p.endsWith('/patch-policy'))return route.fulfill({json:{reboot:false,rollback:false}});
  if(id&&p.endsWith('/patching'))return route.fulfill({json:{events:[{title:scope(id)+' nightly maintenance',start:now+3600,end:now+7200,trigger:'regular',states:{},timezone:'America/New_York'}],windows:[{days:[0,1,2,3,4],start:120,end:240}],recovery:{reboot:false,rollback:false},schedules:[{id:'nightly',name:scope(id)+' nightly maintenance',enabled:true,frequency:'daily',minute:120,timezone:'America/New_York',window_minutes:60,priorities:['high','critical'],high:{enabled:true,after_minutes:60},critical:{enabled:true,after_minutes:10}}]}});
  if(id&&p.endsWith('/window'))return route.fulfill({json:{windows:[]}});
  if(id&&p.endsWith('/snapshot')&&!p.includes('/history/'))return route.fulfill({json:{inventory:{machine_id:scope(id)+'-current'},telemetry:{collected:now},baseline:{fixture:'hash'}}});
  if(id&&p.endsWith('/repositories'))return route.fulfill({json:{package_manager:'apt',last_checked:now,error:'',health:[],keys:[],files:{'/etc/apt/sources.list':'# '+scope(id)+' sources'}}});
  if(id&&p.endsWith('/history'))return route.fulfill({json:[{id:'snapshot',created:now,observed:now}]});
  if(id&&p.endsWith('/history/snapshot'))return route.fulfill({json:{id:'snapshot',host_id:id,inventory:{host:scope(id)}}});
  if(p==='/api/investigations')return route.fulfill({json:[{id:'investigation-'+url.searchParams.get('host_id'),host_id:url.searchParams.get('host_id'),evidence:{executable:'/'+scope(url.searchParams.get('host_id'))+'/service',uid:1000,sha256:'fixture'},last_seen:now,verdict:'pending',approved:false,analysis:'Awaiting '+scope(url.searchParams.get('host_id'))+' review'}]});
  if(p==='/api/jobs')return route.fulfill({json:[{id:'job-'+url.searchParams.get('host_id'),host_id:url.searchParams.get('host_id'),state:'complete',action:'patch',created:now-86400,output:scope(url.searchParams.get('host_id'))+' patch completed'}]});
  if(p==='/api/ai/runs')return route.fulfill({json:{items:[{id:'batch-fixture',purpose:'update_scoring',state:'complete',started:now,model:'gpt-6-luna',calls:1,message:scope(url.searchParams.get('host_id'))+' update scoring completed',shared_batch:true,cost:{status:'estimated',estimated_usd:'0.000123',priced_calls:1,total_calls:1}}],more:false}});
  if(p==='/api/package-history')return route.fulfill({json:{items:[{id:1,host_id:url.searchParams.get('host_id'),name:scope(url.searchParams.get('host_id'))+'-openssl',action:'version_changed',before:['3.0.1'],after:['3.0.2'],observed:now,recorded:now,source:'inventory',state_before:'installed',state_after:'installed'}],more:false}});
  return route.fallback();
 };
 await page.route('**/api/**',handler);
 const tabs=page.locator('.server-tabs');
 const open=async(name)=>{const link=tabs.getByRole('link',{name,exact:true});if(!await link.isVisible())await tabs.locator('summary').click();await link.click();await page.locator('#server-tab-content>h2').filter({hasText:name}).waitFor();};
 try{
  await page.locator('[data-nav=servers]').click();await page.locator('.server-name').filter({hasText:'Atlas'}).click();
  await page.getByText('Atlas-machine',{exact:true}).waitFor();assert.equal(new URL(page.url()).hash,'#servers/'+alpha+'/overview');
  assert.equal(await page.locator('[data-nav=servers]').getAttribute('aria-current'),'page');

  const originalName=hosts[0].name,originalArchitecture=hosts[0].architecture;
  hosts[0].name='Atlas <img src=x onerror="window.__badServerHeader=true">';
  hosts[0].architecture='<svg onload="window.__badServerHeader=true">';
  await page.locator('#refresh-page').click();
  await page.getByRole('heading',{name:hosts[0].name,exact:true}).waitFor();
  assert.equal(await page.locator('#content img[src=x],#content svg[onload]').count(),0);
  assert.equal(await page.evaluate(()=>window.__badServerHeader),undefined);
  hosts[0].name=originalName;hosts[0].architecture=originalArchitecture;
  await page.locator('#refresh-page').click();await page.getByRole('heading',{name:originalName,exact:true}).waitFor();
  const originalSeen=hosts[0].last_seen;hosts[0].last_seen=now+3600;
  await page.locator('#refresh-page').click();await page.getByText('Server contact is stale, missing or future-dated',{exact:true}).waitFor();
  hosts[0].last_seen=originalSeen;await page.locator('#refresh-page').click();await page.getByText('Recent server contact',{exact:true}).waitFor();
  await capture('server-overview');
  await page.getByRole('link',{name:'System & collector',exact:true}).click();
  await page.getByRole('heading',{name:'Collector & freshness',exact:true}).waitFor();
  assert.match(page.url(),/overview\/system$/);
  assert.equal(await page.getByRole('heading',{name:'At a glance',exact:true}).count(),0);
  await page.locator('#server-workspace-select').selectOption(beta);await page.getByText('Borealis-machine',{exact:true}).waitFor();
  assert.match(page.url(),/overview\/system$/);
  await page.goBack();await page.getByText('Atlas-machine',{exact:true}).waitFor();
  await page.reload();await page.getByRole('heading',{name:'Collector & freshness',exact:true}).waitFor();
  await page.getByRole('link',{name:'Patching status',exact:true}).click();
  await page.getByText('Most recently submitted patch:',{exact:false}).waitFor();
  recoveryCount=1;await page.locator('#refresh-page').click();await page.getByRole('alert').filter({hasText:'Recovery is required'}).waitFor();
  recoveryCount=0;await page.locator('#refresh-page').click();await page.getByRole('alert').filter({hasText:'Recovery is required'}).waitFor({state:'hidden'});
  assert.equal(await page.getByRole('heading',{name:'Collector & freshness',exact:true}).count(),0);
  await page.getByRole('link',{name:'Summary',exact:true}).click();await page.getByRole('heading',{name:'At a glance',exact:true}).waitFor();
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   for(const [label,key] of [['Summary','summary'],['System & collector','system'],['Patching status','patching']]){
    await page.getByRole('link',{name:label,exact:true}).click();
    await page.locator('[data-overview-section="'+key+'"]').waitFor();
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
    await capture('server-overview-'+key+'-'+width);
   }
  }
  await page.setViewportSize({width:1440,height:1000});
  await page.getByRole('link',{name:'Summary',exact:true}).click();await page.locator('[data-overview-section=summary]').waitFor();

  assert.equal(await tabs.locator(':scope > a').count(),4);
  const summary=tabs.locator('summary');
  await summary.focus();await page.keyboard.press('Enter');
  assert.equal(await tabs.locator('.section-menu').evaluate(e=>e.open),true);
  assert.equal(await tabs.locator('.section-menu-groups section').count(),3);
  await page.keyboard.press('Escape');assert.equal(await summary.evaluate(e=>e===document.activeElement),true);
  assert.equal(await tabs.locator('.section-menu').evaluate(e=>e.open),false);
  await summary.click();await page.locator('#breadcrumb').click();
  assert.equal(await tabs.locator('.section-menu').evaluate(e=>e.open),false);

  await open('Packages');await page.locator('#server-tab-body').getByText('Atlas-openssl:amd64',{exact:true}).waitFor();
  assert.equal(await page.locator('#server-select').count(),0);
  await page.locator('#select-all-updates').click();assert.equal(await page.locator('.pkg-check:checked').count(),1);
  await page.locator('#patch-selected').click();await page.locator('#confirm-patch').waitFor();
  assert.equal(writes.length,0,'Selecting packages must still require reviewed confirmation');await page.locator('#close-modal').click();
  await page.locator('#server-workspace-select').selectOption(beta);await page.getByText('Borealis-openssl:amd64',{exact:true}).waitFor();
  assert.equal(await page.locator('#server-tab-body').getByText('Atlas-openssl:amd64',{exact:true}).count(),0);
  await page.goBack();await page.locator('#server-tab-body').getByText('Atlas-openssl:amd64',{exact:true}).waitFor();
  await page.reload();await page.locator('#server-tab-body').getByText('Atlas-openssl:amd64',{exact:true}).waitFor();
  await page.locator('#package-search').fill('Atlas');await page.locator('#updates-only').check();
  await open('History');await page.locator('#package-history-table').waitFor();
  await page.goBack();await page.locator('#package-search').waitFor();
  assert.equal(await page.locator('#package-search').inputValue(),'Atlas');assert.equal(await page.locator('#updates-only').isChecked(),true);
  assert.equal(await page.locator('.pkg-check:checked').count(),0,'Returning to a view must not restore installation selections');
  await page.locator('#server-workspace-select').selectOption(beta);await page.locator('#server-tab-body').getByText('Borealis-openssl:amd64',{exact:true}).waitFor();
  assert.equal(await page.locator('#package-search').inputValue(),'');
  await page.locator('#server-workspace-select').selectOption(alpha);await page.locator('#server-tab-body').getByText('Atlas-openssl:amd64',{exact:true}).waitFor();
  assert.equal(await page.locator('#package-search').inputValue(),'Atlas');
  await page.locator('#refresh-page').click();await page.locator('#server-tab-body').getByText('Atlas-openssl:amd64',{exact:true}).waitFor();
  assert.equal(await page.locator('#package-search').inputValue(),'Atlas');assert.equal(await page.locator('#updates-only').isChecked(),true);
  await page.locator('#package-search').fill('');await page.locator('#updates-only').uncheck();
  await open('Patching timeline');await page.getByText('Atlas patch completed',{exact:true}).waitFor({state:'attached'});
  await page.getByText('Atlas nightly maintenance',{exact:false}).first().waitFor();
  assert.equal(requests.filter(p=>p==='/api/audit').length,0,'Server timeline must not fetch fleet audit records');
  await capture('server-patching');
  await open('Investigations');await page.getByText('Awaiting Atlas review',{exact:true}).waitFor();
  await page.getByRole('button',{name:'Review & approve',exact:true}).click();await page.locator('#confirm-trust').click();
  await page.getByText('Awaiting Atlas review',{exact:true}).waitFor();assert.equal(new URL(page.url()).hash,'#servers/'+alpha+'/investigations');
  assert.equal(writes.at(-1).path,'/api/investigations/investigation-'+alpha);
  await open('AI activity');await page.getByText('Atlas update scoring completed',{exact:true}).waitFor();
  await page.getByText('Shared batch',{exact:false}).first().waitFor();
  await open('History');await page.locator('#package-history-table tbody tr').filter({hasText:'Atlas-openssl'}).waitFor();assert.equal(await page.locator('#history-host').count(),0);
  await page.getByRole('link',{name:'Inventory revisions',exact:true}).click();await page.getByRole('link',{name:'Open snapshot',exact:false}).click();await page.locator('.history-detail pre').filter({hasText:'Atlas'}).waitFor();
  await page.locator('#server-workspace-select').selectOption(beta);await page.locator('.snapshot-list').waitFor();assert.equal(new URL(page.url()).hash,'#servers/'+beta+'/history/inventory');
  await page.locator('#server-workspace-select').selectOption(alpha);await page.getByRole('heading',{name:'Atlas · Production',exact:true}).waitFor();await page.locator('.snapshot-list').waitFor();
  await open('Repositories');await page.getByText('/etc/apt/sources.list',{exact:true}).waitFor();
  await open('Connection');await page.locator('#server-connection-form').waitFor();
  await page.locator('#server-connection-form [name=transport]').selectOption('gcp_iap');
  await page.locator('#server-connection-form [name=project]').fill('test-project');
  await page.locator('#server-connection-form [name=zone]').fill('us-central1-a');
  await page.locator('#server-connection-form [name=instance]').fill('test-vm');
  await page.getByRole('button',{name:'Save connection',exact:true}).click();
  await page.getByText('Connection saved. Test it below or wait for normal polling.',{exact:true}).waitFor();
  assert.equal(writes.at(-1).body.connection.transport,'gcp_iap');assert.equal(writes.at(-1).body.expected.transport,'direct');
  await page.getByRole('button',{name:'Test saved connection',exact:true}).click();
  await page.getByText('Pinned SSH identity and bridge response verified.',{exact:true}).waitFor();
  await capture('server-connection');
  await open('Maintenance');await page.locator('#server-recovery-form').waitFor();
  await page.locator('#server-recovery-form [name=reboot]').check();
  const formBeforeRefresh=await page.locator('#server-recovery-form').elementHandle();
  await page.waitForTimeout(31000);
  assert.equal(await formBeforeRefresh.evaluate(form=>form.isConnected),true,'Automatic fleet refresh must not reset editable server tabs');
  assert.equal(await page.locator('#server-recovery-form [name=reboot]').isChecked(),true);
  await page.getByRole('button',{name:'Save recovery policy',exact:true}).click();
  await page.getByText('Saved for Atlas · Production.',{exact:true}).waitFor();assert.equal(writes.at(-1).path,'/api/operations/'+alpha+'/recovery');
  await page.locator('#server-snapshot-load').click();await page.locator('#server-snapshot summary').first().waitFor();
  await page.locator('#server-snapshot summary').first().click();await page.locator('#server-snapshot pre').filter({hasText:'Atlas-current'}).waitFor();
  for(const width of [320,390,768,1440]){
   await page.setViewportSize({width,height:1000});
   for(const name of ['Overview','Settings','Connection','Packages','Patching timeline','Investigations','AI activity','History','Repositories','Maintenance']){
    await open(name);const marker={'Overview':'.server-facts','Settings':'#server-tab-body [data-server-management]','Connection':'#server-connection-form','Packages':'.pkg-check','Patching timeline':'#server-calendar .server-timeline','Investigations':'.investigation','AI activity':'#ai-log-table tbody tr','History':'#package-history-table tbody tr','Repositories':'#source-files','Maintenance':'#server-recovery-form'}[name];await page.locator(marker).first().waitFor();
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,name+' overflows at '+width);
    assert.equal(await page.locator('#retry-server-tab').count(),0);
    if(name==='Overview'){await tabs.locator('summary').click();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('server-sections-'+width);await tabs.locator('summary').click();}
   }
  }
  // A slow response from one server must never replace another server's page.
  let started;const pending=new Promise(resolve=>started=resolve);lateStarted=started;
  await open('Overview');await pending;
  await page.locator('#server-workspace-select').selectOption(beta);await page.getByText('Borealis-machine',{exact:true}).waitFor();
  lateRelease();await page.waitForTimeout(100);assert.equal(await page.getByText('Atlas-machine',{exact:true}).count(),0);
  for(const nextRole of ['viewer','operator']){
   role=nextRole;await page.goto(new URL('/?server-role='+nextRole+'#servers/'+beta+'/overview',page.url()).href);await page.getByText('Borealis-machine',{exact:true}).waitFor();
   assert.equal(await tabs.getByRole('link',{name:'Settings',exact:true}).count(),0);
   assert.equal(await page.locator('[data-host-delete],[data-host-lifecycle]').count(),0);
   await page.evaluate(id=>location.hash='#servers/'+id+'/settings',beta);await page.getByRole('heading',{name:'Administrator access required',exact:true}).waitFor();
   assert.equal(await page.locator('[data-server-management]').count(),0);
   assert.equal(await tabs.getByRole('link',{name:'File integrity',exact:true}).count(),0);
   assert.equal(await tabs.getByRole('link',{name:'Connection',exact:true}).count(),0);
   assert.equal(await tabs.getByRole('link',{name:'Agent health',exact:true}).count(),0);
   assert.equal(await tabs.getByRole('link',{name:'Maintenance',exact:true}).count(),0);
   assert.equal(await tabs.getByRole('link',{name:'AI activity',exact:true}).count(),0);
   await open('Packages');await page.locator('.pkg-check').waitFor();assert.equal(await page.locator('.pkg-check').isDisabled(),nextRole==='viewer');
   await page.evaluate(id=>location.hash='#servers/'+id+'/maintenance',beta);await page.getByRole('heading',{name:'Administrator access required',exact:true}).waitFor();
   await page.locator('[data-nav=servers]').click();await page.locator('.server-directory-card').first().waitFor();
   assert.equal(await page.locator('[data-host-delete],[data-host-lifecycle]').count(),0);
   assert.equal(await page.getByRole('button',{name:'Inspect ↗',exact:true}).count(),2);
  }
  role='admin';await page.evaluate(()=>location.hash='#servers/missing/overview');await page.getByRole('heading',{name:'Server not found.',exact:true}).waitFor();
 }finally{lateRelease?.();await page.unroute('**/api/**',handler);await page.setViewportSize({width:1440,height:1000});}
};
