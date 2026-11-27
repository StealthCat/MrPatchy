const assert=require('assert/strict');
// Administrator features that previously had API endpoints only (#1684): each panel loads,
// saves through the existing endpoint with its revision, and reports refusals in place.
module.exports=async(page,capture)=>{
 const url=path=>new URL(path,page.url()).href;
 const csrf=async()=>(await (await page.request.get(url('/api/session'))).json()).csrf;
 const host=await page.evaluate(async()=>{let list=await(await fetch('/api/hosts')).json();if(list.length)return list[0].id;const session=await(await fetch('/api/session')).json();return(await(await fetch('/api/hosts',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':session.csrf},body:JSON.stringify({name:'admin-tools-host',address:'192.0.2.44'})})).json()).id;});

 // Saved fleet queries on the Servers page: create, run, edit, stale edit, delete.
 await page.goto(url('/#servers'));
 const queries=page.locator('#saved-fleet-queries');
 await queries.getByRole('heading',{name:'Saved queries'}).waitFor();
 await queries.getByRole('button',{name:'+ New saved query'}).click();
 const queryForm=page.locator('#fleet-query-form');
 await queryForm.locator('[name=name]').fill('UI overdue openssl');
 await queryForm.locator('[name=package]').fill('openssl');
 await queryForm.locator('[name=overdue_only]').check();
 await queryForm.getByRole('button',{name:'Create saved query'}).click();
 const row=queries.locator('tr',{hasText:'UI overdue openssl'});
 await row.waitFor();
 assert.match(await row.textContent(),/package contains “openssl” · overdue updates/);
 let stored=(await (await page.request.get(url('/api/fleet/queries'))).json()).find(q=>q.name==='UI overdue openssl');
 assert.deepEqual(stored.filter,{os:'',package:'openssl',state:'',enabled:null,updates_only:false,overdue_only:true});
 await row.getByRole('button',{name:'Run'}).click();
 await page.locator('#fleet-query-results').filter({hasText:'matching servers'}).waitFor();
 if(capture)await capture('saved-query-results',false);
 await page.locator('#close-modal').click();
 await row.getByRole('button',{name:'Edit'}).click();
 await queryForm.locator('[name=enabled]').selectOption('true');
 await queryForm.getByRole('button',{name:'Save changes'}).click();
 await queries.locator('tr',{hasText:'enabled only'}).waitFor();
 stored=(await (await page.request.get(url('/api/fleet/queries'))).json()).find(q=>q.id===stored.id);
 assert.equal(stored.version,2);assert.equal(stored.filter.enabled,true);
 // Another administrator edits the query while this dialog is open: the save is refused in place.
 await queries.locator('tr',{hasText:'UI overdue openssl'}).getByRole('button',{name:'Edit'}).click();
 const other=await page.request.put(url('/api/fleet/queries/'+stored.id),{headers:{'X-CSRF-Token':await csrf()},data:{name:'UI overdue openssl',filter:stored.filter,expected_version:2}});
 assert.equal(other.status(),200);
 await queryForm.getByRole('button',{name:'Save changes'}).click();
 await queryForm.locator('[role=status]').filter({hasText:'changed; reload'}).waitFor();
 await page.locator('#close-modal').click();
 await page.goto(url('/#servers'));
 await queries.locator('tr',{hasText:'UI overdue openssl'}).getByRole('button',{name:'Delete'}).click();
 await page.getByRole('button',{name:'Delete saved query'}).click();
 await queries.locator('tr',{hasText:'UI overdue openssl'}).waitFor({state:'detached'});

 // Change freezes on Patch schedules: add, save, and refuse a stale list.
 await page.goto(url('/#schedules'));
 const freezes=page.locator('#change-freezes');
 await freezes.locator('#freeze-form').waitFor();
 const local=offsetDays=>{const d=new Date(Date.now()+offsetDays*86400e3),p=n=>String(n).padStart(2,'0');return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;};
 await freezes.locator('[name=start]').fill(local(2));
 await freezes.locator('[name=end]').fill(local(1));
 await freezes.locator('[name=reason]').fill('Backwards freeze');
 await freezes.getByRole('button',{name:'Add to list'}).click();
 await freezes.locator('#freeze-status').filter({hasText:'must end after it starts'}).waitFor();
 await freezes.locator('[name=end]').fill(local(3));
 await freezes.locator('[name=reason]').fill('Quarter-end close');
 await freezes.getByRole('button',{name:'Add to list'}).click();
 await freezes.locator('#freeze-rows tr',{hasText:'Quarter-end close'}).waitFor();
 await freezes.getByRole('button',{name:'Save change freezes'}).click();
 await freezes.locator('#freeze-rows tr',{hasText:'admin'}).waitFor();
 let freezeView=await (await page.request.get(url('/api/operations/freezes'))).json();
 assert.equal(freezeView.freezes.length,1);assert.equal(freezeView.freezes[0].reason,'Quarter-end close');assert.equal(freezeView.blocked,false);
 if(capture)await capture('change-freezes');
 const changed=await page.request.put(url('/api/operations/freezes'),{headers:{'X-CSRF-Token':await csrf()},data:{freezes:[],expected_revision:freezeView.revision}});
 assert.equal(changed.status(),200);
 await freezes.locator('[data-freeze-remove]').first().click();
 await freezes.getByRole('button',{name:'Save change freezes'}).click();
 await freezes.locator('#freeze-status').filter({hasText:'reload it before editing'}).waitFor();

 // Application probes on the server Maintenance tab.
 await page.goto(url('/#servers/'+encodeURIComponent(host)+'/maintenance'));
 const probes=page.locator('#server-app-probes');
 await probes.getByRole('heading',{name:'Application probes'}).waitFor();
 await probes.getByRole('button',{name:'+ Add probe'}).click();
 const probe=probes.locator('[data-probe="0"]');
 await probe.locator('[name=name]').fill('web-health');
 await probe.locator('[name=port]').fill('8080');
 await probe.locator('[name=path]').fill('/healthz');
 await probe.locator('[name=reason]').fill('Storefront must answer after patching');
 await probes.getByRole('button',{name:'+ Add probe'}).click();
 const tcp=probes.locator('[data-probe="1"]');
 await tcp.locator('[name=kind]').selectOption('tcp');
 assert.equal(await tcp.locator('[name=path]').isVisible(),false,'TCP probes take no path');
 await tcp.locator('[name=name]').fill('db');await tcp.locator('[name=port]').fill('5432');await tcp.locator('[name=reason]').fill('Database listener');
 await tcp.locator('[name=required]').uncheck();
 await probes.getByRole('button',{name:'Save probes'}).click();
 await probes.locator('#probe-status').filter({hasText:'Probes saved.'}).waitFor();
 const savedProbes=await (await page.request.get(url('/api/operations/'+host+'/probes'))).json();
 assert.deepEqual(savedProbes.probes,[{name:'web-health',kind:'http',port:8080,timeout:5,required:true,reason:'Storefront must answer after patching',path:'/healthz',expect_status:200},{name:'db',kind:'tcp',port:5432,timeout:5,required:false,reason:'Database listener'}]);
 if(capture)await capture('application-probes');

 // Spool batch size on Agent health: success and an unconfirmed target are both reported.
 let spoolReply={status:200,json:{configured:true,version:1,batch_limit_bytes:131072}},spoolBody=null;
 await page.route('**/api/operations/*/spool',route=>{spoolBody=route.request().postDataJSON();return route.fulfill(spoolReply);});
 await page.goto(url('/#servers/'+encodeURIComponent(host)+'/agent'));
 const spool=page.locator('#server-spool-limit');
 await spool.locator('[name=kib]').waitFor();
 await spool.locator('[name=kib]').fill('128');
 await spool.getByRole('button',{name:'Apply to agent'}).click();
 await spool.locator('#spool-limit-status').filter({hasText:'confirmed a 128 KiB'}).waitFor();
 assert.deepEqual(spoolBody,{batch_limit_bytes:131072});
 spoolReply={status:502,json:{detail:'Target did not confirm the requested spool configuration. Check collector state before retrying.'}};
 await spool.getByRole('button',{name:'Apply to agent'}).click();
 await spool.locator('#spool-limit-status').filter({hasText:'did not confirm'}).waitFor();
 await page.unroute('**/api/operations/*/spool');

 // SSO identities on Users: list, unbind, and confirm a replacement after a conflict.
 let bindings=[{subject_digest:'0123456789abcdef',username:'admin'}],bindRequests=[];
 await page.route('**/api/operations/sso-bindings',route=>route.fulfill({json:bindings}));
 await page.route('**/api/operations/sso-bindings/*',route=>{assert.equal(route.request().method(),'DELETE');bindings=[];return route.fulfill({json:{ok:true}});});
 await page.route('**/api/operations/sso-binding',route=>{const body=route.request().postDataJSON();bindRequests.push(body);
  return body.replace_username?route.fulfill({json:{ok:true,subject_digest:'fedcba9876543210'}}):route.fulfill({status:409,json:{detail:'This subject is already bound to admin. Resend with replace_username set to confirm the replacement.'}});});
 await page.goto(url('/#users'));
 const sso=page.locator('#sso-bindings');
 await sso.locator('tr',{hasText:'0123456789abcdef'}).waitFor();
 await sso.getByRole('button',{name:'Unbind'}).click();
 await page.getByRole('button',{name:'Unbind identity'}).click();
 await sso.getByText('No SSO identities are bound.').waitFor();
 await sso.locator('summary',{hasText:'Bind an identity'}).click();
 await sso.locator('[name=subject]').fill('provider-subject-1');
 await sso.getByRole('button',{name:'Bind identity'}).click();
 await sso.getByRole('button',{name:'Replace with admin'}).click();
 await page.locator('#toast').filter({hasText:'SSO identity bound'}).waitFor();
 assert.deepEqual(bindRequests,[{subject:'provider-subject-1',username:'admin'},{subject:'provider-subject-1',username:'admin',replace_username:'admin'}]);
 await page.unroute('**/api/operations/sso-bindings');await page.unroute('**/api/operations/sso-bindings/*');await page.unroute('**/api/operations/sso-binding');

 // Settings search reaches the new sections.
 await page.goto(url('/#settings'));
 await page.locator('#settings-search').fill('backup');
 await page.locator('#settings-hub a[href="#settings/recovery"]').waitFor();
 await page.locator('#settings-search').fill('webhook');
 await page.locator('#settings-hub a[href="#settings/integrations"]').waitFor();

 // Backup & recovery: record a backup receipt; readiness shows it and still lists what is missing.
 await page.goto(url('/#settings/recovery'));
 await page.getByRole('heading',{name:/Recovery readiness/}).waitFor();
 await page.locator('.recovery-receipt summary').click();
 const receipt=page.locator('#recovery-receipt-form');
 await receipt.locator('[name=completed]').fill(local(-0.1));
 for(const [name,value] of [['environment','production'],['adapter','restic'],['backup_id','backup-1'],['database_id','db-1'],['trust_id','trust-1'],['archive_sha256','a'.repeat(64)],['key_fingerprint','b'.repeat(64)],['declared_scope','database, uploads']])await receipt.locator(`[name=${name}]`).fill(value);
 await receipt.locator('[name=key_verified_at]').fill(local(-1));
 await receipt.getByRole('button',{name:'Record receipt'}).click();
 const backupRow=page.locator('tr',{hasText:'Backup'}).first();
 await backupRow.locator('.badge.ok').waitFor();
 assert.match(await page.locator('.notice',{hasText:'What is missing'}).textContent(),/archive verification: missing/);
 if(capture)await capture('recovery-readiness');

 // AI usage inventory and Alerts & sign-in links.
 await page.goto(url('/#settings/ai'));
 await page.locator('#ai-connection-inventory tr',{hasText:'Update scoring'}).waitFor();
 await page.goto(url('/#settings/integrations'));
 await page.getByRole('button',{name:'Open fleet workflows'}).click();
 await page.getByRole('heading',{name:'Reviewed fleet workflows'}).waitFor();
 await page.locator('#close-modal').click();
 await page.getByRole('button',{name:'Open enterprise controls'}).click();
 await page.getByRole('heading',{name:'Enterprise and recovery controls'}).waitFor();
 await page.locator('#close-modal').click();

 // Incident case owner and notes, with stale ownership reported in place.
 const caseUrl='**/api/hosts/*/security/incidents/incident-1/';
 let ownerBody=null,noteBody=null;
 await page.route(caseUrl+'case',route=>route.fulfill({json:{owner:'',revision:0}}));
 await page.route(caseUrl+'owner',route=>{ownerBody=route.request().postDataJSON();return route.fulfill({status:409,json:{detail:'Case ownership changed; refresh before assigning'}});});
 await page.route(caseUrl+'notes',route=>{noteBody=route.request().postDataJSON();return route.fulfill({json:{recorded:true}});});
 await page.evaluate(hostId=>AdminTools.incidentCase(hostId,{id:'incident-1',evidence:{path:'/tmp/sample'}},null),host);
 const ownerForm=page.locator('#incident-owner-form');
 await ownerForm.locator('[name=owner]').selectOption('admin');
 await ownerForm.locator('[name=reason]').fill('Taking this investigation');
 await ownerForm.getByRole('button',{name:'Save owner'}).click();
 await ownerForm.locator('[role=status]').filter({hasText:'refresh before assigning'}).waitFor();
 assert.deepEqual(ownerBody,{owner:'admin',reason:'Taking this investigation',expected_revision:0});
 const noteForm=page.locator('#incident-note-form');
 await noteForm.locator('[name=note]').fill('Hash matches a known test file.');
 await noteForm.getByRole('button',{name:'Add note'}).click();
 await noteForm.locator('[role=status]').filter({hasText:'Note added'}).waitFor();
 assert.deepEqual(noteBody,{note:'Hash matches a known test file.'});
 await page.locator('#close-modal').click();
 for(const suffix of ['case','owner','notes'])await page.unroute(caseUrl+suffix);
};
