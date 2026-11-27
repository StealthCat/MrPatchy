const assert=require('assert/strict');
// Parsed ClamAV event commands render as escaped rows with event, account and conditions; rejected, older-agent, symlinked and RPM files are explained.
module.exports=async(page,capture)=>{
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const command=(line,directive,trigger,text,extra)=>({directive,line,trigger,runs:true,command:text,truncated:false,redacted:false,argv:['sh','-c',text],account:{name:'clamav',source:'DatabaseOwner_default'},waits:null,substitutions:{},command_source:directive,exit_status_outside_daemon:null,...extra});
 const view=(tool,commands,extra)=>({tool,parsed:true,accepted:true,error:null,redacted:false,commands,daemon_line:null,origin:'not_assessed',authorizes_response:false,contract_version:1,...extra});
 const clamd=view('clamd',[command(2,'VirusEvent','virus_found','<img src=x onerror=window.__clamInjected=true> %v --token=[REDACTED]',{account:{name:'clamscan',source:'User',line:1},waits:true,substitutions:{'%v':'detected_signature_name_unescaped','%f':null},redacted:true,truncated:true,command_source:undefined,exit_status_outside_daemon:undefined})],{redacted:true});
 const fresh=view('freshclam',[command(1,'OnUpdateExecute','database_updated','EXIT_1',{exit_status_outside_daemon:1}),command(3,'OnOutdatedExecute','newer_clamav_announced','/bin/old %v',{runs:false,argv:null,command_source:'depends_on_daemon_mode'}),
  command(4,'OnErrorExecute','update_failed','/bin/err',{account:{name:'bob',source:'DatabaseOwner',line:5}})],{daemon_line:6});
 const rejected=view('clamd',[command(1,'VirusEvent','virus_found','/bin/v',{runs:false,account:{name:'root',source:'start_account'},waits:true})],{accepted:false,error:{line:2,reason:'example_config'}});
 const row=(path,extra)=>({path,mechanism:'clamav',mechanism_label:'ClamAV configuration',kind:'regular',uid:0,gid:0,mode:420,sha256:'c'.repeat(64),change:'not_compared',jobs_state:'not_crontab',...extra});
 const handler=route=>route.fulfill({json:{inspection_id:'clamav-receipt',created:Date.now()/1000,state:'collected',baseline_state:'not_compared',digest:'clamav-digest',
  items:[row('/etc/clamav/clamd.conf',{clamav_state:'parsed',clamav:clamd}),row('/etc/clamav/freshclam.conf',{clamav_state:'parsed',clamav:fresh}),row('/etc/clamav/clamd.conf.rejected',{clamav_state:'parsed',clamav:rejected}),
   row('/etc/clamav/clamd.conf.older',{clamav_state:'not_reported'}),row('/etc/clamd.d/scan.conf',{mechanism:'clamav_clamd_d',mechanism_label:'ClamAV clamd configuration',clamav_state:'not_parsed_family'}),
   row('/etc/clamav/clamd.conf.nul',{clamav_state:'parsed',clamav:{...view('clamd',[]),parsed:false,accepted:false}})],
  total:6,more:false,cron:{files:0,jobs:0,unparsed:0,truncated:false,not_reported:0},scope:['/etc/clamav','/etc/clamd.d','/etc/freshclam.conf'],
  catalog:[{id:'clamav',label:'ClamAV configuration · 5 parsed event commands · rejected by the option parser · not reported by this agent version',observed_files:5}],missing_roots:[],skipped:0,gaps:['ClamAV gap'],note:'Bounded stored metadata.'}});
 await page.route('**/api/hosts/*/security/startup-inventory?*',handler);
 try{
  await page.goto(new URL('/#servers/'+host+'/startup/files',page.url()).href);await page.locator('#startup-file-items').waitFor();
  await page.getByRole('heading',{name:'clamd event commands (1)',exact:true}).first().waitFor();
  const tables=page.locator('.startup-clamav-commands');
  const virus=await tables.nth(0).innerText();
  assert.match(virus,/VirusEvent\s+Every detection\s+<img src=x onerror=window\.__clamInjected=true> %v --token=\[REDACTED\]/);
  assert.match(virus,/%v becomes the detected signature name, unescaped · Credentials redacted · Truncated/);
  assert.match(virus,/clamscan \(User, line 1; primary group only\)/);assert.match(virus,/Yes, through \/bin\/sh; clamd waits, and every scan waits with it/);
  await page.getByRole('heading',{name:'freshclam event commands (3)',exact:true}).waitFor();
  const updates=await tables.nth(1).innerText();
  assert.match(updates,/OnUpdateExecute\s+After a database update\s+EXIT_1\s+clamav \(DatabaseOwner default\)\s+In daemon mode only; otherwise freshclam exits with status 1 instead/);
  assert.match(updates,/OnOutdatedExecute\s+When a newer ClamAV is announced\s+\/bin\/old %v/);assert.match(updates,/Depends on daemon mode/);
  assert.match(updates,/OnErrorExecute\s+After a failed update\s+\/bin\/err\s+bob \(DatabaseOwner, line 5\)\s+Yes, through \/bin\/sh/);
  await page.getByText('Line 6 sets daemon in the file, which the contract does not model',{exact:false}).waitFor();
  const notice=await page.locator('.startup-clamav-rejected').innerText();
  assert.match(notice,/clamd rejects this file at line 2 because of an Example line, so it loads no configuration and runs none of these commands/);
  assert.match(await tables.nth(2).innerText(),/Never: the file is rejected/);
  await page.getByText('ClamAV event commands: not reported by this agent version.',{exact:false}).waitFor();
  await page.getByText('RPM-family ClamAV configuration is hashed but not yet parsed',{exact:false}).waitFor();
  await page.getByText('The file contained NUL bytes or was over 1 MiB, so no commands are shown.',{exact:false}).waitFor();
  assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.evaluate(()=>window.__clamInjected),undefined);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('startup-clamav-'+width);}
  await page.getByRole('link',{name:'Coverage',exact:true}).click();await page.getByText('ClamAV configuration · 5 parsed event commands · rejected by the option parser · not reported by this agent version',{exact:true}).waitFor();
 }finally{await page.unroute('**/api/hosts/*/security/startup-inventory?*',handler);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
