const assert=require('assert/strict');
// The runit evaluation renders each service's programs with escaped names, outcomes and timing, and lists blocking gaps.
module.exports=async(page,capture)=>{
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const prog=(path,role,outcome,extra)=>({role,path,argv:['./run'],cwd:path.replace(/\/[^/]+$/,''),event:'e',outcome,reason:'r',automatic:null,...extra});
 const view={directory:'/etc/service',resolved_directory:'/etc/runit/runsvdir/default',runs:3,complete:false,origin:'not_assessed',authorizes_response:false,contract_version:1,
  services:[{name:'ssh',path:'/etc/service/ssh',outcome:'supervised',reason:'s',wanted_down:false,has_log:true,
    programs:[prog('/etc/service/ssh/run','run','runs'),prog('/etc/service/ssh/finish','finish','not_executable'),prog('/etc/service/ssh/log/run','log_run','runs'),
     prog('/etc/service/ssh/control/t','control','runs',{letter:'t',automatic:false})]},
   {name:'<img src=x onerror=window.__runitInjected=true>',path:'/etc/service/x',outcome:'supervised',reason:'s',wanted_down:true,has_log:false,programs:[]},
   {name:'gone',path:'/etc/service/gone',outcome:'stat_failed',reason:'The entry cannot be followed (for example a dangling symlink), so runsvdir skips it.',programs:[]}],
  gaps:[{code:'supervisor_not_observed',blocking:true,detail:'Whether runsvdir runs is not observed.'},{code:'mount_flags_unobserved',blocking:false,detail:'noexec'},
   {code:'symlink_target_unobserved',blocking:true,path:'/etc/service/ext'}]};
 const row=(path,extra)=>({path,mechanism:'runit',mechanism_label:'runit service directory',kind:'symlink',uid:0,gid:0,mode:511,target:'runit/runsvdir/current',change:'not_compared',jobs_state:'not_crontab',...extra});
 const body={inspection_id:'rn-receipt',created:Date.now()/1000,state:'collected',baseline_state:'not_compared',digest:'rn-digest',total:1,more:false,cron:{files:0,jobs:0,unparsed:0,truncated:false,not_reported:0},scope:['/etc/service'],
  catalog:[{id:'runit',label:'runit service directory',observed_files:1}],missing_roots:[],skipped:0,gaps:['runit gap'],note:'Bounded stored metadata.',items:[row('/etc/service',{runit:view})]};
 const handler=route=>route.fulfill({json:body});
 await page.route('**/api/hosts/*/security/startup-inventory?*',handler);
 try{
  await page.goto(new URL('/#servers/'+host+'/startup/files',page.url()).href);await page.locator('#startup-file-items').waitFor();
  await page.getByRole('heading',{name:'runit service programs (3 entries · 3 runnable)',exact:true}).waitFor();
  await page.getByText('This list is incomplete (2 blocking gaps) and is not a safety verdict.',{exact:false}).waitFor();
  const text=await page.locator('.startup-runit-services').innerText();
  assert.match(text,/\/etc\/service\/ssh\/run Runs · Unknown: runsvdir not observed/);assert.match(text,/\/etc\/service\/ssh\/finish No: not executable/);
  assert.match(text,/\/etc\/service\/ssh\/control\/t Runs · Only on an sv command or shutdown/);
  assert.match(text,/<img src=x onerror=window\.__runitInjected=true>\s+Wanted down/);assert.match(text,/dangling symlink/);
  await page.locator('.startup-runit-gaps summary').click();
  const gaps=await page.locator('.startup-runit-gaps').innerText();
  assert.match(gaps,/Blocking: runsvdir not observed/);assert.match(gaps,/Blocking: Link target not observed \/etc\/service\/ext/);assert.match(gaps,/Mount flags not observed/);
  assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.evaluate(()=>window.__runitInjected),undefined);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('startup-runit-'+width);}
 }finally{await page.unroute('**/api/hosts/*/security/startup-inventory?*',handler);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
