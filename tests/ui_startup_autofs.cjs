const assert=require('assert/strict');
// Resolved autofs program maps render as escaped rows with blocking gaps; older agents and refused master maps are explained.
module.exports=async(page,capture)=>{
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const gap=(code,detail,extra)=>({code,detail,blocking:true,...extra});
 const autofs={complete:false,origin:'not_assessed',authorizes_response:false,contract_version:1,
  programs:[{path:'/usr/lib/autofs/prog',argv:['/usr/lib/autofs/prog','<key>'],user:'root',cwd:'/prog',trigger:'every lookup of a key under the mount point'}],
  entries:[{mount_point:'/net',type:'hosts',format:null,map:null,resolved:'hosts',path:null},
   {mount_point:'/prog',type:'program',format:null,map:'/usr/lib/autofs/prog',resolved:'program',path:'/usr/lib/autofs/prog'},
   {mount_point:'/misc',type:null,format:null,map:'auto.misc',resolved:'file',path:'/etc/auto.misc'},
   {mount_point:'/<img src=x onerror=window.__autofsInjected=true>',type:null,format:null,map:'<b>evil</b>',resolved:'refused',path:null}],
  gaps:[gap('nsswitch_not_observed','The automount: sources in /etc/nsswitch.conf were not captured.'),gap('map_text_not_observed','A text map was not captured.',{path:'/etc/auto.misc',mount_point:'/misc'})]};
 const row=(path,extra)=>({path,mechanism:'autofs',mechanism_label:'autofs master map',kind:'regular',uid:0,gid:0,mode:420,sha256:'d'.repeat(64),change:'not_compared',jobs_state:'not_crontab',...extra});
 const handler=route=>route.fulfill({json:{inspection_id:'autofs-receipt',created:Date.now()/1000,state:'collected',baseline_state:'not_compared',digest:'autofs-digest',
  items:[row('/etc/auto.master',{autofs_state:'resolved',autofs}),row('/etc/auto.master.older',{autofs_state:'not_reported'}),row('/etc/auto.master.binary',{autofs_state:'binary'})],
  total:3,more:false,cron:{files:0,jobs:0,unparsed:0,truncated:false,not_reported:0},scope:['/etc/auto.master'],catalog:[{id:'autofs',label:'autofs master map · 1 program map',observed_files:1}],missing_roots:[],skipped:0,gaps:['autofs gap'],note:'Bounded stored metadata.'}});
 await page.route('**/api/hosts/*/security/startup-inventory?*',handler);
 try{
  await page.goto(new URL('/#servers/'+host+'/startup/files',page.url()).href);await page.locator('#startup-file-items').waitFor();
  await page.getByRole('heading',{name:'autofs program maps (1)',exact:true}).waitFor();
  await page.getByText('incomplete (2 blocking gaps); it is not a safety verdict',{exact:false}).waitFor();
  const text=await page.locator('.startup-autofs-maps').first().innerText();
  assert.match(text,/Built-in hosts map/);assert.match(text,/program:\/usr\/lib\/autofs\/prog/);assert.match(text,/Program map/);assert.match(text,/Text map/);assert.match(text,/\/etc\/auto\.misc/);
  assert.match(text,/Refused \(not executable\)/);assert.match(text,/<img src=x onerror/);assert.match(text,/<b>evil<\/b>/);assert.match(text,/\troot/);
  await page.locator('.startup-autofs-gaps summary').first().click();
  await page.getByText('A text map was not captured.',{exact:false}).waitFor();
  await page.getByText('autofs program maps: not reported by this agent version.',{exact:false}).waitFor();
  await page.getByText('The master map was binary (NUL bytes), so no maps are shown.',{exact:false}).waitFor();
  assert.equal(await page.locator('#content img[src=x]').count(),0);assert.equal(await page.locator('#content b').filter({hasText:'evil'}).count(),0);assert.equal(await page.evaluate(()=>window.__autofsInjected),undefined);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('startup-autofs-'+width);}
  await page.getByRole('link',{name:'Coverage',exact:true}).click();await page.getByText('autofs master map · 1 program map',{exact:true}).waitFor();
 }finally{await page.unroute('**/api/hosts/*/security/startup-inventory?*',handler);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
