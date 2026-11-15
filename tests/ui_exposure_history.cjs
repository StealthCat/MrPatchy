const assert=require('assert/strict');
// Server Patching page: durable CVE exposure history card (#893). Read-only, admin-only, contained failures.
module.exports=async(page,capture)=>{
 const host='exposure-host',other='exposure-other',now=Math.floor(Date.now()/1000),day=86400;
 const originalViewport=page.viewportSize();
 let role='admin',mode='fail',advisoryReads=[],release,started;
 const items=[
  {advisory_id:'DSA-5999-1 <img src=x onerror=window.__exposureInjected=true>',package:'openssl',ecosystem:'Debian:12',cve_ids:['CVE-2026-0001','CVE-2026-0002'],state:'open',first_affected_at:now-9*day,first_affected_version:'3.0.11-1~deb12u1',last_affected_at:now-day,last_affected_version:'3.0.11-1~deb12u2',fixed_version:'3.0.15-1~deb12u1',last_observed_at:now-day,last_status:'affected',resolved_at:null,resolved_version:null,resolved_status:null,reopened:2},
  {advisory_id:'DSA-5800-1',package:'curl',ecosystem:'Debian:12',cve_ids:['CVE-2026-1000'],state:'resolved',first_affected_at:now-30*day,first_affected_version:'7.88.1-10',last_affected_at:now-20*day,last_affected_version:'7.88.1-10',fixed_version:'7.88.1-10+deb12u5',last_observed_at:now-2*day,last_status:'fixed',resolved_at:now-19*day,resolved_version:'7.88.1-10+deb12u5',resolved_status:'fixed',reopened:0},
  {advisory_id:'DSA-5700-1',package:'libxml2',ecosystem:'Debian:12',cve_ids:[],state:'resolved',first_affected_at:'yesterday',first_affected_version:'',last_affected_at:-5,last_affected_version:null,fixed_version:null,last_observed_at:now,last_status:'not-listed',resolved_at:now-3*day,resolved_version:'2.9.14',resolved_status:'not-listed',reopened:'many'},
  {advisory_id:'DSA-5600-1',package:'zlib',cve_ids:['CVE-2026-2000'],state:'resolved',first_affected_at:now-40*day,first_affected_version:'1.2.13',last_affected_at:now-40*day,last_affected_version:'1.2.13',resolved_at:null,resolved_status:'fixed'},
  {advisory_id:'DSA-5500-1',package:'bash',cve_ids:[],state:'mystery',first_affected_at:now-50*day,first_affected_version:'5.2',last_affected_at:now-50*day,last_affected_version:'5.2',resolved_at:now,resolved_status:'other'}
 ];
 const coverage='Exposure history records when a manual advisory scan first and last classified each advisory. <b>This is version applicability, not evidence of exploitation.</b>';
 const hosts=[host,other].map((id,i)=>({id,name:i?'Exposure other':'Exposure target',address:'192.0.2.9'+i,port:22,state:'online',integrity:[],enabled:true,last_seen:now,last_repo:now,package_manager:'apt'}));
 const handler=async route=>{
  const request=route.request(),p=new URL(request.url()).pathname;
  if(p==='/api/identity'){const response=await route.fetch();return route.fulfill({response,json:{...await response.json(),role}});}
  if(p==='/api/hosts')return route.fulfill({json:hosts});
  const id=[host,other].find(h=>p.startsWith('/api/hosts/'+h+'/')||p.startsWith('/api/operations/'+h+'/'));
  if(!id)return route.fallback();
  if(request.method()!=='GET')throw new Error('exposure history must not write: '+request.method()+' '+p);
  if(p.endsWith('/advisories')){
   advisoryReads.push(id);
   if(mode==='fail')return route.fulfill({status:500,json:{detail:'Internal <script>fixture</script> details'}});
   if(mode==='hold'){started();await new Promise(resolve=>release=resolve);}
   if(mode==='empty')return route.fulfill({json:{results:[],coverage:'Not checked',exposure_history:{items:[],truncated:false,open:0,coverage}}});
   if(mode==='malformed')return route.fulfill({json:{results:[],exposure_history:'broken'}});
   return route.fulfill({json:{results:[],coverage:'Latest scan',exposure_history:{items,truncated:mode==='truncated',open:mode==='truncated'?37:1,coverage}}});
  }
  if(p.endsWith('/patching'))return route.fulfill({json:{events:[],windows:[],recovery:{reboot:false,rollback:false},schedules:[]}});
  if(p.endsWith('/packages'))return route.fulfill({json:[]});
  if(p.endsWith('/summary'))return route.fulfill({json:{host:hosts.find(h=>h.id===id),system:{},collector:{},counts:{packages:0,updates:0,held:0,overdue:0,unapproved:0,pending_ai:0,investigations:0},jobs:{},spool:null}});
  return route.fulfill({json:[]});
 };
 const jobs=route=>route.fulfill({json:[]});
 await page.route('**/api/**',handler);await page.route('**/api/jobs?*',jobs);
 const card=page.locator('#server-exposure-history');
 const open=async id=>{await page.goto(new URL('/#servers/'+id+'/patching',page.url()).href);await page.getByRole('heading',{name:'Scheduled start windows'}).waitFor();};
 try{
  // A load failure stays inside the card and leaves the page usable.
  await open(host);
  await card.getByRole('alert').filter({hasText:'Exposure history is unavailable'}).waitFor();
  assert.equal(await card.getByText('Internal',{exact:false}).count(),0,'server error details are not shown');
  assert.equal(await page.getByRole('heading',{name:'Pending updates & expected installation'}).isVisible(),true);
  mode='populated';await card.getByRole('button',{name:'Retry exposure history'}).click();
  await card.getByText('Open exposures').waitFor();
  assert.deepEqual(await card.locator('.status-facts span').allTextContents(),['1Open exposures','5Records shown']);
  const rows=card.locator('.exposure-history-list > li');
  assert.equal(await rows.count(),5);
  const first=await rows.nth(0).textContent();
  assert.match(first,/^Open DSA-5999-1 <img src=x onerror=window.__exposureInjected=true> · CVE-2026-0001, CVE-2026-0002/);
  assert.match(first,/Package openssl · Vendor fix 3\.0\.15-1~deb12u1 · Reopened 2 times/);
  assert.match(first,/First affected .+ at version 3\.0\.11-1~deb12u1 · Last affected .+ at version 3\.0\.11-1~deb12u2/);
  assert.doesNotMatch(first,/Resolved/);
  assert.match(await rows.nth(1).textContent(),/^Resolved DSA-5800-1 · CVE-2026-1000.*Resolved .+ at version 7\.88\.1-10\+deb12u5: a fixed version was observed\./);
  const third=await rows.nth(2).textContent();
  assert.match(third,/First affected Unknown at version Unknown · Last affected Unknown at version Unknown/);
  assert.match(third,/the advisory was no longer listed for the installed version\./);
  assert.doesNotMatch(third,/Reopened|Vendor fix/);
  assert.match(await rows.nth(3).textContent(),/^Unknown state DSA-5600-1/,'resolved without a resolution time is not shown as resolved');
  assert.match(await rows.nth(4).textContent(),/^Unknown state DSA-5500-1/,'unrecognised state is not shown as resolved');
  assert.equal(await card.locator('img,b,script').count(),0);
  assert.equal(await page.evaluate(()=>window.__exposureInjected),undefined);
  const text=await card.textContent();
  assert.match(text,/not exploitation evidence, not a clean-host verdict and does not verify that a patch took effect/);
  assert.ok(text.includes('<b>This is version applicability, not evidence of exploitation.</b>'),'coverage is shown escaped');
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true,'no horizontal scroll at '+width);
   await capture('server-exposure-history-'+width);
  }
  await page.setViewportSize(originalViewport);
  // Truncation keeps the API's full open total.
  mode='truncated';await card.getByRole('button',{name:'Refresh exposure history'}).click();
  await card.getByText('Only the first 5 records are shown.',{exact:false}).waitFor();
  assert.deepEqual(await card.locator('.status-facts span').allTextContents(),['37Open exposures','5Records shown']);
  // Empty ledger is not a clean-host verdict.
  mode='empty';await card.getByRole('button',{name:'Refresh exposure history'}).click();
  await card.getByText('No affected advisory has been recorded for this server.',{exact:false}).waitFor();
  assert.match(await card.textContent(),/never had an advisory scan also shows no records, so this is not a clean-host verdict/);
  mode='malformed';await card.getByRole('button',{name:'Refresh exposure history'}).click();
  await card.getByText('Exposure history is unavailable in this response.').waitFor();
  // A late reply for the previous server is ignored after navigating away.
  mode='hold';const held=new Promise(resolve=>started=resolve);
  await card.getByRole('button',{name:'Refresh exposure history'}).click();await held;
  mode='empty';await open(other);
  await card.getByText('No affected advisory has been recorded for this server.',{exact:false}).waitFor();
  mode='populated';release();
  await page.waitForTimeout(300);
  assert.equal(await card.locator('.exposure-history-list').count(),0,'stale reply from the previous server must not render');
  // Viewers never request the admin-only endpoint and get no card.
  role='viewer';const before=advisoryReads.length;
  await page.goto(new URL('/#overview',page.url()).href);await page.reload();
  await open(host);
  assert.equal(await card.count(),0);
  assert.equal(advisoryReads.length,before,'viewers must not request advisories');
 }finally{
  if(release)release();
  await page.unroute('**/api/jobs?*',jobs);await page.unroute('**/api/**',handler);await page.setViewportSize(originalViewport);
  await page.goto(new URL('/#overview',page.url()).href);await page.reload();
  await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
 }
};
