const assert=require('assert/strict');
// Fleet Security coverage page: open CVE exposure across the fleet (#911). Read-only, admin-only, contained failures.
module.exports=async(page,capture)=>{
 const now=Math.floor(Date.now()/1000),day=86400,originalViewport=page.viewportSize();
 let mode='fail',reads=0,release,started;
 const items=[
  {advisory_id:'USN-7001-1 <img src=x onerror=window.__fleetExposureInjected=true>',cve_ids:['CVE-2026-0001','CVE-2026-0002'],servers:2,packages:1,first_affected_at:now-9*day,fixed_known:1,exposures_truncated:true,exposures:[
   {host_id:'fleet host/1',host_name:'Alpha <b>bold</b>',enabled:true,package:'openssl',first_affected_at:now-9*day,first_affected_version:'3.0.13-0ubuntu3',last_affected_at:now-day,last_affected_version:'3.0.13-0ubuntu3.1',fixed_version:'3.0.13-0ubuntu3.4',reopened:2},
   {host_id:'fleet-host-2',host_name:'Bravo',enabled:false,package:'openssl',first_affected_at:'yesterday',first_affected_version:'',last_affected_at:-1,last_affected_version:null,fixed_version:null,reopened:'many'}]},
  {advisory_id:'USN-7002-1',cve_ids:[],servers:1,packages:1,first_affected_at:now-2*day,fixed_known:0,exposures_truncated:false,exposures:[
   {host_id:'fleet-host-2',host_name:'Bravo',enabled:false,package:'curl',first_affected_at:now-2*day,first_affected_version:'8.5.0-2ubuntu10',last_affected_at:now-2*day,last_affected_version:'8.5.0-2ubuntu10',fixed_version:null,reopened:0}]}
 ];
 const coverage='Open exposures come from the durable ledger. <b>Version applicability is not evidence of exploitation.</b>';
 const handler=async route=>{
  const request=route.request();
  if(request.method()!=='GET')throw new Error('fleet exposure must not write');
  reads++;
  if(mode==='fail')return route.fulfill({status:500,json:{detail:'Internal <script>fixture</script> details'}});
  if(mode==='hold'){started();await new Promise(resolve=>release=resolve);}
  if(mode==='empty')return route.fulfill({json:{items:[],truncated:false,totals:{open_exposures:0,servers:0,advisories:0},coverage}});
  if(mode==='malformed')return route.fulfill({json:{items:'broken'}});
  return route.fulfill({json:{items,truncated:mode==='truncated',totals:{open_exposures:mode==='truncated'?412:3,servers:mode==='truncated'?40:2,advisories:mode==='truncated'?250:2},coverage}});
 };
 await page.route('**/api/cve-exposure/fleet',handler);
 const card=page.locator('#fleet-exposure');
 const open=async()=>{await page.goto(new URL('/#overview',page.url()).href);await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();await page.goto(new URL('/#security',page.url()).href);await page.getByRole('heading',{name:'Open CVE exposure across the fleet'}).waitFor();};
 try{
  await open();
  await card.getByRole('alert').filter({hasText:'Fleet exposure is unavailable'}).waitFor();
  assert.equal(await card.getByText('Internal',{exact:false}).count(),0,'server error details are not shown');
  assert.equal(await page.locator('#coverage-search').isVisible(),true,'the coverage list stays usable');
  mode='populated';await card.getByRole('button',{name:'Retry fleet exposure'}).click();
  await card.locator('.fleet-exposure-list').waitFor();
  assert.deepEqual(await card.locator('.status-facts span').allTextContents(),['3Open exposures','2Servers affected','2Advisories']);
  const rows=card.locator('.fleet-exposure-list > li');assert.equal(await rows.count(),2);
  const summary=await rows.nth(0).locator('summary').textContent();
  assert.match(summary,/^Open USN-7001-1 <img src=x onerror=window.__fleetExposureInjected=true> · CVE-2026-0001, CVE-2026-0002 · 2 servers · 1 package · Earliest /);
  assert.match(await rows.nth(1).locator('summary').textContent(),/^Open USN-7002-1 · 1 server · 1 package/);
  await rows.nth(0).locator('summary').click();
  const servers=rows.nth(0).locator('.fleet-exposure-servers > li');
  assert.equal(await servers.count(),2);
  const link=servers.nth(0).getByRole('link',{name:'Alpha <b>bold</b>'});
  assert.equal(await link.getAttribute('href'),'#servers/fleet%20host%2F1/patching');
  assert.match(await servers.nth(0).textContent(),/Package openssl · First affected .+ at version 3\.0\.13-0ubuntu3 · Last affected .+ at version 3\.0\.13-0ubuntu3\.1 · Vendor fix 3\.0\.13-0ubuntu3\.4 · Reopened 2 times/);
  const second=await servers.nth(1).textContent();
  assert.match(second,/Bravo Management disabled · not refreshed/);
  assert.match(second,/First affected Unknown at version Unknown · Last affected Unknown at version Unknown/);
  assert.doesNotMatch(second,/Vendor fix|Reopened/);
  assert.match(await rows.nth(0).textContent(),/More affected servers are not listed/);
  assert.equal(await card.locator('img,b,script').count(),0);
  assert.equal(await page.evaluate(()=>window.__fleetExposureInjected),undefined);
  const text=await card.textContent();
  assert.match(text,/not exploitation evidence, not a clean-host verdict and does not verify that a patch took effect/);
  assert.ok(text.includes('<b>Version applicability is not evidence of exploitation.</b>'),'coverage is shown escaped');
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true,'no horizontal scroll at '+width);
   await card.scrollIntoViewIfNeeded();await capture('fleet-exposure-'+width);
  }
  await page.setViewportSize(originalViewport);
  mode='truncated';await card.getByRole('button',{name:'Refresh fleet exposure'}).click();
  await card.getByText('Only the first 2 advisories are shown',{exact:false}).waitFor();
  assert.deepEqual(await card.locator('.status-facts span').allTextContents(),['412Open exposures','40Servers affected','250Advisories']);
  mode='empty';await card.getByRole('button',{name:'Refresh fleet exposure'}).click();
  await card.getByText('No open exposure is recorded on any current server.',{exact:false}).waitFor();
  assert.match(await card.textContent(),/so this is not a clean-fleet verdict/);
  mode='malformed';await card.getByRole('button',{name:'Refresh fleet exposure'}).click();
  await card.getByText('Fleet exposure is unavailable in this response.').waitFor();
  // A late reply is ignored after leaving the page.
  mode='hold';const held=new Promise(resolve=>started=resolve);
  await card.getByRole('button',{name:'Refresh fleet exposure'}).click();await held;
  await page.goto(new URL('/#overview',page.url()).href);await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
  mode='populated';release();await page.waitForTimeout(300);
  assert.equal(await page.locator('.fleet-exposure-list').count(),0,'stale reply must not render elsewhere');
  assert.equal(reads,6,'each load and refresh reads the endpoint once');
 }finally{
  if(release)release();
  await page.unroute('**/api/cve-exposure/fleet',handler);await page.setViewportSize(originalViewport);
  await page.goto(new URL('/#overview',page.url()).href);
  await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
 }
};
