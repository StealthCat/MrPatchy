const assert=require('assert/strict');
// Fleet-wide Available patches (#512): menu + Overview card entry points, paging, filters, read-only.
module.exports=async(page)=>{
 const total=120,requests=[];let writes=0,mode='rows';
 const observe=r=>{if(new URL(r.url()).pathname.startsWith('/api/')&&r.method()!=='GET')writes++;};
 const handler=route=>{
  const u=new URL(route.request().url());requests.push(u);
  if(mode==='fail')return route.fulfill({status:500,json:{detail:'Update list unavailable'}});
  if(u.searchParams.get('scope')==='inactive')return route.fulfill({json:{items:[{id:'off:x',host_id:'off',host_name:'retired',name:'xpkg',installed:'1',candidate:'2',priority:'normal',held:false,status:'available',repo_state:'unknown',repo_checked:0,repo_error:'',host_active:false,dpkg_state:'install ok installed',available_since:0,due:1e9,contact_stale:true}],total:1,offset:0,limit:50,scope:'inactive'}});
  const q=u.searchParams.get('q')||'',offset=Number(u.searchParams.get('offset')),limit=Number(u.searchParams.get('limit'));
  const all=Array.from({length:total},(_,i)=>({id:'h'+(i%2)+':p'+i,host_id:'h'+(i%2),host_name:i%2?'beta':'alpha',name:'pkg'+i,installed:'1',candidate:'2',priority:'normal',held:i===2,status:i===1?'queued':i===2?'held':i===3?'ineligible':'available',priority_deferred:i===4,repo_state:i===0?'failed':'current',repo_checked:1e9,repo_error:i===0?'mirror unreachable':'',host_active:true,dpkg_state:'install ok installed',available_since:0,due:1e9,contact_stale:i===0})).filter(r=>r.name.includes(q));
  return route.fulfill({json:{items:all.slice(offset,offset+limit),total:all.length,offset,limit}});
 };
 const dashboard=async route=>{const r=await route.fetch();return route.fulfill({response:r,json:{...await r.json(),updates:total}});};
 await page.route('**/api/fleet/updates?*',handler);await page.route('**/api/dashboard',dashboard);page.on('request',observe);
 try{
  await page.goto(new URL('/#overview',page.url()).href);await page.reload();
  await page.getByRole('link',{name:/Updates available/}).click();
  await page.getByRole('heading',{name:'Available patches.'}).waitFor();
  assert.ok(page.url().endsWith('#updates'));assert.equal(requests.at(-1).searchParams.get('host_id'),null);
  await page.getByText('120 matching updates.').waitFor();assert.equal(await page.locator('#fleet-updates-table tbody tr').count(),50);
  await page.getByText('Server contact is stale').waitFor();
  for(const text of ['Queued for installation','Held by target policy','Not installable (package state)','AI priority scoring deferred','Repository check failed','mirror unreachable'])await page.getByText(text,{exact:false}).first().waitFor();
  await page.locator('#fleet-updates-scope').selectOption('inactive');await page.getByText('1 matching update retained on disabled servers; not included in active fleet totals.').waitFor();await page.getByText('Disabled server · inactive record').waitFor();assert.equal(requests.at(-1).searchParams.get('scope'),'inactive');
  await page.locator('#fleet-updates-scope').selectOption('');await page.getByText('120 matching updates.').waitFor();
  await page.locator('#fleet-updates-next').click();await page.getByText('Page 2 of 3').waitFor();
  await page.locator('#fleet-updates-next').click();await page.getByText('Page 3 of 3').waitFor();
  assert.equal(await page.locator('#fleet-updates-table tbody tr').count(),20);assert.equal(await page.locator('#fleet-updates-next').isDisabled(),true);
  await page.reload();await page.getByText('Page 3 of 3').waitFor(); // directly linkable
  await page.locator('#fleet-updates-search').fill('pkg11');await page.getByText('11 matching updates.').waitFor();await page.getByText('Page 1 of 1').waitFor();
  await page.locator('#fleet-updates-search').fill('nothing-like-this');await page.getByText('0 matching updates.').waitFor();await page.getByRole('heading',{name:'No matching updates'}).waitFor();
  await page.locator('#fleet-updates-reset').click();await page.getByText('120 matching updates.').waitFor();assert.ok(page.url().endsWith('#updates'));
  await page.locator('#fleet-updates-priority').selectOption('low');await page.waitForURL(/#updates\?priority=low/);for(let n=0;n<50&&requests.at(-1).searchParams.get('priority')!=='low';n++)await page.waitForTimeout(100);assert.equal(requests.at(-1).searchParams.get('priority'),'low');
  mode='fail';await page.locator('#fleet-updates-reset').click();await page.getByRole('button',{name:'Retry'}).waitFor();mode='rows';await page.getByRole('button',{name:'Retry'}).click();await page.getByText('120 matching updates.').waitFor();
  await page.getByRole('navigation',{name:'Main navigation'}).getByRole('link',{name:'Available patches'}).waitFor();
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);}
  assert.equal(writes,0);
 }finally{page.off('request',observe);await page.unroute('**/api/fleet/updates?*',handler);await page.unroute('**/api/dashboard',dashboard);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#overview',page.url()).href);}
};
