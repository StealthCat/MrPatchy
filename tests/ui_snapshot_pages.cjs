const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const host=await page.evaluate(async()=>{const rows=await(await fetch('/api/hosts')).json();if(rows.length)return rows[0].id;const s=await(await fetch('/api/session')).json();return(await(await fetch('/api/hosts',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':s.csrf},body:JSON.stringify({name:'Snapshot review',address:'192.0.2.88'})})).json()).id;});
 let role='admin',empty=false,fail=false,mismatch=false,writes=0;const reads=[];
 const handler=route=>{const u=new URL(route.request().url());reads.push(u);if(fail)return route.fulfill({status:404,json:{detail:'Snapshot expired <img src=x onerror=window.__snapshotInjected=true>'}});const detail=u.pathname.split('/history/')[1],offset=Number(u.searchParams.get('offset')||0),kind=u.searchParams.get('kind');return route.fulfill({json:detail?{id:detail,host_id:mismatch?'other-server':host,created:1000,observed:1000,inventory:{label:'<img src=x onerror=window.__snapshotInjected=true>'},evidence:{command:'untrusted <svg onload=window.__snapshotInjected=true>'}}:empty?[]:Array.from({length:offset?1:20},(_,i)=>({id:'record-'+(offset+i),created:1000+i,observed:1000+i}))});};
 const identity=async route=>{const r=await route.fetch();return route.fulfill({response:r,json:{...await r.json(),role}});};
 const observe=r=>{if(new URL(r.url()).pathname.startsWith('/api/')&&r.method()!=='GET')writes++;};
 await page.route('**/api/hosts/*/history?*',handler);await page.route('**/api/hosts/*/history/*?*',handler);await page.route('**/api/identity',identity);page.on('request',observe);
 try{
  await page.goto(new URL('/?snapshots=1#servers/'+host+'/history/inventory',page.url()).href);await page.locator('.snapshot-list article').first().waitFor();assert.equal(await page.locator('.snapshot-list article').count(),20);
  await page.locator('#snapshot-list').getByRole('button',{name:'Next',exact:true}).click();await page.getByText('Record record-20',{exact:true}).waitFor();
  await page.getByRole('link',{name:'Open snapshot',exact:false}).click();await page.locator('.history-detail pre').waitFor();assert.equal(await page.locator('#content img[src=x]').count(),0);
  await page.goBack();await page.getByText('Record record-20',{exact:true}).waitFor();
  await page.getByRole('link',{name:'Process observations',exact:true}).click();await page.getByText('Record record-0',{exact:true}).waitFor();
  await page.getByRole('link',{name:'Open snapshot',exact:false}).first().click();await page.locator('.history-detail pre').filter({hasText:'untrusted'}).waitFor();
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('snapshot-detail-'+width);}
  await page.reload();await page.locator('.history-detail pre').waitFor();
  fail=true;await page.reload();await page.getByRole('heading',{name:'Unable to load snapshot',exact:true}).waitFor();assert.equal(await page.locator('#content img[src=x]').count(),0);
  fail=false;await page.getByRole('button',{name:'Retry snapshot',exact:true}).click();await page.locator('.history-detail pre').waitFor();
  mismatch=true;await page.reload();await page.getByText('History record identity differs; reopen the list.',{exact:true}).waitFor();mismatch=false;
  await page.getByRole('link',{name:'Back to snapshot list',exact:true}).click();await page.locator('.snapshot-list').waitFor();
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('snapshot-list-'+width);}
  empty=true;await page.reload();await page.getByRole('heading',{name:'No retained snapshots on this page',exact:true}).waitFor();empty=false;
  fail=true;await page.reload();await page.getByRole('heading',{name:'Unable to load history',exact:true}).waitFor();fail=false;await page.getByRole('button',{name:'Retry history',exact:true}).click();await page.locator('.snapshot-list').waitFor();
  let release,started;const wait=new Promise(r=>release=r),start=new Promise(r=>started=r);
  const delayed=async route=>{started();await wait;await route.fallback();};await page.route('**/api/hosts/*/history/record-0?*',delayed);
  await page.getByRole('link',{name:'Open snapshot',exact:false}).first().click();await start;
  await page.getByRole('link',{name:'Inventory revisions',exact:true}).click();await page.locator('.snapshot-list').waitFor();release();await page.waitForTimeout(100);assert.equal(await page.locator('.history-detail').count(),0);await page.unroute('**/api/hosts/*/history/record-0?*',delayed);
  const inactive=async route=>{const r=await route.fetch();return route.fulfill({response:r,json:(await r.json()).map(h=>h.id===host?{...h,enabled:false}:h)});};await page.route('**/api/hosts',inactive);await page.reload();await page.getByText('Retained history only; management is inactive.',{exact:true}).waitFor();await page.unroute('**/api/hosts',inactive);
  const before=reads.length;role='viewer';await page.reload();await page.getByRole('heading',{name:'Administrator access required',exact:true}).waitFor();assert.equal(reads.length,before);
  assert.equal(writes,0);assert.equal(await page.evaluate(()=>window.__snapshotInjected),undefined);
 }finally{page.off('request',observe);await page.unroute('**/api/hosts/*/history?*',handler);await page.unroute('**/api/hosts/*/history/*?*',handler);await page.unroute('**/api/identity',identity);await page.setViewportSize({width:1440,height:1000});}
};
