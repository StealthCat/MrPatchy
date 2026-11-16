const assert=require('assert/strict');
// Investigations "Show: Cached known good" filter (#924). The filter asks the server for
// cached=true, returns to page 1 and explains an empty result. Its address (#958) is
// <view>/cached: links, reloads and Back/Forward reproduce it; the bare address shows everything.
module.exports=async(page,capture)=>{
 const now=Date.now()/1000,seen=[];
 const card=(id,cached)=>({id,host_id:'fixture',evidence:{executable:'/usr/bin/'+id,uid:0},verdict:'low',approved:false,last_seen:now,analysis:'Assessed.',retry:null,revision:'a'.repeat(64),known_good_reuse:cached?{cached:true}:null});
 let cachedRows=[card('cached-tool',true)];
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const at=hash=>page.waitForFunction(expected=>location.hash===expected,hash);
 const cachedNotice=()=>page.getByText('Showing only verdicts reused from an exact fleet known-good match',{exact:false});
 const rows=route=>{const url=new URL(route.request().url());seen.push(url.search);
  const cached=url.searchParams.get('cached')==='true',offset=Number(url.searchParams.get('offset'));
  if(cached)return route.fulfill({json:cachedRows});
  // Full pages at every offset: an earlier module may leave this view on a later page.
  return route.fulfill({json:Array.from({length:50},(_,i)=>card(i?'tool-'+i:(offset?'page-'+offset+'-tool':'cached-tool'),!i&&!offset))});};
 await page.route('**/api/investigations?*',rows);
 try{
  await page.goto(new URL('/#investigations',page.url()).href);
  const filter=page.locator('#investigation-filter');
  await filter.waitFor();
  assert.equal(await filter.inputValue(),'all');
  // Move to a later page, then filter: the request must return to offset 0.
  const start=Number(new URLSearchParams(seen.at(-1)).get('offset'));
  await page.locator('#content .server-pagination button',{hasText:'Next'}).click();
  await page.getByText('/usr/bin/page-'+(start+50)+'-tool',{exact:true}).waitFor();
  await filter.selectOption('cached');
  await cachedNotice().waitFor();
  assert.equal(await page.evaluate(()=>location.hash),'#investigations/cached');
  assert.match(seen.at(-1),/cached=true&offset=0&limit=50/);
  assert.equal(await page.locator('#content .card.investigation').count(),1);
  assert.equal(await page.locator('#content .card.investigation .cached-known-good').count(),1);
  assert.equal(await page.evaluate(()=>document.activeElement?.id),'investigation-filter');
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await capture('investigation-cached-filter-'+width);
  }
  await page.setViewportSize({width:1440,height:1000});
  // Back returns to the unfiltered list from page 1; Forward restores the filter.
  await page.goBack();await at('#investigations');
  await page.getByText('/usr/bin/tool-1',{exact:true}).waitFor();
  assert.equal(await page.locator('#investigation-filter').inputValue(),'all');
  assert.match(seen.at(-1),/^\?offset=0&limit=50$/);
  await page.goForward();await at('#investigations/cached');
  await cachedNotice().waitFor();
  assert.equal(await page.locator('#investigation-filter').inputValue(),'cached');
  assert.match(seen.at(-1),/cached=true&offset=0&limit=50/);
  // The address survives a reload and can be opened directly.
  await page.reload();
  await cachedNotice().waitFor();
  assert.equal(await page.locator('#investigation-filter').inputValue(),'cached');
  assert.equal(await page.locator('#content .card.investigation').count(),1);
  // The bare address always means every investigation, also after visiting the filter.
  await page.goto(new URL('/#overview',page.url()).href);
  await page.goto(new URL('/#investigations',page.url()).href);
  await page.getByText('/usr/bin/tool-1',{exact:true}).waitFor();
  assert.equal(await page.locator('#investigation-filter').inputValue(),'all');
  assert.doesNotMatch(seen.at(-1),/cached=/);
  // One server's Investigations tab has its own address and scopes the request to that server.
  const serverBase='#servers/'+encodeURIComponent(host)+'/investigations';
  await page.goto(new URL('/'+serverBase+'/cached',page.url()).href);
  await page.getByText('Investigations for this server only.').waitFor();
  await cachedNotice().waitFor();
  assert.equal(await page.locator('#investigation-filter').inputValue(),'cached');
  assert.match(seen.at(-1),/host_id=[^&]+&cached=true&offset=0&limit=50/);
  await page.locator('#investigation-filter').selectOption('all');await at(serverBase);
  await page.getByText('/usr/bin/tool-1',{exact:true}).waitFor();
  assert.doesNotMatch(seen.at(-1),/cached=/);
  assert.equal(await page.evaluate(()=>document.activeElement?.id),'investigation-filter');
  await page.goto(new URL('/#investigations/cached',page.url()).href);
  await cachedNotice().waitFor();
  // The link back from an assessment page returns to the filtered list the visitor came from.
  await page.goto(new URL('/#investigations/item/example/unknown',page.url()).href);
  await page.getByText('Invalid assessment link',{exact:true}).waitFor();
  assert.equal(await page.getByRole('link',{name:'← Investigations'}).getAttribute('href'),'#investigations/cached');
  await page.goBack();await at('#investigations/cached');
  await cachedNotice().waitFor();
  // Empty filtered result explains the filter instead of claiming nothing exists.
  cachedRows=[];
  await page.locator('#investigation-filter').selectOption('all');
  await page.getByText('/usr/bin/tool-1',{exact:true}).waitFor();
  assert.doesNotMatch(seen.at(-1),/cached=/);
  await page.locator('#investigation-filter').selectOption('cached');
  await page.getByText('No cached known-good verdicts',{exact:true}).waitFor();
  // A change made from further down the page keeps the focused control in view,
  // although navigating to the new address scrolls to the top first.
  await page.setViewportSize({width:1440,height:400});
  await page.locator('#investigation-filter').evaluate(node=>node.scrollIntoView({block:'center'}));
  assert.ok(await page.evaluate(()=>scrollY>0),'the filter starts below the first screen');
  await page.locator('#investigation-filter').selectOption('all');await at('#investigations');
  await page.getByText('/usr/bin/tool-1',{exact:true}).waitFor();
  await page.locator('#ai-control-gates:not([aria-busy])').waitFor();
  const box=await page.locator('#investigation-filter').evaluate(node=>{const r=node.getBoundingClientRect();return {top:r.top,bottom:r.bottom,height:innerHeight,focused:document.activeElement===node};});
  assert.ok(box.focused,'focus returns to the filter');
  assert.ok(box.top>=0&&box.bottom<=box.height,'the focused filter is inside the viewport: '+JSON.stringify(box));
 }finally{
  await page.setViewportSize({width:1440,height:1000});
  await page.unroute('**/api/investigations?*',rows);
  await page.goto(new URL('/#overview',page.url()).href);
 }
};
