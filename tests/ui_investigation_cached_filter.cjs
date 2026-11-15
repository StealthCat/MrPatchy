const assert=require('assert/strict');
// Investigations "Show: Cached known good" filter (#924). The filter asks the server for
// cached=true, returns to page 1, keeps the choice per view and explains an empty result.
module.exports=async(page,capture)=>{
 const now=Date.now()/1000,seen=[];
 const card=(id,cached)=>({id,host_id:'fixture',evidence:{executable:'/usr/bin/'+id,uid:0},verdict:'low',approved:false,last_seen:now,analysis:'Assessed.',retry:null,revision:'a'.repeat(64),known_good_reuse:cached?{cached:true}:null});
 let cachedRows=[card('cached-tool',true)];
 const rows=route=>{const url=new URL(route.request().url());seen.push(url.search);
  const cached=url.searchParams.get('cached')==='true',offset=Number(url.searchParams.get('offset'));
  if(cached)return route.fulfill({json:cachedRows});
  return route.fulfill({json:offset?[card('page-two-tool',false)]:Array.from({length:50},(_,i)=>card(i?'tool-'+i:'cached-tool',!i))});};
 await page.route('**/api/investigations?*',rows);
 try{
  await page.goto(new URL('/#investigations',page.url()).href);
  const filter=page.locator('#investigation-filter');
  await filter.waitFor();
  assert.equal(await filter.inputValue(),'all');
  // Move to page 2, then filter: the request must return to offset 0.
  await page.locator('#content .server-pagination button',{hasText:'Next'}).click();
  await page.getByText('/usr/bin/page-two-tool',{exact:true}).waitFor();
  await filter.selectOption('cached');
  await page.getByText('Showing only verdicts reused from an exact fleet known-good match',{exact:false}).waitFor();
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
  // The choice persists when the view is revisited.
  await page.goto(new URL('/#overview',page.url()).href);
  await page.goto(new URL('/#investigations',page.url()).href);
  await page.getByText('Showing only verdicts reused',{exact:false}).waitFor();
  assert.equal(await page.locator('#investigation-filter').inputValue(),'cached');
  assert.match(seen.at(-1),/cached=true/);
  // Empty filtered result explains the filter instead of claiming nothing exists.
  cachedRows=[];
  await page.locator('#investigation-filter').selectOption('all');
  await page.getByText('/usr/bin/tool-1',{exact:true}).waitFor();
  assert.doesNotMatch(seen.at(-1),/cached=/);
  await page.locator('#investigation-filter').selectOption('cached');
  await page.getByText('No cached known-good verdicts',{exact:true}).waitFor();
  await page.locator('#investigation-filter').selectOption('all');
  await page.getByText('/usr/bin/tool-1',{exact:true}).waitFor();
 }finally{
  await page.setViewportSize({width:1440,height:1000});
  await page.unroute('**/api/investigations?*',rows);
  await page.goto(new URL('/#overview',page.url()).href);
 }
};
