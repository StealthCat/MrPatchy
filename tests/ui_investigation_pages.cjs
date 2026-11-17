const assert=require('assert/strict');
// The Investigations page number has an address (#974): <view>[/cached]/page/<n> for page 2 and
// later, the bare view address for page 1. Links, reloads and Back/Forward reproduce the page.
module.exports=async(page,capture)=>{
 const now=Date.now()/1000,seen=[];
 const card=id=>({id,host_id:'fixture',evidence:{executable:'/usr/bin/'+id,uid:0},verdict:'low',approved:false,last_seen:now,analysis:'Assessed.',retry:null,revision:'a'.repeat(64),known_good_reuse:null});
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 // Pages 1-3 are full, so Next is enabled; page 4 and later are past the end of the list.
 const rows=route=>{const url=new URL(route.request().url());seen.push(url.search);
  const cached=url.searchParams.get('cached')==='true',number=Number(url.searchParams.get('offset'))/50+1;
  return route.fulfill({json:number>3?[]:Array.from({length:50},(_,i)=>card((cached?'cached-':'')+'page-'+number+'-tool-'+i))});};
 const at=hash=>page.waitForFunction(expected=>location.hash===expected,hash);
 const shown=(number,cached=false)=>page.getByText('/usr/bin/'+(cached?'cached-':'')+'page-'+number+'-tool-0',{exact:true}).waitFor();
 // Waits for the assessment page's link back to carry this address; text left by a previous page cannot satisfy it.
 const backLink=async hash=>{await page.locator('#content a.button[href="'+hash+'"]',{hasText:'← Investigations'}).waitFor();assert.equal(await page.getByRole('link',{name:'← Investigations'}).count(),1);};
 const open=hash=>page.goto(new URL('/'+hash,page.url()).href);
 const pager=page.locator('#content .server-pagination');
 const next=pager.locator('button',{hasText:'Next'}),previous=pager.locator('button',{hasText:'Previous'});
 const label=async()=>(await pager.locator('.help').textContent()).trim();
 await page.route('**/api/investigations?*',rows);
 try{
  await open('#investigations');await shown(1);
  assert.equal(await label(),'Page 1');assert.equal(await previous.isDisabled(),true);
  assert.match(seen.at(-1),/^\?offset=0&limit=50$/);
  // Next and Previous change the address.
  await next.click();await at('#investigations/page/2');await shown(2);
  assert.equal(await label(),'Page 2');assert.match(seen.at(-1),/^\?offset=50&limit=50$/);
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await capture('investigation-pages-'+width);
  }
  await page.setViewportSize({width:1440,height:1000});
  await next.click();await at('#investigations/page/3');await shown(3);
  assert.match(seen.at(-1),/^\?offset=100&limit=50$/);
  // Back and Forward step through the visited pages.
  await page.goBack();await at('#investigations/page/2');await shown(2);
  await page.goBack();await at('#investigations');await shown(1);
  await page.goForward();await at('#investigations/page/2');await shown(2);
  // A reload stays on the page.
  await page.reload();await shown(2);
  assert.equal(await page.evaluate(()=>location.hash),'#investigations/page/2');
  assert.equal(await label(),'Page 2');assert.match(seen.at(-1),/^\?offset=50&limit=50$/);
  // Previous from page 2 returns to the bare address, which always means page 1.
  await previous.click();await at('#investigations');await shown(1);
  await open('#investigations/page/3');await shown(3);
  await open('#overview');await open('#investigations');await shown(1);
  assert.match(seen.at(-1),/^\?offset=0&limit=50$/);
  // The filter and the page combine; changing the filter returns to page 1.
  await open('#investigations/cached/page/2');await shown(2,true);
  assert.equal(await page.locator('#investigation-filter').inputValue(),'cached');
  assert.match(seen.at(-1),/^\?cached=true&offset=50&limit=50$/);
  await next.click();await at('#investigations/cached/page/3');await shown(3,true);
  await page.locator('#investigation-filter').selectOption('all');await at('#investigations');await shown(1);
  assert.match(seen.at(-1),/^\?offset=0&limit=50$/);
  assert.equal(await page.evaluate(()=>document.activeElement?.id),'investigation-filter');
  // The link back from an assessment page returns to the page and filter the visitor came from.
  await open('#investigations/cached/page/2');await shown(2,true);
  await open('#investigations/item/example/unknown');
  await page.getByText('Invalid assessment link',{exact:true}).waitFor();
  await backLink('#investigations/cached/page/2');
  await page.getByRole('link',{name:'← Investigations'}).click();await at('#investigations/cached/page/2');await shown(2,true);
  // A malformed page address is replaced by the nearest valid one without a history entry of its own.
  for(const [bad,good,number,cached] of [['page/0','',1,false],['page/1','',1,false],['page/abc','',1,false],['page','',1,false],['junk','',1,false],['page/-2','',1,false],['page/2x','',1,false],['page/3/junk','/page/3',3,false],['cached/page/1','/cached',1,true],['cached/junk','/cached',1,true]]){
   await open('#investigations/page/2');await shown(2);
   await open('#investigations/'+bad);await at('#investigations'+good);await shown(number,cached);
   await page.goBack();await at('#investigations/page/2');await shown(2);
  }
  // A page past the end says so and offers the way back.
  await open('#investigations/page/9');
  await page.getByText('Nothing on this page',{exact:true}).waitFor();
  assert.match(seen.at(-1),/^\?offset=400&limit=50$/);
  assert.equal(await label(),'Page 9');assert.equal(await next.isDisabled(),true);assert.equal(await previous.isDisabled(),false);
  assert.equal(await page.getByRole('link',{name:'First page'}).getAttribute('href'),'#investigations');
  await open('#investigations/cached/page/9');
  await page.locator('#content a[href="#investigations/cached"]',{hasText:'First page'}).waitFor();
  await page.getByText('Nothing on this page',{exact:true}).waitFor();
  assert.match(seen.at(-1),/^\?cached=true&offset=400&limit=50$/);
  await page.getByRole('link',{name:'First page'}).click();await at('#investigations/cached');await shown(1,true);
  // One server's Investigations tab has the same addresses and scopes the request to that server.
  const serverBase='#servers/'+encodeURIComponent(host)+'/investigations';
  await open(serverBase+'/page/2');
  await page.getByText('Investigations for this server only.').waitFor();await shown(2);
  assert.match(seen.at(-1),/^\?host_id=[^&]+&offset=50&limit=50$/);assert.equal(await label(),'Page 2');
  await next.click();await at(serverBase+'/page/3');await shown(3);
  await page.goBack();await at(serverBase+'/page/2');await shown(2);
  await page.locator('#investigation-filter').selectOption('cached');await at(serverBase+'/cached');await shown(1,true);
  assert.match(seen.at(-1),/^\?host_id=[^&]+&cached=true&offset=0&limit=50$/);
  await next.click();await at(serverBase+'/cached/page/2');await shown(2,true);
  await open(serverBase+'/item/example/unknown');
  await backLink(serverBase+'/cached/page/2');
  // The fleet view's remembered address is separate from the server's.
  await open('#investigations/item/example/unknown');
  await backLink('#investigations/cached');
 }finally{
  await page.setViewportSize({width:1440,height:1000});
  await page.unroute('**/api/investigations?*',rows);
  await open('#overview');
 }
};
