const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const hosts=await(await page.request.get(new URL('/api/hosts',page.url()).href)).json(),host=hosts[0];let pages=0;
 const endpoint='/api/hosts/'+host.id+'/security/incidents';
 const handler=async route=>{
  const url=new URL(route.request().url());if(!url.pathname.startsWith(endpoint))return route.fallback();
  assert.equal(route.request().method(),'GET');
  if(url.pathname===endpoint)return route.fulfill({json:{items:[{id:'pivot',state:'open',updated:1,evidence:{path:'/srv/app/fixture',sha256:'a'.repeat(64)},plans:[]}],more:false}});
  if(!url.pathname.endsWith('/related'))return route.fallback();pages++;
  const older=url.searchParams.get('offset')==='50';if(older){assert.equal(url.searchParams.get('expected_digest'),'digest');assert.equal(url.searchParams.get('as_of'),'1000');}
  return route.fulfill({json:{path:'/srv/app/'+('long-name-'.repeat(25)),sha256:'a'.repeat(64),as_of:1000,evidence_digest:'digest',page_size:50,more:!older,sources:{scans:{examined:50,more:!older,entries_omitted:0},executions:{examined:1,more:false,entries_omitted:44},inspections:{examined:2,more:false,entries_omitted:0}},items:older?[]:[{source:'executions',id:'event',received:1000,observed:900,state:'recorded',matches:[{kind:'Execution',path:'/srv/app/fixture<script>bad()</script>',sha256:'b'.repeat(64),relation:'path_different_hash',capture:'ebpf',identity_verified:false,uid:0}],matches_omitted:2,gaps:['Capture interrupted'],gaps_omitted:0}]}});
 };
 await page.route('**/api/**',handler);
 try{
  await page.goto(new URL('/#servers/'+host.id+'/security',page.url()).href);
  await page.getByRole('button',{name:'Related evidence',exact:true}).click();
  await page.locator('#related-items').filter({hasText:'Same path · different SHA-256'}).waitFor();
  await page.locator('#related-items').filter({hasText:'Identity not verified'}).waitFor();
  assert.equal(await page.locator('#related-items script').count(),0);
  assert.equal(await page.locator('#related-prev').isDisabled(),true);
  if(capture)await capture('related-evidence-desktop',false);
  await page.setViewportSize({width:390,height:844});
  assert.ok(await page.locator('#modal').evaluate(e=>e.scrollWidth<=e.clientWidth+1),'Evidence dialog must fit mobile width');
  if(capture)await capture('related-evidence-mobile',false);
  await page.locator('#related-next').click();
  await page.locator('#related-items').filter({hasText:'No matching records in this page'}).waitFor();
  assert.equal(await page.locator('#related-next').isDisabled(),true);
  await page.locator('#related-prev').click();
  await page.locator('#related-items').filter({hasText:'Identity not verified'}).waitFor();assert.equal(pages,3);
  await page.locator('#close-modal').click();await page.setViewportSize({width:1440,height:1000});
 }finally{await page.unroute('**/api/**',handler);}
};
