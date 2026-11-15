const assert=require('assert/strict');
// Investigations list marks verdicts reused from the fleet known-good cache (#897).
// The mark is display only, and the administrator links point at the exact reuse and source records.
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;
 const rows=route=>route.fulfill({json:[
  {id:'reused',host_id:'fixture',evidence:{executable:'/usr/bin/cached-tool',uid:0},verdict:'low',approved:false,last_seen:now,analysis:'Exact-match fleet assessment reused.',retry:null,known_good_reuse:{cached:true,assessment_id:'a/1',source_subject:'src 1',source_assessment_id:'s1'}},
  {id:'fresh',host_id:'fixture',evidence:{executable:'/usr/bin/fresh-tool',uid:0},verdict:'low',approved:false,last_seen:now,analysis:'Assessed by the provider.',retry:null,known_good_reuse:null},
  {id:'forged',host_id:'fixture',evidence:{executable:'/usr/bin/forged-tool',uid:0},verdict:'low',approved:false,last_seen:now,analysis:'Not cached.',retry:null,known_good_reuse:{cached:'true'}}
 ]});
 await page.route('**/api/investigations?*',rows);
 try{
  await page.goto(new URL('/#investigations',page.url()).href);
  const card=exe=>page.locator('#content .card.investigation',{has:page.getByText(exe,{exact:true})});
  await card('/usr/bin/cached-tool').waitFor();
  assert.equal(await card('/usr/bin/cached-tool').locator('.cached-known-good').count(),1);
  assert.equal(await card('/usr/bin/fresh-tool').locator('.cached-known-good').count(),0);
  assert.equal(await card('/usr/bin/forged-tool').locator('.cached-known-good').count(),0);
  const reuse=card('/usr/bin/cached-tool');
  assert.equal(await reuse.getByRole('link',{name:'Reuse record'}).getAttribute('href'),'#investigations/item/reused/history/a%2F1');
  assert.equal(await reuse.getByRole('link',{name:'Source assessment'}).getAttribute('href'),'#investigations/item/src%201/history/s1');
  assert.match(await reuse.textContent(),/no provider call was made\. Reuse grants no approval\./);
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
   await capture('investigation-cached-known-good-'+width);
  }
 }finally{
  await page.setViewportSize({width:1440,height:1000});
  await page.unroute('**/api/investigations?*',rows);
  await page.goto(new URL('/#overview',page.url()).href);
 }
};
