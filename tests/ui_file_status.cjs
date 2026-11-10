const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;
 const route=async request=>{
  const query=new URL(request.request().url()).searchParams;
  const next=Number(query.get('offset'))>0;
  await request.fulfill({json:{recorded:51,total:51,more:!next,
   counts:{verified:1,unassessed:50},baseline_state:'not_configured',coverage:[],note:'Recorded files only.',
   items:[{path:next?'/second-page':'/example/<img src=x onerror=window.fileInjected=true>',sha256:'a'.repeat(64),
    sources:['managed_file'],observed:now,stale:false,status:next?'unassessed':'verified',
    method:next?'none':'authenticated_repository',reason:'Recorded assessment',behaviors:[]}]}});
 };
 await page.route('**/api/hosts/*/file-status?*',route);
 try{
  await page.goto(new URL('/#files',page.url()).href);
  await page.locator('.file-status-count').filter({hasText:'51 matching'}).waitFor();
  assert.equal(await page.locator('.file-status-results img').count(),0);
  await page.locator('[data-next]').click();
  await page.locator('.file-status-results code').filter({hasText:'/second-page'}).waitFor();
  assert.equal(await page.locator('[data-next]').isDisabled(),true);
  await page.locator('[data-prev]').click();
  await page.locator('.file-status-results code').filter({hasText:'/example/'}).first().waitFor();
  for(const width of [1440,768,320]){
   await page.setViewportSize({width,height:900});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
   if(capture)await capture('file-status-'+width);
  }
  await page.goto(new URL('/#overview/files',page.url()).href);
  await page.locator('.file-status-count').filter({hasText:'51 matching'}).waitFor();
 }finally{
  await page.unroute('**/api/hosts/*/file-status?*',route);
  await page.setViewportSize({width:1440,height:1000});
 }
};
