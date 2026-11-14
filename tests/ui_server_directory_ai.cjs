const assert=require('assert/strict');
// Servers directory: per-server AI pause badge and administrator AI filter (#864).
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let writes=0;
 const row=(id,name,extra={})=>({id,name,address:'192.0.2.'+(id.length+10),port:22,architecture:'amd64',package_manager:'apt',state:'online',enabled:true,last_seen:now,integrity:[],error:'',...extra});
 let rows=[row('atlas','Atlas · Production',{ai_paused:true}),row('borealis','Borealis · Build',{ai_paused:false}),
  row('cygnus','Cygnus · Database',{ai_paused:true,enabled:false,state:'disabled'}),row('draco','Draco · Legacy reply')];
 const handler=route=>{if(route.request().method()!=='GET')writes++;return route.fulfill({json:rows});};
 await page.route('**/api/hosts',handler);
 const names=async()=>(await page.locator('.server-directory-card .server-name strong').allTextContents()).sort();
 try{
  await page.goto(new URL('/#servers',page.url()).href);await page.locator('.server-directory-card').first().waitFor();
  assert.equal(await page.locator('#server-list-ai').count(),1,'administrators get the AI filter');
  assert.deepEqual(await page.locator('[data-server-ai=paused]').evaluateAll(nodes=>nodes.map(n=>n.closest('.server-directory-card').querySelector('.server-name strong').textContent).sort()),
   ['Atlas · Production','Cygnus · Database']);
  assert.equal(await page.locator('[data-server-ai=paused] .badge').first().textContent(),'AI paused');
  await page.locator('#server-list-ai').selectOption('paused');
  assert.deepEqual(await names(),['Atlas · Production','Cygnus · Database']);
  assert.equal(await page.locator('#server-list-clear').isDisabled(),false);
  // A missing field (older controller reply) is not paused.
  await page.locator('#server-list-ai').selectOption('active');
  assert.deepEqual(await names(),['Borealis · Build','Draco · Legacy reply']);
  await page.locator('#server-list-state').selectOption('disabled');
  await page.getByRole('heading',{name:'No matching servers',exact:true}).waitFor();
  await page.locator('#server-list-ai').selectOption('paused');assert.deepEqual(await names(),['Cygnus · Database']);
  await page.locator('#refresh-page').click();await page.locator('#server-list-ai').waitFor();
  assert.equal(await page.locator('#server-list-ai').inputValue(),'paused','the filter survives a refresh');
  await page.locator('#server-list-clear').click();
  assert.equal(await page.locator('#server-list-ai').inputValue(),'all');assert.equal(await page.locator('.server-directory-card').count(),4);
  await page.locator('#server-list-ai').selectOption('paused');
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});await page.locator('#refresh-page').click();
   await page.locator('[data-server-ai=paused]').first().waitFor();
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
   await capture('server-directory-ai-'+width);
  }
  // Other roles never receive ai_paused; a stale admin filter must not hide their servers.
  await page.evaluate(()=>{window.__realIsAdmin=isAdmin;isAdmin=()=>false;});
  rows=rows.map(({ai_paused,...rest})=>rest);await page.locator('#refresh-page').click();
  await page.locator('#server-list-ai').waitFor({state:'detached'});await page.waitForFunction(()=>document.querySelectorAll('.server-directory-card').length===4&&!document.querySelector('[data-server-ai]'));
  assert.equal(await page.locator('.server-directory-card').count(),4);
  assert.equal(writes,0,'Directory browsing must not change any AI policy');
 }finally{
  await page.evaluate(()=>{if(window.__realIsAdmin){isAdmin=window.__realIsAdmin;delete window.__realIsAdmin;}Object.assign(serverListContext,{q:'',state:'all',ai:'all',offset:0});});
  // Leave no fixture servers in the shared host cache for later modules.
  rows=[];await page.locator('#refresh-page').click();await page.getByRole('heading',{name:'No servers enrolled yet',exact:true}).waitFor();
  await page.unroute('**/api/hosts',handler);await page.setViewportSize({width:1440,height:1000});
 }
};
