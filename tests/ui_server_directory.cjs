const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let writes=0;
 let rows=Array.from({length:29},(_,i)=>({id:'directory-'+i,name:'Node '+String(i+1).padStart(2,'0'),address:'192.0.2.'+(i+1),port:22,architecture:'amd64',package_manager:'apt',state:i===28?'disabled':'online',enabled:i!==28,last_seen:now,integrity:[],error:''}));
 rows[1].address='2001:db8:85a3::8a2e:370:7334';rows[1].port=2222;
 rows[0].name='Node <img src=x onerror="window.__directoryInjected=true">';rows[0].error='Diagnostic <svg onload="window.__directoryInjected=true">';
 const handler=route=>{if(route.request().method()!=='GET')writes++;return route.fulfill({json:rows});};
 await page.route('**/api/hosts',handler);
 try{
  await page.goto(new URL('/#servers',page.url()).href);await page.locator('.server-directory-card').first().waitFor();
  assert.equal(await page.locator('.server-directory-card').count(),24);
  assert.equal(await page.locator('.server-directory-card small').filter({hasText:'2001:db8'}).textContent(),'[2001:db8:85a3::8a2e:370:7334]:2222');
  assert.equal(await page.locator('#content img[src=x],#content svg[onload]').count(),0);
  assert.equal(await page.evaluate(()=>window.__directoryInjected),undefined);
  await page.locator('#server-list-next').click();assert.equal(await page.locator('.server-directory-card').count(),5);
  await page.locator('[data-nav=overview]').click();await page.locator('[data-nav=servers]').click();
  await page.locator('#server-list-page').filter({hasText:'Page 2 of 2'}).waitFor();
  await page.locator('#server-list-state').selectOption('disabled');assert.equal(await page.locator('.server-directory-card').count(),1);
  assert.equal(await page.getByRole('button',{name:'Manage ↗',exact:true}).isDisabled(),true);
  await page.locator('#server-list-search').fill('no such target');await page.getByRole('heading',{name:'No matching servers',exact:true}).waitFor();
  await page.locator('#server-list-clear').click();assert.equal(await page.locator('.server-directory-card').count(),24);
  await page.locator('#server-list-search').fill('192.0.2.29');assert.equal(await page.locator('.server-directory-card').count(),1);
  await page.locator('#refresh-page').click();await page.locator('#server-list-search').waitFor();
  assert.equal(await page.locator('#server-list-search').inputValue(),'192.0.2.29');
  await page.locator('#server-list-clear').click();
  rows=rows.slice(1,4);rows[0].name='Atlas · Production';rows[1].name='Borealis · Build';rows[2].name='Cygnus · Database';
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});await page.locator('#refresh-page').click();
   await page.locator('.server-name').filter({hasText:'Atlas'}).waitFor();
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
   await capture('server-directory-'+width);
  }
  rows=[];await page.locator('#refresh-page').click();await page.getByRole('heading',{name:'No servers enrolled yet',exact:true}).waitFor();
  assert.equal(writes,0,'Directory browsing must not queue or mutate anything');
 }finally{await page.evaluate(()=>Object.assign(serverListContext,{q:'',state:'all',offset:0}));await page.unroute('**/api/hosts',handler);await page.setViewportSize({width:1440,height:1000});}
};
