const assert=require('assert/strict');
// #824: Activity → Alert delivery is the routable target of the alert-delivery notification.
module.exports=async(page,capture)=>{
 let role='admin',unreadable=false,writes=0;const reads=[];const now=Date.now()/1000;
 const identity=async route=>{const r=await route.fetch();return route.fulfill({response:r,json:{...await r.json(),role}});};
 const alerts=route=>{reads.push('alerts');return route.fulfill({json:[
  {id:'a1',host_id:'missing-host',kind:'stale <img src=x onerror=window.__deliveryInjected=true>',message:'x',state:'open',created:now,notified:0,attempted:now,attempts:4,error:'ConnectError <svg onload=window.__deliveryInjected=true>'},
  {id:'a2',host_id:'missing-host',kind:'integrity',message:'y',state:'open',created:now,notified:now,attempted:now,attempts:1,error:''},
  {id:'a3',host_id:'missing-host',kind:'repository',message:'z',state:'acknowledged',created:now,notified:0,attempted:now,attempts:5,error:'ReadTimeout'}]});};
 const config=route=>{reads.push('config');return route.fulfill({json:unreadable?{channel:'webhook',password_configured:false,token_configured:false,unreadable:true}:{enabled:true,channel:'webhook',url:'https://hooks.example.test/secret-path',token_configured:true,password_configured:false,unreadable:false}});};
 const observe=r=>{if(new URL(r.url()).pathname.startsWith('/api/')&&r.method()!=='GET')writes++;};page.on('request',observe);
 await page.route('**/api/identity',identity);await page.route('**/api/operations/alerts',alerts);await page.route('**/api/operations/notifications',config);
 try{
  await page.goto(new URL('/#activity/delivery',page.url()).href);
  await page.getByRole('heading',{name:'Undelivered open alerts',exact:true}).waitFor();
  assert.equal(await page.locator('#content nav a[aria-current=page]').textContent(),'Alert delivery');
  assert.match(await page.locator('#content').textContent(),/Webhook/);
  assert.match(await page.locator('#content').textContent(),/1 open alert has failed three or more delivery attempts/);
  assert.equal(await page.locator('#content tbody tr').count(),1); // delivered and acknowledged alerts are excluded
  assert.doesNotMatch(await page.locator('#content').textContent(),/secret-path|hooks\.example/);
  assert.equal(await page.locator('#content img[src=x],#content svg[onload]').count(),0);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('alert-delivery-'+width);}
  await page.getByRole('button',{name:'Open delivery settings',exact:true}).click();
  await page.locator('#notification-form').waitFor();await page.locator('#close-modal').click();
  await page.getByRole('link',{name:'Workers',exact:true}).click();await page.getByRole('heading',{name:'Worker registrations.'}).waitFor();
  await page.goBack();await page.getByRole('heading',{name:'Undelivered open alerts',exact:true}).waitFor();
  unreadable=true;await page.reload();await page.getByText('Unreadable configuration',{exact:true}).waitFor();
  assert.match(await page.locator('#content [role=alert]').textContent(),/cannot be read/);
  role='viewer';await page.goto(new URL('/#activity',page.url()).href);await page.getByRole('heading',{name:'Operations',exact:true}).waitFor();const count=reads.length;await page.goto(new URL('/#activity/delivery',page.url()).href);await page.getByRole('heading',{name:'Administrator access required',exact:true}).waitFor();assert.equal(reads.length,count);
  assert.equal(writes,0);assert.equal(await page.evaluate(()=>window.__deliveryInjected),undefined);
 }finally{page.off('request',observe);await page.unroute('**/api/identity',identity);await page.unroute('**/api/operations/alerts',alerts);await page.unroute('**/api/operations/notifications',config);await page.setViewportSize({width:1440,height:1000});}
};
