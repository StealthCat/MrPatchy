const assert=require('assert/strict');
// #824: Activity → Alert delivery is the routable target of the alert-delivery notification.
module.exports=async(page,capture)=>{
 let role='admin',unreadable=false,writes=0,limit=3;const reads=[],saves=[];const now=Date.now()/1000;
 const identity=async route=>{const r=await route.fetch();return route.fulfill({response:r,json:{...await r.json(),role}});};
 // #1180: the page reads every open undelivered alert from a paged server route; counts come from the server.
 let paged=false;const pendingOffsets=[];
 const row=(id,attempts,error,kind='stale')=>({id,host_id:'missing-host',kind,state:'open',created:now,notified:0,attempted:now,attempts,error});
 const alerts=route=>{reads.push('alerts');const offset=Number(new URL(route.request().url()).searchParams.get('offset')||0);pendingOffsets.push(offset);
  const all=paged?Array.from({length:51},(_,i)=>row('p'+i,1,'',i===50?'oldest-row':'stale')):[row('a1',4,'ConnectError <svg onload=window.__deliveryInjected=true>','stale <img src=x onerror=window.__deliveryInjected=true>')];
  return route.fulfill({json:{items:all.slice(offset,offset+50),offset,limit:50,total:all.length,failing:paged?0:(4>=limit?1:0),failed_attempts:limit}});};
 const config=route=>{reads.push('config');return route.fulfill({json:unreadable?{channel:'webhook',password_configured:false,token_configured:false,unreadable:true}:{enabled:true,channel:'webhook',url:'https://hooks.example.test/secret-path',token_configured:true,password_configured:false,unreadable:false}});};
 // #1172: the threshold endpoint is the only write this page may make.
 const threshold=async route=>{if(route.request().method()==='PUT'){const body=route.request().postDataJSON();saves.push(body);if(body.expected_failed_attempts!==limit)return route.fulfill({status:409,json:{detail:'Alert delivery threshold changed; reload it before editing'}});limit=body.failed_attempts;}else reads.push('threshold');return route.fulfill({json:{failed_attempts:limit,default:3,minimum:1,maximum:20}});};
 const observe=r=>{const path=new URL(r.url()).pathname;if(path.startsWith('/api/')&&r.method()!=='GET'&&path!=='/api/operations/alert-delivery-threshold')writes++;};page.on('request',observe);
 await page.route('**/api/identity',identity);await page.route('**/api/operations/alert-delivery/pending**',alerts);await page.route('**/api/operations/notifications',config);await page.route('**/api/operations/alert-delivery-threshold',threshold);
 try{
  await page.goto(new URL('/#activity/delivery',page.url()).href);
  await page.getByRole('heading',{name:'Undelivered open alerts',exact:true}).waitFor();
  assert.equal(await page.locator('#content nav a[aria-current=page]').textContent(),'Alert delivery');
  assert.match(await page.locator('#content').textContent(),/Webhook/);
  assert.match(await page.locator('#content').textContent(),/1 open alert has failed 3 or more delivery attempts/);
  assert.equal(await page.locator('#content tbody tr').count(),1);assert.equal(pendingOffsets.at(-1),0);
  assert.match(await page.locator('#pending-deliveries').textContent(),/Showing 1–1 of 1, newest first/);assert.equal(await page.locator('[data-delivery-offset]').count(),0);
  assert.doesNotMatch(await page.locator('#content').textContent(),/secret-path|hooks\.example/);
  assert.equal(await page.locator('#content img[src=x],#content svg[onload]').count(),0);
  const field=page.getByLabel('Notify administrators after this many failed attempts');
  assert.equal(await field.inputValue(),'3');assert.equal(await field.getAttribute('min'),'1');assert.equal(await field.getAttribute('max'),'20');
  await field.fill('5');await page.getByRole('button',{name:'Save threshold',exact:true}).click();
  await page.getByText('No open alert has failed 5 or more delivery attempts.',{exact:true}).waitFor(); // the attempts:4 row is now below the threshold
  assert.deepEqual(saves.at(-1),{failed_attempts:5,expected_failed_attempts:3});assert.equal(await field.inputValue(),'5');
  limit=2;await field.fill('7');await page.getByRole('button',{name:'Save threshold',exact:true}).click(); // a concurrent edit changed it to 2
  await page.locator('#toast',{hasText:'reload it before editing'}).waitFor();
  assert.deepEqual(saves.at(-1),{failed_attempts:7,expected_failed_attempts:5});assert.equal(limit,2);
  limit=3;await page.reload();await page.getByRole('heading',{name:'Failure notification',exact:true}).waitFor();
  paged=true;await page.reload();await page.getByText('Showing 1–50 of 51, newest first. Acknowledge alerts from the Operations panel.',{exact:true}).waitFor();
  assert.match(await page.locator('#content').textContent(),/No open alert has failed 3 or more delivery attempts/);
  await field.fill('9'); // paging replaces only the alert list, so unsaved form input survives
  await page.getByRole('button',{name:'Next alerts',exact:true}).click();await page.getByText('Showing 51–51 of 51, newest first. Acknowledge alerts from the Operations panel.',{exact:true}).waitFor();
  assert.equal(pendingOffsets.at(-1),50);assert.equal(await page.locator('#pending-deliveries tbody tr').count(),1);assert.match(await page.locator('#pending-deliveries tbody').textContent(),/oldest-row/);
  assert.equal(await field.inputValue(),'9');assert.equal(await page.evaluate(()=>document.activeElement?.textContent),'Undelivered open alerts');
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('alert-delivery-paged-'+width);}
  await page.getByRole('button',{name:'Previous alerts',exact:true}).click();await page.getByText('Showing 1–50 of 51, newest first. Acknowledge alerts from the Operations panel.',{exact:true}).waitFor();
  assert.equal(pendingOffsets.at(-1),0);paged=false;await page.reload();await page.getByRole('heading',{name:'Failure notification',exact:true}).waitFor();
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('alert-delivery-'+width);}
  await page.getByRole('button',{name:'Open delivery settings',exact:true}).click();
  await page.locator('#notification-form').waitFor();await page.locator('#close-modal').click();
  await page.getByRole('link',{name:'Workers',exact:true}).click();await page.getByRole('heading',{name:'Worker registrations.'}).waitFor();
  await page.goBack();await page.getByRole('heading',{name:'Undelivered open alerts',exact:true}).waitFor();
  unreadable=true;await page.reload();await page.getByText('Unreadable configuration',{exact:true}).waitFor();
  assert.match(await page.locator('#content [role=alert]').textContent(),/cannot be read/);
  role='viewer';await page.goto(new URL('/#activity',page.url()).href);await page.getByRole('heading',{name:'Operations',exact:true}).waitFor();const count=reads.length;await page.goto(new URL('/#activity/delivery',page.url()).href);await page.getByRole('heading',{name:'Administrator access required',exact:true}).waitFor();assert.equal(reads.length,count);
  assert.equal(writes,0);assert.equal(await page.evaluate(()=>window.__deliveryInjected),undefined);
 }finally{page.off('request',observe);await page.unroute('**/api/identity',identity);await page.unroute('**/api/operations/alert-delivery/pending**',alerts);await page.unroute('**/api/operations/notifications',config);await page.unroute('**/api/operations/alert-delivery-threshold',threshold);await page.setViewportSize({width:1440,height:1000});}
};
