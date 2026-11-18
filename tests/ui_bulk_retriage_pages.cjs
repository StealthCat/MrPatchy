const assert=require('assert/strict');
// The Re-triage selection survives paging and the Show filter, up to the endpoint's 50-item limit.
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const hex=n=>n.toString(16).padStart(64,'0');
 const make=(index,approved=false)=>({id:hex(index),host_id:host,evidence:{executable:'/srv/pages/fixture-'+index+'<img src=x onerror=window.__pagesInjected=true>',uid:'1000'},verdict:'low',analysis:'Previous advisory result',approved,last_seen:now,revision:hex(index+1000)});
 // Page 1 holds 50 completed rows, so Next is enabled. Page 2 holds two completed rows and one pending row.
 const first=Array.from({length:50},(_,n)=>make(n+1,n===1));
 let second=[make(101),make(102),{...make(103),verdict:'pending'}];
 const posts=[];
 const rows=route=>{const url=new URL(route.request().url());if(url.searchParams.get('cached')==='true')return route.fulfill({json:[first[0]]});return route.fulfill({json:Number(url.searchParams.get('offset'))>=50?second:first});};
 const submit=async route=>{const data=route.request().postDataJSON();posts.push(data);await route.fulfill({json:{ok:true,queued:data.items.length,request_ids:data.items.map((_,n)=>'request-'+n),detail:`Fresh triage queued for ${data.items.length} investigation(s). Prior assessments retained; AI pause, model settings and admission limits still apply.`}});};
 await page.route('**/api/investigations?*',rows);await page.route('**/api/investigations/retriage',submit);
 const count=page.locator('#bulk-retriage-count'),scope=page.locator('#bulk-retriage-scope'),boxes=page.locator('[data-retriage-select]');
 const next=page.locator('.server-pagination button').last(),previous=page.locator('.server-pagination button').first();
 const waitCount=async n=>page.waitForFunction(n=>document.querySelector('#bulk-retriage-count')?.textContent===String(n),n);
 try{
  await page.goto(new URL('/#investigations',page.url()).href);
  await page.locator('#bulk-retriage').waitFor();assert.equal(await boxes.count(),50);
  await boxes.nth(0).check();await boxes.nth(1).check();await waitCount(2);
  // Paging keeps the selection and says how much of it is off this page.
  await next.click();await page.locator('[data-retriage-select][data-id="'+hex(101)+'"]').waitFor();
  assert.equal(await count.textContent(),'2');await scope.filter({hasText:'2 selected on other pages or filters.'}).waitFor();
  await boxes.nth(0).check();await waitCount(3);
  await previous.click();await page.locator('[data-retriage-select][data-id="'+hex(1)+'"]').waitFor();
  assert.equal(await boxes.nth(0).isChecked(),true);assert.equal(await boxes.nth(1).isChecked(),true);assert.equal(await boxes.nth(2).isChecked(),false);
  await scope.filter({hasText:'1 selected on other pages or filters.'}).waitFor();
  // The Show filter keeps the same selection.
  await page.locator('#investigation-filter').selectOption('cached');
  await page.waitForFunction(()=>document.querySelectorAll('[data-retriage-select]').length===1);
  assert.equal(await count.textContent(),'3');assert.equal(await boxes.nth(0).isChecked(),true);
  await page.locator('#investigation-filter').selectOption('all');await page.waitForFunction(()=>document.querySelectorAll('[data-retriage-select]').length===50);
  // The selection stops at the endpoint's 50-item limit; unchecked boxes are disabled with an explanation.
  for(let n=2;n<49;n++)await boxes.nth(n).check();
  await waitCount(50);await scope.filter({hasText:'Selection limit reached: at most 50 investigations can be re-triaged at once.'}).waitFor();
  assert.equal(await boxes.nth(49).isDisabled(),true);assert.equal(await boxes.nth(0).isDisabled(),false);
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await capture('bulk-retriage-pages-'+width);}
  await page.setViewportSize({width:1440,height:1000});
  await boxes.nth(48).uncheck();await waitCount(49);assert.equal(await boxes.nth(49).isDisabled(),false);
  // A selected row that returns with a new revision is dropped rather than resubmitted with a stale or swapped revision.
  second=[{...second[0],revision:hex(9999)},second[1],second[2]];
  await next.click();await page.locator('[data-retriage-select][data-id="'+hex(101)+'"][data-revision="'+hex(9999)+'"]').waitFor();
  await waitCount(48);assert.equal(await boxes.nth(0).isChecked(),false);
  // A page with no selectable rows still shows the bar while a selection exists.
  second=[{...make(103),verdict:'pending'}];
  await previous.click();await page.locator('[data-retriage-select][data-id="'+hex(1)+'"]').waitFor();
  await next.click();await page.waitForFunction(()=>document.querySelectorAll('[data-retriage-select]').length===0&&document.querySelector('#bulk-retriage'));
  assert.equal(await count.textContent(),'48');await scope.filter({hasText:'48 selected on other pages or filters.'}).waitFor();
  // Submitting covers every selected item, including the approved one, and clears the selection.
  await page.locator('#bulk-retriage').click();await page.locator('#bulk-retriage-form').waitFor();
  await page.locator('.retriage-bulk-list li').filter({hasText:'and 38 more'}).waitFor();
  await page.locator('#bulk-retriage-form [name=reason]').fill('Threat context changed across pages');
  await page.locator('#bulk-retriage-form [name=withdraw]').check();
  await page.getByRole('button',{name:'Queue fresh triage for 48',exact:true}).click();
  await page.locator('#toast').filter({hasText:'Fresh triage queued for 48 investigation(s).'}).waitFor();
  assert.equal(posts.length,1);assert.equal(posts[0].items.length,48);assert.equal(posts[0].withdraw_approval,true);
  const expected=first.slice(0,48).map(row=>({id:row.id,expected_revision:row.revision}));
  assert.deepEqual([...posts[0].items].sort((a,b)=>a.id.localeCompare(b.id)),expected.sort((a,b)=>a.id.localeCompare(b.id)));
  await page.locator('#bulk-retriage').waitFor({state:'detached'});
  await previous.click();await page.locator('[data-retriage-select][data-id="'+hex(1)+'"]').waitFor();
  assert.equal(await count.textContent(),'0');assert.equal(await page.locator('[data-retriage-select]:checked').count(),0);
  // Selections are per view: a server's Investigations tab starts empty while the fleet view has one.
  await boxes.nth(0).check();await waitCount(1);
  await page.goto(new URL('/#servers/'+encodeURIComponent(host)+'/investigations',page.url()).href);
  await page.getByText('Investigations for this server only.').waitFor();await page.locator('#bulk-retriage').waitFor();assert.equal(await count.textContent(),'0');
  assert.equal(await page.locator('[data-retriage-select]:checked').count(),0);
  await page.goto(new URL('/#investigations',page.url()).href);await page.locator('[data-retriage-select]').first().waitFor();
  await waitCount(1);await page.locator('#bulk-retriage-clear').click();await waitCount(0);
  assert.equal(await page.evaluate(()=>window.__pagesInjected),undefined);
 }finally{
  await page.setViewportSize({width:1440,height:1000});await page.unroute('**/api/investigations?*',rows);await page.unroute('**/api/investigations/retriage',submit);await page.goto(new URL('/#overview',page.url()).href);
 }
};
