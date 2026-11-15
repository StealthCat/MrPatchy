const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;
 const host=await page.evaluate(async()=>(await(await fetch('/api/hosts')).json())[0].id);
 const make=(index,verdict,approved=false)=>({id:String(index).repeat(64),host_id:host,evidence:{executable:'/srv/bulk/fixture-'+index+'<img src=x onerror=window.__bulkInjected=true>',uid:'1000'},verdict,analysis:'Previous advisory result',approved,last_seen:now,revision:String(index+1).repeat(64).slice(0,64)});
 let items=[make(1,'low'),make(2,'high',true),make(3,'pending'),make(4,'unknown')];const posts=[];let refuse=true;
 const rows=route=>route.fulfill({json:items});
 const submit=async route=>{const data=route.request().postDataJSON();posts.push(data);if(refuse)return route.fulfill({status:409,json:{detail:'Nothing was queued. 1 selected investigation(s) cannot be re-triaged — /srv/bulk/fixture-2: Assessment or approval changed; reopen Re-triage before submitting. Refresh the list and select again.'}});items=items.map(row=>data.items.some(item=>item.id===row.id)?{...row,verdict:'pending',approved:false}:row);await route.fulfill({json:{ok:true,queued:data.items.length,request_ids:data.items.map((_,n)=>'request-'+n),detail:`Fresh triage queued for ${data.items.length} investigation(s). Prior assessments retained; AI pause, model settings and admission limits still apply.`}});};
 await page.route('**/api/investigations?*',rows);await page.route('**/api/investigations/retriage',submit);
 try{
  await page.goto(new URL('/#investigations',page.url()).href);
  const button=page.locator('#bulk-retriage');await button.waitFor();
  // Only completed assessments are selectable; pending work keeps the Retry workflow.
  assert.equal(await page.locator('[data-retriage-select]').count(),3);assert(await button.isDisabled());
  assert.equal(await page.locator('#content img[src=x]').count(),0);
  const boxes=page.getByRole('checkbox',{name:'Select for Re-triage'});
  await boxes.nth(0).check();await boxes.nth(1).check();
  await page.getByRole('button',{name:'Re-triage selected (2)',exact:true}).waitFor();
  await page.getByRole('button',{name:'Clear selection',exact:true}).click();assert(await button.isDisabled());
  await boxes.nth(0).check();await boxes.nth(1).check();await boxes.nth(2).check();
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await capture('bulk-retriage-select-'+width);}
  await button.click();await page.locator('#bulk-retriage-form').waitFor();
  assert.equal(await page.locator('.retriage-bulk-list li').count(),3);assert.equal(await page.locator('#modal img[src=x]').count(),0);
  await page.locator('#bulk-retriage-form [name=reason]').fill('Threat context changed for these');
  const queue=page.getByRole('button',{name:'Queue fresh triage for 3',exact:true});
  await queue.click();assert.equal(posts.length,0,'an approved selection requires explicit withdrawal');
  await page.locator('#bulk-retriage-form [name=withdraw]').check();
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert(await page.locator('#modal').evaluate(el=>el.scrollWidth<=el.clientWidth+1));await capture('bulk-retriage-confirm-'+width,false);}
  await queue.click();await page.getByRole('alert').filter({hasText:'Nothing was queued'}).waitFor();
  assert.equal(posts.length,1);assert.equal(await page.locator('#bulk-retriage-form [name=reason]').inputValue(),'Threat context changed for these');assert.equal(await queue.isDisabled(),false);
  assert.deepEqual(posts[0],{items:[items[0],items[1],items[3]].map(row=>({id:row.id,expected_revision:row.revision})),reason:'Threat context changed for these',withdraw_approval:true});
  refuse=false;await page.locator('#bulk-retriage-form').evaluate(form=>{form.requestSubmit();form.requestSubmit();});
  await page.locator('#toast').filter({hasText:'Fresh triage queued for 3 investigation(s).'}).waitFor();assert.equal(posts.length,2);
  // After the refresh every item is pending, so nothing remains selectable.
  await page.locator('#bulk-retriage').waitFor({state:'detached'});assert.equal(await page.locator('[data-retriage-select]').count(),0);
  assert.equal(await page.evaluate(()=>window.__bulkInjected),undefined);
 }finally{
  await page.setViewportSize({width:1440,height:1000});await page.unroute('**/api/investigations?*',rows);await page.unroute('**/api/investigations/retriage',submit);await page.goto(new URL('/#overview',page.url()).href);
 }
};
