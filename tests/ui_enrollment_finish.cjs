const assert=require('assert/strict');
module.exports=async function finishEnrollmentUI(page,apiPath,capture){
 const id=apiPath.split('/').pop();let state='queued',posts=0,reads=0,lost=false,wrong=false;
 const jobs='**/api/jobs?host_id='+id+'&limit=100',detail='**/api/jobs/enrollment-fixture',deploy='**'+apiPath+'/actions/deploy';
 await page.route(jobs,route=>route.fulfill({json:posts?[{id:'enrollment-fixture',host_id:id,action:'deploy',state}]:[]}));
 await page.route(deploy,route=>{posts++;return lost?route.abort():route.fulfill({json:{job_id:'enrollment-fixture'}});});
 await page.route(detail,route=>{reads++;return route.fulfill({json:{id:'enrollment-fixture',host_id:wrong?'another-server':id,action:'deploy',state,output:state==='failed'?'Fixture verification failed':''}});});
 await page.getByRole('button',{name:'I ran the script · Proceed to step 3'}).click();
 await page.locator('[name=fingerprint]').fill('SHA256:'+'a'.repeat(43));
 await page.getByRole('button',{name:'Finish and verify installation',exact:true}).click();
 await page.locator('#enrollment-result').filter({hasText:'Installation queued'}).waitFor();
 assert.equal(posts,1);assert.equal(await page.locator('#modal').evaluate(e=>e.open),true);
 await capture('enrollment-pending',false);
 // Reload reattaches to the job and never POSTs a duplicate operation.
 await page.reload();
 await page.locator('#enrollment-result').filter({hasText:'Installation queued'}).waitFor();
 assert.equal(posts,1);
 state='failed';
 await page.locator('#enrollment-result').filter({hasText:'Fixture verification failed'}).waitFor();
 assert.equal(await page.locator('#modal').evaluate(e=>e.open),true);
 assert.equal(await page.getByRole('button',{name:'Retry installation after reviewing Activity'}).isEnabled(),true);
 await page.setViewportSize({width:390,height:844});
 assert.equal(await page.locator('#modal').evaluate(e=>e.scrollWidth>e.clientWidth),false);
 await capture('enrollment-failed-mobile',false);
 await page.setViewportSize({width:1440,height:1000});
 // The explicit retry loses its POST response; recover by reading job history.
 state='running';lost=true;
 // Hide the old terminal job from the pre-submit baseline.
 await page.unroute(jobs);let queries=0;
 await page.route(jobs,route=>route.fulfill({json:++queries===1?[]:[{id:'enrollment-fixture',host_id:id,action:'deploy',state}]}));
 wrong=true;
 await page.getByRole('button',{name:'Retry installation after reviewing Activity'}).click();
 await page.locator('#enrollment-result').filter({hasText:'Operation identity does not match'}).waitFor();
 assert.equal(posts,2);assert.equal(await page.locator('#modal').evaluate(e=>e.open),true);
 wrong=false;state='complete';
 await page.getByRole('button',{name:'Check installation status',exact:true}).click();
 await page.waitForURL('**/#servers/'+id+'/overview');
 await page.locator('#server-tab-body').getByRole('status').filter({hasText:'Installation verified'}).waitFor();
 assert.equal(await page.locator('#modal').evaluate(e=>e.open),false);
 assert.equal(await page.locator('#server-workspace-select').inputValue(),id);
 assert.equal(posts,2);assert.ok(reads>=3);
 await capture('enrollment-verified-overview');
 await page.reload();
 await page.locator('#server-tab-body').getByRole('status').filter({hasText:'Installation verified'}).waitFor();
 assert.equal(posts,2);assert.equal(await page.locator('#modal').evaluate(e=>e.open),false);
 // Terminal interruption/cancellation stays actionable, and closed progress cannot redirect.
 lost=false;
 for(const terminal of ['interrupted','cancelled']){
  state=terminal;await page.evaluate(id=>finishServer(id),id);
  await page.getByRole('button',{name:'Finish and verify installation',exact:true}).click();
  await page.locator('#enrollment-result').filter({hasText:'Installation '+terminal}).waitFor();
  assert.equal(await page.locator('#modal').evaluate(e=>e.open),true);
  await page.locator('#close-modal').click();
 }
 state='queued';await page.evaluate(id=>finishServer(id),id);
 await page.getByRole('button',{name:'Finish and verify installation',exact:true}).click();
 await page.locator('#enrollment-result').filter({hasText:'Installation queued'}).waitFor();
 await page.locator('#close-modal').click();
 await page.locator('[data-nav=activity]').click();state='complete';
 await page.waitForTimeout(2200);assert.match(page.url(),/#activity$/);
 state='queued';await page.evaluate(id=>finishServer(id),id);
 await page.getByRole('button',{name:'Stop tracking (job continues)',exact:true}).click();
 assert.equal(await page.locator('#modal').evaluate(e=>e.open),false);
 // A stopped tracker must not reappear when a delayed submit response arrives.
 await page.unroute(deploy);await page.unroute(jobs);
 await page.route(jobs,route=>route.fulfill({json:[]}));
 let releaseSubmit,markSubmit;
 const delayedSubmit=new Promise(r=>releaseSubmit=r),submitted=new Promise(r=>markSubmit=r);
 await page.route(deploy,async route=>{markSubmit();await delayedSubmit;await route.fulfill({json:{job_id:'enrollment-fixture'}});});
 await page.evaluate(id=>finishServer(id),id);
 await page.getByRole('button',{name:'Finish and verify installation',exact:true}).click();await submitted;
 await page.getByRole('button',{name:'Stop tracking (job continues)',exact:true}).click();
 releaseSubmit();await page.waitForTimeout(200);
 assert.equal(await page.evaluate(()=>sessionStorage.getItem('mrpatchy-enrollment:admin')),null);
 await page.unroute(jobs);await page.unroute(detail);await page.unroute(deploy);
 await page.locator('[data-nav=servers]').click();
};
