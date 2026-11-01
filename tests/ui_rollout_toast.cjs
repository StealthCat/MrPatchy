const assert=require('assert/strict');
module.exports=async(page)=>{
 let posts=0,release;const waiting=new Promise(resolve=>release=resolve);
 const policy=route=>route.fulfill({json:{}});
 const rollout=async route=>{posts++;await waiting;await route.fulfill({json:{jobs:[{id:'a'},{id:'b'}]}});};
 await page.route('**/api/hosts/*/patch-policy',policy);
 await page.route('**/api/operations/rollouts',rollout);
 try{
  await page.getByRole('button',{name:'Account',exact:true}).click();
  await page.locator('#operations-panel').click();
  await page.locator('#expert-workflows').click();
  await page.locator('#rollout-form textarea[name=packages]').fill('openssl:amd64');
  await page.locator('#rollout-form button[type=submit], #rollout-form .primary').first().click();
  await page.locator('#confirm-rollout').waitFor();
  await page.locator('#confirm-rollout').click();
  await page.waitForFunction(()=>document.querySelector('#confirm-rollout').disabled);
  release();
  await page.locator('#toast').filter({hasText:'Rollout queued: 2 servers'}).waitFor({state:'visible'});
  assert.equal(await page.locator('#modal').evaluate(d=>d.open),false);
  assert.equal(posts,1);
 }finally{release();await page.unroute('**/api/hosts/*/patch-policy',policy);await page.unroute('**/api/operations/rollouts',rollout);}
};
