const assert=require('assert/strict');
// Stale sign-in errors must not survive a later login, and forced sign-outs must say why.
module.exports=async function loginFeedbackUI(page){
  const button=page.getByRole('button',{name:'Open your workspace'});
  // Sign-in inputs mirror the server's Login contract so out-of-contract values never leave the browser (#419).
  const username=page.locator('#login-form [name=username]'),password=page.locator('#login-form [name=password]');
  assert.equal(await username.getAttribute('maxlength'),'64');
  assert.equal(await password.getAttribute('maxlength'),'1024');
  let loginRequests=0;const countLogin=request=>{if(new URL(request.url()).pathname==='/login')loginRequests++;};
  page.on('request',countLogin);
  for(const rejected of ['bad user','admin<script>','ops$','']){
    await username.fill(rejected);
    assert.equal(await username.evaluate(input=>input.validity.valid),false,rejected);
  }
  await username.fill('a'.repeat(65));
  assert.equal((await username.inputValue()).length,64);
  for(const accepted of ['admin','ops.team_1-x','a'.repeat(64)]){
    await username.fill(accepted);
    assert.equal(await username.evaluate(input=>input.validity.valid),true,accepted);
  }
  await username.fill('bad user');await password.fill('ui-test-password-long');
  await button.click();
  await page.waitForTimeout(200);
  assert.equal(loginRequests,0);
  assert.equal(await page.locator('#login-error').textContent(),'');
  page.off('request',countLogin);
  await username.fill('admin');
  await page.locator('[name=password]').fill('wrong-password-value');
  await button.click();
  await page.waitForFunction(()=>document.querySelector('#login-error').textContent.trim().length>0);
  await page.locator('[name=password]').fill('ui-test-password-long');
  await button.click();
  await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
  assert.equal(await page.locator('#login-error').textContent(),'');
  await page.locator('#logout').click();
  await button.waitFor();
  assert.equal(await page.locator('#login-error').textContent(),'');
  await page.locator('[name=username]').fill('admin');
  await page.locator('[name=password]').fill('ui-test-password-long');
  await button.click();
  await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
};
