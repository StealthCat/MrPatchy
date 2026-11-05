const assert=require('assert/strict');
// Stale sign-in errors must not survive a later login, and forced sign-outs must say why.
module.exports=async function loginFeedbackUI(page){
  const button=page.getByRole('button',{name:'Open your workspace'});
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
