const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 await page.locator('[href="#settings/ai"]').first().click();
 await page.locator('#ai-key-form').waitFor();
 let listCalls=0,testCalls=0,releaseList,startedList;
 const waitingList=new Promise(r=>releaseList=r),startList=new Promise(r=>startedList=r);
 const listHandler=async route=>{
  listCalls++;
  if(listCalls===1||listCalls===3)return route.fulfill({status:502,json:{detail:'OpenAI API HTTP 404 (model_not_found); request ID: req_model_fixture'}});
  if(listCalls===4){startedList();await waitingList;return route.fulfill({json:{models:['late-model']}});}
  return route.fulfill({json:{models:['new-model','other-model']}});
 };
 const testHandler=async route=>{
  testCalls++;
  const body=route.request().postDataJSON();
  const stored=await (await page.request.get(new URL('/api/settings',page.url()).href)).json();
  assert.equal(body.expected_model,stored.ai_model,'test must follow successful model persistence');
  assert.equal(body.expected_key_revision,stored.api_key_revision);
  if(testCalls===1){assert.equal(body.expected_model,'missing-model');return route.fulfill({status:502,json:{detail:'Test failed for model missing-model. OpenAI API HTTP 404 (model_not_found); request ID: req_test_fixture. Your saved model was not changed.'}});}
  assert.equal(body.expected_model,'new-model');
  return route.fulfill({json:{ok:true,model:'new-model',detail:'Structured-output test passed for model new-model.'}});
 };
 await page.route('**/api/settings/ai-models',listHandler);
 await page.route('**/api/settings/ai-test',testHandler);
 try{
  // Fresh setup: save the key without any model; failed discovery is not a dead end.
  await page.locator('#ai-key-form [name=api_key]').fill('fixture-key-not-real');
  await page.getByRole('button',{name:'Save API key',exact:true}).click();
  await page.locator('#ai-key-result').filter({hasText:'API key saved'}).waitFor();
  await page.locator('#ai-model-status').filter({hasText:'HTTP 404'}).waitFor();
  assert.equal(await page.locator('#ai-key-form [name=api_key]').inputValue(),'');
  await page.locator('#ai-model').selectOption('__manual__');
  await page.locator('#ai-model-manual').fill('missing-model');
  await page.getByRole('button',{name:'Save AI settings',exact:true}).click();
  await page.locator('#ai-save-result').filter({hasText:'AI settings saved. Model: missing-model'}).waitFor();
  assert.equal(testCalls,0);
  await page.locator('#ai-test').click();
  await page.locator('#ai-test-result').filter({hasText:'req_test_fixture'}).waitFor();
  assert.match(await page.locator('#ai-save-result').textContent(),/AI settings saved/);
  let state=await (await page.request.get(new URL('/api/settings',page.url()).href)).json();
  assert.equal(state.ai_model,'missing-model');
  // Select a replacement: Save and test must send the replacement, not the old model.
  await page.locator('#ai-model-refresh').click();
  await page.locator('#ai-model-status').filter({hasText:'2 available model IDs'}).waitFor();
  await page.locator('#ai-model').selectOption('new-model');
  await page.locator('#ai-test').click();
  await page.locator('#ai-test-result').filter({hasText:'passed for model new-model'}).waitFor();
  assert.match(await page.locator('#ai-saved-model').textContent(),/new-model/);
  await capture('ai-settings');
  await page.locator('#ai-model-refresh').click();
  await page.locator('#ai-model-status').filter({hasText:'HTTP 404'}).waitFor();
  assert.equal(await page.locator('#ai-model').inputValue(),'new-model');
  // An unsaved key may not be silently ignored by testing the old key.
  await page.locator('#ai-key-form [name=api_key]').fill('not-saved');
  await page.locator('#ai-test').click();
  await page.locator('#ai-save-result').filter({hasText:'Save the new API key above first'}).waitFor();
  assert.equal(testCalls,2);await page.locator('#ai-key-form [name=api_key]').fill('');
  await page.locator('#ai-model-refresh').click();await startList;
  await page.locator('[href="#settings/history"]').first().click();
  await page.locator('#history-settings-form').waitFor();
  releaseList();await page.waitForTimeout(100);
  assert.equal(await page.getByText('late-model').count(),0);
 }finally{releaseList();await page.unroute('**/api/settings/ai-models',listHandler);await page.unroute('**/api/settings/ai-test',testHandler);}
 await page.locator('[href="#settings/ai"]').first().click();
 await page.locator('#ai-settings-form').waitFor();
};
