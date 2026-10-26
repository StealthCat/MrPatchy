const assert=require('assert/strict');
module.exports=async function enrollmentUI(page,apiPath,capture){
  // Exercise the real API with the initial built-in Internal profile.
  await page.locator('#install-endpoint').selectOption('internal');
  await page.locator('#install-command pre').filter({hasText:'https://localhost/enroll/'}).waitFor();
  const endpoints=[
    {id:'default',label:'Default (PUBLIC_URL)',url:'https://patchy.example.test'},
    {id:'internal',label:'Internal HTTPS',url:'https://patchy.internal.test:8443'},
    {id:'external',label:'External HTTPS',url:'https://patchy.example.test'}];
  const choices='**'+apiPath+'/enrollment-endpoints',links='**'+apiPath+'/enrollment-link';
  await page.route(choices,route=>route.fulfill({json:{endpoints}}));
  let releaseExternal,markExternal;
  let slowExternal=false;
  const delayed=new Promise(resolve=>releaseExternal=resolve),started=new Promise(resolve=>markExternal=resolve);
  const submitted=[];
  await page.route(links,async route=>{
    const {endpoint}=route.request().postDataJSON();submitted.push(endpoint);
    if(endpoint==='external'&&slowExternal){markExternal();await delayed;}
    const url=endpoints.find(item=>item.id===endpoint).url+'/enroll/fixture';
    await route.fulfill({json:{url,endpoint,expires_in:3600,command:`curl -fsSL ${url} -o /tmp/mrpatchy-enroll.sh && sudo bash /tmp/mrpatchy-enroll.sh`}});
  });
  await page.locator('#install-mode').selectOption('offline');
  await page.locator('#install-mode').selectOption('curl');
  await page.locator('#install-command pre').filter({hasText:'https://patchy.internal.test:8443/enroll/'}).waitFor();
  assert.equal(await page.locator('#install-endpoint option').count(),3);
  await capture('enrollment-curl',false);
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.locator('#modal').evaluate(node=>node.scrollWidth>node.clientWidth),false);
  await capture('enrollment-curl-mobile',false);
  await page.setViewportSize({width:1440,height:1000});
  await page.locator('#install-endpoint').selectOption('external');
  await page.locator('#install-command pre').filter({hasText:'https://patchy.example.test/enroll/'}).waitFor();
  // A late response must not replace the newly selected endpoint's command.
  slowExternal=true;
  await page.locator('#install-endpoint').selectOption('internal');
  await page.locator('#install-command pre').filter({hasText:'https://patchy.internal.test:8443/enroll/'}).waitFor();
  await page.locator('#install-endpoint').selectOption('external');
  await started;
  assert.equal(await page.locator('#install-command pre').count(),0);
  await page.locator('#install-endpoint').selectOption('internal');
  await page.locator('#install-command pre').filter({hasText:'https://patchy.internal.test:8443/enroll/'}).waitFor();
  releaseExternal();await page.waitForTimeout(100);
  assert.match(await page.locator('#install-command').innerText(),/patchy\.internal\.test:8443/);
  assert.ok(submitted.includes('external')&&submitted.includes('internal'));
  // Failure clears the previous command; ordinary/offline downloads remain available.
  await page.unroute(links);
  await page.route(links,route=>route.fulfill({status:400,json:{detail:'HTTPS endpoint is unavailable.'}}));
  await page.locator('#install-endpoint').selectOption('external');
  await page.getByText('Unable to generate a link. Select an endpoint to retry.',{exact:true}).waitFor();
  assert.equal(await page.locator('#install-command pre').count(),0);
  await page.locator('#install-mode').selectOption('download');
  assert.equal(await page.locator('#install-delivery a[download]').count(),1);
  await page.unroute(choices);await page.unroute(links);
};
