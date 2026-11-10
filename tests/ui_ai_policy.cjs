const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const hosts=await(await page.request.get(new URL('/api/hosts',page.url()).href)).json(),host=hosts[0];
 await page.goto(new URL('/#servers/'+host.id+'/overview',page.url()).href);
 await page.getByRole('heading',{name:'AI integration · Globally disabled',exact:true}).waitFor();
 await page.getByText('2 process investigation slots',{exact:true}).waitFor();
 await page.getByRole('button',{name:'Change AI capacity',exact:true}).click();
 await page.locator('#server-ai-capacity-form select').selectOption('1');
 await page.locator('#server-ai-capacity-form textarea').fill('Use serial investigation capacity for this server.');
 await page.getByRole('button',{name:'Save AI capacity',exact:true}).click();
 await page.getByText('1 process investigation slot',{exact:true}).waitFor();
 await page.reload();await page.getByText('1 process investigation slot',{exact:true}).waitFor();
 await page.getByRole('button',{name:'Pause AI',exact:true}).click();
 await page.locator('#server-ai-form textarea').fill('Pause this server AI for an operator review.');
 await page.getByRole('button',{name:'Save AI state',exact:true}).click();
 await page.getByRole('heading',{name:'AI integration · Paused',exact:true}).waitFor();
 await page.reload();await page.getByRole('heading',{name:'AI integration · Paused',exact:true}).waitFor();
 if(capture)await capture('server-ai-paused');
 await page.setViewportSize({width:390,height:844});
 assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
 if(capture)await capture('server-ai-paused-mobile');
 await page.getByRole('button',{name:'Resume AI',exact:true}).click();
 await page.locator('#server-ai-form textarea').fill('Resume this server under global AI settings.');
 await page.getByRole('button',{name:'Save AI state',exact:true}).click();
 await page.getByRole('heading',{name:'AI integration · Globally disabled',exact:true}).waitFor();
 // #656: a background refresh that replaces the policy panel while a dialog is open must not strand a successful save.
 for(const mode of ['capacity','pause']){
  const hostsUrl=new URL('/api/hosts',page.url()).href;let release,held=false;
  const gate=new Promise(resolve=>{release=resolve;});
  await page.route(hostsUrl,async route=>{
   if(held||route.request().method()!=='GET')return route.continue();
   held=true;const response=await route.fetch();const body=await response.json();await gate;
   await route.fulfill({response,json:body.map((row,index)=>index?row:{...row,name:row.name+' (renamed '+mode+')'})});
  });
  // Also hold the replacement panel's first policy GET after reading its real pre-save response,
  // so it can only be released after the save has completed (stale read must not win).
  const policyUrl='**/api/hosts/*/security/ai-policy';let releasePolicy,policyHeld=false,policyRead,policyDone;
  const policyGate=new Promise(resolve=>{releasePolicy=resolve;});
  const policyFetched=new Promise(resolve=>{policyRead=resolve;}),policyFulfilled=new Promise(resolve=>{policyDone=resolve;});
  await page.route(policyUrl,async route=>{
   if(policyHeld||route.request().method()!=='GET')return route.continue();
   policyHeld=true;const response=await route.fetch();const body=await response.json();policyRead();await policyGate;
   await route.fulfill({response,json:body});policyDone();
  });
  await page.evaluate(()=>{window.__refresh=refreshInBackground();});
  await page.waitForFunction(()=>true);
  const old=await page.evaluateHandle(()=>document.querySelector('#server-ai-policy'));
  const capacity=mode==='capacity';
  await page.getByRole('button',{name:capacity?'Change AI capacity':'Pause AI',exact:true}).click();
  if(capacity)await page.locator('#server-ai-capacity-form select').selectOption('2');
  await page.locator(capacity?'#server-ai-capacity-form textarea':'#server-ai-form textarea').fill('Deterministic refresh race regression '+mode+'.');
  release();await page.evaluate(()=>window.__refresh);
  await page.waitForFunction(node=>!node.isConnected,old);
  await policyFetched;
  assert.ok(await page.locator('#modal').evaluate(node=>node.open),'dialog stays open until submitted');
  await page.getByRole('button',{name:capacity?'Save AI capacity':'Save AI state',exact:true}).click();
  await page.locator('#modal').waitFor({state:'hidden'});
  const assertSaved=async()=>{
   if(capacity)await page.getByText('2 process investigation slots',{exact:true}).waitFor();
   else await page.getByRole('heading',{name:'AI integration · Paused',exact:true}).waitFor();
  };
  await assertSaved();
  releasePolicy();await policyFulfilled;
  await page.evaluate(()=>new Promise(resolve=>setTimeout(resolve,250)));
  await assertSaved();
  assert.equal(await page.locator('#server-ai-policy').count(),1);
  assert.equal(await page.getByText(capacity?'1 process investigation slot':'AI integration · Globally disabled',{exact:true}).count(),0,'stale pre-save policy read must not replace the saved display');
  assert.equal(await page.getByText('Unable to load server policy').count(),0);
  await page.unroute(hostsUrl);await page.unroute(policyUrl);
 }
 await page.setViewportSize({width:1440,height:1000});
};
