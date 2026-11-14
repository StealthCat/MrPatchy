const assert=require('assert/strict');
// #621: global Agent maintenance defaults in Settings and per-server
// inherit/override controls on Agent health.
module.exports=async(page,capture)=>{
  const hosts=await page.evaluate(async()=>await(await fetch('/api/hosts')).json());
  const host=hosts.find(h=>!h.deleted_at)||hosts[0];
  const original=page.viewportSize();
  const noScroll=async label=>{for(const width of [320,768,1440]){await page.setViewportSize({width,height:900});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true,label+' must fit '+width+'px');if(capture)await capture(label+'-'+width);}await page.setViewportSize(original);};

  // Settings → Agent maintenance against the real API.
  const before=await page.evaluate(async()=>await(await fetch('/api/settings/agent-maintenance')).json());
  assert.deepEqual(before,{auto_upgrade:false,auto_repair:false});
  await page.goto(new URL('/#settings/agents',page.url()).href);
  const form=page.locator('#agent-defaults-form');
  await form.waitFor();
  await page.getByRole('heading',{name:'Agent maintenance',exact:true}).waitFor();
  assert.equal(await form.locator('[name=auto_upgrade]').isChecked(),false);
  assert.equal(await form.locator('[name=auto_repair]').isChecked(),false);
  assert.match(await form.textContent(),/keeps every server override/);
  await form.locator('[name=auto_upgrade]').check();
  await page.getByRole('button',{name:'Save agent maintenance defaults',exact:true}).click();
  await page.locator('#agent-defaults-result').filter({hasText:'Agent maintenance defaults saved.'}).waitFor();
  assert.deepEqual(await page.evaluate(async()=>await(await fetch('/api/settings/agent-maintenance')).json()),{auto_upgrade:true,auto_repair:false});
  // A stale editor is refused by the server's compare-and-set and the message is shown.
  let staleOnce=true;
  const stale=async route=>{if(route.request().method()==='PUT'&&staleOnce){staleOnce=false;return route.fulfill({status:409,json:{detail:'Global agent policy changed; refresh before saving'}});}return route.fallback();};
  await page.route('**/api/settings/agent-maintenance',stale);
  try{
    await form.locator('[name=auto_repair]').check();
    await page.getByRole('button',{name:'Save agent maintenance defaults',exact:true}).click();
    await page.locator('#agent-defaults-result').filter({hasText:'refresh before saving'}).waitFor();
  }finally{await page.unroute('**/api/settings/agent-maintenance',stale);}
  assert.deepEqual(await page.evaluate(async()=>await(await fetch('/api/settings/agent-maintenance')).json()),{auto_upgrade:true,auto_repair:false});
  await noScroll('settings-agent-maintenance');
  // The hub search finds the new section.
  await page.goto(new URL('/#settings',page.url()).href);
  await page.locator('#settings-search').fill('agent repair');
  await page.locator('#settings-hub a[href="#settings/agents"]').waitFor();

  // Server Agent health: inherited vs override display and Use global default.
  const prefix='/api/hosts/'+host.id+'/security/agent';
  let state={policy:{auto_upgrade:true,auto_repair:false},sources:{auto_upgrade:'inherited',auto_repair:'override'},global:{auto_upgrade:true,auto_repair:true}};
  const puts=[];let gets=0;
  const agent=async route=>{
    const request=route.request(),url=new URL(request.url());
    if(url.pathname!==prefix)return route.fallback();
    if(request.method()==='GET'){gets++;return route.fulfill({json:{...state,status:{state:'current',checked:Date.now()/1000,stale:false,issues:[],report:{}},enrolled_outdated:false}});}
    if(request.method()==='PUT'){
      const body=request.postDataJSON();puts.push(body);
      const own=Object.fromEntries(['auto_upgrade','auto_repair'].filter(k=>body[k]!==null&&body[k]!==undefined).map(k=>[k,body[k]]));
      state={policy:{...state.global,...own},sources:Object.fromEntries(['auto_upgrade','auto_repair'].map(k=>[k,k in own?'override':'inherited'])),global:state.global};
      return route.fulfill({json:state.policy});
    }
    return route.fallback();
  };
  await page.route('**/api/hosts/*/security/agent',agent);
  try{
    await page.goto(new URL('/#servers/'+host.id+'/agent',page.url()).href);
    const policy=page.locator('#agent-policy');
    await policy.waitFor();
    const upgrade=policy.locator('[data-option=auto_upgrade]'),repair=policy.locator('[data-option=auto_repair]');
    assert.equal(await upgrade.getAttribute('data-source'),'inherited');
    assert.equal(await policy.locator('[name=auto_upgrade]').inputValue(),'inherit');
    assert.equal(await policy.locator('[name=auto_upgrade] option[value=inherit]').textContent(),'Use global default (On)');
    assert.match(await upgrade.locator('.agent-policy-effective').textContent(),/Effective: On · Inherited Uses the global default, currently On\./);
    // An explicit Off override stays distinct from inheriting the default.
    assert.equal(await repair.getAttribute('data-source'),'override');
    assert.equal(await policy.locator('[name=auto_repair]').inputValue(),'off');
    assert.match(await repair.locator('.agent-policy-effective').textContent(),/Effective: Off · Override This server is set to Off; the global default is On\./);
    assert.equal(await policy.locator('a[href="#settings/agents"]').count(),1);
    await noScroll('server-agent-policy');
    // Saving without changes keeps the inherited option inherited (sends null, not its value).
    await page.getByRole('button',{name:'Save agent policy',exact:true}).click();
    await page.waitForFunction(()=>document.querySelector('#toast').textContent.includes('Agent policy saved'));
    assert.deepEqual(puts.at(-1),{auto_upgrade:null,auto_repair:false,expected:{auto_upgrade:true,auto_repair:false}});
    // Use global default removes the override and the page reloads the effective state.
    const reloaded=gets;
    await policy.locator('[name=auto_repair]').selectOption('inherit');
    await page.getByRole('button',{name:'Save agent policy',exact:true}).click();
    await page.waitForFunction(n=>document.querySelector('[data-option=auto_repair]')?.dataset.source==='inherited',null);
    assert.ok(gets>reloaded,'saving reloads the effective state');
    assert.deepEqual(puts.at(-1),{auto_upgrade:null,auto_repair:null,expected:{auto_upgrade:true,auto_repair:false}});
    assert.match(await page.locator('[data-option=auto_repair] .agent-policy-effective').textContent(),/Effective: On · Inherited/);
    // An explicit override on an inherited option.
    await page.locator('#agent-policy [name=auto_upgrade]').selectOption('off');
    await page.getByRole('button',{name:'Save agent policy',exact:true}).click();
    await page.waitForFunction(()=>document.querySelector('[data-option=auto_upgrade]')?.dataset.source==='override');
    assert.deepEqual(puts.at(-1),{auto_upgrade:false,auto_repair:null,expected:{auto_upgrade:true,auto_repair:true}});
    // Untrusted/missing global data never renders markup.
    state={...state,global:null};
    await page.locator('#agent-refresh').click();
    await page.locator('#agent-policy [name=auto_upgrade] option[value=inherit]').filter({hasText:'Use global default (unavailable)'}).waitFor({state:'attached'});
  }finally{await page.unroute('**/api/hosts/*/security/agent',agent);await page.setViewportSize(original);}

  // Restore the real global default for later modules.
  await page.goto(new URL('/#settings/agents',page.url()).href);
  await page.locator('#agent-defaults-form').waitFor();
  await page.locator('#agent-defaults-form [name=auto_upgrade]').uncheck();
  await page.getByRole('button',{name:'Save agent maintenance defaults',exact:true}).click();
  await page.locator('#agent-defaults-result').filter({hasText:'Agent maintenance defaults saved.'}).waitFor();
  assert.deepEqual(await page.evaluate(async()=>await(await fetch('/api/settings/agent-maintenance')).json()),{auto_upgrade:false,auto_repair:false});
};
