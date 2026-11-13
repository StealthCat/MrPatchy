const assert=require('assert/strict');
// Fleet endpoint-agent health on Activity → Workers (issue #737).
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;let failure=false,role='admin';const calls=[];
 const row=(id,health,extra={})=>({host_id:id,name:id,deployment_type:health==='healthy'?'systemd':null,verification:{state:health==='healthy'?'current':health==='offline'?'unavailable':null,checked:now-30,age_seconds:30,issue_count:0},telemetry:{state:'fresh',collected:now-20},health,reason:'Fixture reason for '+health+'.',...extra});
 const agents=route=>{const offset=Number(new URL(route.request().url()).searchParams.get('offset')||0);calls.push(offset);if(failure)return route.fulfill({status:500,json:{detail:'Agent health unavailable'}});
  const items=offset===50?[row('last-agent','healthy')]:[row('down-agent','offline'),row('<img src=x onerror="window.__agentInjected=true">','unknown'),row('ok-agent','healthy')];
  return route.fulfill({json:{generated_at:now,items,offset,limit:50,total:51,more:offset===0,counts:{offline:1,degraded:0,unknown:1,healthy:49},verification_stale_seconds:600,telemetry_stale_seconds:900,gaps:['Disabled servers are not monitored.']}});};
 const identity=async route=>{const response=await route.fetch();return route.fulfill({response,json:{...await response.json(),role}});};
 await page.route('**/api/operations/agents*',agents);await page.route('**/api/identity',identity);
 try{
  await page.goto(new URL('/#activity/workers',page.url()).href);
  const section=page.locator('#endpoint-agent-health');
  await section.locator('.endpoint-agent-table').waitFor();
  assert.equal(await section.locator('tbody tr').count(),3);
  assert.equal(await section.locator('img').count(),0);assert.equal(await page.evaluate(()=>window.__agentInjected),undefined);
  await section.getByText('systemd service (verified receipt)',{exact:false}).waitFor();
  await section.getByText('Deployment type not verified',{exact:false}).first().waitFor();
  await section.getByText('49 healthy',{exact:true}).waitFor();
  assert.equal(await section.getByRole('link',{name:'down-agent'}).getAttribute('href'),'#servers/down-agent/agent');
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('endpoint-agents-'+width);}
  await page.setViewportSize({width:1440,height:1000});
  await section.getByRole('button',{name:'Next agents'}).click();await page.locator('#endpoint-agent-health').getByText('last-agent',{exact:true}).waitFor();
  await page.locator('#endpoint-agent-health').getByRole('button',{name:'Previous agents'}).click();await page.locator('#endpoint-agent-health').getByText('ok-agent',{exact:true}).waitFor();
  assert.deepEqual(calls.slice(-3),[0,50,0]);
  failure=true;await page.locator('#refresh-page').click();await page.locator('#endpoint-agent-health [role=alert]').filter({hasText:'Agent health unavailable'}).waitFor();
  await page.locator('#controller-registrations').waitFor();assert.ok(await page.locator('.worker-registry-table, #worker-registrations, .card').count()>1,'Workers page still renders when agent health fails');
  failure=false;role='viewer';const before=calls.length;await page.reload();await page.getByRole('heading',{name:'Administrator access required',exact:true}).waitFor();assert.equal(calls.length,before,'Unauthorized view must not fetch agent health');
 }finally{await page.unroute('**/api/operations/agents*',agents);await page.unroute('**/api/identity',identity);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
