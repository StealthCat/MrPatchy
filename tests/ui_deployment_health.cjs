const assert=require('assert/strict');
// Unified deployment-health summary on Activity → Workers (issue #843).
module.exports=async(page,capture)=>{
 let failure=false,role='admin';const calls=[];
 const counts=(o={})=>({offline:0,degraded:0,unknown:0,maintenance:0,healthy:0,...o});
 const summary=route=>{calls.push(route.request().url());if(failure)return route.fulfill({status:500,json:{detail:'Deployment health unavailable'}});
  return route.fulfill({json:{generated_at:Date.now()/1000,states:['offline','degraded','unknown','maintenance','healthy'],
   overall:{state:'offline',reason:'Workers: at least one component is offline, missing or stopped.'},
   components:{controllers:{counts:counts({healthy:1}),total:1,state:'healthy',source:'registrations',gaps:['MRPATCHY_EXPECTED_CONTROLLER_IDS is not configured, so a missing or stopped controller cannot be detected.'],error:null},
    workers:{counts:counts({offline:2,maintenance:1,healthy:3}),total:6,state:'offline',source:'configuration',gaps:[],error:null},
    endpoint_agents:{counts:counts(),total:0,state:null,source:'servers',gaps:['<img src=x onerror="window.__deployInjected=true">'],error:null}},
   gaps:['GCP integration nodes are not inventoried yet.']}});};
 const identity=async route=>{const response=await route.fetch();return route.fulfill({response,json:{...await response.json(),role}});};
 await page.route('**/api/operations/deployment-health',summary);await page.route('**/api/identity',identity);
 try{
  await page.goto(new URL('/#activity/workers',page.url()).href);
  const section=page.locator('#deployment-health');
  await section.locator('.deployment-health-table').waitFor();
  assert.equal(await page.locator('#content .card').first().getAttribute('id'),'deployment-health','Summary leads the Workers page');
  await section.locator('.deployment-health-overall .badge.offline').waitFor();
  await section.getByText('Workers: at least one component is offline',{exact:false}).waitFor();
  assert.equal(await section.locator('tbody tr').count(),3);
  const workers=section.locator('tbody tr').nth(1);
  await workers.getByText('2 offline',{exact:true}).waitFor();await workers.getByText('1 maintenance',{exact:true}).waitFor();await workers.getByText('3 healthy',{exact:true}).waitFor();
  await section.locator('tbody tr').nth(2).getByText('none counted',{exact:true}).waitFor();
  assert.equal(await section.locator('img').count(),0);assert.equal(await page.evaluate(()=>window.__deployInjected),undefined);
  await page.locator('#controller-registrations').waitFor();
  for(const width of [320,768,1440]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await capture('deployment-health-'+width);}
  await page.setViewportSize({width:1440,height:1000});
  failure=true;await page.locator('#refresh-page').click();await page.locator('#deployment-health [role=alert]').filter({hasText:'Deployment health unavailable'}).waitFor();
  await page.locator('#controller-registrations').waitFor();
  failure=false;role='viewer';const before=calls.length;await page.reload();await page.getByRole('heading',{name:'Administrator access required',exact:true}).waitFor();assert.equal(calls.length,before,'Unauthorized view must not fetch deployment health');
 }finally{await page.unroute('**/api/operations/deployment-health',summary);await page.unroute('**/api/identity',identity);await page.setViewportSize({width:1440,height:1000});await page.goto(new URL('/#activity',page.url()).href);}
};
