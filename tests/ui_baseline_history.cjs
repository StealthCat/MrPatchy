const assert=require('assert/strict');
module.exports=async(page)=>{
 const hosts=await (await page.request.get(new URL('/api/hosts',page.url()).href)).json(),host=hosts[0];
 const offsets=[];
 const row=n=>({id:'review-'+n,actor:'reviewer-'+n,created:1700000000+n,reason:'Reason for review '+n+' <b>x</b>'});
 const handler=async route=>{
  const url=new URL(route.request().url());
  if(url.pathname.endsWith('/security/baseline/history')){const offset=Number(url.searchParams.get('offset')||0);offsets.push(offset);return route.fulfill({json:{items:offset?[row(21)]:Array.from({length:20},(_,i)=>row(i+1)),more:!offset}});}
  if(url.pathname.endsWith('/security/baseline')&&route.request().method()==='GET')return route.fulfill({json:{state:'not_configured',baseline:null,eligible:true,latest:{id:'inspection-job',created:Date.now()/1000,digest:'c'.repeat(64),inventory:{scope:['/etc/cron.d'],entries:[],missing_roots:[]}},comparison:{state:'unavailable',changes:[]}}});
  if(url.pathname.endsWith('/security/inspections'))return route.fulfill({json:{items:[],more:false}});
  if(url.pathname.endsWith('/security/execution-scans')&&route.request().method()==='GET')return route.fulfill({json:{policy:{enabled:false,paths:['/srv/app'],debounce_seconds:30,cooldown_minutes:15,max_per_hour:4,revision:'',activated:0},state:'disabled',limited:false,counts:{},coverage:{},last_seen:Date.now()/1000,collector_issues:[],items:[],more:false}});
  return route.fallback();
 };
 await page.route('**/api/**',handler);
 try{
  await page.goto(new URL('/#activity',page.url()).href);await page.goto(new URL('/#servers/'+host.id+'/security',page.url()).href);await page.reload();
  await page.getByRole('heading',{name:'Execution-triggered scans',exact:true}).waitFor();
  const header=await page.locator('#execution-scan-panel p').first().innerText();
  assert.ok(!header.includes('{'),header);assert.ok(header.includes('No triggers recorded'),header);
  await page.goto(new URL('/#servers/'+host.id+'/integrity',page.url()).href);
  await page.getByRole('button',{name:'Baseline review history',exact:true}).click();
  const out=page.locator('#startup-baseline-history-output');await out.locator('li').first().waitFor();
  assert.equal(await out.locator('li').count(),20);
  assert.ok((await out.innerText()).includes('reviewer-1'));assert.equal(await out.locator('b').count(),0);
  assert.ok(!(await out.innerText()).includes('"items"'));
  await out.getByRole('button',{name:'Next reviews',exact:true}).click();
  await out.getByText('reviewer-21').waitFor();assert.equal(offsets.at(-1),20);
  await out.getByRole('button',{name:'Previous reviews',exact:true}).click();
  await out.getByText('reviewer-1',{exact:false}).first().waitFor();assert.equal(offsets.at(-1),0);
 }finally{await page.unroute('**/api/**',handler);}
};
