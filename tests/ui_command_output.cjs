const assert=require('assert/strict');
// #753: recorded command output keeps whitespace and columns, scrolls inside its own block,
// renders markup literally and copies the exact original text.
module.exports=async(page,capture)=>{
 const now=Date.now()/1000;
 const long='E: '+'unable-to-fetch-archive-segment-'.repeat(12)+'END';
 const output='\nPackage           Current      Candidate\nopenssl           3.0.2-0ubuntu1   3.0.2-0ubuntu1.18\n\tindented\twith tabs\n    four leading spaces  and  double  gaps   \n<b>literal markup</b> <img src=x onerror=window.__outputInjected=true>\n'+long+'\n';
 const job={id:'output-operation',host_id:'output-host',action:'patch',created:now,state:'succeeded',output};
 const detail=route=>route.fulfill({json:job});
 const list=route=>route.fulfill({json:[job]});
 await page.context().grantPermissions(['clipboard-read','clipboard-write'],{origin:new URL(page.url()).origin});
 await page.route('**/api/jobs/output-operation*',detail);await page.route('**/api/jobs',list);await page.route('**/api/jobs?*',list);
 const check=async(scope)=>{
  const pre=scope.locator('.command-output pre');await pre.waitFor();
  assert.equal(await pre.evaluate(e=>e.textContent),output,'rendered text must equal the original, including the leading newline, tabs and trailing spaces');
  const style=await pre.evaluate(e=>{const s=getComputedStyle(e);return {ws:s.whiteSpace,wrap:s.overflowWrap,font:s.fontFamily,ox:s.overflowX};});
  assert.ok(['pre'].includes(style.ws)||style.ws.startsWith('pre ')||style.ws==='preserve nowrap',`white-space ${style.ws}`);
  assert.match(style.font,/monospace/);assert.equal(style.ox,'auto');
  assert.equal(await pre.locator('b,img').count(),0);
  return pre;
 };
 try{
  for(const width of [320,768,1440]){
   await page.setViewportSize({width,height:1000});
   await page.goto(new URL('/#activity/jobs/output-operation',page.url()).href);await page.getByRole('heading',{name:'Operation detail',exact:true}).waitFor();
   const pre=await check(page.locator('#content'));
   assert.equal(await pre.evaluate(e=>e.scrollWidth>e.clientWidth),true,'a long line scrolls inside the output block');
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'output must not stretch the page at '+width);
   await capture('operation-output-'+width);
  }
  await page.getByRole('button',{name:'Copy output',exact:true}).click();
  await page.locator('.command-output-status').filter({hasText:'Output copied.'}).waitFor();
  assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),output,'copy keeps the exact original text');
  await page.goto(new URL('/#activity',page.url()).href);
  const row=page.locator('#content details.source').first();await row.locator('summary').click();
  await check(row);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  job.output='';await page.goto(new URL('/#activity/jobs/output-operation',page.url()).href);await page.getByText('No output recorded yet.').waitFor();
  assert.equal(await page.getByRole('button',{name:'Copy output',exact:true}).count(),0,'no copy control for missing output');
  assert.equal(await page.evaluate(()=>window.__outputInjected),undefined);
 }finally{job.output=output;await page.unroute('**/api/jobs/output-operation*',detail);await page.unroute('**/api/jobs',list);await page.unroute('**/api/jobs?*',list);await page.context().clearPermissions();await page.setViewportSize({width:1440,height:1000});}
};
