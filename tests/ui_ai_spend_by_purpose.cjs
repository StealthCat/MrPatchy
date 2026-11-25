// Settings → AI: current-window spend by activity (issue #982).
const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const limitations=['Amounts are local public-price estimates and conservative reservations, not provider invoices.',
  'Attribution follows each call\'s link to retained AI run history.<img src=x onerror=window.__purposeInjected=true>'];
 const capped={generated_at:1793404800,mode:'daily_cap',enabled:true,timezone:'UTC<img src=x onerror=window.__purposeInjected=true>',
  window_start:1793404800,next_reset:1793491200,next_reset_authoritative:true,call_count:6,counted_usd:'1.636',limitations,groups:[
   {purpose:'triage',call_count:3,settled_usd:'0.125',reserved_usd:'0.2',uncertain_usd:'0.3',counted_usd:'0.625'},
   {purpose:'update_scoring',call_count:1,settled_usd:'0',reserved_usd:'0',uncertain_usd:'0.4',counted_usd:'0.4'},
   {purpose:'<img src=x onerror=window.__purposeInjected=true>',call_count:1,settled_usd:'0',reserved_usd:'0',uncertain_usd:'0',counted_usd:'0.5'},
   {purpose:'unattributed',call_count:1,settled_usd:'0.05',reserved_usd:'0.03',uncertain_usd:'0',counted_usd:'0.111'}]};
 const split={...capped,groups:capped.groups.map((row,index)=>({...row,
  sent_usd:index===0?'0.3':'0',uncertain_outcome_usd:index===1?'0.4':'0'}))};
 const replies=[
  {json:capped},
  {status:503,json:{detail:'Spend fixture temporarily unavailable.'}},
  {json:{...capped,mode:'rate',enabled:false,timezone:null,window_start:null,next_reset:null,call_count:0,counted_usd:'0',groups:[]}},
  {json:{...capped,timezone:'UTC',call_count:0,counted_usd:'0',groups:[]}},
  {json:{...split,next_reset_authoritative:false}},
 ];
 let reads=0;
 const handler=route=>route.fulfill(replies[Math.min(reads++,replies.length-1)]);
 await page.route('**/api/settings/ai-spend-by-purpose',handler);
 try{
  await page.locator('[href="#settings/ai"]').first().click();
  const card=page.locator('#ai-spend-purpose'),refresh=page.locator('#ai-spend-purpose-refresh');
  await card.locator('table').waitFor();
  assert.equal(await card.getByRole('heading',{name:'4. Current window spend by activity'}).count(),1);
  const rows=await card.locator('tbody tr').evaluateAll(list=>list.map(row=>[...row.cells].map(cell=>cell.textContent)));
  assert.deepEqual(rows,[
   ['Process triage','3','$0.125','$0.2','$0.3','$0.625'],
   ['Update importance scoring','1','$0','$0','$0.4','$0.4'],
   // An unknown code never reaches the page as markup or as its raw text.
   ['Other recorded activity','1','$0','$0','$0','$0.5'],
   ['Not attributed (run history pruned or no run)','1','$0.05','$0.03','$0','$0.111'],
  ]);
  assert.deepEqual(await card.locator('tfoot tr').evaluate(row=>[...row.cells].map(cell=>cell.textContent)),['All activity','6','','$1.636']);
  assert.match(await card.textContent(),/Budget window resets .* \(local time\) · Budget timezone UTC<img/s);
  assert.match(await card.textContent(),/not provider invoices/);
  assert.match(await card.textContent(),/read-only: it does not change admission, reservations or the cap/);
  assert.equal(await card.locator('img[src=x]').count(),0);
  assert.equal(await page.evaluate(()=>window.__purposeInjected),undefined);
  await capture?.('settings-ai-spend-by-activity');
  await refresh.click();
  await card.getByRole('alert').filter({hasText:'Spend fixture temporarily unavailable'}).waitFor();
  assert.equal(await card.locator('table').count(),0,'a failed load must not leave stale amounts on screen');
  assert.match(await card.locator('.error-state img').getAttribute('src'),/mr-patchy-error\.webp$/);
  await refresh.click();
  await card.getByRole('status').filter({hasText:'No daily spend cap applies in the current control mode'}).waitFor();
  assert.equal(await card.locator('table').count(),0);
  await refresh.click();
  await card.getByRole('status').filter({hasText:'No billable AI calls are counted in the current budget window'}).waitFor();
  assert.match(await card.textContent(),/not provider invoices/);
  await refresh.click();
  await card.locator('table').waitFor();
  assert.match(await card.textContent(),/Budget recheck at .* \(local time\) · Budget timezone UTC<img/s);
  assert.match(await card.textContent(),/Spend from an earlier budget window may still count after this time\./);
  assert.doesNotMatch(await card.textContent(),/Budget window resets/);
  assert.equal(await card.locator('img[src=x]').count(),0);
  assert.equal(await refresh.isEnabled(),true);
  assert.equal(reads,5);
  await card.getByRole('columnheader',{name:'Unreconciled usage'}).waitFor();
  const splitRows=await card.locator('tbody tr').evaluateAll(list=>list.map(row=>[...row.cells].slice(4).map(cell=>cell.innerText)));
  assert.deepEqual(splitRows,[
   ['Sent: $0.3\nUncertain: $0','$0.625'],['Sent: $0\nUncertain: $0.4','$0.4'],
   ['Sent: $0\nUncertain: $0','$0.5'],['Sent: $0\nUncertain: $0','$0.111'],
  ]);
  // Narrow screens: the card stays inside the viewport and its table scrolls in its own region.
  const size=page.viewportSize();
  await page.setViewportSize({width:320,height:800});
  try{
   await card.scrollIntoViewIfNeeded();
   const fit=await card.evaluate(node=>{
    const width=document.documentElement.clientWidth,wrap=node.querySelector('.table-wrap');
    const outside=[node,...node.querySelectorAll('*')].filter(item=>!(wrap.contains(item)&&item!==wrap)).filter(item=>{const box=item.getBoundingClientRect();return box.left<-1||box.right>width+1;});
    return {outside:outside.length,scrolls:wrap.scrollWidth>=wrap.clientWidth&&getComputedStyle(wrap).overflowX!=='visible'};
   });
   assert.deepEqual(fit,{outside:0,scrolls:true});
   await capture?.('settings-ai-spend-by-activity-320');
  }finally{await page.setViewportSize(size);}
 }finally{await page.unroute('**/api/settings/ai-spend-by-purpose',handler);}
};
