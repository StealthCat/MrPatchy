const assert=require('assert/strict');

// Per-server process-triage backlog panel on fleet AI activity (#975).
module.exports=async(page,capture)=>{
  const pattern='**/api/investigation-status/servers';
  const originalViewport=page.viewportSize();
  let calls=0,release,requestStarted;
  const held=new Promise(resolve=>release=resolve),started=new Promise(resolve=>requestStarted=resolve);
  const policyNotice='A server with an invalid saved AI policy stays paused until an administrator repairs it.';
  const populated={generated_at:1700000000,servers_with_backlog:51,truncated:true,max_servers:50,limitations:['Point-in-time read <b>only</b>.',policyNotice],servers:[
    {host_id:'host/<one>',name:'web-<01>',pending:7,active:1,eligible:3,blocked:2,retry_wait:1,paused:true,active_leases:2,investigation_limit:2,at_investigation_limit:true,oldest_pending_observation_at:1700000000,next_retry_at:null},
    {host_id:'host-two',name:'',pending:1,active:0,eligible:0,blocked:0,retry_wait:1,paused:false,active_leases:0,investigation_limit:3,at_investigation_limit:false,oldest_pending_observation_at:1700000000,next_retry_at:1700003600},
  ]};
  const routeHandler=async route=>{
    switch(++calls){
      case 1:return route.fulfill({status:503,json:{detail:'Internal fixture details'}});
      case 2:return route.fulfill({json:{generated_at:1700000000,servers:[],servers_with_backlog:0,truncated:false,max_servers:50,limitations:['Not shown when empty']}});
      case 3:return route.fulfill({json:populated});
      default:requestStarted();await held;return route.fulfill({json:populated});
    }
  };
  await page.route(pattern,routeHandler);
  try{
    await page.locator('[data-nav=ai-logs]').click();
    const panel=page.getByRole('region',{name:'Servers holding the triage backlog',exact:true});
    await panel.getByRole('button',{name:'Load server backlog'}).click();
    await panel.getByRole('status').filter({hasText:'Server backlog is unavailable'}).waitFor();
    assert.equal(await panel.getByText('Internal fixture details').count(),0);
    assert.equal(await page.locator('#ai-log-table').isVisible(),true);
    await panel.getByRole('button',{name:'Retry server backlog'}).click();
    await panel.getByRole('status').filter({hasText:'No server has pending process investigations.'}).waitFor();
    assert.equal(await panel.getByRole('table').isVisible(),false);
    assert.equal(await panel.getByText('Not shown when empty').isVisible(),false);
    await panel.getByRole('button',{name:'Refresh server backlog'}).click();
    const first=panel.getByRole('row',{name:/web-<01>/});
    await first.waitFor();
    assert.deepEqual((await first.getByRole('cell').allTextContents()).slice(1,7),['7','1','3','1','2','AI paused · At limit (2 of 2)']);
    assert.equal((await first.getByRole('cell').allTextContents())[8],'—');
    assert.equal(await first.getByRole('link').getAttribute('href'),'#servers/'+encodeURIComponent('host/<one>')+'/investigations');
    // An unnamed server falls back to its ID; a server below its limit shows lease use.
    const second=panel.getByRole('row',{name:/host-two/});
    assert.equal((await second.getByRole('cell').allTextContents())[6],'0 of 3 leases');
    assert.notEqual((await second.getByRole('cell').allTextContents())[8],'—');
    assert.match(await panel.getByRole('status').textContent(),/51 servers with pending process investigations\. Showing the 2 largest backlogs\./);
    // Untrusted text renders as text, never markup.
    assert.equal(await panel.locator('li').first().textContent(),'Point-in-time read <b>only</b>.');
    assert.equal(await panel.locator('b').count(),0);
    for(const width of [320,768,1440]){
      await page.setViewportSize({width,height:900});
      assert.equal(await panel.getByText(policyNotice,{exact:true}).isVisible(),true);
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
      await capture('ai-triage-servers-'+width);
    }
    // A late reply after leaving the page must not touch the old panel or throw.
    await panel.getByRole('button',{name:'Refresh server backlog'}).click();await started;
    const response=page.waitForResponse(pattern);
    await page.locator('[data-nav=overview]').click();
    await page.getByRole('heading',{name:'A healthier fleet starts here.'}).waitFor();
    release();await response;
    assert.equal(await panel.count(),0);
  }finally{
    release();await page.unroute(pattern,routeHandler);await page.setViewportSize(originalViewport);
  }
};
