const assert=require('assert/strict');
module.exports=async(page,capture)=>{
 const id='lifecycle-ui-host',now=Date.now()/1000;let revision='',enabled=true,deleted=false;const writes=[];let blockDeletion=true;
 const host=()=>({id,name:'Lifecycle UI server',address:'192.0.2.201',port:22,state:deleted?'deleted':enabled?'online':'disabled',enabled,deleted_at:deleted?now:0,lifecycle_revision:revision,integrity:[],last_seen:now,error:'',repo_error:'',package_manager:'apt'});
 const handler=async route=>{
  const request=route.request(),url=new URL(request.url()),p=url.pathname;
  if(p==='/api/hosts')return route.fulfill({json:url.searchParams.get('deleted')==='true'?(deleted?[host()]:[]):deleted?[]:[host()]});
  if(!p.startsWith('/api/hosts/'+id))return route.fallback();
  if(p.endsWith('/lifecycle')){const body=request.postDataJSON();assert.equal(body.expected_revision,revision);assert.ok(body.reason.length>=10);enabled=body.enabled;revision='revision-'+writes.length;writes.push(p);return route.fulfill({json:{host:host(),cancelled_jobs:enabled?0:2}});}
  if(p==='/api/hosts/'+id&&request.method()==='DELETE'){const body=request.postDataJSON();assert.equal(body.confirmation,'Lifecycle UI server');assert.equal(body.expected_revision,revision);assert.ok(body.reason.length>=10);if(blockDeletion){blockDeletion=false;return route.fulfill({status:409,json:{detail:'Reconcile the active response hold before deleting this server'}});}deleted=true;enabled=false;writes.push(p);return route.fulfill({json:{deleted:true,history_retained:true}});}
  if(p.endsWith('/security/ai-policy'))return route.fulfill({json:{paused:false,state:'eligible',global_enabled:true,revision:'',reason:''}});
  if(p.endsWith('/summary'))return route.fulfill({json:{host:host(),system:{os:'Fixture OS',architecture:'amd64'},collector:{processes:0,managed_files:0},counts:{packages:0,updates:0,held:0,overdue:0,unapproved:0,pending_ai:0},jobs:{cancelled:2},last_patch:null}});
  if(p.endsWith('/security/history'))return route.fulfill({json:{items:[{id:'retained-scan',report:{state:'incomplete'}}],more:false}});
  return route.fallback();
 };
 await page.route('**/api/**',handler);
 try{
  await page.goto(new URL('/#servers',page.url()).href);
  await page.getByRole('button',{name:'Manage ↗',exact:true}).click();
  const manage=page.locator('#modal [data-server-management]');
  await manage.getByRole('button',{name:'Delete server',exact:true}).click();
  await page.locator('#host-lifecycle-form [name=confirmation]').waitFor();assert.equal(writes.length,0);
  await page.locator('#close-modal').click();

  await page.getByRole('button',{name:'Disable server',exact:true}).click();assert.equal(writes.length,0);
  await page.locator('#host-lifecycle-form [name=reason]').fill('Temporarily suspend management while reviewing the server.');
  await page.getByRole('button',{name:'Disable this server',exact:true}).click();await page.locator('#modal').waitFor({state:'hidden'});
  await page.getByRole('button',{name:'Enable server',exact:true}).waitFor();assert.equal(enabled,false);
  await page.getByRole('link',{name:'Open server →',exact:true}).click();
  await page.locator('.server-tabs').getByRole('link',{name:'Settings',exact:true}).click();
  const management=page.locator('#server-tab-body [data-server-management]');
  await management.getByRole('button',{name:'Delete server',exact:true}).waitFor();
  assert.equal(await management.getByRole('button',{name:'Delete server',exact:true}).count(),1);
  await management.getByRole('button',{name:'Enable server',exact:true}).click();
  await page.locator('#host-lifecycle-form [name=reason]').fill('Resume management after the maintenance review.');
  await page.getByRole('button',{name:'Enable this server',exact:true}).click();await page.locator('#modal').waitFor({state:'hidden'});assert.equal(enabled,true);
  await management.getByRole('button',{name:'Disable server',exact:true}).waitFor();
  assert.equal(new URL(page.url()).hash,'#servers/'+id+'/settings');
  if(capture)await capture('server-delete-settings');
  await page.setViewportSize({width:390,height:844});
  await management.scrollIntoViewIfNeeded();
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  if(capture)await capture('server-delete-settings-mobile',false);
  await management.getByRole('button',{name:'Delete server',exact:true}).click();assert.equal(deleted,false);
  if(capture)await capture('server-delete-confirmation-mobile',false);
  await page.locator('#host-lifecycle-form [name=reason]').fill('Remove management while retaining investigation and audit history.');
  await page.locator('#host-lifecycle-form [name=confirmation]').fill('wrong name');
  await page.getByRole('button',{name:'Delete this server',exact:true}).click();assert.equal(deleted,false);
  await page.locator('#host-lifecycle-form [name=confirmation]').fill('Lifecycle UI server');
  await page.getByRole('button',{name:'Delete this server',exact:true}).click();
  await page.locator('#modal-message').filter({hasText:'Reconcile the active response hold'}).waitFor();assert.equal(deleted,false);
  const afterDelete=[];const track=r=>{const u=new URL(r.url());if(u.pathname==='/api/hosts'||u.pathname==='/api/identity')afterDelete.push(r.method()+' '+u.pathname);};page.on('request',track);
  await page.getByRole('button',{name:'Delete this server',exact:true}).click();await page.locator('#modal').waitFor({state:'hidden'});
  await page.getByRole('heading',{name:'Servers'}).first().waitFor().catch(()=>{});await page.waitForLoadState('networkidle');page.off('request',track);
  assert.equal(afterDelete.filter(x=>x==='GET /api/hosts').length,1,'deletion renders the destination once: '+afterDelete);
  assert.equal(afterDelete.filter(x=>x==='GET /api/identity').length,1,'deletion fetches identity once: '+afterDelete);
  await page.setViewportSize({width:1440,height:1000});
  await page.getByRole('link',{name:'Deleted servers',exact:true}).click();
  await page.getByRole('heading',{name:'Deleted servers',exact:true}).waitFor();
  await page.getByRole('link',{name:'View retained records',exact:true}).click();
  await page.getByRole('heading',{name:'Lifecycle UI server',exact:true}).waitFor();
  assert.equal(await page.getByRole('button',{name:'Enable server',exact:true}).count(),0);
  assert.equal(await page.getByRole('button',{name:'Delete server',exact:true}).count(),0);
  await page.locator('.server-tabs').getByRole('link',{name:'Settings',exact:true}).click();
  await page.locator('#server-tab-body').filter({hasText:'Its retained records are read-only'}).waitFor();
  assert.equal(await page.locator('#server-tab-body [data-host-delete],#server-tab-body [data-host-lifecycle]').count(),0);
  await page.getByRole('link',{name:'Security',exact:true}).click();
  await page.getByRole('heading',{name:'Retained security records',exact:true}).waitFor();
  await page.locator('#retained-security-data').filter({hasText:'retained-scan'}).waitFor();
  assert.equal(writes.length,3);
 }finally{await page.unroute('**/api/**',handler);}
};
