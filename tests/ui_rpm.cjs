const assert=require('assert/strict');
module.exports=async(page,hosts,capture)=>{
  const rpmHosts=hosts.map((h,i)=>i?h:{...h,name:'Fedora build server',package_manager:'rpm',architecture:'x86_64'});
  const id=rpmHosts[0].id;
  const hostHandler=route=>route.fulfill({json:rpmHosts});
  const repoHandler=route=>route.fulfill({json:{package_manager:'rpm',last_checked:Date.now()/1000,error:'',health:[],keys:['/etc/pki/rpm-gpg/vendor.asc'],editable_paths:['/etc/yum.repos.d/vendor.repo'],files:{'/etc/yum.repos.d/vendor.repo':'[vendor]\nname=Vendor\nbaseurl=https://repo.example.test/rpm\ngpgcheck=1\n','/etc/dnf/dnf.conf':'[main]\ninstallonly_limit=3\n'}}});
  await page.route('**/api/hosts',hostHandler);
  await page.route('**/api/hosts/'+id+'/repositories',repoHandler);
  try{
    await page.locator('[data-nav=servers]').click();
    await page.getByText('Fedora build server',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Manage ↗'}).first().click();
    assert.equal(await page.locator('#release-upgrade').isDisabled(),true);
    await page.locator('#repair-packages').click();
    await page.getByText('Rebuild and verify the RPM database',{exact:false}).waitFor();
    await page.locator('#close-modal').click();
    await page.evaluate(host=>{selected=host;},id);
    await page.locator('[data-nav=repositories]').click();
    await page.locator('summary').filter({hasText:'/etc/yum.repos.d/vendor.repo'}).click();
    assert.equal(await page.locator('textarea[data-path="/etc/yum.repos.d/vendor.repo"]').isEditable(),true);
    assert.equal(await page.locator('textarea[data-path="/etc/dnf/dnf.conf"]').isEditable(),false);
    await capture('rpm-repositories');
    await page.locator('#new-source').click();
    assert.equal(await page.locator('#new-source-form [name=path]').inputValue(),'/etc/yum.repos.d/custom.repo');
    assert.match(await page.locator('#new-source-form [name=content]').getAttribute('placeholder'),/gpgcheck=1/);
    await page.locator('#close-modal').click();
    await page.locator('#upload-key').click();
    await page.getByText('RPM keys are imported into the system RPM trust database',{exact:false}).waitFor();
    await page.locator('#close-modal').click();
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  }finally{
    await page.unroute('**/api/hosts',hostHandler);
    await page.unroute('**/api/hosts/'+id+'/repositories',repoHandler);
    await page.setViewportSize({width:1440,height:1000});
  }
};
