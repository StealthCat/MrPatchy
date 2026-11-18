const assert=require('assert/strict');
// Issue #1083: a traversal started while browser Back is still settling can be dropped,
// which left Back -> Stay on the previous page, and Discard then moved one entry too far.
// Each case drops the guard's first moves (rejected, or silently resolved without moving).
module.exports=async page=>{
 const dialog=page.locator('#modal');
 // Entries are compared by key: the suite runs at Chromium's 50-entry history cap, where a new
 // entry evicts the oldest and indexes stop growing.
 const state=()=>page.evaluate(()=>{const e=navigation.entries(),i=navigation.currentEntry.index;
  return {hash:location.hash,key:navigation.currentEntry.key,previous:e[i-1]?.key??null};});
 const settle=async(hash)=>{await page.waitForFunction(h=>location.hash===h&&!navigation.transition,hash,{timeout:3000}).catch(()=>{});return state();};
 const drop=(mode,count=1)=>page.evaluate(([mode,count])=>{
  // The guard's first moves are dropped whichever API it uses.
  window.__realTraverseTo??=navigation.traverseTo;
  const real=window.__realTraverseTo.bind(navigation),go=History.prototype.go;let left=count;
  history.go=function(delta){if(left<=0)return go.call(this,delta);left--;};
  navigation.traverseTo=(key,options)=>{
   if(left<=0)return real(key,options);
   left--;
   const outcome=mode==='reject'?Promise.reject(new DOMException('dropped','AbortError')):Promise.resolve();
   outcome.catch(()=>{});
   return {committed:outcome,finished:outcome};
  };
 },[mode,count]);
 await page.locator('[data-nav=settings]').click();
 await page.locator('[href="#settings/history"]').first().click();
 const history=page.locator('[name=history_days]');await history.waitFor();
 await page.locator('.settings-nav [href="#settings/patching"]').click();
 const repo=page.locator('[name=repo_minutes]');await repo.waitFor();
 const minutes=await repo.inputValue();
 const start=await state();
 for(const mode of ['reject','resolve']){
  // Back -> Stay returns to the edited page even when the first undo is dropped.
  await drop(mode);
  await repo.fill(String(+minutes+5));
  await page.goBack();
  await page.locator('#modal-title').filter({hasText:'Leave without saving?'}).waitFor();
  await page.locator('#unsaved-stay').click();
  await dialog.waitFor({state:'hidden'});
  assert.deepEqual(await settle('#settings/patching'),start,`Stay after a dropped undo (${mode})`);
  assert.equal(await repo.inputValue(),String(+minutes+5),'Stay must keep the edits');
  // Back -> Discard reaches exactly the requested entry, not one beyond it, even when
  // the undo and all of its retries were lost and the page never left that entry.
  await drop(mode,4);
  await page.goBack();
  await page.locator('#modal-title').filter({hasText:'Leave without saving?'}).waitFor();
  await page.waitForTimeout(500);
  assert.equal((await state()).hash,'#settings/history','the undo was expected to be lost');
  await page.locator('#unsaved-discard').click();
  await history.waitFor();
  const left=await settle('#settings/history');
  assert.equal(left.key,start.previous,`Discard after a lost undo must reach the previous entry, not one beyond it (${mode})`);
  assert.equal(await dialog.evaluate(d=>d.open),false);
  await page.goForward();await repo.waitFor();
  assert.equal(await repo.inputValue(),minutes,'discarded edits were not saved');
 }
 // An in-app tab click with a dropped undo also stays, and Discard then opens that tab once.
 await drop('reject');
 await repo.fill(String(+minutes+5));
 await page.locator('.settings-nav [href="#settings/history"]').click();
 await page.locator('#modal-title').filter({hasText:'Leave without saving?'}).waitFor();
 assert.deepEqual(await settle('#settings/patching'),start,'a held tab click restores the edited entry');
 await page.locator('#unsaved-discard').click();
 await history.waitFor();
 const opened=await settle('#settings/history');
 assert.equal(opened.previous,start.key,'Discard opens the tab directly after the edited entry');
 await page.evaluate(()=>{navigation.traverseTo=window.__realTraverseTo;delete history.go;delete window.__realTraverseTo;});
 assert.equal(await page.evaluate(()=>history.go===History.prototype.go),true);
};
