from app import package_history, update_scores


def _inv():
    return {'package_manager':'rpm','rpm_packages':[
        {'name':'kernel','arch':'x86_64','evr':'5.1-2'},{'name':'kernel','arch':'x86_64','evr':'5.1-1'},
        {'name':'bash','arch':'x86_64','evr':'5.2-1'}]}


def test_version_index_matches_scan():
    inv=_inv();index=package_history.version_index(inv)
    for name in ('kernel:x86_64','bash:x86_64','missing:noarch'):
        assert package_history.versions(inv,name,'fb',index)==package_history.versions(inv,name,'fb')
    assert index['kernel:x86_64']==['5.1-1','5.1-2']


def test_identity_unchanged_with_index():
    class H:id='h1';inventory=_inv()
    class P:name='kernel:x86_64';installed='5.1-2';candidate='5.2-1';priority='normal';priority_manual=False;held=False;dpkg_state='install ok installed'
    index=package_history.version_index(H.inventory)
    assert update_scores.identity(H,P)==update_scores.identity(H,P,index)


def test_apt_host_index_empty_uses_fallback():
    inv={'package_manager':'apt'}
    assert package_history.version_index(inv)=={}
    assert package_history.versions(inv,'curl','1.0',{})==['1.0']


def test_memoized_identity_reuses_unchanged_and_invalidates_on_change(monkeypatch):
    update_scores._MEMO.clear()
    class H:id='h-memo';inventory=_inv()
    class P:name='kernel:x86_64';installed='5.1-2';candidate='5.2-1';priority='normal';priority_manual=False;held=False;dpkg_state='ok'
    calls={'index':0,'identity':0}
    real_index,real_identity=update_scores.version_index,update_scores.identity
    monkeypatch.setattr(update_scores,'version_index',lambda inv:(calls.__setitem__('index',calls['index']+1),real_index(inv))[1])
    monkeypatch.setattr(update_scores,'identity',lambda *a:(calls.__setitem__('identity',calls['identity']+1),real_identity(*a))[1])
    first=update_scores.cached_identity(H,P,update_scores._memo(H))
    for _ in range(3):assert update_scores.cached_identity(H,P,update_scores._memo(H))==first
    assert calls=={'index':1,'identity':1}
    assert first==real_identity(H,P)
    H.inventory={**_inv(),'rpm_packages':_inv()['rpm_packages']+[{'name':'kernel','arch':'x86_64','evr':'5.1-3'}]}
    changed=update_scores.cached_identity(H,P,update_scores._memo(H))
    assert changed!=first and changed==real_identity(H,P) and calls=={'index':2,'identity':2}
    P.candidate='5.3-1'
    assert update_scores.cached_identity(H,P,update_scores._memo(H))==real_identity(H,P)
