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
