from app import ha_artifacts as ha

FULL={name:True for name in ha.CAPABILITIES}


def test_full_backend_is_ready():
    result=ha.assess(FULL)
    assert result['ready'] and result['blocked']==[] and result['reason']==''


def test_empty_or_malformed_backend_is_never_ready():
    for backend in (None,{},[],'yes',{'atomic_publish':'true','read_after_publish':1}):
        result=ha.assess(backend)
        assert not result['ready'] and 'instance_key' in result['blocked_authoritative']


def test_missing_capability_blocks_only_dependent_consumers():
    result=ha.assess({**FULL,'symlink_safe_directories':False})
    assert result['blocked']==['evidence_archive']
    assert result['consumers'][4]['missing']==['symlink_safe_directories']


def test_missing_locks_block_coordination_not_authoritative_state():
    result=ha.assess({**FULL,'advisory_locks':False})
    assert not result['ready'] and result['blocked_authoritative']==[]
    assert result['blocked']==['operation_locks','database_maintenance_lock']


def test_caches_never_block_and_inventory_is_consistent():
    ids=[c['id'] for c in ha.inventory()]
    assert len(ids)==len(set(ids))
    for c in ha.inventory():
        assert set(c['requires'])<=set(ha.CAPABILITIES)
        if c['class']==ha.CACHE:assert c['requires']==[]
    ha.inventory()[0]['requires'].append('x')
    assert 'x' not in ha.CONSUMERS[0]['requires']


def test_inventory_matches_source_paths():
    import pathlib
    src=''.join(p.read_text() for p in pathlib.Path('app').glob('*.py') if p.name!='ha_artifacts.py')
    for needle in ('secret.key',"'ssh'","'evidence-archive'","'vendor-packages'","'yara-rules'","'locks'",'database-maintenance.lock',"'apt'","'rpm'"):
        assert needle in src
