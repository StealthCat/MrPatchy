import pytest
from app import deployment_topology as t

NOW=10000
def c(id,host,kind='worker',source='registration',conf='verified',at=NOW-10,**k):
    return dict(id=id,kind=kind,host_identity=host,source=source,confidence=conf,observed_at=at,**k)

def test_colocated_workers_are_not_independent():
    rows=t.classify([c('w1','h1'),c('w2','h1')],NOW)
    r=t.redundancy(rows,'worker')
    assert not r['independent'] and r['domains']==[['w1','w2']]

def test_distinct_hosts_are_independent():
    rows=t.classify([c('w1','h1'),c('w2','h2')],NOW)
    assert t.redundancy(rows,'worker')['independent']

def test_shared_storage_merges_domains():
    rows=t.classify([c('d1','h1','db',storage_id='san'),c('d2','h2','db',storage_id='san')],NOW)
    assert not t.redundancy(rows,'db')['independent']

def test_name_match_stale_and_missing_never_proven():
    rows=t.classify([c('w1','h1',source='config',conf='declared'),c('w2','h2',at=NOW-9999),c('w3',None)],NOW)
    assert [r['state'] for r in rows]==['unverified','stale','unknown']
    r=t.redundancy(rows,'worker')
    assert not r['independent'] and r['unproven']==['w1','w2','w3'] and r['reason']=='no proven placement'

def test_manual_cannot_override_fresh_conflicting_proof():
    rows=t.classify([c('w1','h1'),c('w1','h2',source='manual',conf='declared')],NOW)
    assert rows[0]['host_identity']=='h1' and rows[0]['conflict']
    rows=t.classify([c('w1','h1',at=NOW-9999),c('w1','h2',source='manual',conf='declared')],NOW)
    assert rows[0]['host_identity']=='h2' and rows[0]['state']=='unverified'

def test_future_timestamp_and_bad_input():
    assert t.classify([c('w1','h1',at=NOW+99999)],NOW)[0]['state']=='stale'
    with pytest.raises(ValueError):t.classify([c('','h1')],NOW)
    with pytest.raises(ValueError):t.classify([c('w1','h1'),c('w1','h2')],NOW)
