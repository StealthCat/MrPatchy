"""Read-only recovery readiness from drill receipts (issue #345 slice)."""
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor
import pytest
from app import recovery_readiness as rr
from app.db import Session, Audit
from sqlalchemy import select

NOW=1_800_000_000
IDS={stage:hashlib.sha256(stage.encode()).hexdigest()[:32] for stage in rr.STAGES}


def rec(stage,result='success',age=60,**extra):
    value={'version':2,'stage':stage,'result':result,'completed':NOW-age,'environment':'drill','adapter':'lvm',
           'declared_scope':[],'verified':[],'backup_id':'backup-one','archive_sha256':'a'*64,
           'database_id':'db-one','trust_id':'trust-one','key_fingerprint':'b'*64,'key_verified_at':NOW-age-60,
           'parent_id':IDS[rr.PARENT[stage]] if stage in rr.PARENT else ''}
    if stage=='backup':value.update(declared_scope=['db','evidence'],key_custody='external')
    value.update(extra);return value


def full(**over):
    items=[rec('backup'),rec('archive_verification'),rec('isolated_restore',verified=['db','evidence']),rec('application_recovery',verified=['db'])]
    return [{'id':IDS[x['stage']],**rr.receipt(x,NOW)} for x in items]


def test_no_receipts_is_not_ready():
    r=rr.readiness([],NOW)
    assert not r['ready'] and r['stages']['backup']['state']=='missing' and r['key_custody']=='unknown'


def test_archive_checksum_alone_is_never_ready():
    items=[rr.receipt(rec('backup'),NOW),rr.receipt(rec('archive_verification'),NOW)]
    r=rr.readiness(items,NOW)
    assert not r['ready'] and 'isolated_restore: missing' in r['blockers']


def test_complete_evidence_is_ready():
    r=rr.readiness(full(),NOW)
    assert r['ready'] and r['blockers']==[] and r['unverified_scope']==[]
    assert r['stages']['boot_recovery']['state']=='missing' and not r['stages']['boot_recovery']['required']


def test_stale_failed_and_unverified_scope_block():
    items=full()
    stale=rr.readiness(items,NOW+36*86400)
    assert not stale['ready'] and stale['stages']['isolated_restore']['state']=='stale'
    items=[x for x in items if x['stage']!='isolated_restore']+[rr.receipt(rec('isolated_restore',verified=['db']),NOW)]
    r=rr.readiness(items,NOW)
    assert not r['ready'] and r['unverified_scope']==['evidence']
    failed=rr.readiness(items+[rr.receipt(rec('backup','failure',age=1,declared_scope=[]),NOW)],NOW)
    assert failed['stages']['backup']['state']=='failed' and not failed['ready']


def test_unknown_key_custody_blocks_ready():
    items=[x for x in full() if x['stage']!='backup']+[rr.receipt(rec('backup',key_custody='unknown'),NOW)]
    r=rr.readiness(items,NOW)
    assert not r['ready'] and any('encryption-key custody is not confirmed' in x for x in r['blockers'])


@pytest.mark.parametrize('bad',[{'stage':'x'},{'result':'maybe'},{'completed':NOW+9999},{'completed':True},{'key':'secret'},
                                {'environment':''},{'verified':'db'},{'key_custody':'abc'},{'declared_scope':[]}])
def test_invalid_receipts_rejected(bad):
    with pytest.raises(ValueError):rr.receipt({**rec('backup'),**bad},NOW)


def test_history_is_bounded():
    items=[]
    for _ in range(rr.MAX_RECEIPTS+5):items,_x=rr.add(items,rec('archive_verification'),NOW)
    assert len(items)==rr.MAX_RECEIPTS


def test_api_records_receipts_audits_and_reports(admin):
    assert admin.get('/api/recovery/readiness').json()['ready'] is False
    now=time.time()
    parents={}
    def post(stage,**extra):
        body=rec(stage,**extra);body.update(completed=now-10,key_verified_at=now-20,
            parent_id=parents[rr.PARENT[stage]] if stage in rr.PARENT else '')
        return admin.post('/api/recovery/receipts',json=body)
    assert admin.post('/api/recovery/receipts',json={'stage':'backup','secret_key':'x'}).status_code==400
    for stage,extra in (('backup',{}),('archive_verification',{}),('isolated_restore',{'verified':['db','evidence']}),('application_recovery',{})):
        response=post(stage,**extra)
        assert response.status_code==200
        parents[stage]=response.json()['receipt']['id']
    body=admin.get('/api/recovery/readiness').json()
    assert body['ready'] is True and 'secret' not in str(body).lower()
    with Session() as s:
        assert len(s.scalars(select(Audit).where(Audit.action=='record recovery receipt')).all())==4


def test_viewer_cannot_read_or_record(admin):
    from app.identity import User
    with Session() as s:
        s.get(User,'admin').role='viewer';s.commit()
    assert admin.get('/api/recovery/readiness').status_code==403
    assert admin.post('/api/recovery/receipts',json=rec('backup')).status_code==403


@pytest.mark.parametrize('field,value',[
    ('environment','other'),('adapter','zfs'),('backup_id','other-backup'),
    ('archive_sha256','c'*64),('database_id','other-db'),('trust_id','other-trust'),
    ('key_fingerprint','d'*64),
])
def test_unrelated_evidence_cannot_compose_into_ready(field,value):
    items=full();items[1]={**items[1],field:value}
    report=rr.readiness(items,NOW)
    assert not report['ready'] and report['stages']['archive_verification']['state']=='mismatched'


def test_forged_parent_and_local_key_custody_cannot_be_ready():
    items=full();items[2]={**items[2],'parent_id':'f'*32}
    assert not rr.readiness(items,NOW)['ready']
    items=full();items[0]['key_custody']='local'
    assert not rr.readiness(items,NOW)['ready']


def test_legacy_unversioned_or_malformed_retained_evidence_is_unknown():
    items=full();del items[0]['version']
    report=rr.readiness(items,NOW)
    assert not report['ready'] and report['stages']['backup']['state']=='unknown'
    items=full();items[1]['completed']='not-a-time'
    assert not rr.readiness(items,NOW)['ready']
    items=full();items[0]['declared_scope']=[{}]
    assert not rr.readiness(items,NOW)['ready']


def test_concurrent_api_appends_preserve_every_receipt_and_audit(admin,monkeypatch):
    original=rr.add
    def slow_add(*args,**kwargs):
        time.sleep(.02)
        return original(*args,**kwargs)
    monkeypatch.setattr(rr,'add',slow_add)
    now=time.time();body=rec('backup');body.update(completed=now-10,key_verified_at=now-20)
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses=list(pool.map(lambda _:admin.post('/api/recovery/receipts',json=body),range(8)))
    assert all(response.status_code==200 for response in responses)
    ids={response.json()['receipt']['id'] for response in responses}
    from app.db import Setting
    with Session() as session:
        retained=session.get(Setting,'recovery-receipts').value['items']
        assert {item['id'] for item in retained}==ids and len(ids)==8
        assert len(session.scalars(select(Audit).where(Audit.action=='record recovery receipt')).all())==8
