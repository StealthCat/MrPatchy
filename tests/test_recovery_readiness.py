"""Read-only recovery readiness from drill receipts (issue #345 slice)."""
import time
import pytest
from app import recovery_readiness as rr
from app.db import Session, Audit
from sqlalchemy import select

NOW=1_800_000_000


def rec(stage,result='success',age=60,**extra):
    value={'stage':stage,'result':result,'completed':NOW-age,'environment':'drill','adapter':'lvm','declared_scope':[],'verified':[]}
    if stage=='backup':value.update(declared_scope=['db','evidence'],key_custody='external')
    value.update(extra);return value


def full(**over):
    items=[rec('backup'),rec('archive_verification'),rec('isolated_restore',verified=['db','evidence']),rec('application_recovery',verified=['db'])]
    return [rr.receipt(x,NOW) for x in items]


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
    assert not r['ready'] and 'encryption-key custody is not confirmed' in r['blockers']


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
    def post(stage,**extra):
        body=rec(stage,**extra);body['completed']=now-10
        return admin.post('/api/recovery/receipts',json=body)
    assert admin.post('/api/recovery/receipts',json={'stage':'backup','secret_key':'x'}).status_code==400
    for stage,extra in (('backup',{}),('archive_verification',{}),('isolated_restore',{'verified':['db','evidence']}),('application_recovery',{})):
        assert post(stage,**extra).status_code==200
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
