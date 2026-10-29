import time
from types import SimpleNamespace
import pytest
from app import security_coverage as coverage
from app.db import Session,Host,Job
from app.incidents import Scan,Incident
from app.identity import User


def report(engine='ClamAV',**changes):
    return {'engine':engine,'state':'no_detections','available':True,'scanned':3,'findings':[],'roots':['/srv'],'gaps':[],'signatures':{'state':'recent','built_at':time.time(),'expires':time.time()+3600},**changes}


def test_engine_separation_latest_failure_and_disabled_history(admin):
    now=time.time()
    with Session() as s:
        for id in ('one','two','deleted'):s.add(Host(id=id,name=id,address='192.0.2.1',fingerprint='',enabled=id!='two',deleted_at=now if id=='deleted' else 0))
        s.add(Scan(id='clam-old',host_id='one',created=now-100,report=report()))
        s.add(Scan(id='yara-new',host_id='one',created=now-10,report=report('YARA')))
        s.add(Job(id='failed',host_id='one',action='security-scan',state='failed',created=now-5));s.commit()
    r=admin.get('/api/security/coverage');assert r.status_code==200
    data=r.json();assert data['summary']['servers']==2
    first=data['items'][0];assert first['id']=='one'
    assert first['engines']['ClamAV']['state']=='attempt_failed'
    assert first['engines']['YARA']['state']=='recorded'
    assert data['items'][1]['enabled'] is False
    assert data['items'][1]['engines']['ClamAV']['state']=='never_scanned'


@pytest.mark.parametrize('changes,expected',[
    ({'signatures':{'state':'recent','built_at':0}},'incomplete'),
    ({'available':False},'incomplete'),({'gaps':['limit']},'incomplete'),
    ({'state':'completed_with_findings','findings':[{'path':'/srv/file'}]},'findings'),
    ({'state':'completed_with_findings'},'incomplete')])
def test_conservative_coverage(changes,expected):
    scan=SimpleNamespace(id='scan',created=time.time(),report=report(**changes))
    assert coverage.assessment(scan,None,time.time(),86400)['state']==expected


def test_future_signatures_are_incomplete_at_assessment_time():
    # Construct relative timestamps at execution, not collection: MySQL suites can
    # take long enough for collection-time future dates to enter the skew budget.
    now=time.time()
    scan=SimpleNamespace(id='scan',created=now,report=report(signatures={'state':'recent','built_at':now+1000}))
    result=coverage.assessment(scan,None,now,86400)
    assert result['state']=='incomplete' and result['signatures']=='future'


def test_expiry_and_scan_age_are_recomputed():
    now=time.time()
    scan=SimpleNamespace(id='scan',created=now-90000,report=report())
    assert coverage.assessment(scan,None,now,86400)['state']=='overdue'
    scan.report=report('YARA',signatures={'state':'recent','expires':now-1})
    assert coverage.assessment(scan,None,now,86400)['signatures']=='stale'


def test_search_pagination_and_role_boundaries(admin):
    with Session() as s:
        for id in ('alpha','alpha%','beta'):s.add(Host(id=id,name=id,address='192.0.2.1',fingerprint=''))
        s.commit()
    assert len(admin.get('/api/security/coverage?q=%25').json()['items'])==1
    first=admin.get('/api/security/coverage?limit=1').json();assert first['more'] and first['items'][0]['id']=='alpha'
    assert admin.get('/api/security/coverage?limit=0').status_code==400
    for role in ('viewer','operator'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get('/api/security/coverage').status_code==403


def test_missing_receipts_and_pending_attempts_do_not_promote_old_coverage():
    now=time.time();scan=SimpleNamespace(id='old',created=now-10,report=report())
    attempt=SimpleNamespace(id='new',created=now,state='complete')
    assert coverage.assessment(scan,attempt,now,86400)['state']=='receipt_missing'
    attempt.state='running'
    assert coverage.assessment(scan,attempt,now,86400)['state']=='pending'
    scan.report.pop('signatures');assert coverage.assessment(scan,None,now,86400)['state']=='incomplete'
