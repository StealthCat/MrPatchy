import pytest
from app.db import Session,Host
from app.ai_runs import AIRun,AIRunHost
from app.update_scores import UpdateScore
from app.identity import User


def test_detail_scope_direct_shared_legacy_and_unlinked(admin,monkeypatch):
    from app import ai,ssh
    monkeypatch.setattr(ai,'request',lambda *a,**k:pytest.fail('History must not call AI'))
    monkeypatch.setattr(ssh,'call',lambda *a,**k:pytest.fail('History must not contact targets'))
    with Session() as s:
        for host in ('a','b','c'):s.add(Host(id=host,name=host,address='192.0.2.1',fingerprint='',enabled=False))
        s.add_all([AIRun(id='direct',purpose='triage',host_id='a'),AIRun(id='shared',purpose='update_scoring'),AIRun(id='legacy',purpose='update_scoring')]);s.flush()
        s.add_all([AIRunHost(run_id='shared',host_id='a'),AIRunHost(run_id='shared',host_id='b'),UpdateScore(id='score',host_id='a',name='fixture',installed='1',candidate='2',run_id='legacy')]);s.commit()
    for run in ('direct','shared','legacy'):
        result=admin.get('/api/ai/runs/'+run+'?host_id=a');assert result.status_code==200
        assert result.json()['shared_batch']==(run=='shared')
        assert admin.get('/api/ai/runs/'+run+'?host_id=c').status_code==404
    assert admin.get('/api/ai/runs/shared?host_id=b').status_code==200
    assert admin.get('/api/ai/runs/shared?host_id=missing').status_code==404
    assert admin.get('/api/ai/runs/missing?host_id=a').status_code==404
    assert admin.get('/api/ai/runs/direct').status_code==200


@pytest.mark.parametrize('role',['viewer','operator'])
def test_detail_scope_requires_admin(admin,role):
    with Session() as s:s.get(User,'admin').role=role;s.commit()
    assert admin.get('/api/ai/runs/anything?host_id=a').status_code==403
