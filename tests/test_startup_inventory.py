import time
import pytest
from app.db import Session,Host
from app.incidents import Inspection
from app.identity import User
from app import startup_inventory as view

@pytest.fixture
def seeded(admin):
    with Session() as s:
        s.add(Host(id='one',name='fixture',address='192.0.2.1',fingerprint='fixture'))
        s.add(Host(id='two',name='other',address='192.0.2.2',fingerprint='fixture'))
        entries=[dict(path='/etc/cron.d/job'+str(i).zfill(2),kind='regular',uid=0,gid=0,mode=420,size=1,mtime_ns=1,sha256='a'*64) for i in range(30)]
        s.add(Inspection(id='receipt',host_id='one',report={'persistence':dict(state='incomplete',scope=['/etc/cron.d'],entries=entries,gaps=['Permission denied'],missing_roots=[],skipped=1)}));s.commit()
    return admin


def test_paging_search_roles_history_and_no_provider(seeded,monkeypatch):
    from app import ai,ssh
    monkeypatch.setattr(ai,'request',lambda *a,**k:pytest.fail('no AI'))
    monkeypatch.setattr(ssh,'call',lambda *a,**k:pytest.fail('no target'))
    url='/api/hosts/one/security/startup-inventory'
    first=seeded.get(url).json();assert len(first['items'])==25 and first['more'] and first['total']==30
    assert first['items'][0]['origin']=='not_assessed' and first['items'][0]['change']=='not_compared'
    assert 'Permission denied' in first['gaps'] and first['skipped']==1
    assert len(seeded.get(url,params={'offset':25,'expected_digest':first['digest']}).json()['items'])==5
    assert seeded.get(url,params={'q':'job29'}).json()['total']==1
    assert seeded.get(url.replace('/one/','/two/')).json()['state']=='unavailable'
    with Session() as s:
        s.get(Host,'one').enabled=False;s.get(Host,'one').deleted_at=time.time()
        row=s.get(Inspection,'receipt');row.report={};s.commit()
    assert seeded.get(url,params={'expected_digest':first['digest']}).status_code==400
    for role in ('operator','viewer'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert seeded.get(url).status_code==403

@pytest.mark.parametrize('path,key',[('/etc/crontab','cron'),('/etc/cron.daily/a','cron'),('/etc/systemd/system/a','systemd_local'),('/home/user/.profile','additional')])
def test_mechanisms_do_not_claim_defaults(path,key):assert view.mechanism(path)[0]==key
