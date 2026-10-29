import time
import pytest
from app.db import Session,Host,Observation
from app.incidents import Incident,Scan,Inspection
from app.identity import User
from app import security_correlation as correlation

PATH='/srv/app/fixture';HASH='a'*64
BASE='/api/hosts/one/security/incidents/incident/related'

@pytest.fixture
def seeded(admin):
    with Session() as s:
        for id in ('one','two'):s.add(Host(id=id,name=id,address='192.0.2.1',fingerprint=''))
        s.add(Incident(id='incident',host_id='one',scan_id='scan',evidence={'path':PATH,'sha256':HASH}));s.commit()
    return admin


def test_cross_source_exact_identity_and_host_scope(seeded,monkeypatch):
    from app import ssh,ai
    monkeypatch.setattr(ssh,'call',lambda *a,**k:pytest.fail('read must not contact target'))
    monkeypatch.setattr(ai,'request',lambda *a,**k:pytest.fail('read must not contact AI'))
    with Session() as s:
        s.add(Scan(id='scan',host_id='one',report={'state':'incomplete','findings':[{'path':PATH,'sha256':HASH}],'gaps':['Signature stale']}))
        s.add(Observation(id='event',host_id='one',observed=1,evidence={'processes':[{'executable':'/tmp/other','sha256':HASH,'capture':'ebpf','identity_verified':False,'uid':7,'environment':'SECRET','args':'SECRET'},{'executable':PATH,'sha256':'b'*64}]}))
        s.add(Inspection(id='inspection',host_id='one',report={'state':'collected','persistence':{'entries':[{'path':PATH,'sha256':HASH}]},'vendor_verification':{'findings':[{'path':PATH,'expected_sha256':HASH,'observed_sha256':'c'*64}]},'packages':[{'findings':[{'path':PATH}]}]}))
        s.add(Scan(id='foreign',host_id='two',report={'findings':[{'path':PATH,'sha256':HASH}]}));s.commit()
    r=seeded.get(BASE);assert r.status_code==200
    data=r.json();assert {i['id'] for i in data['items']}=={'scan','event','inspection'}
    event=next(i for i in data['items'] if i['source']=='executions')
    assert event['matches'][0]['relation']=='hash' and event['matches'][0]['identity_verified'] is False
    assert event['matches'][1]['relation']=='path_different_hash'
    inspection=next(i for i in data['items'] if i['source']=='inspections')
    assert [m['relation'] for m in inspection['matches']]==['path_and_hash','path_different_hash','path_only']
    assert 'SECRET' not in r.text
    assert next(i for i in data['items'] if i['source']=='scans')['gaps']==['Signature stale']


def test_bounded_search_pages_and_time_boundary(seeded):
    now=time.time()
    with Session() as s:
        for i in range(51):s.add(Scan(id=str(i),host_id='one',created=now-i,report={'findings':[{'path':PATH,'sha256':HASH}]}))
        s.commit()
    first=seeded.get(BASE).json();assert len(first['items'])==50 and first['more']
    with Session() as s:s.add(Scan(id='new',host_id='one',created=first['as_of']+1,report={'findings':[{'path':PATH}]}));s.commit()
    second=seeded.get(BASE,params={'offset':50,'as_of':first['as_of'],'expected_digest':first['evidence_digest']}).json()
    assert [r['id'] for r in second['items']]==['50'] and not second['more']
    assert first['sources']['executions']['examined']==0


def test_entry_and_display_limits_are_explicit(seeded):
    with Session() as s:
        s.add(Observation(id='many',host_id='one',observed=1,evidence={'processes':[{'executable':PATH,'sha256':HASH}]*300}));s.commit()
    data=seeded.get(BASE).json();assert data['sources']['executions']['entries_omitted']==44
    assert len(data['items'][0]['matches'])==5 and data['items'][0]['matches_omitted']==251


def test_role_host_deleted_history_and_revision_guards(seeded):
    assert seeded.get(BASE.replace('/one/','/two/')).status_code==404
    assert seeded.get(BASE,params={'offset':-1}).status_code==400
    assert seeded.get(BASE,params={'offset':1_000_001}).status_code==400
    assert seeded.get(BASE,params={'as_of':float('inf')}).status_code==400
    assert seeded.get(BASE,params={'as_of':time.time()+100}).status_code==400
    data=seeded.get(BASE).json()
    with Session() as s:
        row=s.get(Incident,'incident');row.evidence={'path':PATH,'sha256':'b'*64}
        s.get(Host,'one').enabled=False;s.get(Host,'one').deleted_at=time.time();s.commit()
    assert seeded.get(BASE).status_code==200
    assert seeded.get(BASE,params={'expected_digest':data['evidence_digest']}).status_code==400
    for role in ('viewer','operator'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert seeded.get(BASE).status_code==403


def test_malformed_historical_data_and_no_matches(seeded):
    with Session() as s:
        s.add(Inspection(id='bad',host_id='one',report={'persistence':None,'packages':[None],'vendor_verification':[],'gaps':None}))
        s.add(Observation(id='bad-event',host_id='one',observed=0,evidence={'processes':[None,[],{'executable':PATH+'/similar','sha256':'invalid'}]}));s.commit()
    data=seeded.get(BASE).json();assert data['items']==[] and not data['more']
    with Session() as s:s.get(Incident,'incident').evidence={'path':PATH,'sha256':'invalid'};s.commit()
    assert seeded.get(BASE).status_code==400


def test_expected_vendor_hash_is_not_observed_identity():
    assert correlation.match({'path':'/other','expected_sha256':HASH},PATH,HASH,vendor=True) is None
    result=correlation.match({'path':PATH,'expected_sha256':HASH},PATH,HASH,vendor=True)
    assert result['relation']=='path_only' and result['sha256'] is None


def test_nested_gaps_and_imported_oversize_receipts(seeded):
    with Session() as s:
        s.add(Inspection(id='nested',host_id='one',report={'state':'incomplete','persistence':{'entries':[{'path':PATH}]*260,'gaps':['Inventory inaccessible']},'packages':[{'findings':[{'path':'/unrelated'}]*201,'gaps':['Database incomplete']}]}));s.commit()
    data=seeded.get(BASE).json();source=data['sources']['inspections']
    assert source['limited_receipts']==1 and source['entries_omitted']==5
    assert data['items'][0]['gaps']==['Inventory inaccessible','Database incomplete']
    assert data['items'][0]['matches_omitted']==251
