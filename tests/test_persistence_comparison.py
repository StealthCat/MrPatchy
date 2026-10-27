import copy
import pytest
from app import persistence,incidents
from app.db import Session,Host
from app.identity import User


def inventory():
    return {'scope':['/etc/cron.d'],'state':'collected','entries':[{'path':'/etc/cron.d/task','kind':'regular','uid':0,'gid':0,'mode':0o644,'size':4,'mtime_ns':1,'sha256':'a'*64}],
            'gaps':[],'skipped':0,'missing_roots':[]}


def test_added_removed_metadata_and_hash_changes():
    old=inventory();new=copy.deepcopy(old)
    new['entries'][0].update(sha256='b'*64,mode=0o666,mtime_ns=2)
    result=persistence.compare(old,new)
    assert result['state']=='compared' and result['changes'][0]['fields']==['sha256','mode']
    new['entries']=[]
    assert persistence.compare(old,new)['changes'][0]['kind']=='removed'
    assert persistence.compare(new,old)['changes'][0]['kind']=='added'
    old['entries'][0]['mtime_ns']=3
    assert persistence.compare(old,inventory())['changes']==[]


@pytest.mark.parametrize('change',[{'state':'incomplete','gaps':['unreadable']},{'scope':['/etc/cron.d','/etc/profile.d']},{'entries':[{}]}, {'missing_roots':['/etc/cron.d']}, {'skipped':1}])
def test_coverage_gaps_never_become_removals(change):
    old=inventory();new={**inventory(),**change}
    assert persistence.compare(old,new)['state']=='unavailable'
    assert not persistence.compare(new,old)['changes']


def test_receipt_validation_rejects_duplicate_and_escaping_entries():
    for path in ('/elsewhere/task','/etc/cron.d/../task','//etc/cron.d/task'):
        item=inventory();item['entries'][0]['path']=path
        with pytest.raises(ValueError):persistence.validate(item)
    item=inventory();item['entries']*=2
    with pytest.raises(ValueError):persistence.validate(item)


def test_comparison_api_host_scope_coverage_and_roles(admin):
    with Session() as s:
        s.add(Host(id='one',name='One',address='example',fingerprint='pinned'));s.add(Host(id='two',name='Two',address='example',fingerprint='pinned'))
        for identifier,created,inv in [('first',1,inventory()),('package-only',2,None),('second',3,{**inventory(),'entries':[]})]:
            s.add(incidents.Inspection(id=identifier,host_id='one',created=created,report={'persistence':inv}))
        s.commit()
    url='/api/hosts/one/security/inspections/second/comparison'
    result=admin.get(url).json()
    assert result['previous_id']=='first' and result['changes'][0]['kind']=='removed'
    assert admin.get(url.replace('/one/','/two/')).status_code==404
    assert admin.get(url.replace('second','first')).json()['state']=='unavailable'
    with Session() as s:
        s.add(incidents.Inspection(id='gap',host_id='one',created=2.5,report={'persistence':{**inventory(),'state':'incomplete'}}));s.commit()
    result=admin.get(url).json();assert result['previous_id']=='gap' and result['state']=='unavailable'
    for role in ('viewer','operator'):
        with Session() as s:s.get(User,'admin').role=role;s.commit()
        assert admin.get(url).status_code==403
