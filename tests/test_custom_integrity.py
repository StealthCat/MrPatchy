import copy
import json
import os
import time
from contextlib import contextmanager
import pytest
from target import agent
from app import incidents,persistence,worker
from app.db import Session,Host,Job
from test_persistence_comparison import inventory
from test_persistence_monitoring import receipt


@pytest.mark.parametrize('paths', [['/'],['relative'],['/tmp/../file'],['//tmp/file'],['/tmp/file/'],['/tmp/./file'],['/tmp/a\nfile'],['/proc/a'],['/sys'],['/dev/x'],['/run/x'],['/var/lib/mrpatchy-quarantine/x'],['/etc'],['/etc/cron.d/x'],['/tmp/a','/tmp/a'],['/tmp/a','/tmp/a/b'],['/tmp/'+str(i) for i in range(17)]])
def test_custom_scope_rejects_unsafe_overlapping_and_unbounded_paths(paths):
    with pytest.raises(ValueError):agent.validate_custom_paths(paths)


def isolate(monkeypatch):
    monkeypatch.setattr(agent,'PERSISTENCE_ROOTS',())
    monkeypatch.setattr(agent,'PERSISTENCE_FILES',())


def test_custom_file_directory_symlinks_missing_and_metadata_only(tmp_path,monkeypatch):
    isolate(monkeypatch)
    file=tmp_path/'config';file.write_text('SECRET CONFIG')
    tree=tmp_path/'tree';tree.mkdir();(tree/'file').write_text('file')
    outside=tmp_path/'outside';outside.mkdir();(outside/'hidden').write_text('outside')
    (tree/'link').symlink_to(outside,target_is_directory=True)
    missing=tmp_path/'missing';paths=[str(file),str(tree),str(missing)]
    report=agent.persistence_inventory(time.monotonic()+5,paths)
    persistence.validate(report)
    assert report['scope']==paths and report['state']=='collected' and report['missing_roots']==[str(missing)]
    assert len(report['entries'])==3 and 'SECRET CONFIG' not in json.dumps(report) and 'hidden' not in json.dumps(report)
    assert next(e for e in report['entries'] if e['path']==str(file))['sha256']
    after=copy.deepcopy(report);after['entries'][0]['mode']^=0o111
    assert persistence.compare(report,after)['changes']
    assert persistence.compare(report,{**report,'scope':[str(file)]})['state']=='unavailable'


def test_custom_parent_alias_special_files_and_limits_are_gaps(tmp_path,monkeypatch):
    isolate(monkeypatch)
    tree=tmp_path/'tree';tree.mkdir();(tree/'large').write_bytes(b'x'*(1024*1024+1));os.mkfifo(tree/'pipe')
    alias=tmp_path/'alias';alias.symlink_to(tree,target_is_directory=True)
    report=agent.persistence_inventory(time.monotonic()+5,[str(tree),str(alias/'child')])
    assert report['state']=='incomplete' and report['skipped']>=3
    persistence.validate(report)
    with pytest.raises(ValueError):agent.validate_inspection([],False,[str(tree)])


def test_empty_custom_directory_replacement_is_incomplete(tmp_path,monkeypatch):
    isolate(monkeypatch);root=tmp_path/'tree';root.mkdir();original=agent.scan_root;calls=0
    @contextmanager
    def changed(path):
        nonlocal calls
        if path==root:
            calls+=1
            if calls==2:root.rename(tmp_path/'old');root.mkdir()
        with original(path) as fd:yield fd
    monkeypatch.setattr(agent,'scan_root',changed)
    result=agent.persistence_inventory(time.monotonic()+5,[str(root)])
    assert result['state']=='incomplete' and result['gaps']


def test_manual_custom_protocol_and_scope_cannot_be_silently_ignored(admin,monkeypatch):
    with Session() as s:s.add(Host(id='scope-host',name='scope',address='192.0.2.1',fingerprint='pin',state='online'));s.commit()
    path='/api/hosts/scope-host/security/inspections';selected=['/srv/app/config']
    assert admin.post(path,json={'packages':[],'custom_paths':['/proc/x']}).status_code==400
    result=admin.post(path,json={'packages':[],'persistence':True,'custom_paths':selected});assert result.status_code==200
    inv=inventory();inv['scope']=agent.validate_custom_paths(selected)
    def call(host,request,**kwargs):
        assert request=={'action':'security-inspect-custom','packages':[],'persistence':True,'custom_paths':selected}
        return receipt(inv)
    monkeypatch.setattr(worker.ssh,'call',call);worker.execute(result.json()['job_id'])
    with Session() as s:assert s.get(Job,result.json()['job_id']).state=='complete'
    result=admin.post(path,json={'packages':[],'persistence':True,'custom_paths':selected})
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:receipt(inventory()))
    worker.execute(result.json()['job_id'])
    with Session() as s:
        job=s.get(Job,result.json()['job_id']);assert job.state=='failed' and 'scope' in job.output
        assert s.get(incidents.Inspection,job.id) is None


def test_scheduled_custom_scope_revision_and_baseline_incidents(admin,monkeypatch):
    with Session() as s:s.add(Host(id='scope-host',name='scope',address='192.0.2.1',fingerprint='pin',state='online'));s.commit()
    base='/api/hosts/scope-host/security'
    data={'enabled':True,'link_incidents':True,'custom_paths':['/srv/app/config'],'expected_revision':''}
    policy=admin.put(base+'/persistence-monitor',json=data);assert policy.status_code==200;policy=policy.json()
    assert admin.put(base+'/persistence-monitor',json={**data,'custom_paths':['/etc']}).status_code==400
    persistence.schedule_tick()
    with Session() as s:
        job=s.query(Job).one();identifier=job.id
        assert job.payload['custom_paths']==data['custom_paths']
    assert admin.put(base+'/persistence-monitor',json={**data,'custom_paths':['/srv/other'],'expected_revision':policy['revision']}).status_code==200
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:pytest.fail('Changed queued policy must not contact target'))
    worker.execute(identifier)
    with Session() as s:assert s.get(Job,identifier).state=='failed'
    inv=inventory();inv['scope']=agent.validate_custom_paths(['/srv/other'])
    inv['entries'][0]['path']='/srv/other/config';inv['missing_roots']=[]
    with Session() as s:
        incidents.record_inspection(s,'scope-host','baseline-custom',receipt(inv));s.commit()
        current=persistence.status(s,'scope-host')
        persistence.approve(s,'scope-host','baseline-custom',current['latest']['digest'],'','Reviewed custom application configuration.','admin');s.commit()
        changed=copy.deepcopy(inv);changed['entries'][0]['sha256']='f'*64
        incidents.record_inspection(s,'scope-host','drift-custom',receipt(changed));s.commit()
        assert persistence.status(s,'scope-host')['state']=='drifted'
        assert s.query(incidents.PersistenceIncident).count()==1
        incomplete={**changed,'state':'incomplete','gaps':['read failed'],'skipped':1}
        incidents.record_inspection(s,'scope-host','gap-custom',receipt(incomplete));s.commit()
        assert persistence.status(s,'scope-host')['state']=='unavailable'
        assert s.query(incidents.PersistenceIncident).count()==1
