import copy
import time
from types import SimpleNamespace

import pytest
from app import file_status, ai, ai_assessments, known_good, worker
from app.db import Session, Host, Behavior, Setting
from app.identity import User
from app.incidents import Inspection
from app.security import seal
from test_known_good import complete, retained
from test_persistence_comparison import inventory

PATH = '/usr/bin/fixture'
HASH = 'a'*64


def report(checksum=HASH):
    basis = 'controller_authenticated_debian_artifact'
    return {'trust_basis': basis,
        'vendor_manifest': {'package': 'fixture', 'version': '1', 'architecture': 'amd64',
                            'entries': [{'path': PATH, 'sha256': checksum, 'size': 4}]},
        'vendor_authentication': {'bundle_id': 'fixture', 'artifact_sha256': 'b'*64,
            'keyring_sha256': 'c'*64, 'authenticated_at': time.time(), 'release_sha256': 'd'*64,
            'index_sha256': 'e'*64, 'signers': ['F'*40]},
        'vendor_verification': {'trust_basis': basis, 'package': 'fixture', 'version': '1',
            'architecture': 'amd64', 'state': 'matches_artifact_bytes', 'examined': 1,
            'scope_files': 1, 'findings': [], 'gaps': []}}


def setup():
    with Session() as s:
        s.add(Host(id='host-one', name='One', address='192.0.2.1', fingerprint='',
                   telemetry={'hashed_at': time.time(), 'managed': {PATH: HASH, '/unknown': 'f'*64}},
                   baseline={'/missing': HASH}))
        s.add(Inspection(id='vendor-one', host_id='host-one', report=report()))
        s.commit()


def test_repository_precedence_and_hash_mismatch(client):
    setup()
    with Session() as s:
        proofs = file_status.repositories(s, 'host-one')
        assert file_status.resolve(PATH, HASH, proofs)['status'] == 'verified'
        assert file_status.resolve(PATH, 'f'*64, proofs)['status'] == 'changed'
        assert file_status.resolve('/unknown', HASH, proofs)['status'] == 'unassessed'
        assert file_status.resolve(PATH, None, proofs)['status'] == 'unavailable'
        assert not file_status.repositories(s, 'other-host')


def test_newest_authenticated_artifact_wins_and_local_claims_are_ignored(client):
    setup()
    with Session() as s:
        s.add(Inspection(id='new', host_id='host-one', created=time.time()+1, report=report('f'*64)))
        forged=report();forged['trust_basis']='target_local_package_database'
        s.add(Inspection(id='forged', host_id='host-one', created=time.time()+2, report=forged))
        s.commit()
        result=file_status.resolve(PATH,HASH,file_status.repositories(s,'host-one'))
        assert result['status']=='changed' and result['reference']['inspection_id']=='new'


def test_target_assessment_is_replaced_without_mutating_input(client):
    setup()
    evidence={'executable': '/unknown', 'sha256': HASH, 'file_assessment': {'status': 'verified'}}
    original=copy.deepcopy(evidence)
    with Session() as s:
        actual=file_status.before_ai(s,SimpleNamespace(evidence=evidence,host_id='host-one'))
    assert actual['file_assessment']['status']=='unassessed' and evidence==original


def test_triage_validates_only_receipts_that_can_resolve_the_exact_path(client, monkeypatch):
    checked = []
    validate = file_status.vendor.validate_authenticated

    def counted(manifest, proof, receipt):
        checked.append(proof['bundle_id'])
        return validate(manifest, proof, receipt)

    monkeypatch.setattr(file_status.vendor, 'validate_authenticated', counted)
    with Session() as s:
        unrelated = report()
        unrelated['vendor_manifest']['entries'][0]['path'] = PATH.upper()
        unrelated['vendor_authentication']['bundle_id'] = 'unrelated'
        newest = report('f'*64)
        newest['vendor_authentication']['bundle_id'] = 'newest'
        corrupt = report()
        corrupt['vendor_authentication'].update(bundle_id='corrupt', artifact_sha256='invalid')
        for index in range(105):
            s.add(Inspection(id=f'older-{index}', host_id='host-one', created=100 + index,
                             report=report()))
            s.add(Inspection(id=f'unrelated-{index}', host_id='host-one', created=300 + index,
                             report=unrelated))
        s.add_all([
            Inspection(id='target-a', host_id='host-one', created=220, report=report()),
            Inspection(id='target-z', host_id='host-one', created=220, report=newest),
            Inspection(id='corrupt', host_id='host-one', created=230, report=corrupt),
        ])
        s.commit()

        row = SimpleNamespace(host_id='host-one', evidence={'executable': PATH, 'sha256': HASH})
        assessment = file_status.before_ai(s, row)['file_assessment']
        assert assessment['status'] == 'changed'
        assert assessment['reference']['inspection_id'] == 'target-z'
        assert not assessment.get('trusted')
        assert checked == ['corrupt', 'newest']

        # A following query on the same session must work after early exit.
        proofs = file_status.repositories(s, 'host-one')
        assert proofs[PATH] == assessment['reference']
        assert proofs[PATH.upper()]['expected_sha256'] == HASH


def test_page_includes_unassessed_missing_baseline_and_all_pages(admin):
    setup()
    with Session() as s:
        h=s.get(Host,'host-one');h.telemetry={'hashed_at':time.time(),
            'managed': {f'/file/{n:03}': HASH for n in range(75)}}
        s.add(Inspection(id='startup',host_id=h.id,report={'persistence':inventory()}));s.commit()
    url='/api/hosts/host-one/file-status'
    first=admin.get(url).json();second=admin.get(url+'?offset=50').json()
    assert len(first['items'])==50 and first['more'] and not second['more']
    assert first['recorded']==78 and len(second['items'])==28
    assert first['counts']=={'unassessed':76,'unavailable':1,'verified':1}
    assert admin.get(url+'?q=missing').json()['items'][0]['status']=='unavailable'
    assert admin.get(url+'?status=verified').json()['total']==1
    assert admin.get(url+'?offset=-1').status_code==422
    assert admin.get('/api/hosts/absent/file-status').status_code==404


@pytest.mark.parametrize('role',['viewer','operator'])
def test_file_evidence_preserves_admin_boundary(admin,role):
    setup()
    with Session() as s:s.get(User,'admin').role=role;s.commit()
    assert admin.get('/api/hosts/host-one/file-status').status_code==403


@pytest.mark.parametrize('cached,mismatch',[(False,False),(True,False),(True,True)])
def test_worker_orders_repository_cache_then_provider(client,monkeypatch,cached,mismatch):
    setup();snapshot=complete();source=retained()
    source.policy_hash=ai_assessments.digest([ai.investigation_policy()])
    with Session() as s:
        if mismatch:s.get(Inspection,'vendor-one').report=report('f'*64)
        s.add(Behavior(id='current',host_id='host-one',evidence=snapshot,verdict='pending'))
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'gpt-fixture'}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('private-key')}))
        if cached:s.add(source);known_good.publish(s,source)
        s.commit()
    events=[];resolve=file_status.repositories;lookup=known_good.lookup
    def repositories(*args, **kwargs):
        events.append('repository');return resolve(*args, **kwargs)
    def cache(*args,**kwargs):
        events.append('cache');return lookup(*args,**kwargs)
    def provider(evidence,*args):
        events.append('ai')
        assert evidence['file_assessment']['status']==('changed' if mismatch else 'verified')
        return {'risk':'low','explanation':'Behavior reviewed','recommended_checks':'Monitor','requested_checks':[]}
    monkeypatch.setattr(file_status,'repositories',repositories)
    monkeypatch.setattr(known_good,'lookup',cache)
    monkeypatch.setattr(ai,'investigate',provider)
    worker.investigate_one()
    assert events[:2]==['repository','cache']
    assert ('ai' in events) is (not cached or mismatch)
    with Session() as s:
        b=s.get(Behavior,'current')
        assert b.verdict=='low' and not b.approved
        assert b.evidence['file_assessment']['status']==('changed' if mismatch else 'verified')
