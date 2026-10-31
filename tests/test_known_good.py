import copy
import pytest

from app import known_good
from app.db import Session
from app.incidents import Inspection


def sha(letter):
    return letter * 64


def complete():
    snapshot = {
        'executable': '/usr/bin/fixture', 'sha256': sha('a'), 'identity_verified': True,
        'host_id': 'host-one', 'observed': 100,
        'investigation': {'details': {
            'version': 2, 'identity_verified': True,
            'context': {'version': 1, 'process': {'pid': 10, 'start_ticks': 20},
                'coverage': {'scope': 'recorded_process_identity', 'gaps': []}},
            'known_good_context': {
                'version': 1,
                'artifact': {'version': 1, 'verified': True, 'path': '/usr/bin/fixture',
                    'sha256': sha('a'), 'manifest_sha256': sha('b'), 'kind': 'elf'},
                'provenance': {'version': 1, 'verified': True, 'scheme': 'vendor-signature',
                    'subject': 'fixture-package', 'release': '1.0-1',
                    'manifest_sha256': sha('c'), 'proof_sha256': sha('d')},
                'configuration': {'version': 1, 'complete': True, 'manifest_sha256': sha('e')},
                'behavior': {'version': 1, 'complete': True, 'manifest_sha256': sha('f'),
                    'privileges_sha256': sha('1'), 'startup_sha256': sha('2'),
                    'network_sha256': sha('3'), 'execution_sha256': sha('4'),
                    'memory_sha256': sha('5')},
                'followup': {'version': 1, 'complete': True, 'requirements_sha256': sha('6'),
                    'evidence_sha256': sha('7'), 'policy_version': 'process-followup-v1'},
                'coverage': {'version': 1, 'complete': True, 'manifest_sha256': sha('8'), 'gaps': []},
                'observation': {'host_id': 'host-one', 'pid': 10, 'start_ticks': 20,
                    'collected': 100, 'ephemeral_source_ports': [49152]},
            },
        }},
    }
    return snapshot


def evaluate(snapshot=None, **overrides):
    values = {'snapshot': snapshot or complete(), 'model': 'gpt-fixture',
        'policy_hash': sha('9'), 'result': {'risk': 'low', 'explanation': 'Safe with complete evidence'},
        'source': 'ai'}
    values.update(overrides)
    return known_good.evaluate(**values)


def codes(result):
    return [reason['code'] for reason in result['reasons']]


def test_complete_contract_creates_non_published_candidate():
    result = evaluate()
    assert result == {'version': 1, 'eligible': True, 'published': False,
        'fingerprint': result['fingerprint'], 'reasons': []}
    assert len(result['fingerprint']) == 64


def test_host_process_time_and_ephemeral_port_observations_do_not_change_fingerprint():
    first = complete(); second = copy.deepcopy(first)
    second['host_id'] = 'host-two'; second['observed'] = 999
    second['investigation']['details']['context']['process'] = {'pid': 999, 'start_ticks': 888}
    second['investigation']['details']['known_good_context']['observation'] = {
        'host_id': 'host-two', 'pid': 999, 'start_ticks': 888, 'boot_id': 'other',
        'collected': 999, 'ephemeral_source_ports': [60000],
    }
    assert evaluate(first)['fingerprint'] == evaluate(second)['fingerprint']


@pytest.mark.parametrize('component,field',[('artifact','manifest_sha256'),('provenance','proof_sha256'),
    ('configuration','manifest_sha256'),('behavior','network_sha256'),
    ('followup','evidence_sha256'),('coverage','manifest_sha256')])
def test_every_security_manifest_changes_the_fingerprint(component,field):
    changed = complete()
    changed['investigation']['details']['known_good_context'][component][field] = sha('0')
    assert evaluate(changed)['fingerprint'] != evaluate()['fingerprint']


@pytest.mark.parametrize('component,marker',[('artifact','verified'),('provenance','verified'),
    ('configuration','complete'),('behavior','complete'),('followup','complete'),('coverage','complete')])
def test_unverified_or_incomplete_components_are_explicit_misses(component,marker):
    snapshot = complete();snapshot['investigation']['details']['known_good_context'][component][marker] = False
    result = evaluate(snapshot)
    assert not result['eligible'] and not result['fingerprint']
    assert any(code.startswith(component+'_binding') for code in codes(result))


def test_host_fields_inside_canonical_components_are_rejected_not_silently_ignored():
    snapshot = complete();snapshot['investigation']['details']['known_good_context']['behavior']['host_id'] = 'leak'
    result = evaluate(snapshot)
    assert not result['eligible'] and 'observation_fields_invalid' in codes(result)


@pytest.mark.parametrize('changes,reason',[
    ({'source': 'legacy'}, 'source_not_ai'),
    ({'result': {'risk': 'medium', 'explanation': 'Not safe'}}, 'result_not_safe'),
    ({'model': ''}, 'model_missing'),
    ({'policy_hash': ''}, 'policy_binding_missing'),
])
def test_assessment_provenance_and_policy_fail_closed(changes,reason):
    result = evaluate(**changes)
    assert not result['eligible'] and reason in codes(result)


def test_current_partial_receipt_is_a_miss_without_guessing_missing_context():
    snapshot = {'executable': '/usr/bin/fixture', 'sha256': sha('a'), 'identity_verified': True,
        'investigation': {'details': {'version': 2, 'identity_verified': True,
            'context': {'coverage': {'scope': 'recorded_process_identity',
                'gaps': ['package_authentication_missing']}}}}}
    result = evaluate(snapshot)
    assert not result['eligible'] and result['fingerprint'] == ''
    assert codes(result) == ['coverage_incomplete', 'known_good_context_missing']


def test_malformed_saved_coverage_fails_closed_without_breaking_history():
    snapshot = complete();snapshot['investigation']['details']['context']['coverage'] = ['untrusted']
    result = evaluate(snapshot)
    assert not result['eligible']
    assert {'coverage_incomplete', 'recorded_process_not_bound'} <= set(codes(result))


def test_model_and_policy_are_part_of_the_exact_match_contract():
    baseline = evaluate()['fingerprint']
    assert evaluate(model='other-model')['fingerprint'] != baseline
    assert evaluate(policy_hash=sha('0'))['fingerprint'] != baseline


def vendor_report(path='/usr/bin/fixture',checksum=None,state='matches_artifact_bytes'):
    checksum=checksum or sha('a')
    manifest={'package':'fixture','version':'1.0-1','architecture':'amd64',
        'entries':[{'path':path,'sha256':checksum,'size':123}]}
    proof={'bundle_id':'fixture','release_sha256':sha('b'),'index_sha256':sha('c'),
        'artifact_sha256':sha('d'),'keyring_sha256':sha('e'),'signers':['A'*40],
        'authenticated_at':123,'scope':'fixture'}
    receipt={'trust_basis':'controller_authenticated_debian_artifact','package':'fixture','version':'1.0-1',
        'architecture':'amd64','scope_files':1,'examined':1,'state':state,'gaps':[],'findings':[]}
    return {'version':1,'trust_basis':'controller_authenticated_debian_artifact','state':'collected','packages':[],
        'persistence':None,'vendor_manifest':manifest,'vendor_authentication':proof,'vendor_verification':receipt}


def partial(host='one',pid=10,collected=100):
    return {'executable':'/usr/bin/fixture','sha256':sha('a'),'identity_verified':True,
        'investigation':{'collected':collected,'details':{'version':2,'identity_verified':True,
            'context':{'version':1,'process':{'pid':pid,'start_ticks':20,'boot_id':'a'*8+'-'+'a'*4+'-'+'a'*4+'-'+'a'*4+'-'+'a'*12,
                'proc_device':30,'proc_inode':40},'coverage':{'cache_eligible':False,'scope':'recorded_process_identity',
                'gaps':['package_authentication_missing','configuration_not_collected']}}}}}


def test_controller_authenticated_vendor_receipt_binds_exact_artifact_but_stays_ineligible(client):
    with Session() as s:
        s.add(Inspection(id='vendor-one',host_id='one',created=123,report=vendor_report()));s.commit()
        bound=known_good.bind_vendor_provenance(s,'one',partial(),100)
    details=bound['investigation']['details'];contract=details['known_good_context']
    assert 'package_authentication_missing' not in details['context']['coverage']['gaps']
    assert contract['artifact']['sha256']==sha('a') and contract['provenance']['verified']
    result=evaluate(bound)
    assert not result['eligible'] and result['fingerprint']==''
    assert 'provenance_binding_invalid' not in codes(result)
    assert {'configuration_binding_invalid','behavior_binding_invalid','followup_binding_invalid','coverage_binding_invalid'}<=set(codes(result))


def test_vendor_binding_is_cross_host_stable_but_observations_remain_local(client):
    report=vendor_report()
    with Session() as s:
        s.add_all([Inspection(id='vendor-cross-one',host_id='cross-one',created=123,report=report),
            Inspection(id='vendor-cross-two',host_id='cross-two',created=456,report=copy.deepcopy(report))]);s.commit()
        first=known_good.bind_vendor_provenance(s,'cross-one',partial('cross-one',10,100),100)
        second=known_good.bind_vendor_provenance(s,'cross-two',partial('cross-two',99,900),900)
    left=first['investigation']['details']['known_good_context'];right=second['investigation']['details']['known_good_context']
    assert {name:left[name] for name in known_good.COMPONENTS}=={name:right[name] for name in known_good.COMPONENTS}
    assert left['observation']!=right['observation']


@pytest.mark.parametrize('inspection_id,host,report',[
    ('vendor-miss-hash','miss-hash',vendor_report(checksum=sha('f'))),
    ('vendor-miss-state','miss-state',vendor_report(state='differences')),
])
def test_changed_or_incomplete_vendor_receipt_is_a_contextual_miss(client,inspection_id,host,report):
    with Session() as s:
        s.add(Inspection(id=inspection_id,host_id=host,created=123,report=report));s.commit()
        bound=known_good.bind_vendor_provenance(s,host,partial(host),100)
    assert 'known_good_context' not in bound['investigation']['details']
    assert 'package_authentication_missing' in bound['investigation']['details']['context']['coverage']['gaps']


@pytest.mark.parametrize('details',[None,{},{'version':2,'identity_verified':True,'context':None},
    {'version':2,'identity_verified':True,'context':{'coverage':{'scope':'recorded_process_identity','gaps':[None]}}}])
def test_malformed_followup_never_crashes_vendor_binding(client,details):
    evidence={'executable':'/usr/bin/fixture','sha256':sha('a'),'investigation':{'details':details}}
    with Session() as s:assert known_good.bind_vendor_provenance(s,'one',evidence,100)==evidence
