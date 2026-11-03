import inspect
from types import SimpleNamespace
import pytest
from app import worker

KEYS={'response_id','process_id','read_only_response_id','staging_response_id','publication_id','publication_response_id','local_observation','service_response_id'}
NONE={k:None for k in KEYS}
NONE['local_observation']=False


def job(action,**payload):
    return SimpleNamespace(action=action,payload=payload)


def scope(**changes):
    return {**NONE,**changes}


CASES=[
    ('patch',{'quarantine_id':'q','process_id':'p'},{}),
    ('quarantine-apply',{'quarantine_id':'q'},{'response_id':'q'}),
    ('quarantine-restore',{'quarantine_id':'q'},{'response_id':'q'}),
    ('process-suspend',{'quarantine_id':'q','process_id':'p'},{'response_id':'q','process_id':'p'}),
    ('process-prepare',{'quarantine_id':'q','process_id':'p'},{'response_id':'q'}),
    ('trusted-repair-prepare',{'quarantine_id':'q'},{'response_id':'q','read_only_response_id':'q'}),
    ('trusted-repair-stage',{'quarantine_id':'q'},{'response_id':'q','staging_response_id':'q'}),
    ('trusted-repair-stage-status',{'quarantine_id':'q'},{'response_id':'q','staging_response_id':'q'}),
    ('trusted-repair-publish',{'quarantine_id':'q','publication_id':'u'},{'response_id':'q','publication_id':'u','publication_response_id':'q'}),
    ('trusted-repair-publish-status',{'quarantine_id':'q','publication_id':'u'},{'response_id':'q','publication_id':'u','publication_response_id':'q'}),
    ('trusted-repair-publish',{'quarantine_id':'q'},{'response_id':'q'}),
    ('response-service-health',{'quarantine_id':'q'},{'response_id':'q','read_only_response_id':'q','service_response_id':'q'}),
    # Service watches get no exemption at all and stay subject to every hold.
    ('response-service-health',{'quarantine_id':'q','_service_watch':True},{}),
    ('evidence-archive-status',{},{'local_observation':True}),
    ('refresh',{'publication_id':'u'},{}),
]


@pytest.mark.parametrize('action,payload,expected',CASES)
def test_response_hold_scope_table(action,payload,expected):
    assert worker.response_hold_scope(job(action,**payload))==scope(**expected)


def test_scope_keys_match_host_quarantined_exemptions():
    from app import operations
    assert KEYS<=set(inspect.signature(operations.host_quarantined).parameters)
    assert set(worker.response_hold_scope(job('patch')))==KEYS


def test_admission_and_execution_share_the_resolver():
    source=inspect.getsource(worker)
    assert source.count('response_hold_scope(')==3  # definition + execution + admission
    assert 'read_only_response_id=' not in source.replace('read_only_response_id=payload','')
