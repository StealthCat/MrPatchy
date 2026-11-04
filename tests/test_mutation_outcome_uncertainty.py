"""Non-patch mutations retain a review hold when their remote outcome is unknown."""
import json
import time
from contextlib import contextmanager

import pytest
from sqlalchemy import select
from app import host_lifecycle, operations, ssh, worker
from app.db import Audit, Host, Job, Session, Setting

ACTIONS = ('repair', 'repository', 'key')
HOST = 'mutation-outcome-host'
RECEIPT = {'output': 'Fixture mutation applied', 'saved': '/fixture/config'}


def setup(action):
    payload = {'repair': {}, 'repository': {'path': '/etc/apt/sources.list.d/fixture.sources', 'content': 'fixture'},
               'key': {'name': 'fixture.asc', 'data': 'Zml4dHVyZQ=='}}[action]
    with Session() as s:
        s.add(Host(id=HOST, name='Fixture', address='192.0.2.10', fingerprint='fixture', last_repo=time.time()))
        s.add(Job(id='mutation', host_id=HOST, action=action, payload=payload))
        s.commit()
        s.add(Job(id='later', host_id=HOST, action='repair'))
        s.commit()


def execute(monkeypatch, outcome, inventory=None):
    calls = []
    def call(host, request, **kwargs):
        calls.append(request['action'])
        result = inventory if request['action'] == 'inventory' else outcome if len(calls) == 1 else {}
        if isinstance(result, BaseException):
            raise result
        return {} if result is None else result
    monkeypatch.setattr(worker.ssh, 'call', call)
    monkeypatch.setattr(worker, 'save_inventory', lambda *args: None)
    worker.execute('mutation')
    worker.execute('later')
    # Neither re-execution nor another dispatcher pass may replay a held job.
    worker.execute('mutation')
    return calls


def error(kind):
    if kind == 'lost': return ssh.RemoteProtocolError('Fixture SSH stream closed without an exit status')
    if kind == 'malformed': return ssh.RemoteProtocolError('Fixture incomplete or invalid JSON')
    if kind == 'timeout': return TimeoutError('Fixture total deadline exceeded')
    if kind == 'unmarked': return RuntimeError('Fixture bridge exited without receipt')
    result = RuntimeError('Fixture transport failure after start')
    result.remote_started = True
    return result


@pytest.mark.parametrize('action', ACTIONS)
@pytest.mark.parametrize('kind', ['lost', 'malformed', 'timeout', 'unmarked', 'started'])
def test_unknown_mutation_receipt_holds_host_without_replay(admin, monkeypatch, action, kind):
    setup(action)
    failure = error(kind)
    calls = execute(monkeypatch, failure)
    assert calls == [action]
    with Session() as s:
        job = s.get(Job, 'mutation')
        assert job.state == 'recovery_required'
        assert action in job.output.lower() and str(failure) in job.output
        assert 'without a trustworthy completion receipt' in job.output
        assert 'not be replayed automatically' in job.output
        assert operations.host_quarantined(s, HOST)
        assert s.get(Job, 'later').state == 'queued'
        assert s.scalar(select(Audit).where(Audit.action == 'uncertain ' + action,
                                           Audit.detail.contains('mutation ')))


@pytest.mark.parametrize('action', ACTIONS)
def test_post_mutation_inventory_failure_holds_and_keeps_receipt(admin, monkeypatch, action):
    setup(action)
    calls = execute(monkeypatch, RECEIPT, ssh.RemoteProtocolError('Fixture inventory unreadable'))
    assert calls == [action, 'inventory']
    with Session() as s:
        job = s.get(Job, 'mutation')
        assert job.state == 'recovery_required'
        assert 'post-' + action + ' inventory' in job.output
        assert action.capitalize() + ' receipt: ' + json.dumps(RECEIPT) in job.output
        assert operations.host_quarantined(s, HOST)
        assert s.get(Job, 'later').state == 'queued'


@pytest.mark.parametrize('action', ACTIONS)
@pytest.mark.parametrize('kind', ['verified', 'unstarted', 'inactive'])
def test_known_failure_releases_host_and_allows_later_work(admin, monkeypatch, action, kind):
    setup(action)
    if kind == 'verified':
        failure = ssh.RemoteFailure('Fixture target failure receipt')
        failure.remote_started = True
    elif kind == 'inactive':
        failure = host_lifecycle.Inactive('Fixture lifecycle guard refused command')
    else:
        failure = RuntimeError('Fixture SSH connect refused')
        failure.remote_started = False
    calls = execute(monkeypatch, failure)
    assert calls == [action, 'repair', 'inventory']
    with Session() as s:
        job = s.get(Job, 'mutation')
        assert job.state == 'failed' and str(failure) in job.output
        assert 'not be replayed' not in job.output
        assert not operations.host_quarantined(s, HOST)
        assert s.get(Job, 'later').state == 'complete'
        assert s.scalar(select(Audit).where(Audit.action == 'failed ' + action))


@pytest.mark.parametrize('action', ACTIONS)
def test_lifecycle_lock_refusal_is_known_unstarted_and_releases_host(admin, monkeypatch, action):
    setup(action);calls=[];refuse=[True];original=host_lifecycle.activity
    @contextmanager
    def activity(host_ids, kind, **kwargs):
        if refuse[0]:
            refuse[0]=False
            raise host_lifecycle.Busy('Fixture lifecycle lock is active')
        with original(host_ids, kind, **kwargs) as revisions:
            yield revisions
    monkeypatch.setattr(host_lifecycle, 'activity', activity)
    monkeypatch.setattr(ssh, '_call', lambda host, request, *args, **kwargs: calls.append(request['action']) or {})
    monkeypatch.setattr(worker, 'save_inventory', lambda *args: None)
    worker.execute('mutation')
    worker.execute('later')
    worker.execute('mutation')
    assert calls == ['repair', 'inventory']
    with Session() as s:
        job=s.get(Job, 'mutation')
        assert job.state == 'failed' and 'lifecycle lock is active' in job.output
        assert not operations.host_quarantined(s, HOST)
        assert s.get(Job, 'later').state == 'complete'
        assert s.scalar(select(Audit).where(Audit.action == 'failed ' + action))


@pytest.mark.parametrize('action', ACTIONS)
def test_successful_mutation_retains_receipt_and_releases_host(admin, monkeypatch, action):
    setup(action)
    calls = execute(monkeypatch, RECEIPT)
    assert calls == [action, 'inventory', 'repair', 'inventory']
    with Session() as s:
        assert s.get(Job, 'mutation').state == 'complete'
        assert json.loads(s.get(Job, 'mutation').output) == RECEIPT
        assert not operations.host_quarantined(s, HOST)


@pytest.mark.parametrize('action', ACTIONS)
def test_pre_send_validation_failure_does_not_create_uncertain_hold(admin, monkeypatch, action):
    setup(action)
    with Session() as s:
        s.add(Setting(key='agent-status:' + HOST, value={'state': 'blocked'}))
        s.commit()
    calls = execute(monkeypatch, AssertionError('No command may be sent'))
    assert calls == []
    with Session() as s:
        job = s.get(Job, 'mutation')
        assert job.state == 'failed' and 'Agent verification failed' in job.output
        assert not operations.host_quarantined(s, HOST)


@pytest.mark.parametrize('action', ACTIONS)
def test_hold_requires_explicit_target_review_and_never_replays(admin, monkeypatch, action):
    setup(action)
    calls = execute(monkeypatch, error('lost'))
    assert calls == [action]
    endpoint = '/api/operations/jobs/mutation/reconcile'
    assert admin.post(endpoint, json={}).status_code == 400
    busy = [True]
    def observed(host, request, **kwargs):
        calls.append(request['action'])
        return {'busy': busy[0]} if request['action'] == 'operation-status' else {}
    monkeypatch.setattr(worker.ssh, 'call', observed)
    assert admin.post(endpoint, json={'verified_target_state': True}).status_code == 409
    worker.execute('later')
    with Session() as s:
        assert s.get(Job, 'mutation').state == 'recovery_required'
        assert s.get(Job, 'later').state == 'queued'
    busy[0] = False
    assert admin.post(endpoint, json={'verified_target_state': True}).status_code == 200
    worker.execute('mutation')
    worker.execute('later')
    assert calls == [action, 'operation-status', 'operation-status', 'repair', 'inventory']
    with Session() as s:
        assert s.get(Job, 'mutation').state == 'interrupted'
        assert s.get(Job, 'later').state == 'complete'
        assert s.scalar(select(Audit).where(Audit.action == 'reconcile job', Audit.detail.contains('mutation')))
