"""Ordinary patches keep a review hold when the package outcome is unknown (#119)."""
import json
import time
import paramiko
import pytest
from app import host_lifecycle, operations, ssh, worker
from app.db import Session, Host, Job, Audit
from sqlalchemy import select

HOST = 'uncertain-host'


def setup_jobs(**payload):
    with Session() as s:
        s.add(Host(id=HOST, name='Fixture', address='192.0.2.1', fingerprint='fixture', state='waiting', last_repo=time.time()))
        s.add(Job(id='patch', host_id=HOST, action='patch',
                  payload={'packages': ['demo:amd64=2'], '_recovery_policy': {'reboot': False, 'rollback': False}, **payload}))
        s.commit()
        # Created later, so it queues behind the patch operation.
        s.add(Job(id='later', host_id=HOST, action='repair'))
        s.commit()


def run(monkeypatch, behaviour):
    calls = []
    inventories = []

    def call(host, request, **kwargs):
        calls.append(request['action'])
        outcome = behaviour(request['action'], calls)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(worker.ssh, 'call', call)
    monkeypatch.setattr(worker, 'save_inventory', lambda s, h, inventory: inventories.append(inventory))
    monkeypatch.setattr(worker, 'validate_patch', lambda *args: None)
    worker.execute('patch')
    worker.execute('later')
    return calls, inventories


def inventory_first(action, calls, then):
    if action == 'inventory' and calls.count('inventory') == 1:
        return {'inventory': 'before'}
    return then(action, calls)


def assert_held(fragment):
    with Session() as s:
        job = s.get(Job, 'patch')
        assert job.state == 'recovery_required'
        assert 'may have been applied' in job.output and 'not be replayed' in job.output
        assert fragment in job.output
        assert operations.host_quarantined(s, HOST)
        assert s.get(Job, 'later').state == 'queued'
        assert s.scalar(select(Audit).where(Audit.action == 'uncertain patch', Audit.detail.contains('patch ')))
        return job


def started(error):
    error.remote_started = True
    return error


@pytest.mark.parametrize('error', [
    ssh.RemoteProtocolError('SSH stream closed without an exit status; verify target state before retrying'),
    ssh.RemoteProtocolError('SSH returned incomplete or invalid JSON at character 4 (9 bytes received).'),
    TimeoutError('SSH operation exceeded its total deadline; verify target state before retrying'),
    started(RuntimeError('SSH connection unavailable. Verify target operation state before retrying a patch.')),
    started(RuntimeError('Remote bridge failed')),
])
def test_lost_or_malformed_patch_receipt_holds_host(admin, monkeypatch, error):
    setup_jobs()
    calls, inventories = run(monkeypatch, lambda action, calls: inventory_first(
        action, calls, lambda action, calls: error if action == 'patch' else {}))
    assert calls == ['inventory', 'patch']
    job = assert_held(str(error))
    assert 'without a trustworthy completion receipt' in job.output
    # The later queued mutation was not started and the patch was not replayed.
    assert inventories == [{'inventory': 'before'}]


def test_post_patch_inventory_failure_holds_host_and_keeps_receipt(admin, monkeypatch):
    setup_jobs()
    receipt = {'output': 'Setting up demo (2) ...'}

    def behaviour(action, calls):
        if action == 'patch':
            return receipt
        return ssh.RemoteProtocolError('SSH returned incomplete or invalid JSON')
    calls, _ = run(monkeypatch, lambda action, calls: inventory_first(action, calls, behaviour))
    assert calls == ['inventory', 'patch', 'inventory']
    job = assert_held('post-patch inventory could not be read')
    assert 'Patch receipt: ' + json.dumps(receipt) in job.output


@pytest.mark.parametrize('error', [
    ssh.RemoteFailure('E: Version 2 for demo was not found'),
    host_lifecycle.Inactive('Server management is disabled or deleted'),
])
def test_known_unstarted_or_verified_failure_releases_host(admin, monkeypatch, error):
    if not isinstance(error, host_lifecycle.Inactive):
        error.remote_started = True
    setup_jobs()
    calls, _ = run(monkeypatch, lambda action, calls: inventory_first(
        action, calls, lambda action, calls: error if action == 'patch' else {}))
    assert calls == ['inventory', 'patch', 'repair', 'inventory']
    with Session() as s:
        job = s.get(Job, 'patch')
        assert job.state == 'failed' and str(error) in job.output
        assert 'may have been applied' not in job.output
        assert s.get(Job, 'later').state == 'complete'


def test_connection_failure_before_remote_start_releases_host(admin, monkeypatch):
    """The real ssh.call marks errors raised before the remote command starts."""
    setup_jobs()
    sent = []

    class Refused(paramiko.SSHClient):
        def connect(self, *args, **kwargs):
            raise paramiko.ssh_exception.NoValidConnectionsError({('192.0.2.1', 22): OSError('refused')})

        def exec_command(self, *args, **kwargs):
            sent.append(args)
            raise AssertionError('must not start a command')

    real = ssh.call
    monkeypatch.setattr(ssh.paramiko, 'SSHClient', Refused)

    def call(host, request, **kwargs):
        if request['action'] == 'patch':
            return real(host, request, **kwargs)
        return {}
    monkeypatch.setattr(worker.ssh, 'call', call)
    monkeypatch.setattr(worker, 'save_inventory', lambda *args: None)
    monkeypatch.setattr(worker, 'validate_patch', lambda *args: None)
    worker.execute('patch')
    with Session() as s:
        job = s.get(Job, 'patch')
        assert job.state == 'failed' and 'SSH connection unavailable' in job.output
        assert not operations.host_quarantined(s, HOST)
    assert not sent


def test_ssh_call_marks_errors_after_remote_start(admin, monkeypatch):
    class Channel:
        def shutdown_write(self):
            pass

    class Stream:
        channel = Channel()

        def write(self, data):
            pass

        def flush(self):
            pass

    class Transport:
        def set_keepalive(self, interval):
            pass

    class Started(paramiko.SSHClient):
        def connect(self, *args, **kwargs):
            pass

        def get_transport(self):
            return Transport()

        def exec_command(self, *args, **kwargs):
            return Stream(), Stream(), Stream()

        def close(self):
            pass

    with Session() as s:
        s.add(Host(id=HOST, name='Fixture', address='192.0.2.1', fingerprint='fixture', state='waiting'))
        s.commit()
        h = s.get(Host, HOST)
        s.expunge(h)
    monkeypatch.setattr(ssh.paramiko, 'SSHClient', Started)
    monkeypatch.setattr(ssh, 'read_channel', lambda channel, deadline: (_ for _ in ()).throw(
        ssh.RemoteProtocolError('SSH stream closed without an exit status')))
    with pytest.raises(ssh.RemoteProtocolError) as raised:
        ssh.call(h, {'action': 'patch', 'packages': ['demo=2']}, key_file='unused')
    assert raised.value.remote_started is True and not ssh.request_unstarted(raised.value)
    monkeypatch.setattr(ssh, 'read_channel', lambda channel, deadline: (_ for _ in ()).throw(ssh.RemoteFailure('E: held')))
    with pytest.raises(ssh.RemoteFailure, match='SSH patch failed: E: held'):
        ssh.call(h, {'action': 'patch', 'packages': ['demo=2']}, key_file='unused')


class Finished:
    def __init__(self, output, status):
        self.output, self.status, self.eof_received = output, status, True

    def recv_ready(self):
        return bool(self.output)

    def recv(self, size):
        data, self.output = self.output, b''
        return data

    def recv_stderr_ready(self):
        return False

    def exit_status_ready(self):
        return True

    def recv_exit_status(self):
        return self.status


def test_only_structured_bridge_errors_are_failure_receipts():
    deadline = time.monotonic() + 1
    with pytest.raises(ssh.RemoteFailure, match='apt failed'):
        ssh.read_channel(Finished(b'{"error":"apt failed"}', 1), deadline)
    with pytest.raises(ssh.RemoteFailure, match='refused'):
        ssh.read_channel(Finished(b'{"error":"refused"}', 0), deadline)
    with pytest.raises(RuntimeError) as crashed:
        ssh.read_channel(Finished(b'', 137), deadline)
    assert not isinstance(crashed.value, ssh.RemoteFailure)


def test_health_regression_after_observed_patch_keeps_failed_rollout_state(admin, monkeypatch):
    """A known, observed outcome stays a terminal failure with its receipt."""
    setup_jobs(_depends_on=[])
    healthy = {'failed_units': '', 'collector_active': True, 'reboot_required': False}
    broken = {**healthy, 'failed_units': 'new.service loaded failed failed New'}
    samples = iter([healthy, broken])

    def behaviour(action, calls):
        if action == 'health':
            return next(samples)
        return {'output': 'upgraded'} if action == 'patch' else {}
    run(monkeypatch, behaviour)
    with Session() as s:
        job = s.get(Job, 'patch')
        assert job.state == 'failed' and 'Patch receipt: {"output": "upgraded"}' in job.output
        assert 'new_failed_units' in job.output
