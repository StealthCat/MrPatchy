import pytest

from app import db_failover as f


def held(**kw):
    base = {'deployment_epoch': 3, 'ownership_epoch': 7, 'locks': []}
    base.update(kw)
    return base


def cur(**kw):
    base = {'deployment_epoch': 3, 'ownership_epoch': 7, 'owner_is_self': True}
    base.update(kw)
    return base


def test_unsent_is_replayable_only_after_pool_invalidation():
    assert f.classify_outcome('before_send', 'op1', pool_invalidated=True) == {
        'outcome': 'unsent', 'action': 'replay', 'reason': ''}
    assert f.classify_outcome('before_send', 'op1')['reason'] == 'pool_not_invalidated'
    assert f.classify_outcome('before_send', 'op1')['action'] == 'refuse'


@pytest.mark.parametrize('phase', ['sent', 'commit_sent'])
def test_lost_acknowledgment_is_reconciled_never_replayed(phase):
    got = f.classify_outcome(phase, 'op1', pool_invalidated=True)
    assert got == {'outcome': 'uncertain', 'action': 'reconcile', 'reason': ''}


@pytest.mark.parametrize('phase', ['sent', 'commit_sent'])
def test_uncertain_without_operation_id_is_refused(phase):
    assert f.classify_outcome(phase, None, pool_invalidated=True) == {
        'outcome': 'uncertain', 'action': 'refuse', 'reason': 'no_operation_id'}


def test_acknowledged_needs_nothing():
    assert f.classify_outcome('acknowledged')['action'] == 'none'


@pytest.mark.parametrize('args', [('bogus',), ('sent', ''), ('sent', 5), ('sent', 'a', 1)])
def test_malformed_outcome_input_fails_closed(args):
    got = f.classify_outcome(*args)
    assert got['action'] == 'refuse' and got['reason'] == 'invalid_input'


def test_resume_requires_matching_epochs_and_verified_writer():
    assert f.resume_gate(held(), cur(), True) == {'resume': True, 'reason': ''}
    assert f.resume_gate(held(), cur(), False)['reason'] == 'writer_unverified'
    assert f.resume_gate(held(), cur(deployment_epoch=4), True)['reason'] == 'deployment_epoch_changed'
    assert f.resume_gate(held(), cur(ownership_epoch=8), True)['reason'] == 'ownership_lost'
    assert f.resume_gate(held(), cur(owner_is_self=False), True)['reason'] == 'ownership_lost'


def test_reconnect_does_not_restore_session_lock_ownership():
    locks = [{'name': 'scheduler', 'kind': 'session_lock'}]
    assert f.resume_gate(held(locks=locks), cur(), True)['reason'] == 'session_locks_discarded'
    durable = [{'name': 'scheduler', 'kind': 'durable_row'}]
    assert f.resume_gate(held(locks=durable), cur(), True)['resume'] is True


@pytest.mark.parametrize('bad', [
    (None, cur(), True), (held(), None, True), (held(), cur(), 'yes'),
    (held(deployment_epoch=True), cur(), True), (held(ownership_epoch=-1), cur(), True),
    (held(), cur(owner_is_self=1), True), (held(locks='x'), cur(), True),
    (held(locks=[{'name': 'a', 'kind': 'weird'}]), cur(), True),
])
def test_resume_malformed_input_fails_closed(bad):
    assert f.resume_gate(*bad) == {'resume': False, 'reason': 'invalid_input'}
