from app import firmware_operation as op


def req(**kw):
    base = {'host_id': 'h1', 'enrollment_id': 'e1', 'device_id': 'd1',
            'action': 'upgrade', 'release_version': '2.0',
            'artifact_sha256': 'a' * 64, 'policy_digest': 'p1'}
    base.update(kw)
    return base


def good_facts(**kw):
    f = {k: True for k in (
        'device_identity_matches', 'signature_trusted', 'policy_allows', 'power_ok',
        'provider_requirements_met', 'boot_prerequisites_met', 'free_space_ok',
        'recovery_requirements_met', 'approval_current')}
    f.update({'anti_rollback_violation': False, 'manual_steps_pending': False})
    f.update(kw)
    return f


def test_binding_changes_with_any_bound_field():
    base = op.bind_operation(req())
    assert base['ok'] and len(base['operation_id']) == 64
    for field, value in (('host_id', 'h2'), ('device_id', 'd2'), ('action', 'downgrade'),
                         ('artifact_sha256', 'b' * 64), ('policy_digest', 'p2')):
        assert op.bind_operation(req(**{field: value}))['operation_id'] != base['operation_id']
    assert op.approval_valid(base['operation_id'], req())
    assert not op.approval_valid(base['operation_id'], req(policy_digest='p2'))
    assert not op.approval_valid(None, req())


def test_rejects_malformed_unsupported_and_force_flags():
    assert not op.bind_operation('x')['ok']
    assert 'missing_device_id' in op.bind_operation(req(device_id=' '))['errors']
    assert 'unsupported_action' in op.bind_operation(req(action='raw'))['errors']
    r = op.bind_operation(req(flags=['Force']))
    assert not r['ok'] and 'forbidden_flag' in r['errors']
    assert 'malformed_flags' in op.bind_operation(req(flags='force'))['errors']


def test_preflight_unknown_is_a_blocker():
    assert op.preflight_blockers(good_facts()) == []
    assert op.preflight_blockers(None) == ['facts_unavailable']
    assert op.preflight_blockers({}) != []
    assert 'power_insufficient' in op.preflight_blockers(good_facts(power_ok=False))
    assert 'power_insufficient' in op.preflight_blockers(good_facts(power_ok='yes'))
    assert 'anti_rollback' in op.preflight_blockers(good_facts(anti_rollback_violation=True))
    assert 'manual_steps_pending' in op.preflight_blockers(good_facts(manual_steps_pending=None))


def test_transitions_and_cancellation():
    assert op.can_transition('queued', 'preflight')
    assert not op.can_transition('queued', 'succeeded')
    assert not op.can_transition('succeeded', 'failed')
    assert not op.can_transition('recovery_required', 'queued')
    assert not op.can_transition('bogus', 'queued')
    for s in op.TERMINAL_STATES:
        assert not any(op.can_transition(s, n) for n in op.STATES)
    assert op.can_cancel('staged') and not op.can_cancel('writing')
    assert not op.can_cancel('pending_activation')


def test_outcome_never_treats_staging_or_exit_code_as_success():
    ok = {'receipt_valid': True, 'device_present': True, 'expected_version': '2.0',
          'running_version': '2.0', 'history_confirms': True, 'write_started': True}
    assert op.classify_outcome(ok)['state'] == 'succeeded'
    assert op.classify_outcome({**ok, 'activation_pending': True})['state'] == 'pending_activation'
    assert op.classify_outcome({**ok, 'running_version': '1.0'})['state'] == 'recovery_required'
    assert op.classify_outcome({**ok, 'history_confirms': False})['state'] == 'recovery_required'
    assert op.classify_outcome({**ok, 'device_present': False})['state'] == 'recovery_required'
    assert op.classify_outcome({**ok, 'receipt_valid': False})['state'] == 'recovery_required'
    assert op.classify_outcome({'receipt_valid': False})['state'] == 'failed'
    assert op.classify_outcome({**ok, 'write_started': False, 'running_version': '1.0'})['state'] == 'failed'
    assert op.classify_outcome(None)['state'] == 'recovery_required'
    assert 'succeeded' not in op.NOT_COMPLETE_STATES


def test_overlong_values_are_rejected_not_truncated():
    prefix = 'x' * op.MAX_TEXT
    a = op.bind_operation(req(artifact_sha256=prefix + 'a'))
    b = op.bind_operation(req(artifact_sha256=prefix + 'b'))
    assert not a['ok'] and not b['ok']
    assert 'overlong_artifact_sha256' in a['errors'] and a['operation_id'] is None
    # A value exactly at the limit is still accepted and distinct.
    assert op.bind_operation(req(policy_digest='p' * op.MAX_TEXT))['ok']
    assert 'overlong_flags' in op.bind_operation(req(flags=['y' * (op.MAX_TEXT + 1)]))['errors']
    # An overlong reported version can never verify by matching a shared prefix.
    ok = {'receipt_valid': True, 'device_present': True, 'history_confirms': True,
          'write_started': True, 'expected_version': prefix + '1', 'running_version': prefix + '2'}
    assert op.classify_outcome(ok)['state'] == 'recovery_required'
    assert op.classify_outcome({**ok, 'running_version': prefix + '1'})['state'] == 'recovery_required'


def test_unknown_request_fields_are_rejected():
    for extra in ({'target_path': '/dev/mtd0'}, {'provider_option': 'x'}, {'remote': 'lvfs'},
                  {1: 'x'}):
        r = op.bind_operation({**req(), **extra})
        assert not r['ok'] and 'unknown_field' in r['errors'] and r['operation_id'] is None
    base = op.bind_operation(req())
    assert not op.approval_valid(base['operation_id'], {**req(), 'target_path': '/dev/mtd0'})


def test_permitted_flags_are_bound_into_the_operation_id():
    base = op.bind_operation(req())
    empty = op.bind_operation(req(flags=[]))
    assert empty['ok'] and empty['operation_id'] == base['operation_id']
    offline = op.bind_operation(req(flags=['offline']))
    assert offline['ok'] and offline['operation_id'] != base['operation_id']
    assert not op.approval_valid(base['operation_id'], req(flags=['offline']))
    assert not op.approval_valid(offline['operation_id'], req(flags=['offline', 'no-reboot-check']))
    # Order and duplicates do not change meaning; whitespace is normalized.
    assert (op.bind_operation(req(flags=['b', 'a', 'a']))['operation_id']
            == op.bind_operation(req(flags=[' a', 'b ']))['operation_id'])
    for bad in ([1], [''], ['  '], [None]):
        assert 'malformed_flags' in op.bind_operation(req(flags=bad))['errors']
    assert 'malformed_flags' in op.bind_operation(req(flags=None))['errors']
