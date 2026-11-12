import pytest

from app import transport_envelope as te


def make(**over):
    args = {'host_id': 1, 'resource_id': 'i-0abc', 'generation': 2, 'agent_version': '1.4', 'action': 'patch',
            'payload': {'b': 1, 'a': [1]}, 'job_id': 9, 'nonce': 'n-1', 'now': 1000}
    args.update(over)
    return te.build_request(**args)


def receipt(request, **over):
    value = {field: request[field] for field in te.BINDING_FIELDS}
    value.update(version=te.VERSION, binding=request['binding'], executed_at=1100)
    value.update(over)
    return value


def test_request_is_canonical_and_bound():
    base = make()
    assert base['expires_at'] == 1300
    assert base['binding'] == make(payload={'a': [1], 'b': 1})['binding']
    for over in ({'resource_id': 'i-0def'}, {'generation': 3}, {'agent_version': '1.5'}, {'action': 'reboot'},
                 {'payload': {}}, {'job_id': 10}, {'nonce': 'n-2'}, {'host_id': 2}, {'now': 1001}):
        assert make(**over)['binding'] != base['binding']


def test_invalid_requests_are_rejected():
    for over in ({'generation': 0}, {'generation': True}, {'host_id': ''}, {'lifetime': 0}, {'lifetime': 7200},
                 {'payload': {'x': float('nan')}}, {'payload': object()}, {'nonce': None}):
        with pytest.raises(ValueError):
            make(**over)


def test_replayed_nonce_is_refused_per_resource():
    seen = set()
    request = make()
    te.check_replay(seen, request)
    with pytest.raises(ValueError):
        te.check_replay(seen, request)
    te.check_replay(seen, make(resource_id='i-0def'))


def test_receipt_must_echo_the_exact_request():
    request = make()
    assert te.verify_receipt(request, receipt(request)) == (True, '')
    assert te.verify_receipt(request, receipt(request, resource_id='i-0def')) == (False, 'binding_mismatch')
    assert te.verify_receipt(request, receipt(request, generation=1)) == (False, 'binding_mismatch')
    assert te.verify_receipt(request, receipt(request, binding='0' * 64)) == (False, 'binding_mismatch')
    assert te.verify_receipt(request, receipt(request, version=2)) == (False, 'unsupported_version')
    assert te.verify_receipt(request, receipt(request, executed_at=1301)) == (False, 'expired')
    assert te.verify_receipt(request, receipt(request, executed_at=None)) == (False, 'expired')
    assert te.verify_receipt(request, None) == (False, 'unsupported_version')


def test_unsupported_routes_are_blocked_before_dispatch():
    matrix = {'ssh': ['patch', 'reboot'], 'aws-ssm': ['patch']}
    assert te.route_allowed(matrix, 'aws-ssm', 'patch')
    assert not te.route_allowed(matrix, 'aws-ssm', 'reboot')
    assert not te.route_allowed(matrix, 'azure', 'patch')


def test_unknown_mutation_is_recovery_required_never_replayed():
    assert te.classify_submission(te.ACCEPTED) == (te.ACCEPTED, 'await_receipt')
    assert te.classify_submission(te.REJECTED) == (te.REJECTED, 'fail')
    assert te.classify_submission('timeout') == (te.UNKNOWN, te.RECOVERY_REQUIRED)
    assert te.classify_submission(None, mutating=False) == (te.UNKNOWN, 'retry_read')
