import pytest

from app import ingress_routing as ir


def n(name='a', role='active', live=True, ready=True):
    return {'name': name, 'role': role, 'live': live, 'ready': ready}


def test_liveness_alone_never_makes_a_node_serving():
    for role in ('standby', 'fenced', 'incompatible'):
        assert not ir.eligibility(n(role=role), 'active_standby')['serving']
        assert not ir.eligibility(n(role=role), 'active_active')['serving']
    assert ir.eligibility(n(ready=False), 'active_standby') == {'serving': False, 'reason': 'not_ready'}
    assert ir.eligibility(n(live=False), 'active_standby')['reason'] == 'not_live'


def test_role_must_match_mode():
    assert ir.eligibility(n(role='active'), 'active_standby')['serving']
    assert ir.eligibility(n(role='active_active'), 'active_active')['serving']
    assert ir.eligibility(n(role='active'), 'active_active')['reason'] == 'role_mode_mismatch'
    assert ir.eligibility(n(role='active_active'), 'active_standby')['reason'] == 'role_mode_mismatch'


@pytest.mark.parametrize('bad', [None, {}, n(role='boss'), {**n(), 'live': 1}, {**n(), 'ready': None}])
def test_malformed_facts_fail_closed(bad):
    assert ir.eligibility(bad, 'active_standby') == {'serving': False, 'reason': 'invalid_input'}
    assert not ir.route_decision(bad, 'active_standby', 'read')['route']
    assert ir.eligibility(n(), 'bogus')['reason'] == 'invalid_input'


def test_only_reads_are_replay_safe_and_admin_is_never_routed():
    assert ir.route_decision(n(), 'active_standby', 'read') == {'route': True, 'reason': '', 'replay_safe': True}
    assert ir.route_decision(n(), 'active_standby', 'mutation')['replay_safe'] is False
    assert ir.route_decision(n(), 'active_standby', 'stream')['replay_safe'] is False
    assert ir.route_decision(n(), 'active_standby', 'admin') == {'route': False, 'reason': 'admin_not_public', 'replay_safe': False}
    assert ir.route_decision(n(), 'active_standby', 'x')['reason'] == 'invalid_input'


def test_standby_receives_no_mutation():
    assert ir.route_decision(n(role='standby'), 'active_standby', 'mutation') == {
        'route': False, 'reason': 'standby', 'replay_safe': False}


def test_pool_active_standby_routes_to_the_single_active():
    got = ir.pool([n('a'), n('b', role='standby')], 'active_standby', 'mutation')
    assert got == {'ok': True, 'reason': '', 'members': ['a']}


def test_pool_refuses_split_brain_even_when_one_active_is_unready():
    got = ir.pool([n('a'), n('b', ready=False)], 'active_standby', 'read')
    assert got['reason'] == 'multiple_active' and not got['ok']
    assert ir.pool([n('a'), n('b')], 'active_standby', 'read')['reason'] == 'multiple_active'


def test_pool_active_active_uses_every_ready_member():
    nodes = [n('b', 'active_active'), n('a', 'active_active'), n('c', 'active_active', ready=False)]
    assert ir.pool(nodes, 'active_active', 'read') == {'ok': True, 'reason': '', 'members': ['a', 'b']}


def test_pool_with_nothing_serving_or_bad_inventory_is_refused():
    assert ir.pool([n('a', 'standby')], 'active_standby', 'read')['reason'] == 'no_serving_node'
    assert ir.pool([], 'active_standby', 'read')['reason'] == 'invalid_input'
    assert ir.pool([n('a'), n('a', 'standby')], 'active_standby', 'read')['reason'] == 'duplicate_node'
    assert ir.pool([{**n(), 'name': ''}], 'active_standby', 'read')['reason'] == 'invalid_input'
    assert ir.pool([n()], 'active_standby', 'admin')['reason'] == 'no_serving_node'
