from app import controller_membership as cm

DEP = {'protocol': 1, 'schema': 5}
NOW = 1000


def m(id, **kw):
    base = {'id': id, 'boot': 1, 'domain': 'd-' + id, 'version': '1.42.0', 'protocol': 1, 'schema': 5,
            'heartbeat': NOW - 1, 'desired': 'standby', 'observed': 'standby', 'ready': True}
    base.update(kw)
    return base


def test_validity_and_freshness():
    assert cm.member_valid(m('a'))
    assert not cm.member_valid(m('a', boot=True))
    assert not cm.member_valid(m('a', version='1.2'))
    assert not cm.member_valid(m('a', observed='leader'))
    assert cm.is_fresh(m('a'), NOW)
    assert not cm.is_fresh(m('a', heartbeat=NOW - 31), NOW)
    assert not cm.is_fresh(m('a', heartbeat=NOW + 5), NOW)
    assert not cm.is_fresh(m('a'), None)


def test_registration_collision_and_shared_domain():
    reg = [m('a')]
    assert cm.registration_decision(reg, m('a', boot=1), NOW)['reason'] == 'identity_collision'
    assert cm.registration_decision(reg, m('a', boot=0), NOW)['reason'] == 'identity_collision'
    assert cm.registration_decision(reg, m('a', boot=2), NOW)['allowed']
    stale = [m('a', heartbeat=NOW - 100)]
    assert cm.registration_decision(stale, m('a', boot=1), NOW)['allowed']
    res = cm.registration_decision(reg, m('b', domain='d-a'), NOW)
    assert res['allowed'] and res['shared_domain']
    assert not cm.registration_decision(reg, {'id': 'x'}, NOW)['allowed']
    assert cm.registration_decision([{'id': 'x'}], m('b'), NOW)['reason'] == 'invalid_registry'


def test_keep_single_live_serving():
    members = [m('a', observed='serving'), m('b')]
    r = cm.serving_decision(DEP, members, NOW)
    assert (r['serving'], r['action']) == ('a', 'keep')


def test_split_brain_holds():
    members = [m('a', observed='serving'), m('b', observed='serving')]
    r = cm.serving_decision(DEP, members, NOW)
    assert r['action'] == 'hold' and r['serving'] is None and r['reason'] == 'split_brain'


def test_stale_serving_is_quarantined_and_standby_promoted():
    members = [m('a', observed='serving', heartbeat=NOW - 90), m('b', ready=True), m('c', ready=False)]
    r = cm.serving_decision(DEP, members, NOW)
    assert (r['serving'], r['action'], r['quarantine']) == ('b', 'promote', ['a'])


def test_incompatible_serving_is_not_trusted():
    members = [m('a', observed='serving', schema=4), m('b')]
    r = cm.serving_decision(DEP, members, NOW)
    assert r['action'] == 'promote' and r['serving'] == 'b' and r['quarantine'] == ['a']


def test_no_candidate_never_guesses():
    members = [m('a', ready=False), m('b', heartbeat=NOW - 99), m('c', observed='draining')]
    r = cm.serving_decision(DEP, members, NOW)
    assert r['action'] == 'hold' and r['reason'] == 'no_eligible_standby'


def test_promotion_preference_is_deterministic():
    members = [m('b', boot=3), m('a', boot=3), m('c', boot=9, desired='serving')]
    assert cm.serving_decision(DEP, members, NOW)['serving'] == 'c'
    members = [m('b', boot=3), m('a', boot=3)]
    assert cm.serving_decision(DEP, members, NOW)['serving'] == 'a'


def test_bad_input_holds():
    assert cm.serving_decision(DEP, [], NOW)['reason'] == 'invalid_input'
    assert cm.serving_decision(DEP, [m('a'), m('a')], NOW)['reason'] == 'identity_collision'
    assert cm.serving_decision(None, [m('a')], NOW)['action'] == 'hold'


def test_missing_expected_members():
    assert cm.missing_expected(['a', 'b', 'c'], [m('a')]) == ['b', 'c']
    assert cm.missing_expected(None, []) is None

def test_desired_draining_standby_is_never_promoted():
    # Coordinator review on #508: a member selected for drain must not become the promotion target
    # even while it still reports observed standby, ready and fresh.
    draining = m('a', desired='draining', observed='standby')
    assert not cm.standby_ready(DEP, draining, NOW)
    r = cm.serving_decision(DEP, [m('old', observed='serving', heartbeat=NOW - 100), draining], NOW)
    assert r['action'] == 'hold' and r['serving'] is None and r['reason'] == 'no_eligible_standby'
    assert r['quarantine'] == ['old']
    r = cm.serving_decision(DEP, [draining, m('b')], NOW)
    assert r['action'] == 'promote' and r['serving'] == 'b'
