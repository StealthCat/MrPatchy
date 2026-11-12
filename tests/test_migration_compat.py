import pytest

from app import migration_compat as mc


def node(version='1.42.31', protocol=1, lo=5, hi=6, name='n'):
    return {'name': name, 'version': version, 'protocol': protocol, 'schema_min': lo, 'schema_max': hi}


def dep(schema=6, protocol=1, receipt='1.42.31'):
    return {'schema': schema, 'protocol': protocol, 'receipt_version': receipt}


def test_parse_version_is_strict():
    assert mc.parse_version('1.42.31') == (1, 42, 31)
    for bad in (None, 1, '1.42', '1.x.3', '1.2.3.4', '-1.2.3', ''):
        assert mc.parse_version(bad) is None


def test_join_requires_protocol_and_schema_range():
    assert mc.join_decision(dep(), node())['allowed']
    assert mc.join_decision(dep(protocol=2), node())['reason'] == 'protocol_mismatch'
    assert mc.join_decision(dep(schema=7), node())['reason'] == 'schema_unsupported'
    assert mc.join_decision(dep(schema=4), node())['reason'] == 'schema_unsupported'


@pytest.mark.parametrize('bad', [None, {}, node(lo=7, hi=6), node(version='x'), {**node(), 'protocol': True}])
def test_join_fails_closed_on_malformed_node(bad):
    assert mc.join_decision(dep(), bad) == {'allowed': False, 'reason': 'invalid_input'}
    assert mc.join_decision(None, node())['reason'] == 'invalid_input'


def test_old_node_cannot_overwrite_newer_receipt():
    assert not mc.receipt_writable(dep(receipt='1.43.0'), node(version='1.42.31'))
    assert mc.receipt_writable(dep(receipt='1.42.31'), node(version='1.42.31'))
    assert mc.receipt_writable(dep(receipt=None), node())
    assert not mc.receipt_writable(dep(), None)


def test_new_migration_validates():
    assert mc.new_migration('m1', 5, 6)['phase'] == 'pending'
    for args in (('', 5, 6), ('m', 6, 6), ('m', 7, 6), ('m', True, 6)):
        with pytest.raises(ValueError):
            mc.new_migration(*args)


def test_resume_never_races_a_live_owner():
    rec = {**mc.new_migration('m', 5, 6), 'phase': 'expand', 'owner': 'a', 'expires_at': 100}
    assert mc.resume_decision(rec, 'b', 50) == {'action': 'wait', 'reason': 'owner_live'}
    assert mc.resume_decision(rec, 'a', 50)['action'] == 'continue'


def test_pending_starts_and_done_only_validates():
    assert mc.resume_decision(mc.new_migration('m', 5, 6), 'a', 1)['action'] == 'start'
    assert mc.resume_decision({**mc.new_migration('m', 5, 6), 'phase': 'done'}, 'a', 1)['action'] == 'validate'


def test_owner_crash_restarts_only_idempotent_expand_phase():
    rec = {**mc.new_migration('m', 5, 6), 'phase': 'expand', 'owner': 'a', 'expires_at': 100}
    assert mc.resume_decision(rec, 'b', 101) == {'action': 'restart_phase', 'reason': 'owner_lost_idempotent'}
    for phase in mc.DESTRUCTIVE:
        got = mc.resume_decision({**rec, 'phase': phase}, 'b', 101)
        assert got == {'action': 'block', 'reason': 'owner_lost_destructive_phase'}


def test_resume_fails_closed_on_bad_input():
    rec = mc.new_migration('m', 5, 6)
    assert mc.resume_decision(rec, '', 1)['reason'] == 'invalid_input'
    assert mc.resume_decision({**rec, 'phase': 'bogus'}, 'a', 1)['reason'] == 'invalid_input'
    assert mc.resume_decision(rec, 'a', True)['reason'] == 'invalid_input'


def test_contract_gate_blocks_old_replicas_missing_inventory_and_missing_approval():
    old, new = node(lo=5, hi=6, name='old'), node(lo=6, hi=6, name='new')
    got = mc.contract_gate(6, [old, new], True)
    assert got == {'allowed': False, 'reason': 'incompatible_replicas_present', 'blockers': ['old']}
    assert mc.contract_gate(6, [], True)['reason'] == 'invalid_input'
    assert mc.contract_gate(6, [new], None)['reason'] == 'approval_required'
    assert mc.contract_gate(6, [new], 'yes')['reason'] == 'approval_required'
    assert mc.contract_gate(6, [new], True)['allowed']


def test_rollback_refused_after_destructive_phase():
    mig = {**mc.new_migration('m', 5, 6), 'phase': 'expand'}
    assert mc.rollback_possible(dep(schema=5), node(lo=5, hi=5), mig)['possible']
    assert mc.rollback_possible(dep(schema=6), node(lo=5, hi=5), mig)['reason'] == 'schema_unsupported'
    for phase in ('migrate', 'contract', 'done'):
        got = mc.rollback_possible(dep(schema=6), node(lo=5, hi=6), {**mig, 'phase': phase})
        assert got == {'possible': False, 'reason': 'destructive_phase_reached'}
