import pytest

from app import rollout_rings as r

INV = {f'h{i}': {'service': 'web' if i < 4 else 'db', 'site': 'a' if i % 2 else 'b'} for i in range(6)}


def definition(**over):
    d = {'version': 1, 'rings': [
        {'name': 'canary', 'canary': True, 'hosts': ['h0'], 'soak_seconds': 600},
        {'name': 'main', 'hosts': ['h1', 'h2', 'h3', 'h4', 'h5'], 'max_parallel': 3, 'max_failures': 1}],
        'limits': [{'scope': 'service', 'name': 'web', 'max_unavailable': 2}]}
    d.update(over)
    return d


@pytest.mark.parametrize('bad', [
    {'version': 2, 'rings': []},
    {'version': 1, 'rings': []},
    {'version': 1, 'rings': [{'name': 'a', 'hosts': ['h0']}, {'name': 'a', 'hosts': ['h1']}]},
    {'version': 1, 'rings': [{'name': 'a', 'hosts': ['h0']}, {'name': 'b', 'hosts': ['h0']}]},
    {'version': 1, 'rings': [{'name': 'a', 'hosts': ['h0']}, {'name': 'b', 'canary': True, 'hosts': ['h1']}]},
    {'version': 1, 'rings': [{'name': 'a', 'hosts': ['h0'], 'max_parallel': 0}]},
    {'version': 1, 'rings': [{'name': 'a', 'hosts': ['h0'], 'max_parallel': True}]},
    {'version': 1, 'rings': [{'name': 'a', 'hosts': ['h0'], 'soak_seconds': 10**9}]},
    {'version': 1, 'rings': [{'name': 'a', 'hosts': ['bad host']}]},
    {'version': 1, 'rings': [{'name': 'a', 'hosts': ['h0']}], 'limits': [{'scope': 'zone', 'name': 'x', 'max_unavailable': 1}]},
])
def test_validate_rejects(bad):
    with pytest.raises(r.RingError):
        r.validate(bad)


def test_plan_is_exact_and_digest_stable():
    a, b = r.plan(definition(), INV), r.plan(definition(), INV)
    assert a['digest'] == b['digest']
    assert a['members']['h4'] == {'service': 'db', 'site': 'b'}
    assert r.plan(definition(limits=[]), INV)['digest'] != a['digest']
    with pytest.raises(r.RingError, match='not in inventory'):
        r.plan(definition(), {'h0': {}})


def test_canary_first_then_soak_then_advance():
    p = r.plan(definition(), INV)
    s = r.admit(p, {'ring': 0}, 100)
    assert (s['action'], s['hosts']) == ('start', ['h0'])
    assert r.admit(p, {'ring': 0, 'in_flight': ['h0']}, 100)['action'] == 'wait'
    done = {'ring': 0, 'done': ['h0']}
    assert 'ring_finished_at' in r.admit(p, done, 100)['reason']
    assert r.admit(p, {**done, 'ring_finished_at': 100}, 400)['reason'].endswith('300s remaining')
    assert r.admit(p, {**done, 'ring_finished_at': 100}, 700)['action'] == 'advance'
    assert r.admit(p, {'ring': 2}, 0)['action'] == 'complete'


def test_availability_budget_counts_existing_outages_and_other_rollouts():
    p = r.plan(definition(), INV)
    s = r.admit(p, {'ring': 1}, 0)
    assert s['hosts'] == ['h1', 'h2', 'h4']  # web budget 2; db host h4 unconstrained
    assert any('h3' in b for b in s['blocked'])
    s = r.admit(p, {'ring': 1, 'done': [], 'unavailable': ['h0']}, 0)  # outage outside the ring uses budget
    assert s['hosts'] == ['h1', 'h4', 'h5']
    s = r.admit(p, {'ring': 1, 'unavailable': ['h1']}, 0)  # already-down pending host adds no new outage
    assert s['hosts'][:2] == ['h1', 'h2']
    s = r.admit(p, {'ring': 1, 'unavailable': ['h2', 'h3']}, 0)  # budget already spent
    assert s['hosts'] == ['h2', 'h3', 'h4']  # h1 would be a third outage


def test_budget_blocks_all_is_visible():
    p = r.plan(definition(limits=[{'scope': 'service', 'name': 'web', 'max_unavailable': 0}], rings=[
        {'name': 'a', 'hosts': ['h1', 'h2']}]), INV)
    s = r.admit(p, {}, 0)
    assert s['action'] == 'wait' and len(s['blocked']) == 2


def test_failures_halt_and_failed_hosts_keep_capacity():
    p = r.plan(definition(), INV)
    assert r.admit(p, {'ring': 1, 'failed': ['h4', 'h5']}, 0)['action'] == 'halt'
    s = r.admit(p, {'ring': 1, 'failed': ['h1']}, 0)  # within threshold; h1 still consumes budget
    assert 'h2' in s['hosts'] and 'h3' not in s['hosts']


def test_uncertain_outcome_blocks_new_work():
    p = r.plan(definition(), INV)
    s = r.admit(p, {'ring': 1, 'uncertain': ['h4']}, 0)
    assert s['action'] == 'wait' and 'uncertain' in s['reason']


def test_parallelism_and_state_validation():
    p = r.plan(definition(), INV)
    assert r.admit(p, {'ring': 1, 'in_flight': ['h4', 'h5', 'h1']}, 0)['reason'] == 'ring parallelism is full'
    with pytest.raises(r.RingError):
        r.admit(p, {'ring': 1, 'done': 'h1'}, 0)
    with pytest.raises(r.RingError):
        r.admit(p, {'ring': 9}, 0)
    with pytest.raises(r.RingError):
        r.admit(p, {'ring': 0, 'done': ['h0'], 'ring_finished_at': 500}, 100)


def test_external_host_outage_consumes_same_service_budget():
    d=definition(rings=[{'name':'only','hosts':['h0']}],
        limits=[{'scope':'service','name':'web','max_unavailable':1}])
    p=r.plan(d,{**INV,'external':{'service':'web','site':'a'}})
    assert r.admit(p,{'unavailable':['external']},100)['action']=='wait'
    assert 'external' not in p['members']


@pytest.mark.parametrize('bad',[float('nan'),float('inf'),float('-inf')])
def test_nonfinite_soak_evidence_never_advances(bad):
    p=r.plan(definition(),INV)
    with pytest.raises(r.RingError):r.admit(p,{'done':['h0'],'ring_finished_at':bad},100)
    with pytest.raises(r.RingError):r.admit(p,{},bad)


def test_unknown_limited_scope_membership_requires_current_inventory():
    with pytest.raises(r.RingError):r.plan(definition(),{**INV,'external':{'site':'a'}})


def test_strict_definition_rejects_unknown_fields_and_newline_names():
    with pytest.raises(r.RingError):r.validate({**definition(),'soakSeconds':100})
    with pytest.raises(r.RingError):r.validate(definition(rings=[{'name':'ring\n','hosts':['h0']}]))
