"""Known-good cache miss explanations (roadmap B slice, issue #763)."""
import pytest
from sqlalchemy import select

from app import ai, ai_assessments, ai_runs, known_good, worker
from app.db import Behavior, Host, Session, Setting
from app.security import seal
from tests.test_known_good import complete, retained, sha


def explain(s, snapshot=None, **kwargs):
    return known_good.explain_miss(s, snapshot or complete(), 'gpt-fixture', [sha('9')], **kwargs)


def test_bypass_reasons_take_precedence_and_need_no_context(client):
    with Session() as s:
        assert explain(s, {}, refresh=True)['code'] == 'bypassed_refresh'
        assert explain(s, {}, changed=True)['code'] == 'bypassed_changed'


def test_ineligible_context_lists_bounded_fixed_labels_without_evidence_values(client):
    snapshot = complete()
    snapshot['identity_verified'] = False
    snapshot['investigation']['details']['known_good_context']['artifact']['verified'] = False
    snapshot['investigation']['details']['known_good_context']['provenance']['verified'] = False
    snapshot['investigation']['details']['known_good_context']['configuration']['complete'] = False
    with Session() as s:
        result = explain(s, snapshot)
    assert result['code'] == 'context_ineligible'
    labels = [text for text in known_good.REASON_TEXT.values() if text in result['message']]
    assert 1 <= len(labels) <= known_good.MISS_REASON_LIMIT
    assert '/usr/bin/fixture' not in result['message'] and sha('a') not in result['message']


def test_missing_active_and_revoked_candidates_are_distinguished(client):
    row = retained()
    with Session() as s:
        assert explain(s)['code'] == 'no_candidate'
        s.add(row); status = known_good.publish(s, row); s.commit()
        assert known_good.lookup(s, complete(), 'gpt-fixture', [sha('9')]) is not None
        # An active entry that lookup refuses failed provenance revalidation.
        s.get(ai_assessments.Assessment, row.id).result = {
            **row.result, 'explanation': 'Mutated after publication'}
        s.commit()
        assert known_good.lookup(s, complete(), 'gpt-fixture', [sha('9')]) is None
        assert explain(s)['code'] == 'candidate_unverified'
        s.get(known_good.Entry, status['fingerprint']).active = False; s.commit()
        assert explain(s)['code'] == 'candidate_revoked'


def current():
    snapshot = complete(); snapshot['host_id'] = 'host-two'
    snapshot['investigation']['details']['known_good_context']['observation']['host_id'] = 'host-two'
    return snapshot


def seed(snapshot=None):
    with Session() as s:
        s.add_all([Host(id='host-two', name='Current', address='192.0.2.2', fingerprint=''),
            Behavior(id='behavior-two', host_id='host-two', evidence=snapshot or current(),
                verdict='pending')])
        s.merge(Setting(key='config', value={'ai_enabled': True, 'ai_model': 'gpt-fixture'}))
        s.merge(Setting(key='openai_key', value={'encrypted': seal('private-key')}))
        s.commit()


def run_events():
    with Session() as s:
        run = s.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.subject == 'behavior-two'))
        return [(row.stage, row.message) for row in s.scalars(
            select(ai_runs.AIEvent).where(ai_runs.AIEvent.run_id == run.id))]


def test_worker_records_miss_reason_before_paid_investigation(client, monkeypatch):
    seed()
    monkeypatch.setattr(ai, 'investigate', lambda *a, **k: {
        'risk': 'low', 'explanation': 'Fresh provider result',
        'recommended_checks': 'Continue deterministic monitoring', 'requested_checks': []})
    worker.investigate_one()
    events = run_events()
    assert ('known_good_lookup', known_good.MISS_TEXT['no_candidate']) in events
    with Session() as s:
        behavior = s.get(Behavior, 'behavior-two')
        assert behavior.verdict == 'low', behavior.analysis


def test_worker_records_no_miss_event_on_a_cache_hit(client, monkeypatch):
    source = retained(snapshot=complete())
    source.policy_hash = ai_assessments.digest([ai.investigation_policy()])
    seed()
    with Session() as s:
        s.add(Host(id='host-one', name='Source', address='192.0.2.1', fingerprint=''))
        s.add(source); known_good.publish(s, source); s.commit()
    monkeypatch.setattr(ai, 'investigate', lambda *a, **k: pytest.fail('cache hit called provider'))
    worker.investigate_one()
    assert not [event for event in run_events() if event[0] == 'known_good_lookup']


def test_miss_diagnostic_failure_never_fails_triage(client, monkeypatch):
    seed()
    monkeypatch.setattr(known_good, 'explain_miss',
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError('diagnostic broke')))
    monkeypatch.setattr(ai, 'investigate', lambda *a, **k: {
        'risk': 'low', 'explanation': 'Fresh provider result',
        'recommended_checks': 'Continue deterministic monitoring', 'requested_checks': []})
    worker.investigate_one()
    with Session() as s:
        behavior = s.get(Behavior, 'behavior-two')
        assert behavior.verdict == 'low', behavior.analysis
    assert not [event for event in run_events() if event[0] == 'known_good_lookup']
