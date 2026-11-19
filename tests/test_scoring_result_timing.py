"""Update scoring records one result-persistence timing per revalidated reply (#1159)."""
import json
import re
import time
import pytest
import sqlalchemy.orm
from sqlalchemy import event, select
from app import ai, ai_runs, update_scores
from app.db import Session, Host, Package, Setting
from app.security import seal


TIMING = re.compile(r'result persistence: [0-9]+\.[0-9]{3} ms; outcome=(complete|error)')


def seed(count=2):
    now = time.time()
    with Session() as s:
        s.add(Host(id='persist-host', name='Fixture', address='192.0.2.1', fingerprint='',
                   inventory={'os': 'ID=debian\nVERSION_ID=12'}))
        s.merge(Setting(key='config', value={'ai_enabled': True, 'ai_updates_enabled': True,
                                             'ai_model': 'fixture', 'ai_control_mode': 'unthrottled'}))
        s.merge(Setting(key='openai_key', value={'encrypted': seal('fixture-key')}))
        s.add_all(Package(id='persist-host:pkg' + str(i), host_id='persist-host', name='pkg' + str(i),
                          installed='1', candidate='2', available_since=now - 1000 + i) for i in range(count))
        s.commit()


def reply(payload, key):
    return {'assessments': [{'id': r['id'], 'score': 40, 'confidence': 'low', 'explanation': 'Fixture',
                             'limitations': 'No advisory verification'} for r in json.loads(payload['input'])]}


def outcomes():
    """Return (run, result-persistence outcomes, all timing stages) for the only scoring run."""
    with Session() as s:
        run = s.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.purpose == 'update_scoring'))
        events = list(s.scalars(select(ai_runs.AIEvent).where(
            ai_runs.AIEvent.run_id == run.id, ai_runs.AIEvent.stage.like('timing_%')).order_by(ai_runs.AIEvent.id)))
        persisted = [TIMING.fullmatch(e.message)[1] for e in events if e.stage == 'timing_result_persistence']
        return run, persisted, [e.stage.removeprefix('timing_') for e in events]


def score_states():
    with Session() as s:
        return sorted(row.state for row in s.scalars(select(update_scores.UpdateScore)))


def test_committed_reply_records_one_complete_result_persistence(admin, monkeypatch):
    seed()
    monkeypatch.setattr(ai, 'request', reply)
    update_scores.run_one()
    run, persisted, stages = outcomes()
    assert run.state == 'complete'
    assert persisted == ['complete']
    assert stages.count('run') == 1
    assert score_states() == ['complete', 'complete']


def test_superseded_revalidation_is_still_one_complete_persistence(admin, monkeypatch):
    seed()
    def changed(payload, key):
        # Evidence changes while the provider call is outstanding.
        with Session() as s:
            s.get(Package, 'persist-host:pkg0').candidate = '3'
            s.commit()
        return reply(payload, key)
    monkeypatch.setattr(ai, 'request', changed)
    update_scores.run_one()
    _, persisted, _ = outcomes()
    assert persisted == ['complete']
    assert score_states() == ['complete', 'superseded']


def test_failed_result_write_records_error_and_keeps_retry_behavior(admin, monkeypatch):
    seed()
    monkeypatch.setattr(ai, 'request', reply)
    def refuse_completion(session, context, instances):
        if any(isinstance(row, update_scores.UpdateScore) and row.state == 'complete' for row in session.dirty):
            raise RuntimeError('fixture database write failure')
    event.listen(sqlalchemy.orm.Session, 'before_flush', refuse_completion)
    try:
        update_scores.run_one()
    finally:
        event.remove(sqlalchemy.orm.Session, 'before_flush', refuse_completion)
    run, persisted, _ = outcomes()
    assert run.state == 'error'
    assert persisted == ['error']
    # Unchanged failure handling: the batch is retried under normal timing, not blocked.
    assert score_states() == ['error', 'error']


@pytest.mark.parametrize('failure', [
    ai.AIError('The model refused this request.', cause='model_refusal'),
    ai.AIError('Model output reached max_output_tokens.', cause='token_budget'),
])
def test_provider_refusals_record_no_result_persistence(admin, monkeypatch, failure):
    seed()
    def refuse(payload, key):
        raise failure
    monkeypatch.setattr(ai, 'request', refuse)
    update_scores.run_one()
    run, persisted, stages = outcomes()
    assert run.state == 'error' and persisted == [] and stages.count('run') == 1
    assert 'complete' not in score_states()


@pytest.mark.parametrize('malformed', [
    lambda batch: {'assessments': batch[:1]},
    lambda batch: {'assessments': [dict(r, id='other') for r in batch]},
    lambda batch: {'assessments': [dict(r, score=101) for r in batch]},
    lambda batch: {'not_assessments': []},
])
def test_malformed_replies_record_no_result_persistence(admin, monkeypatch, malformed):
    seed()
    monkeypatch.setattr(ai, 'request', lambda payload, key: malformed(reply(payload, key)['assessments']))
    update_scores.run_one()
    run, persisted, _ = outcomes()
    assert run.state == 'error' and persisted == []
    assert 'complete' not in score_states()
