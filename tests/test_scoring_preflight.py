import pytest
from sqlalchemy import event

from app import ai, ai_runs, update_scores
from app.db import Host, Package, Session, Setting, engine
from app.security import seal


@pytest.mark.parametrize('fleet', ['empty', 'paused', 'inactive'])
def test_idle_scoring_polls_read_once_and_skip_the_lock(admin, monkeypatch, fleet):
    monkeypatch.setattr(update_scores, '_MEMO', {})
    with Session() as session:
        session.merge(Setting(key='config', value={'ai_enabled': True, 'ai_updates_enabled': True,
                                                   'ai_model': 'fixture', 'ai_control_mode': 'unthrottled'}))
        session.merge(Setting(key='openai_key', value={'encrypted': seal('fixture-key')}))
        if fleet != 'empty':
            session.add(Host(id='idle', name='Idle', address='192.0.2.1',
                             fingerprint='', enabled=fleet != 'inactive'))
            session.add(Package(id='idle:fixture', host_id='idle', name='fixture',
                                installed='1', candidate='2'))
            if fleet == 'paused':
                session.add(Setting(key='server-ai:idle', value={'paused': True}))
        session.commit()

    locks = []
    acquire_lock = update_scores.Lock

    def observe_lock(name):
        locks.append(name)
        return acquire_lock(name)

    def no_provider(*args, **kwargs):
        pytest.fail('An idle scoring poll cannot call the provider')

    reads = []

    def observe(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith('SELECT'):
            reads.append(statement)

    monkeypatch.setattr(update_scores, 'Lock', observe_lock)
    monkeypatch.setattr(ai, 'request', no_provider)
    event.listen(engine, 'before_cursor_execute', observe)
    try:
        for _ in range(4):
            update_scores.run_one()
    finally:
        event.remove(engine, 'before_cursor_execute', observe)

    assert locks == []
    assert len(reads) == 4


def test_scoring_preflight_preserves_recovery_without_candidates(admin, monkeypatch):
    monkeypatch.setattr(update_scores, '_MEMO', {})
    with Session() as session:
        session.merge(Setting(key='config', value={'ai_enabled': False, 'ai_updates_enabled': False}))
        session.add(ai_runs.AIRun(id='unfinished-score', model='fixture', purpose='update_scoring'))
        session.commit()

    update_scores.run_one()

    with Session() as session:
        assert session.get(ai_runs.AIRun, 'unfinished-score').state == 'interrupted'


def test_idle_scoring_preserves_pruning_of_absent_memo_hosts(admin, monkeypatch):
    monkeypatch.setattr(update_scores, '_MEMO', {'absent': (None, {}, {})})
    with Session() as session:
        session.merge(Setting(key='config', value={'ai_enabled': True, 'ai_updates_enabled': True,
                                                   'ai_model': 'fixture', 'ai_control_mode': 'unthrottled'}))
        session.merge(Setting(key='openai_key', value={'encrypted': seal('fixture-key')}))
        session.commit()

    update_scores.run_one()

    assert not update_scores._MEMO
