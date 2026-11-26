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

def test_legacy_scoring_probe_holds_at_threshold_and_reopens_on_cutoff(admin, monkeypatch):
    from types import SimpleNamespace

    started=1_750_000_000
    now=[started]
    monkeypatch.setattr(update_scores, 'time', SimpleNamespace(time=lambda:now[0]))
    monkeypatch.setattr(update_scores, '_MEMO', {})
    with Session() as session:
        session.merge(Setting(key='config',value={'ai_enabled':True,'ai_updates_enabled':True,
            'ai_model':'fixture','ai_control_mode':'legacy','ai_update_hourly_limit':2}))
        session.merge(Setting(key='openai_key',value={'encrypted':seal('fixture-key')}))
        session.add(Host(id='score-host',name='Scoring fixture',address='192.0.2.1',fingerprint=''))
        session.add(Package(id='score-host:fixture',host_id='score-host',name='fixture',installed='1',candidate='2'))
        session.add_all([
            ai_runs.AIRun(id='older-score',purpose='update_scoring',started=started-3599,state='complete'),
            ai_runs.AIRun(id='newer-score',purpose='update_scoring',started=started-30,state='complete'),
            ai_runs.AIRun(id='recent-triage',purpose='triage',started=started-10,state='complete'),
        ])
        session.commit()

    inspected=[]
    def candidates(_session):
        inspected.append(now[0])
        return []
    monkeypatch.setattr(update_scores,'scoring_candidates',candidates)

    probes=[]
    def capture(_conn,_cursor,statement,*_args):
        sql=' '.join(statement.lower().split())
        if sql.startswith('select') and 'ai_runs.started >' in sql:
            probes.append(sql)
    event.listen(engine,'before_cursor_execute',capture)
    try:
        update_scores.run_one()
        assert inspected==[]
        now[0]+=1
        update_scores.run_one()
    finally:
        event.remove(engine,'before_cursor_execute',capture)

    assert inspected==[started+1]
    assert len(probes)==2
    assert all('exists (' in sql and ' limit ' in sql and 'count(' not in sql for sql in probes)
