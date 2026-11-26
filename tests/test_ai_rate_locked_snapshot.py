from contextlib import contextmanager

import pytest
from sqlalchemy import event

from app import ai, ai_admission
from app.db import Session, Setting, engine
from tests.test_ai_admission import configure


@pytest.mark.parametrize('blocked', [False, True])
def test_provider_admission_reads_paced_settings_and_deadline_once(admin, monkeypatch, blocked):
    configure('rate', rate=20)
    now = 6000.0
    monkeypatch.setattr(ai_admission.time, 'time', lambda: now)
    with Session() as session:
        session.add(ai_admission.Admission(id='global', next_at=now + 45 if blocked else now, admitted=4))
        session.commit()

    original = ai_admission.Lock
    reads, calls = [], []

    def observe(conn, cursor, statement, params, context, many):
        sql = statement.lower()
        if sql.startswith('select') and ('settings' in sql or 'ai_admission' in sql):
            reads.append(sql)

    @contextmanager
    def observe_locked(name):
        assert name == 'ai-shared-admission'
        with original(name):
            event.listen(engine, 'before_cursor_execute', observe)
            try:
                yield
            finally:
                event.remove(engine, 'before_cursor_execute', observe)

    def provider(*args):
        calls.append(1)
        return {'fixture': True}

    monkeypatch.setattr(ai_admission, 'Lock', observe_locked)
    monkeypatch.setattr(ai, '_request', provider)
    payload = {'model': 'fixture-model', 'input': 'bounded fixture'}
    if blocked:
        with pytest.raises(ai.AIError) as refused:
            ai.request(payload, 'fixture-key')
        assert refused.value.policy_wait and refused.value.retry_after == 45
        assert calls == []
    else:
        assert ai.request(payload, 'fixture-key') == {'fixture': True}
        assert calls == [1]
    with Session() as session:
        row = session.get(ai_admission.Admission, 'global')
        assert (row.next_at, row.admitted) == ((now + 45, 4) if blocked else (now + 180, 5))
    assert len(reads) == 1
    assert 'settings' in reads[0] and 'ai_admission' in reads[0]


def test_rate_admission_uses_defaults_when_both_rows_are_absent(admin, monkeypatch):
    with Session() as session:
        settings = session.get(Setting, 'config')
        if settings is not None:
            session.delete(settings)
        assert session.get(ai_admission.Admission, 'global') is None
        session.commit()
    monkeypatch.setattr(ai_admission.time, 'time', lambda: 6000.0)
    assert ai_admission.admit('fixture-model') == {
        'mode': 'rate', 'admitted': True, 'next_at': 6180.0,
    }
    with Session() as session:
        assert session.get(ai_admission.Admission, 'global').admitted == 1
