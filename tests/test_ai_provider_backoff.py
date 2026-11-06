import json
from contextlib import contextmanager
import subprocess
import sys
import time

import httpx
import pytest
from sqlalchemy import event, select

from app import ai, ai_admission, ai_provider_backoff, ai_runs
from app.db import Session, Setting, engine


def configure(mode='unthrottled'):
    with Session() as session:
        session.merge(Setting(key='config', value={
            'ai_enabled': True, 'ai_model': 'fixture-model',
            'ai_control_mode': mode, 'ai_rate_per_hour': 20,
        }))
        session.commit()


def payload():
    return {'model': 'fixture-model', 'input': 'bounded fixture',
            'max_output_tokens': 100, 'store': False}


def response(status=503, code='server_error', headers=None):
    return httpx.Response(status, json={'error': {'code': code}}, headers=headers,
                          request=httpx.Request('POST', ai.URL))


def success():
    return httpx.Response(200, json={'status': 'completed', 'model': 'fixture-model',
        'service_tier': 'default', 'usage': {'input_tokens': 10, 'output_tokens': 10,
        'input_tokens_details': {'cached_tokens': 0}, 'output_tokens_details': {}},
        'output': [{'content': [{'type': 'output_text', 'text': '{}'}]}]},
        request=httpx.Request('POST', ai.URL))


def test_retry_after_blocks_other_purposes_before_admission_or_transport(admin, monkeypatch):
    configure(mode='rate');calls=[]
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: calls.append(k['json']) or
                        response(headers={'retry-after': '120'}))
    with pytest.raises(ai.AIError, match='HTTP 503'):
        with ai_runs.track('triage', 'fixture-model'):ai.request(payload(), 'fixture-key')
    with Session() as session:
        row=session.get(ai_provider_backoff.ProviderBackoff, 'global')
        assert row.failures==1 and 119 < row.blocked_until-time.time() <= 120
        admitted=session.get(ai_admission.Admission, 'global').admitted
        receipts=len(list(session.scalars(select(ai_runs.AICall))))
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: pytest.fail('shared backoff must block transport'))
    with pytest.raises(ai.AIError) as blocked:
        with ai_runs.track('connection_test', 'fixture-model'):ai.request(payload(), 'fixture-key')
    assert blocked.value.policy_wait and blocked.value.retry_after > 0
    with Session() as session:
        assert session.get(ai_admission.Admission, 'global').admitted==admitted
        assert len(list(session.scalars(select(ai_runs.AICall))))==receipts
        status=ai_provider_backoff.status(session)
        assert status['blocked'] and status['failures']==1 and status['next_at']>time.time()
    assert len(calls)==1


def test_backoff_persists_and_no_header_uses_bounded_exponential_jitter(admin, monkeypatch):
    configure();bounds=[]
    monkeypatch.setattr(ai_provider_backoff.random, 'uniform', lambda low, high: bounds.append((low, high)) or high)
    first=ai.AIError('transient', transient=True)
    assert ai_provider_backoff.failed(first, now=1000)==60
    with Session() as session:
        row=session.get(ai_provider_backoff.ProviderBackoff, 'global');row.blocked_until=0;session.commit()
    second=ai.AIError('transient', transient=True)
    assert ai_provider_backoff.failed(second, now=1010)==120
    assert bounds==[(30,60),(30,120)]
    persisted=json.loads(subprocess.check_output([sys.executable, '-c',
        "import json;from app.db import Session;from app.ai_provider_backoff import ProviderBackoff;s=Session();r=s.get(ProviderBackoff,'global');print(json.dumps({'failures':r.failures,'next_at':r.blocked_until}));s.close()"],
        text=True, timeout=20))
    assert persisted=={'failures': 2, 'next_at': 1130.0}


def test_success_clears_shared_backoff_and_status(admin, monkeypatch):
    configure();ai_provider_backoff.failed(ai.AIError('transient',transient=True,retry_after=5))
    with Session() as session:
        row=session.get(ai_provider_backoff.ProviderBackoff,'global');row.blocked_until=0;session.commit()
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: success())
    assert ai.request(payload(), 'fixture-key')=={}
    with Session() as session:
        row=session.get(ai_provider_backoff.ProviderBackoff,'global')
        assert row.failures==0 and row.blocked_until==0
        assert ai_provider_backoff.status(session)['blocked'] is False


def test_older_parallel_success_does_not_clear_a_newer_failure(admin):
    configure();error=ai.AIError('transient',transient=True,retry_after=120)
    ai_provider_backoff.failed(error,now=2000)
    ai_provider_backoff.succeeded(request_started=1999,now=2001)
    with Session() as session:
        row=session.get(ai_provider_backoff.ProviderBackoff,'global')
        assert row.failures==1 and row.blocked_until==2120
    ai_provider_backoff.succeeded(request_started=2001,now=2002)
    with Session() as session:
        row=session.get(ai_provider_backoff.ProviderBackoff,'global')
        assert row.failures==0 and row.blocked_until==0


@pytest.mark.parametrize('state', ['absent', 'clear', 'newer'])
def test_healthy_completion_skips_global_lock_and_update(admin, monkeypatch, state):
    configure()
    if state != 'absent':
        with Session() as session:
            active = state == 'newer'
            session.add(ai_provider_backoff.ProviderBackoff(
                id='global', updated=101, failures=int(active),
                blocked_until=221 if active else 0,
                reason='Provider Retry-After floor is active.' if active else ''))
            session.commit()

    locks, updates = [], []
    original_lock = ai_provider_backoff.Lock

    def record_lock(name):
        locks.append(name)
        return original_lock(name)

    def record_sql(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().lower().startswith('update ai_provider_backoff'):
            updates.append(statement)

    monkeypatch.setattr(ai_provider_backoff, 'Lock', record_lock)
    event.listen(engine, 'before_cursor_execute', record_sql)
    try:
        for _ in range(3):
            ai_provider_backoff.succeeded(request_started=100, now=102)
        # A clear row should be a no-op even for requests newer than the row.
        if state == 'clear':
            ai_provider_backoff.succeeded(request_started=102, now=103)
    finally:
        event.remove(engine, 'before_cursor_execute', record_sql)

    assert (len(locks), len(updates)) == (0, 0)
    with Session() as session:
        row = session.get(ai_provider_backoff.ProviderBackoff, 'global')
        if state == 'absent':
            assert row is None
        else:
            assert row.updated == 101
            assert row.failures == int(state == 'newer')
            assert row.blocked_until == (221 if state == 'newer' else 0)


def test_eligible_reset_rechecks_after_concurrent_failure(admin, monkeypatch):
    configure()
    first = ai.AIError('provider wait', transient=True, retry_after=30)
    ai_provider_backoff.failed(first, now=100)
    original_lock = ai_provider_backoff.Lock

    @contextmanager
    def concurrent_failure(name):
        with monkeypatch.context() as inner:
            inner.setattr(ai_provider_backoff, 'Lock', original_lock)
            later = ai.AIError('provider wait', transient=True, retry_after=120)
            ai_provider_backoff.failed(later, now=102)
        with original_lock(name):
            yield

    monkeypatch.setattr(ai_provider_backoff, 'Lock', concurrent_failure)
    ai_provider_backoff.succeeded(request_started=101, now=103)
    with Session() as session:
        row = session.get(ai_provider_backoff.ProviderBackoff, 'global')
        assert (row.failures, row.blocked_until, row.updated) == (2, 222, 102)


def test_nontransient_provider_error_does_not_create_global_backoff(admin, monkeypatch):
    configure();ai_provider_backoff.failed(ai.AIError('transient',transient=True,retry_after=5))
    with Session() as session:
        session.get(ai_provider_backoff.ProviderBackoff,'global').blocked_until=0;session.commit()
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: response(429,'insufficient_quota'))
    with pytest.raises(ai.AIError) as error:ai.request(payload(), 'fixture-key')
    assert not error.value.transient
    with Session() as session:
        row=session.get(ai_provider_backoff.ProviderBackoff,'global')
        assert row.failures==0 and row.blocked_until==0


def test_huge_retry_after_is_capped_and_admin_can_clear_it_with_audit(admin, monkeypatch):
    configure(mode='rate')
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: response(headers={'retry-after': '300000000'}))
    with pytest.raises(ai.AIError) as failed:
        with ai_runs.track('triage', 'fixture-model'):ai.request(payload(), 'fixture-key')
    cap=ai_provider_backoff.MAX_PROVIDER_DELAY
    assert failed.value.provider_retry_after==cap
    with Session() as session:
        row=session.get(ai_provider_backoff.ProviderBackoff, 'global')
        assert cap-5 < row.blocked_until-time.time() <= cap
        assert 'capped' in ai_provider_backoff.status(session)['reason']
    assert admin.post('/api/ai/provider-backoff/clear').json()=={'cleared': True}
    with Session() as session:
        assert not ai_provider_backoff.status(session)['blocked']
        from app.db import Audit
        assert any(a.action=='clear AI provider backoff' for a in session.scalars(select(Audit)))
    assert admin.post('/api/ai/provider-backoff/clear').json()=={'cleared': False}


def test_internal_backoff_is_not_stored_as_provider_retry_after(admin, monkeypatch):
    configure(mode='rate')
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: response())
    with pytest.raises(ai.AIError) as failed:
        with ai_runs.track('triage', 'fixture-model'):ai.request(payload(), 'fixture-key')
    assert failed.value.retry_after>0 and failed.value.provider_retry_after==0


def test_clear_provider_backoff_requires_admin(client):
    assert client.post('/api/ai/provider-backoff/clear').status_code in (401, 403)


def test_clear_revokes_provider_only_item_waits_but_keeps_attempts(admin):
    from app import ai_retry
    now=time.time();far=now+300000000
    with Session() as session:
        session.add_all([
            ai_retry.TriageRetry(subject='legacy',configuration='c',attempts=2,state='deferred',next_at=far,provider_until=far),
            ai_retry.TriageRetry(subject='blocked',configuration='c',attempts=5,state='blocked',next_at=0,provider_until=far),
            ai_retry.TriageRetry(subject='policy',configuration='c',attempts=1,state='deferred',next_at=far,provider_until=0)])
        session.commit()
    assert ai_provider_backoff.clear(now=now) is True
    with Session() as session:
        legacy,blocked,policy=(session.get(ai_retry.TriageRetry,k) for k in ('legacy','blocked','policy'))
        assert legacy.provider_until==0 and legacy.next_at<=now and legacy.attempts==2
        assert blocked.provider_until==0 and blocked.attempts==5 and blocked.state=='blocked'
        assert policy.next_at==far  # unrelated policy/rate waits are untouched
        ai_retry.manual(session,type('R',(),{'id':'blocked'})(),now=now)


@pytest.mark.parametrize('local_delay,provider_delay,expected_delay', [
    (120, 10, 120),
    (10, 120, 0),
    (120, 120, 0),
])
def test_clear_preserves_later_local_retry_gate(admin, local_delay, provider_delay, expected_delay):
    from app import ai_retry
    now=time.time()
    with Session() as session:
        session.add(ai_retry.TriageRetry(subject='mixed',configuration='c',attempts=2,
            state='deferred',next_at=now+max(local_delay,provider_delay),
            provider_until=now+provider_delay))
        session.commit()
    assert ai_provider_backoff.clear(now=now) is True
    with Session() as session:
        retry=session.get(ai_retry.TriageRetry,'mixed')
        assert retry.provider_until==0
        assert retry.next_at==now+expected_delay
        assert retry.state=='deferred' and retry.attempts==2


@pytest.mark.parametrize('failure_delay',[1.25,121])
def test_clear_releases_provider_policy_wait_after_admission_race(admin,failure_delay):
    from app import ai_retry
    from app.db import Behavior
    now=time.time()
    ai_provider_backoff.failed(ai.AIError('provider wait',transient=True,retry_after=120),now=now)
    with Session() as session:
        row=Behavior(id='raced',host_id='fixture',evidence={});session.add(row);session.flush()
        ai_retry.begin(session,row,'configuration',now);session.commit()
    with pytest.raises(ai.AIError) as refused:ai_provider_backoff.admit(now=now+1)
    with Session() as session:
        row=session.get(Behavior,'raced')
        ai_retry.failed(session,row,refused.value,now+failure_delay);session.commit()
    with Session() as session:
        retry=session.get(ai_retry.TriageRetry,'raced')
        assert retry.next_at<=max(now+120,now+failure_delay)
    ai_provider_backoff.clear(now=now+failure_delay+1)
    with Session() as session:
        retry=session.get(ai_retry.TriageRetry,'raced')
        assert retry.provider_until<=now+failure_delay+1 and retry.next_at<=now+failure_delay+1
        if failure_delay<120:assert retry.provider_until==0
        assert retry.state=='deferred' and retry.attempts==0


def test_local_pool_timeout_keeps_other_provider_work_eligible(admin, monkeypatch):
    configure()

    def pool_timeout(*args, **kwargs):
        raise httpx.PoolTimeout('raw transport detail')

    monkeypatch.setattr(ai.transport, 'post', pool_timeout)
    with pytest.raises(ai.AIError) as failed:
        ai.request(payload(), 'fixture-key')
    with Session() as session:
        assert session.get(ai_provider_backoff.ProviderBackoff, 'global') is None

    error = failed.value
    assert error.transient and error.provider_retry_after == 0
    assert ai.defer_until(error, now=1000) == 1005
    assert 'local AI connection pool' in error.diagnostic
    assert 'raw transport detail' not in error.diagnostic

    monkeypatch.setattr(ai.transport, 'post', lambda *args, **kwargs: success())
    with ai_runs.track('connection_test', 'fixture-model'):
        assert ai.request(payload(), 'fixture-key') == {}


def test_local_pool_timeout_preserves_a_concurrent_provider_floor(admin, monkeypatch):
    configure()
    now = time.time()

    def concurrent_provider_failure(*args, **kwargs):
        error = ai.AIError('provider wait', transient=True, retry_after=120)
        ai_provider_backoff.failed(error, now=now)
        raise httpx.PoolTimeout('local contention')

    monkeypatch.setattr(ai.transport, 'post', concurrent_provider_failure)
    with pytest.raises(ai.AIError):
        ai.request(payload(), 'fixture-key')

    with Session() as session:
        status = ai_provider_backoff.status(session, now=now)
        assert status['blocked'] and status['failures'] == 1
        assert status['next_at'] == now + 120
        assert status['reason'] == 'Provider Retry-After floor is active.'


def test_ambiguous_read_timeout_still_creates_shared_backoff(admin, monkeypatch):
    configure()

    def read_timeout(*args, **kwargs):
        raise httpx.ReadTimeout('raw transport detail')

    monkeypatch.setattr(ai.transport, 'post', read_timeout)
    with pytest.raises(ai.AIError, match='OpenAI API request timed out') as failed:
        ai.request(payload(), 'fixture-key')
    assert failed.value.transient and failed.value.retry_after >= 30

    with Session() as session:
        status = ai_provider_backoff.status(session)
        assert status['blocked'] and status['failures'] == 1
