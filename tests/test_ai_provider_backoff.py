import json
import subprocess
import sys
import time

import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_admission, ai_provider_backoff, ai_runs
from app.db import Session, Setting


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
