"""Provider request size and strict JSON checks precede all billable state."""
import httpx
import pytest
from sqlalchemy import func, select
from app import ai, ai_admission, ai_budget, ai_provider_backoff, ai_runs
from app.db import Session, Setting


def configure(mode):
    with Session() as s:
        s.merge(Setting(key='config', value={'ai_enabled': True, 'ai_control_mode': mode,
            'ai_model': 'gpt-6-luna', 'ai_rate_per_hour': 20, 'ai_daily_cap_usd': 10}))
        s.commit()


def provider_result():
    return httpx.Response(200, request=httpx.Request('POST', ai.URL),
        json={'status': 'completed', 'output': [
            {'content': [{'type': 'output_text', 'text': '{"ok":true}'}]}]})


@pytest.mark.parametrize('value', ['é' * 30, 'x' * 10_000, float('nan'), object(), '\ud800'],
    ids=['multibyte-overflow', 'oversized-string', 'non-finite', 'unsupported', 'surrogate'])
def test_rejected_provider_bodies_do_not_reach_admission_or_create_receipts(admin, monkeypatch, value):
    configure('rate_and_daily')
    monkeypatch.setattr(ai, 'MAX_REQUEST_BYTES', 80, raising=False)
    calls = []
    monkeypatch.setattr(ai_provider_backoff, 'admit', lambda: calls.append('backoff'))
    monkeypatch.setattr(ai.transport, 'post', lambda *args, **kwargs: calls.append('send') or provider_result())
    with ai_runs.track('connection_test', 'gpt-6-luna'):
        with pytest.raises(ai.AIError, match='request body is invalid or exceeds'):
            ai.request({'model': 'gpt-6-luna', 'input': value, 'max_output_tokens': 10}, 'fixture-key')

    assert calls == []
    with Session() as s:
        for model in (ai_admission.Admission, ai_budget.BudgetEntry, ai_runs.AICall):
            assert s.scalar(select(func.count()).select_from(model)) == 0


def test_provider_sends_exact_utf8_boundary_and_preserves_request_shape(admin, monkeypatch):
    configure('unthrottled')
    payload = {'model': 'gpt-6-luna', 'input': 'é🔧', 'max_output_tokens': 10}
    expected = httpx.Request('POST', ai.URL, json=payload).content
    monkeypatch.setattr(ai, 'MAX_REQUEST_BYTES', len(expected), raising=False)
    seen = []

    def reply(request):
        seen.append(request)
        return httpx.Response(200, stream=httpx.ByteStream(provider_result().content))

    with httpx.Client(transport=httpx.MockTransport(reply)) as client:
        monkeypatch.setattr(ai.transport, '_client', client)
        with ai_runs.track('connection_test', 'gpt-6-luna'):
            assert ai.request(payload, 'fixture-key') == {'ok': True}
            with pytest.raises(ai.AIError, match='request body is invalid or exceeds'):
                ai.request({**payload, 'input': payload['input'] + 'x'}, 'fixture-key')

    assert len(seen) == 1
    assert seen[0].content == expected
    assert seen[0].headers['content-type'] == 'application/json'
    assert seen[0].headers['content-length'] == str(len(expected))
    with Session() as s:
        assert s.scalar(select(func.count()).select_from(ai_runs.AICall)) == 1
