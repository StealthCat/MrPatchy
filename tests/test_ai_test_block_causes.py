"""The Settings model test names refusals and token-budget exhaustion (#1219).

Drives the real ``POST /api/settings/ai-test`` route; only the provider transport is a fixture.
"""
import httpx
import pytest
from sqlalchemy import select

from app import ai, main
from app.ai_runs import AIRun
from app.db import Session, Setting
from tests.test_ai_diagnostics import setup_ai, success


def reply(body):
    def post(*args, **kwargs):
        post.calls += 1
        return httpx.Response(200, json=body, request=httpx.Request('POST', ai.URL))
    post.calls = 0
    return post


REFUSAL = {'status': 'completed', 'output': [{'content': [{'type': 'refusal', 'refusal': 'I cannot help with that.'}]}]}
TOKEN_BUDGET = {'status': 'incomplete', 'incomplete_details': {'reason': 'max_output_tokens'},
                'output': [{'content': [{'type': 'output_text', 'text': '{"risk": '}]}]}
INVALID_OUTPUT = {'status': 'completed', 'output': [{'content': [{'type': 'output_text', 'text': 'not json'}]}]}
INCOMPLETE_OTHER = {'status': 'incomplete', 'incomplete_details': {'reason': 'content_filter'}, 'output': []}

PREFIX = 'Test failed for model fixture-model. '
SUFFIX = ' Your saved model was not changed.'


def last_run():
    with Session() as s:
        return s.scalars(select(AIRun).where(AIRun.purpose == 'connection_test').order_by(AIRun.started.desc())).first()


@pytest.mark.parametrize('body,expected', [
    (REFUSAL, main.AI_TEST_MODEL_REFUSAL),
    (TOKEN_BUDGET, main.AI_TEST_TOKEN_BUDGET),
])
def test_cause_specific_test_failure(admin, monkeypatch, body, expected):
    setup_ai()
    post = reply(body)
    monkeypatch.setattr(ai.transport, 'post', post)
    response = admin.post('/api/settings/ai-test')
    assert post.calls == 1 and response.status_code == 502
    detail = response.json()['detail']
    assert detail == PREFIX + expected + SUFFIX
    assert 'may be billed' in detail and 'Changing the API key does not help' in detail
    # Process-triage wording must not leak into the compatibility test.
    assert 'observation' not in detail and 'safety assessment' not in detail
    assert 'I cannot help' not in response.text  # provider text is never returned
    run = last_run()
    assert run.id == response.json()['run_id'] and run.state == 'error' and run.message == expected
    with Session() as s:
        assert s.get(Setting, 'config').value['ai_model'] == 'fixture-model'


@pytest.mark.parametrize('body,diagnostic', [
    (INVALID_OUTPUT, 'OpenAI returned invalid structured output. No assessment was accepted; check model support for JSON schemas.'),
    (INCOMPLETE_OTHER, 'OpenAI did not complete the structured response. No partial assessment was accepted; retry or review the model configuration.'),
])
def test_other_structured_failures_keep_the_existing_text(admin, monkeypatch, body, diagnostic):
    setup_ai()
    monkeypatch.setattr(ai.transport, 'post', reply(body))
    response = admin.post('/api/settings/ai-test')
    assert response.status_code == 502 and response.json()['detail'] == PREFIX + diagnostic + SUFFIX
    assert last_run().message == diagnostic


def test_rejected_key_keeps_the_existing_text(admin, monkeypatch):
    setup_ai()
    def fail(*a, **kw):
        return httpx.Response(401, json={'error': {'code': 'invalid_api_key', 'message': 'secret-test-key'}}, request=httpx.Request('POST', ai.URL))
    monkeypatch.setattr(ai.transport, 'post', fail)
    detail = admin.post('/api/settings/ai-test').json()['detail']
    assert 'HTTP 401' in detail and 'may be billed' not in detail and 'secret-test-key' not in detail
    assert main.AI_TEST_MODEL_REFUSAL not in detail and main.AI_TEST_TOKEN_BUDGET not in detail


def test_refusal_keeps_rate_limit_and_releases_the_lock(admin, monkeypatch):
    setup_ai()
    post = reply(REFUSAL)
    monkeypatch.setattr(ai.transport, 'post', post)
    assert admin.post('/api/settings/ai-test').status_code == 502
    assert admin.post('/api/settings/ai-test').status_code == 429 and post.calls == 1
    with Session() as s:
        s.get(Setting, 'ai-test:last').value = {'attempted': 0}
        s.commit()
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **kw: success())
    assert admin.post('/api/settings/ai-test').status_code == 200
