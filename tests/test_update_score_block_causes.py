"""Blocked update scores name refusals and token-budget exhaustion (#1162).

Drives the real ``update_scores.run_one`` path; only the provider transport is a fixture.
"""
import json

import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_retry, scoring_block_notifications, update_scores
from app.db import Session, Setting, config
from app.security import seal
from test_scoring_block_notifications import rejected_key, seed, success


def reply(body):
    def post(*args, **kwargs):
        post.calls += 1
        return httpx.Response(200, json=body, request=httpx.Request('POST', ai.URL))
    post.calls = 0
    return post


REFUSAL = {'status': 'completed', 'output': [{'content': [{'type': 'refusal', 'refusal': 'I cannot help with that.'}]}]}
TOKEN_BUDGET = {'status': 'incomplete', 'incomplete_details': {'reason': 'max_output_tokens'},
                'output': [{'content': [{'type': 'output_text', 'text': '{"assessments": ['}]}]}
INVALID_OUTPUT = {'status': 'completed', 'output': [{'content': [{'type': 'output_text', 'text': 'not json'}]}]}
INCOMPLETE_OTHER = {'status': 'incomplete', 'incomplete_details': {'reason': 'content_filter'}, 'output': []}


def rows():
    with Session() as s:
        return {r.host_id: (r.state, r.explanation, r.configuration) for r in s.scalars(select(update_scores.UpdateScore))}


def signature():
    with Session() as s:
        cfg = config(s)
        return ai_retry.configuration_signature(cfg['ai_model'], s.get(Setting, 'openai_key').value)


@pytest.mark.parametrize('body,expected', [
    (REFUSAL, update_scores.MODEL_REFUSAL_EXPLANATION),
    (TOKEN_BUDGET, update_scores.TOKEN_BUDGET_EXPLANATION),
])
def test_cause_specific_explanation_on_every_package_in_the_batch(admin, monkeypatch, body, expected):
    seed(('one', 'two'))
    post = reply(body)
    monkeypatch.setattr(ai.transport, 'post', post)
    update_scores.run_one()
    assert post.calls == 1
    current = signature()
    for state, explanation, configuration in rows().values():
        assert state == 'blocked' and configuration == current
        assert explanation == expected + update_scores.BLOCKED_SUFFIX
        assert 'may be billed' in explanation and 'Changing the API key does not help' in explanation
        # The process-triage wording must not leak into update scoring.
        assert 'observation' not in explanation and 'safety assessment' not in explanation
        assert 'I cannot help' not in explanation  # provider text is never stored


@pytest.mark.parametrize('body,diagnostic', [
    (INVALID_OUTPUT, 'OpenAI returned invalid structured output. No assessment was accepted; check model support for JSON schemas.'),
    (INCOMPLETE_OTHER, 'OpenAI did not complete the structured response. No partial assessment was accepted; retry or review the model configuration.'),
])
def test_other_structured_failures_keep_the_existing_text(admin, monkeypatch, body, diagnostic):
    seed()
    monkeypatch.setattr(ai.transport, 'post', reply(body))
    update_scores.run_one()
    state, explanation, _ = rows()['one']
    assert state == 'blocked' and explanation == diagnostic + update_scores.BLOCKED_SUFFIX


def test_provider_configuration_failure_keeps_the_existing_text(admin, monkeypatch):
    seed()
    rejected_key.calls = 0
    monkeypatch.setattr(ai.transport, 'post', rejected_key)
    update_scores.run_one()
    state, explanation, _ = rows()['one']
    assert state == 'blocked' and explanation.endswith(update_scores.BLOCKED_SUFFIX)
    assert 'may be billed' not in explanation and 'sk-leaked-secret' not in explanation
    assert explanation not in (update_scores.MODEL_REFUSAL_EXPLANATION + update_scores.BLOCKED_SUFFIX,
                               update_scores.TOKEN_BUDGET_EXPLANATION + update_scores.BLOCKED_SUFFIX)


@pytest.mark.parametrize('body', [REFUSAL, TOKEN_BUDGET])
def test_blocked_count_and_model_change_readmission_are_unchanged(admin, monkeypatch, body):
    seed(('one', 'two'))
    post = reply(body)
    monkeypatch.setattr(ai.transport, 'post', post)
    update_scores.run_one()
    with Session() as s:
        assert scoring_block_notifications.blocked_count(s, config(s))[0] == 2
    # Same model and key: still blocked, no new provider request.
    update_scores.run_one()
    assert post.calls == 1
    with Session() as s:
        setting = s.get(Setting, 'config')
        setting.value = {**setting.value, 'ai_model': 'other-model'}
        s.commit()
        assert scoring_block_notifications.blocked_count(s, config(s))[0] == 0
    monkeypatch.setattr(ai.transport, 'post', success)
    update_scores.run_one()
    assert {state for state, _, _ in rows().values()} == {'complete'}


def test_key_change_still_readmits(admin, monkeypatch):
    # The text says a key change does not help, but eligibility is deliberately unchanged.
    seed()
    monkeypatch.setattr(ai.transport, 'post', reply(REFUSAL))
    update_scores.run_one()
    with Session() as s:
        s.merge(Setting(key='openai_key', value={'encrypted': seal('another-key')}))
        s.commit()
    monkeypatch.setattr(ai.transport, 'post', success)
    update_scores.run_one()
    assert rows()['one'][0] == 'complete'
