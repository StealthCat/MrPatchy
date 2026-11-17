"""#1007: a blocked investigation's retry reason and the admin notification name the right cause.

Evidence over the 64 KB sharing limit is refused locally before any provider
request. It must not be blamed on the API key, quota or model, while a provider
rejection keeps its configuration guidance. Eligibility, signatures and the
notification identity are unchanged. These tests drive the real worker path;
only the provider transport and SSH are fixtures.
"""
import json
import time

import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_retry, notifications, operations, triage_block_notifications, worker
from app.db import Behavior, Host, Session, Setting
from app.security import seal

SMALL = {'executable': '/srv/small', 'sha256': 'b' * 64, 'uid': '1000', 'identity_verified': True}
BIG = {'executable': '/srv/big', 'sha256': 'a' * 64, 'uid': '1000', 'identity_verified': True,
       'service': 'x' * (ai.INVESTIGATION_BYTES + 1000)}
CONFIG_WORDS = ('API configuration', 'key', 'quota', 'model')


def configure(**changes):
    with Session() as s:
        s.merge(Setting(key='config', value={'ai_enabled': True, 'ai_model': 'fixture-model', **changes}))
        s.merge(Setting(key='openai_key', value={'encrypted': seal('private-key')}))
        s.commit()


def add(host, evidence):
    with Session() as s:
        s.add(Host(id=host, name=host, address='192.0.2.10', fingerprint='', state='online',
                   inventory={'os': 'ID=debian\nVERSION_ID=12'}))
        s.add(Behavior(id='subject-' + host, host_id=host, evidence=json.loads(json.dumps(evidence))))
        s.commit()


class Provider:
    def __init__(self, status=200):
        self.calls = 0
        self.status = status

    def __call__(self, *args, **kwargs):
        self.calls += 1
        request = httpx.Request('POST', ai.URL)
        if self.status != 200:
            return httpx.Response(self.status, json={'error': {'code': 'invalid_api_key', 'message': 'sk-x'}},
                                  request=request)
        data = {'risk': 'low', 'explanation': 'Fixture', 'recommended_checks': 'None', 'requested_checks': []}
        usage = {'input_tokens': 10, 'output_tokens': 10, 'total_tokens': 20}
        return httpx.Response(200, request=request, json={
            'model': kwargs['json']['model'], 'status': 'completed', 'usage': usage,
            'output': [{'content': [{'type': 'output_text', 'text': json.dumps(data)}]}]})


@pytest.fixture
def ssh(monkeypatch):
    monkeypatch.setattr(worker.ssh, 'call', lambda host, request, **kwargs: {'identity_verified': True,
                                                                             'sha256': 'a' * 64})


def retry(subject):
    with Session() as s:
        row = s.get(ai_retry.TriageRetry, subject)
        return (row.state, row.reason, row.next_at), s.get(Behavior, subject).analysis


def test_oversized_evidence_block_names_the_local_cause_not_the_key_or_model(admin, monkeypatch, ssh):
    configure()
    add('host-big', BIG)
    provider = Provider()
    monkeypatch.setattr(ai.transport, 'post', provider)
    worker.investigate_one()
    assert provider.calls == 0
    (state, reason, next_at), analysis = retry('subject-host-big')
    assert state == 'blocked' and next_at == 0
    assert reason == ai_retry.EVIDENCE_SIZE_BLOCKED_REASON
    assert 'nothing was sent' in reason and 'does not help' in reason
    assert 'correct API configuration' not in reason and 'correct API configuration' not in analysis
    # The local diagnostic still reaches the investigation.
    assert '64 KB' in analysis


def test_provider_rejection_keeps_the_configuration_guidance(admin, monkeypatch, ssh):
    configure()
    add('host-key', SMALL)
    provider = Provider(status=401)
    monkeypatch.setattr(ai.transport, 'post', provider)
    worker.investigate_one()
    assert provider.calls == 1
    (state, reason, _), analysis = retry('subject-host-key')
    assert state == 'blocked' and reason == ai_retry.PROVIDER_BLOCKED_REASON
    assert 'correct API configuration' in reason and 'sk-x' not in analysis


def test_cause_changes_only_wording_not_eligibility(admin, monkeypatch, ssh):
    configure()
    add('host-big', BIG)
    monkeypatch.setattr(ai.transport, 'post', Provider())
    worker.investigate_one()
    with Session() as s:
        signature = ai_retry.configuration(s)
        row = s.get(ai_retry.TriageRetry, 'subject-host-big')
        assert row.configuration == signature and row.attempts == 1
        eligible = s.scalar(select(ai_retry.TriageRetry.subject).join(
            Behavior, Behavior.id == ai_retry.TriageRetry.subject).where(ai_retry.eligible(signature, time.time())))
        assert eligible is None
        assert triage_block_notifications.blocked_count(s, time.time())[0] == 1
    # A model change still re-admits it exactly as before; it is refused locally again.
    configure(ai_model='other-model')
    with Session() as s:
        summary = ai_retry.summary(s.get(ai_retry.TriageRetry, 'subject-host-big'),
                                   ai_retry.configuration(s), time.time())
        assert summary['state'] == 'ready'


def test_blocked_notification_is_cause_neutral_for_an_evidence_size_block(admin, monkeypatch, ssh):
    configure()
    add('host-big', BIG)
    monkeypatch.setattr(ai.transport, 'post', Provider())
    worker.investigate_one()
    operations.collect_alerts(time.time())
    with Session() as s:
        items = [item for item in notifications.list_for_user(s, 'admin') if item['kind'] == 'configuration-blocked']
    assert len(items) == 1
    reason = items[0]['reason']
    assert reason == triage_block_notifications.MESSAGE
    # It no longer asserts that a key, quota or model problem caused every block...
    assert 'under the current model and API key' not in reason
    # ...and tells the administrator a model/key change does not fix oversized evidence.
    assert 'Evidence too large to share needs manual review' in reason and 'does not help' in reason
    assert 'retry reason names the cause' in reason


def test_evidence_size_error_is_the_only_local_cause():
    with pytest.raises(ai.AIError) as error:
        ai.investigation_payload(BIG, 'fixture-model')
    assert error.value.cause == ai.EVIDENCE_SIZE and not error.value.transient and not error.value.policy_wait
    assert ai.AIError('provider').cause == 'provider'


class FollowUpProvider(Provider):
    """First stage asks for package evidence; a second call must never happen."""
    def __call__(self, *args, **kwargs):
        self.calls += 1
        request = httpx.Request('POST', ai.URL)
        data = {'risk': 'unknown', 'explanation': 'Need package', 'recommended_checks': 'Package',
                'requested_checks': ['package']}
        usage = {'input_tokens': 10, 'output_tokens': 10, 'total_tokens': 20}
        return httpx.Response(200, request=request, json={
            'model': kwargs['json']['model'], 'status': 'completed', 'usage': usage,
            'output': [{'content': [{'type': 'output_text', 'text': json.dumps(data)}]}]})


def test_oversized_follow_up_evidence_says_the_first_call_was_sent(admin, monkeypatch):
    """#1007 review: the target controls the follow-up reply size, so the 64 KB refusal
    can fire after the first paid call. It must not claim that nothing was sent."""
    configure()
    add('host-follow', SMALL)
    big = {'identity_verified': True, 'sha256': 'b' * 64, 'package': 'p' * (ai.INVESTIGATION_BYTES + 1000)}
    monkeypatch.setattr(worker.ssh, 'call', lambda host, request, **kwargs: big)
    provider = FollowUpProvider()
    monkeypatch.setattr(ai.transport, 'post', provider)
    worker.investigate_one()
    assert provider.calls == 1
    (state, reason, next_at), analysis = retry('subject-host-follow')
    assert state == 'blocked' and next_at == 0
    assert reason == ai_retry.FOLLOW_UP_EVIDENCE_SIZE_BLOCKED_REASON
    assert 'nothing was sent' not in reason and 'first-stage request was sent' in reason
    assert 'does not help' in reason and 'correct API configuration' not in reason
    assert '64 KB' in analysis
