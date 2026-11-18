"""Roadmap A milestone 4: role and CSRF boundaries for daily-cap AI controls (#1010).

``tests/test_route_roles.py`` checks each route's declared minimum role with empty
bodies. These tests send *valid* requests that would expand spend or start billable
work if accepted: switching to unthrottled, raising the daily cap, saving a key,
running a connection test, queuing re-triage and clearing provider backoff. Each
request comes from an operator, a viewer, an administrator session without its CSRF
token, or an administrator demoted while still signed in. Every refusal leaves the
stored controls, audit history, spend ledger, AI runs, queued re-triage and provider
transmissions unchanged. The same requests from an authorized administrator succeed,
so the refusals are not caused by the request bodies.
"""
import json

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app import ai, ai_assessments, ai_budget, ai_runs
from app.db import Audit, Behavior, Host, Session, Setting
from app.main import app
from tests.ai_settings_helpers import confirmed_put

PASSWORD = 'role-password-long-enough'
MODEL = 'gpt-6-astra'
EVIDENCE = {'executable': '/srv/fixture', 'sha256': 'a' * 64, 'uid': '1000', 'identity_verified': True}
CAPPED = {'ai_enabled': True, 'ai_model': MODEL, 'ai_control_mode': 'daily_cap',
          'ai_daily_cap_usd': 2.0, 'ai_budget_timezone': 'UTC'}
READS = ('/api/settings/ai-spend-history', '/api/settings/ai-spend-history.csv',
         '/api/settings/ai-control-status', '/api/settings')


@pytest.fixture
def provider(monkeypatch):
    sent = []

    def post(*args, **kwargs):
        sent.append(kwargs.get('json'))
        body = {'model': MODEL, 'status': 'completed',
                'output': [{'content': [{'type': 'output_text', 'text': json.dumps(
                    {'risk': 'unknown', 'explanation': 'Fixture', 'recommended_checks': 'None',
                     'requested_checks': []})}]}]}
        return httpx.Response(200, json=body, request=httpx.Request('POST', ai.URL))
    monkeypatch.setattr(ai.transport, 'post', post)
    return sent


@pytest.fixture
def capped(admin):
    """A capped installation with a saved key and one completed investigation."""
    assert admin.put('/api/settings/ai-key', json={'api_key': 'fixture-key'}).status_code == 200
    assert confirmed_put(admin, '/api/settings/ai', CAPPED).status_code == 200
    with Session() as s:
        s.add(Host(id='host-0', name='Fixture', address='192.0.2.1', fingerprint=''))
        s.add(Behavior(id='subject', host_id='host-0', verdict='low', analysis='Retained result',
                       evidence=dict(EVIDENCE)))
        s.commit()
    return admin


def session_for(admin, name, role):
    assert admin.put('/api/users', json={'username': name, 'password': PASSWORD, 'role': role,
                                         'enabled': True}).status_code == 200
    client = TestClient(app)
    login = client.post('/api/login', json={'username': name, 'password': PASSWORD})
    assert login.status_code == 200
    client.headers['X-CSRF-Token'] = login.json()['csrf']
    return client


def state():
    with Session() as s:
        return {
            'config': s.get(Setting, 'config').value,
            'key': s.get(Setting, 'openai_key').value,
            'connection_test': s.get(Setting, 'ai-test:last'),
            # Every request writes a generic 'request' row; count only action rows.
            'audit': s.scalar(select(func.count()).select_from(Audit).where(Audit.action != 'request')),
            'ledger': s.scalar(select(func.count()).select_from(ai_budget.BudgetEntry)),
            'runs': s.scalar(select(func.count()).select_from(ai_runs.AIRun)),
            'refreshes': s.scalar(select(func.count()).select_from(ai_assessments.Refresh)),
        }


def revision(admin):
    response = admin.get('/api/investigations/subject/history')
    assert response.status_code == 200
    return response.json()['current']['revision']


def attempts(admin):
    """Valid requests that expand spend, start billable work or change AI controls."""
    settings = admin.get('/api/settings').json()
    expand = {'ai_control_mode': 'unthrottled', 'expected_ai_controls_revision': settings['ai_controls_revision']}
    raise_cap = {'ai_daily_cap_usd': 500.0, 'expected_ai_controls_revision': settings['ai_controls_revision']}
    preview = admin.post('/api/settings/ai/preview', json={'ai_control_mode': 'unthrottled'}).json()
    expand['confirm_ai_expansion'] = preview['expansion_confirmation']
    current = revision(admin)
    return [
        ('PUT', '/api/settings/ai', expand),
        ('PUT', '/api/settings/ai', raise_cap),
        ('POST', '/api/settings/ai/preview', {'ai_control_mode': 'unthrottled'}),
        ('PUT', '/api/settings/ai-key', {'api_key': 'replacement-key'}),
        ('POST', '/api/settings/ai-test', {'expected_model': MODEL, 'expected_key_revision': settings['api_key_revision']}),
        ('POST', '/api/investigations/subject/retriage', {'expected_revision': current, 'reason': 'Review changed threat context'}),
        ('POST', '/api/investigations/retriage', {'items': [{'id': 'subject', 'expected_revision': current}],
                                                  'reason': 'Review changed threat context'}),
        ('POST', '/api/ai/provider-backoff/clear', {'expected_revision': '0' * 64, 'reason': 'Reviewed fixture floor',
                                                    'confirmation': 'CLEAR BACKOFF'}),
    ]


def assert_refused(client, requests, before, provider, status=403):
    for method, path, body in requests:
        response = client.request(method, path, json=body)
        assert response.status_code == status, (method, path, response.text)
        assert state() == before, (method, path)
    assert provider == []


@pytest.mark.parametrize('role', ['operator', 'viewer'])
def test_lower_roles_cannot_change_controls_start_billable_work_or_read_spend(capped, provider, role):
    requests = attempts(capped)
    client = session_for(capped, 'test-' + role, role)
    before = state()
    assert_refused(client, requests, before, provider)
    for path in READS:
        assert client.get(path).status_code == 403, path
    assert state() == before and before['config']['ai_control_mode'] == 'daily_cap'
    assert before['config']['ai_daily_cap_usd'] == 2.0


@pytest.mark.parametrize('token', [None, '', 'not-the-session-token'])
def test_admin_session_without_its_csrf_token_changes_nothing(capped, provider, token):
    requests = attempts(capped)
    good = capped.headers.pop('X-CSRF-Token')
    if token is not None:
        capped.headers['X-CSRF-Token'] = token
    before = state()
    assert_refused(capped, requests, before, provider)
    # Reads need no token and stay available to the administrator.
    for path in READS:
        assert capped.get(path).status_code == 200, path
    assert state() == before
    capped.headers['X-CSRF-Token'] = good


def test_same_requests_with_the_token_are_accepted(capped, provider):
    """Positive control: an authorized administrator gets past authentication with these
    bodies. Each request is answered on its merits (applied, or a 409 conflict that the
    earlier requests in the list cause), never with 401, 403 or 422."""
    requests = {(method, path, i): body for i, (method, path, body) in enumerate(attempts(capped))}
    responses = {key[1] + '#' + str(key[2]): capped.request(key[0], key[1], json=body)
                 for key, body in requests.items()}
    statuses = {key: response.status_code for key, response in responses.items()}
    # The first save switches to unthrottled. The cap raise then carries a stale revision.
    assert statuses['/api/settings/ai#0'] == 200
    assert statuses['/api/settings/ai#1'] == 409
    assert statuses['/api/settings/ai/preview#2'] == 200
    assert statuses['/api/settings/ai-key#3'] == 200
    # The key changed, so the connection test refuses its stale key revision before sending.
    assert statuses['/api/settings/ai-test#4'] == 409
    assert statuses['/api/investigations/subject/retriage#5'] == 200
    # Already queued by the single re-triage: refused as a whole.
    assert statuses['/api/investigations/retriage#6'] == 409
    # No active backoff floor matches this revision.
    assert statuses['/api/ai/provider-backoff/clear#7'] == 409
    after = state()
    assert after['config']['ai_control_mode'] == 'unthrottled' and after['refreshes'] == 1
    assert provider == []


def test_demoted_administrator_session_is_revoked_before_any_change(capped, provider):
    deputy = session_for(capped, 'deputy-admin', 'admin')
    requests = attempts(deputy)
    assert capped.put('/api/users', json={'username': 'deputy-admin', 'role': 'operator',
                                          'enabled': True}).status_code == 200
    before = state()
    assert_refused(deputy, requests, before, provider, status=401)
    # Signing in again yields an operator session, which is still refused.
    login = deputy.post('/api/login', json={'username': 'deputy-admin', 'password': PASSWORD})
    assert login.status_code == 200
    deputy.headers['X-CSRF-Token'] = login.json()['csrf']
    relogged = state()
    # Sign-in records its own audit row; nothing else changed.
    assert {k: v for k, v in relogged.items() if k != 'audit'} == {k: v for k, v in before.items() if k != 'audit'}
    assert_refused(deputy, requests, relogged, provider)
    assert state()['config']['ai_daily_cap_usd'] == 2.0
