import json

import pytest

from app.db import Host, Session
from app.identity import User
from app.operations import Alert


@pytest.fixture
def findings(admin):
    with Session() as session:
        for host_id in ('active', 'disabled', 'deleted'):
            session.add(Host(
                id=host_id, name=host_id, address='192.0.2.1', fingerprint='',
                enabled=host_id == 'active', deleted_at=1 if host_id == 'deleted' else 0,
                last_seen=300, telemetry={'collected': 299, 'hashed_at': 280, 'other': 'private'},
                integrity=[{'path': '/etc/'+host_id, 'issue': 'Changed'}],
            ))
        session.add_all([
            Alert(id='recorded', host_id='active', kind='integrity', state='resolved', created=240,
                  message=json.dumps([{'path': '/etc/older', 'issue': 'Missing', 'other': 'private'}])),
            Alert(id='unresolved', host_id='active', kind='integrity', state='open', created=280,
                  message='[{"path": "/etc/open"}]'),
            Alert(id='other-kind', host_id='active', kind='reboot', state='resolved', created=290,
                  message='[{"path": "/etc/unrelated"}]'),
            Alert(id='truncated', host_id='disabled', kind='integrity', state='resolved', created=245,
                  message='[{"path": "/incomplete'),
        ])
        session.commit()
    return admin


def test_findings_retains_existing_scope_and_reports_history_limits(findings):
    endpoint = '/api/hosts/{}/integrity-findings'
    response = findings.get(endpoint.format('active'))
    assert response.status_code == 200, response.text
    assert response.json() == {
        'items': [{'path': '/etc/active', 'issue': 'Changed'}],
        'last_seen': 300, 'collected': 299, 'hashed_at': 280, 'inactive': False,
        'resolved_alert': {'opened_at': 240, 'items': [{'path': '/etc/older', 'issue': 'Missing'}],
                           'complete': True},
    }
    inactive = findings.get(endpoint.format('disabled')).json()
    assert inactive['inactive'] is True
    assert inactive['resolved_alert'] == {'opened_at': 245, 'items': [], 'complete': False}
    assert findings.get(endpoint.format('deleted')).json()['items'][0]['path'] == '/etc/deleted'
    assert findings.get(endpoint.format('missing')).status_code == 404


@pytest.mark.parametrize('role', ['operator', 'viewer'])
def test_findings_read_only_roles_keep_current_and_cannot_read_admin_history(findings, role):
    with Session() as session:
        session.get(User, 'admin').role = role
        session.commit()
    for host in ('active', 'disabled'):
        response = findings.get(f'/api/hosts/{host}/integrity-findings')
        assert response.status_code == 200, response.text
        assert response.json()['items'] == [{'path': f'/etc/{host}', 'issue': 'Changed'}]
        assert 'resolved_alert' not in response.json()
        assert findings.get(f'/api/hosts/{host}/security/inspections').status_code == 403
    assert findings.get('/api/hosts/deleted/integrity-findings').status_code == 403


def test_findings_requires_authentication(client):
    assert client.get('/api/hosts/active/integrity-findings').status_code == 401
