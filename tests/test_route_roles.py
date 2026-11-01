import os
import re

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app import route_roles
from app.main import ROLE_DEPENDENCIES, app, viewer_user

PASSWORD = os.environ['ADMIN_PASSWORD']

# Minimum role every route declares. Adding a route without an entry here fails
# test_every_route_has_an_expected_role, so each new route forces a role decision.
EXPECTED_ROLES = {
    ('GET','/'):'public',
    ('POST','/api/ai/known-good/{fingerprint}/revoke'):'admin',
    ('GET','/api/ai/runs'):'admin',
    ('GET','/api/ai/runs/{run_id}'):'admin',
    ('GET','/api/audit'):'admin',
    ('GET','/api/audit/entries/{entry_id}'):'admin',
    ('GET','/api/audit/export'):'admin',
    ('GET','/api/dashboard'):'viewer',
    ('GET','/api/hosts'):'viewer',
    ('POST','/api/hosts'):'admin',
    ('DELETE','/api/hosts/{host_id}'):'admin',
    ('POST','/api/hosts/{host_id}/actions/refresh'):'operator',
    ('POST','/api/hosts/{host_id}/actions/{action}'):'admin',
    ('GET','/api/hosts/{host_id}/backups'):'admin',
    ('GET','/api/hosts/{host_id}/connection'):'admin',
    ('PUT','/api/hosts/{host_id}/connection'):'admin',
    ('POST','/api/hosts/{host_id}/connection/test'):'admin',
    ('GET','/api/hosts/{host_id}/enrollment-endpoints'):'admin',
    ('POST','/api/hosts/{host_id}/enrollment-link'):'admin',
    ('PUT','/api/hosts/{host_id}/fingerprint'):'admin',
    ('GET','/api/hosts/{host_id}/history'):'admin',
    ('GET','/api/hosts/{host_id}/history/{record_id}'):'admin',
    ('GET','/api/hosts/{host_id}/installer'):'admin',
    ('PUT','/api/hosts/{host_id}/keys'):'admin',
    ('PUT','/api/hosts/{host_id}/lifecycle'):'admin',
    ('GET','/api/hosts/{host_id}/packages'):'viewer',
    ('POST','/api/hosts/{host_id}/patch'):'operator',
    ('GET','/api/hosts/{host_id}/patch-policy'):'viewer',
    ('GET','/api/hosts/{host_id}/patching'):'viewer',
    ('POST','/api/hosts/{host_id}/preview'):'operator',
    ('PUT','/api/hosts/{host_id}/priority'):'admin',
    ('GET','/api/hosts/{host_id}/releases'):'admin',
    ('POST','/api/hosts/{host_id}/releases'):'admin',
    ('GET','/api/hosts/{host_id}/releases/{plan_id}'):'admin',
    ('POST','/api/hosts/{host_id}/releases/{plan_id}/decision'):'admin',
    ('GET','/api/hosts/{host_id}/repositories'):'admin',
    ('PUT','/api/hosts/{host_id}/repositories'):'admin',
    ('GET','/api/hosts/{host_id}/repository-access'):'admin',
    ('PUT','/api/hosts/{host_id}/repository-access'):'admin',
    ('GET','/api/hosts/{host_id}/sbom'):'viewer',
    ('GET','/api/hosts/{host_id}/security'):'admin',
    ('POST','/api/hosts/{host_id}/security'):'admin',
    ('GET','/api/hosts/{host_id}/security/agent'):'admin',
    ('PUT','/api/hosts/{host_id}/security/agent'):'admin',
    ('POST','/api/hosts/{host_id}/security/agent/{action}'):'admin',
    ('GET','/api/hosts/{host_id}/security/ai-policy'):'admin',
    ('PUT','/api/hosts/{host_id}/security/ai-policy'):'admin',
    ('GET','/api/hosts/{host_id}/security/baseline'):'admin',
    ('POST','/api/hosts/{host_id}/security/baseline'):'admin',
    ('GET','/api/hosts/{host_id}/security/baseline/history'):'admin',
    ('GET','/api/hosts/{host_id}/security/evidence-archives'):'admin',
    ('GET','/api/hosts/{host_id}/security/evidence-archives/{archive_id}/history'):'admin',
    ('POST','/api/hosts/{host_id}/security/evidence-archives/{archive_id}/quarantine'):'admin',
    ('POST','/api/hosts/{host_id}/security/evidence-archives/{archive_id}/status'):'admin',
    ('GET','/api/hosts/{host_id}/security/evidence-copies'):'admin',
    ('POST','/api/hosts/{host_id}/security/evidence-copies/{copy_id}/acquire'):'admin',
    ('POST','/api/hosts/{host_id}/security/evidence-copies/{copy_id}/execute'):'admin',
    ('POST','/api/hosts/{host_id}/security/evidence-copies/{copy_id}/status'):'admin',
    ('GET','/api/hosts/{host_id}/security/execution-scans'):'admin',
    ('PUT','/api/hosts/{host_id}/security/execution-scans'):'admin',
    ('POST','/api/hosts/{host_id}/security/export'):'admin',
    ('GET','/api/hosts/{host_id}/security/history'):'admin',
    ('GET','/api/hosts/{host_id}/security/incidents'):'admin',
    ('PUT','/api/hosts/{host_id}/security/incidents/{incident_id}'):'admin',
    ('POST','/api/hosts/{host_id}/security/incidents/{incident_id}/plan'):'admin',
    ('POST','/api/hosts/{host_id}/security/incidents/{incident_id}/preservation'):'admin',
    ('GET','/api/hosts/{host_id}/security/incidents/{incident_id}/related'):'admin',
    ('GET','/api/hosts/{host_id}/security/incidents/{incident_id}/timeline'):'admin',
    ('GET','/api/hosts/{host_id}/security/inspections'):'admin',
    ('POST','/api/hosts/{host_id}/security/inspections'):'admin',
    ('GET','/api/hosts/{host_id}/security/inspections/{inspection_id}/comparison'):'admin',
    ('GET','/api/hosts/{host_id}/security/persistence-incidents'):'admin',
    ('PUT','/api/hosts/{host_id}/security/persistence-incidents/{incident_id}'):'admin',
    ('GET','/api/hosts/{host_id}/security/persistence-incidents/{incident_id}/history'):'admin',
    ('POST','/api/hosts/{host_id}/security/persistence-incidents/{incident_id}/plan'):'admin',
    ('POST','/api/hosts/{host_id}/security/persistence-incidents/{incident_id}/plans/{plan_id}/approve'):'admin',
    ('GET','/api/hosts/{host_id}/security/persistence-monitor'):'admin',
    ('PUT','/api/hosts/{host_id}/security/persistence-monitor'):'admin',
    ('POST','/api/hosts/{host_id}/security/plans/{plan_id}/approve'):'admin',
    ('GET','/api/hosts/{host_id}/security/policy'):'admin',
    ('PUT','/api/hosts/{host_id}/security/policy'):'admin',
    ('GET','/api/hosts/{host_id}/security/process-responses'):'admin',
    ('POST','/api/hosts/{host_id}/security/process-responses/{process_id}/actions/{action}'):'admin',
    ('GET','/api/hosts/{host_id}/security/process-responses/{process_id}/history'):'admin',
    ('POST','/api/hosts/{host_id}/security/process-responses/{process_id}/verify'):'admin',
    ('GET','/api/hosts/{host_id}/security/quarantines'):'admin',
    ('GET','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/checks'):'admin',
    ('POST','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/execute'):'admin',
    ('POST','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/export'):'admin',
    ('GET','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/history'):'admin',
    ('POST','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/process-preparations'):'admin',
    ('GET','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/processes'):'admin',
    ('POST','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/processes'):'admin',
    ('POST','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/release'):'admin',
    ('POST','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/repair-preparations'):'admin',
    ('POST','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/restore'):'admin',
    ('GET','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/service-health'):'admin',
    ('POST','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/service-health'):'admin',
    ('GET','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/service-watch'):'admin',
    ('PUT','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/service-watch'):'admin',
    ('POST','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/service-watch/release'):'admin',
    ('POST','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/status'):'admin',
    ('PUT','/api/hosts/{host_id}/security/quarantines/{quarantine_id}/watch'):'admin',
    ('GET','/api/hosts/{host_id}/security/repair-preparations'):'admin',
    ('POST','/api/hosts/{host_id}/security/repair-preparations/{preparation_id}/stage'):'admin',
    ('GET','/api/hosts/{host_id}/security/repair-publications'):'admin',
    ('GET','/api/hosts/{host_id}/security/repair-publications/{publication_id}/history'):'admin',
    ('POST','/api/hosts/{host_id}/security/repair-publications/{publication_id}/release'):'admin',
    ('POST','/api/hosts/{host_id}/security/repair-publications/{publication_id}/status'):'admin',
    ('GET','/api/hosts/{host_id}/security/repair-stages'):'admin',
    ('GET','/api/hosts/{host_id}/security/repair-stages/{stage_id}/history'):'admin',
    ('POST','/api/hosts/{host_id}/security/repair-stages/{stage_id}/publish'):'admin',
    ('POST','/api/hosts/{host_id}/security/repair-stages/{stage_id}/status'):'admin',
    ('GET','/api/hosts/{host_id}/security/response-monitor'):'admin',
    ('PUT','/api/hosts/{host_id}/security/response-monitor'):'admin',
    ('GET','/api/hosts/{host_id}/security/service-monitor'):'admin',
    ('GET','/api/hosts/{host_id}/security/startup-inventory'):'admin',
    ('POST','/api/hosts/{host_id}/security/vendor-inspections'):'admin',
    ('POST','/api/hosts/{host_id}/security/yara'):'admin',
    ('GET','/api/hosts/{host_id}/snapshot'):'admin',
    ('GET','/api/hosts/{host_id}/summary'):'viewer',
    ('GET','/api/identity'):'self-service',
    ('POST','/api/identity/mfa'):'self-service',
    ('POST','/api/identity/mfa/confirm'):'self-service',
    ('PUT','/api/identity/password'):'self-service',
    ('DELETE','/api/identity/sessions'):'self-service',
    ('GET','/api/investigation-status'):'viewer',
    ('GET','/api/investigations'):'viewer',
    ('PUT','/api/investigations/{behavior_id}'):'admin',
    ('GET','/api/investigations/{behavior_id}/history'):'admin',
    ('GET','/api/investigations/{behavior_id}/history/{assessment_id}'):'admin',
    ('POST','/api/investigations/{behavior_id}/retriage'):'admin',
    ('POST','/api/investigations/{behavior_id}/retry'):'admin',
    ('GET','/api/jobs'):'viewer',
    ('GET','/api/jobs/{job_id}'):'viewer',
    ('POST','/api/login'):'public',
    ('POST','/api/logout'):'self-service',
    ('GET','/api/metrics'):'viewer',
    ('GET','/api/operations/alerts'):'admin',
    ('POST','/api/operations/alerts/{alert_id}/ack'):'admin',
    ('POST','/api/operations/jobs/{job_id}/cancel'):'admin',
    ('POST','/api/operations/jobs/{job_id}/reconcile'):'admin',
    ('GET','/api/operations/notifications'):'admin',
    ('PUT','/api/operations/notifications'):'admin',
    ('POST','/api/operations/rollouts'):'admin',
    ('PUT','/api/operations/smtp'):'admin',
    ('PUT','/api/operations/sso-binding'):'admin',
    ('GET','/api/operations/workers'):'admin',
    ('POST','/api/operations/workers/control'):'admin',
    ('GET','/api/operations/{host_id}/advisories'):'admin',
    ('POST','/api/operations/{host_id}/advisories'):'admin',
    ('PUT','/api/operations/{host_id}/observability'):'admin',
    ('PUT','/api/operations/{host_id}/recovery'):'admin',
    ('GET','/api/operations/{host_id}/window'):'admin',
    ('PUT','/api/operations/{host_id}/window'):'admin',
    ('GET','/api/package-history'):'viewer',
    ('GET','/api/schedules'):'admin',
    ('POST','/api/schedules'):'admin',
    ('GET','/api/schedules/calendar'):'admin',
    ('DELETE','/api/schedules/{schedule_id}'):'admin',
    ('PUT','/api/schedules/{schedule_id}'):'admin',
    ('GET','/api/security/coverage'):'admin',
    ('GET','/api/security/indicators/{sha256}'):'admin',
    ('GET','/api/session'):'viewer',
    ('GET','/api/settings'):'admin',
    ('PUT','/api/settings'):'admin',
    ('PUT','/api/settings/ai'):'admin',
    ('PUT','/api/settings/ai-key'):'admin',
    ('GET','/api/settings/ai-models'):'admin',
    ('POST','/api/settings/ai-test'):'admin',
    ('GET','/api/settings/database'):'admin',
    ('PUT','/api/settings/database'):'admin',
    ('PUT','/api/settings/history'):'admin',
    ('PUT','/api/settings/patching'):'admin',
    ('GET','/api/sso'):'public',
    ('GET','/api/tls'):'admin',
    ('PUT','/api/tls'):'admin',
    ('PUT','/api/tls/{profile}'):'admin',
    ('GET','/api/users'):'admin',
    ('PUT','/api/users'):'admin',
    ('GET','/auth/sso'):'public',
    ('GET','/auth/sso/callback'):'public',
    ('GET','/enroll/{token}'):'public',
    ('GET','/healthz'):'public',
}


def test_every_route_has_an_expected_role():
    declared = route_roles.inventory(app, ROLE_DEPENDENCIES)
    assert sorted(set(declared) - set(EXPECTED_ROLES)) == [], 'route has no entry in EXPECTED_ROLES'
    assert sorted(set(EXPECTED_ROLES) - set(declared)) == [], 'EXPECTED_ROLES lists a route that no longer exists'
    assert {k: v for k, v in declared.items() if v != EXPECTED_ROLES[k]} == {}


def test_route_without_a_role_fails_closed():
    undeclared = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @undeclared.get('/api/new-report')
    def new_report():
        return {}

    with pytest.raises(RuntimeError, match='declares no role'):
        route_roles.inventory(undeclared, ROLE_DEPENDENCIES)


def test_declared_role_route_and_public_allow_list_are_checked():
    ok = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @ok.get('/api/new-report')
    def new_report(user=Depends(viewer_user)):
        return {}

    assert route_roles.inventory(ok, ROLE_DEPENDENCIES) == {('GET', '/api/new-report'): 'viewer'}
    public_with_role = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @public_with_role.get('/healthz')
    def health(user=Depends(viewer_user)):
        return {}

    with pytest.raises(RuntimeError, match='public but also declares'):
        route_roles.inventory(public_with_role, ROLE_DEPENDENCIES)


def test_application_refuses_to_start_when_a_route_has_no_role():
    app.add_api_route('/api/unprotected-probe', lambda: {}, methods=['GET'])
    try:
        with pytest.raises(RuntimeError, match='declares no role'):
            with TestClient(app):
                pass
    finally:
        app.router.routes.pop()


def concrete(path):
    return re.sub(r'\{[^}]+\}', 'missing-id', path)


def session_for(admin, role):
    name = 'test-' + role
    assert admin.put('/api/users', json={'username': name, 'password': 'role-password-long-enough', 'role': role, 'enabled': True}).status_code == 200
    client = TestClient(app)
    result = client.post('/api/login', json={'username': name, 'password': 'role-password-long-enough'})
    assert result.status_code == 200
    client.headers['X-CSRF-Token'] = result.json()['csrf']
    return client


def authenticated(declared_role):
    return sorted(key for key, role in EXPECTED_ROLES.items() if role == declared_role)


def call(client, method, path):
    return client.request(method, concrete(path), json={} if method not in ('GET', 'DELETE') else None)


def test_unauthenticated_requests_are_rejected_on_every_declared_route(client):
    anonymous = TestClient(app)
    for role in ('viewer', 'operator', 'admin', 'self-service'):
        for method, path in authenticated(role):
            assert call(anonymous, method, path).status_code == 401, (method, path)


def test_viewer_is_refused_every_admin_and_operator_route(admin):
    viewer = session_for(admin, 'viewer')
    for role in ('admin', 'operator'):
        for method, path in authenticated(role):
            assert call(viewer, method, path).status_code == 403, (method, path)


def test_operator_is_refused_every_admin_route_but_may_reach_operator_routes(admin):
    operator = session_for(admin, 'operator')
    for method, path in authenticated('admin'):
        assert call(operator, method, path).status_code == 403, (method, path)
    for method, path in authenticated('operator'):
        assert call(operator, method, path).status_code not in (401, 403), (method, path)


def test_each_role_reaches_the_routes_it_may_use(admin):
    viewer = session_for(admin, 'viewer')
    for method, path in authenticated('viewer'):
        assert call(viewer, method, path).status_code not in (401, 403), (method, path)
    for method, path in authenticated('self-service'):
        if path in ('/api/logout', '/api/identity/password', '/api/identity/mfa', '/api/identity/mfa/confirm', '/api/identity/sessions'):
            continue  # mutating self-service calls would end or alter the session used for the remaining checks
        assert call(viewer, method, path).status_code not in (401, 403), (method, path)
    for method, path in authenticated('admin'):
        if method == 'GET' or '{' in path:
            assert call(admin, method, path).status_code != 403, (method, path)
