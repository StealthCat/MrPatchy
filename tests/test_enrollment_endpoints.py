import shlex
from urllib.parse import urlsplit

import pytest
from sqlalchemy import func, select

from app import tls
from app.db import Session, Setting
from app.identity import User


@pytest.fixture
def endpoints(admin, monkeypatch):
    profiles = tls.defaults()
    profiles['internal'].update(domain='patchy.internal.test', mode='acme',
                                acme_url='https://ca.internal.test/acme/directory',
                                ca='private CA material', eab_key='secret')
    profiles['external'].update(domain='patchy.example.test', enabled=True, https_port=443)
    monkeypatch.setattr(tls, 'read_profiles', lambda: profiles)
    monkeypatch.setenv('HTTPS_PORT', '8443')
    monkeypatch.setenv('PUBLIC_URL', 'https://canonical.example.test:9443/')
    host_id = admin.post('/api/hosts', json={'name':'Test target','address':'192.0.2.10'}).json()['id']
    return '/api/hosts/'+host_id, profiles


def test_select_internal_external_and_default(admin, endpoints):
    path, _ = endpoints
    response = admin.get(path+'/enrollment-endpoints')
    assert response.status_code == 200
    assert response.json()['endpoints'] == [
        {'id':'default','label':'Default (PUBLIC_URL)','url':'https://canonical.example.test:9443'},
        {'id':'internal','label':'Internal HTTPS','url':'https://patchy.internal.test:8443'},
        {'id':'external','label':'External HTTPS','url':'https://patchy.example.test'}]
    assert 'secret' not in response.text and 'CA material' not in response.text
    assert '/acme/directory' not in response.text
    for item in response.json()['endpoints']:
        result = admin.post(path+'/enrollment-link', json={'endpoint':item['id']})
        assert result.status_code == 200
        link = result.json()
        assert link['url'].startswith(item['url']+'/enroll/')
        assert link['endpoint'] == item['id'] and link['expires_in'] == 3600
        assert shlex.split(link['command']) == ['curl','-fsSL',link['url'],'-o','/tmp/mrpatchy-enroll.sh',
                                                '&&','sudo','bash','/tmp/mrpatchy-enroll.sh']
        # The personalized download is accessible without a login cookie on either origin.
        token_path = urlsplit(link['url']).path
        assert admin.get(token_path).text == admin.get(path+'/installer').text
    assert admin.post(path+'/enrollment-link').json()['url'].startswith('https://canonical.example.test:9443/enroll/')


def test_disabled_or_unknown_endpoint_does_not_issue_token(admin, endpoints):
    path, profiles = endpoints
    # A profile may be disabled after the selector has loaded.
    assert len(admin.get(path+'/enrollment-endpoints').json()['endpoints']) == 3
    profiles['external']['enabled'] = False
    assert [item['id'] for item in admin.get(path+'/enrollment-endpoints').json()['endpoints']] == ['default','internal']
    for endpoint in ['external','unknown','https://attacker.example.test']:
        assert admin.post(path+'/enrollment-link', json={'endpoint':endpoint}).status_code == 400
    with Session() as session:
        assert session.scalar(select(func.count()).select_from(Setting).where(Setting.key.like('enroll:%'))) == 0
    assert admin.get('/api/hosts/missing/enrollment-endpoints').status_code == 404


@pytest.mark.parametrize('port,expected', [(None,'https://[2001:db8::1]:8443'), (443,'https://[2001:db8::1]'), (9443,'https://[2001:db8::1]:9443')])
def test_ipv6_and_profile_port_override(admin, endpoints, port, expected):
    path, profiles = endpoints
    profiles['internal'].update(domain='2001:db8::1',https_port=port)
    result = admin.post(path+'/enrollment-link',json={'endpoint':'internal'}).json()
    assert result['url'].startswith(expected+'/enroll/')


def test_generated_command_quotes_url(admin, endpoints, monkeypatch):
    path, _ = endpoints
    monkeypatch.setenv('PUBLIC_URL', "https://canonical.example.test/a'$(id)")
    result = admin.post(path+'/enrollment-link').json()
    assert shlex.split(result['command'])[2] == result['url']
    assert "'\"'\"'" in result['command']


def test_enrollment_endpoints_require_admin_and_links_require_csrf(admin, endpoints):
    path, _ = endpoints
    saved = admin.headers.pop('X-CSRF-Token')
    assert admin.post(path+'/enrollment-link',json={'endpoint':'internal'}).status_code == 403
    admin.headers['X-CSRF-Token'] = saved
    with Session() as session:
        user = session.get(User,'admin'); user.role = 'viewer'; session.commit()
    assert admin.get(path+'/enrollment-endpoints').status_code == 403
    assert admin.post(path+'/enrollment-link',json={'endpoint':'internal'}).status_code == 403
    admin.cookies.clear()
    assert admin.get(path+'/enrollment-endpoints').status_code == 401
