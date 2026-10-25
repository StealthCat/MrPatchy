import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from app import tls


def certificate(hosts):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc)+timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hosts]), False)
            .sign(key, hashes.SHA256()))
    return {'certificate': cert.public_bytes(serialization.Encoding.PEM).decode(),
            'private_key': key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()}


@pytest.fixture
def configured(tmp_path, monkeypatch):
    monkeypatch.setenv('TLS_DIR', str(tmp_path)); monkeypatch.setenv('DOMAIN', 'patchy.internal.test')
    monkeypatch.setenv('HTTPS_PORT', '8443')
    calls = []
    class OK:
        def raise_for_status(self): pass
    monkeypatch.setattr(tls.httpx, 'post', lambda *a, **kw: calls.append(kw['content']) or OK())
    return tmp_path, calls


def test_independent_profiles_preserve_each_other_and_redact_material(configured):
    root, calls = configured
    private = certificate(['patchy.internal.test', 'alias.internal.test'])
    tls.apply({'domain':'patchy.internal.test','aliases':['alias.internal.test'],'mode':'uploaded',**private})
    result = tls.apply({'domain':'patchy.external.test','mode':'acme','enabled':True,'email':'ops@example.test',
                        'acme_url':'https://ca.example.test/directory','eab_id':'account-id','eab_key':'YWJj'}, 'external')
    assert result['profiles']['internal']['certificate_configured']
    assert result['profiles']['external']['eab_configured']
    assert result['profiles']['external']['effective_https_port'] == 8443
    for secret in [private['certificate'], private['private_key'], 'YWJj']:
        assert secret not in json.dumps(result)
    assert 'https://patchy.internal.test, https://alias.internal.test' in calls[-1]
    assert 'https://patchy.external.test' in calls[-1]
    assert 'test_dir "https://ca.example.test/directory"' in calls[-1]
    assert 'https://patchy.external.test:{$HTTPS_PORT:443}{uri}' in calls[-1]
    assert 'external' in tls.read_profiles()
    assert all(p.stat().st_mode & 0o077 == 0 for p in root.rglob('*') if p.is_file())
    assert tls.public_state() == result


def test_preserve_certificate_and_scoped_acme_secrets(configured):
    _, calls = configured
    material = certificate(['patchy.internal.test'])
    tls.apply({'domain':'patchy.internal.test','mode':'uploaded',**material})
    tls.apply({'domain':'patchy.internal.test','mode':'uploaded','certificate':'','private_key':''})
    assert tls.read_profiles()['internal']['private_key'] == material['private_key']
    body = {'domain':'patchy.external.test','enabled':True,'mode':'acme','email':'ops@example.test',
            'acme_url':'https://ca.example.test/directory','ca':material['certificate'],'eab_id':'account','eab_key':'YWJj'}
    tls.apply(body, 'external')
    tls.apply({**body,'ca':'','eab_key':''}, 'external')
    previous = calls[-1]
    with pytest.raises(ValueError, match='trusted CA'):
        tls.apply({**body,'acme_url':tls.DEFAULT_ACME,'ca':'','eab_key':''}, 'external')
    with pytest.raises(ValueError, match='EAB'):
        tls.apply({**body,'email':'other@example.test','ca':'','eab_key':''}, 'external')
    assert calls[-1] == previous
    result = tls.apply({**body,'acme_url':tls.DEFAULT_ACME,'ca':'','eab_key':'','clear_ca':True,'clear_eab':True}, 'external')
    assert not result['profiles']['external']['ca_configured']
    assert not result['profiles']['external']['eab_configured']
    assert 'trusted_roots' not in calls[-1] and 'eab ' not in calls[-1]


def test_duplicate_names_disable_all_and_uncovered_aliases_rejected(configured):
    root, calls = configured
    tls.apply({'domain':'patchy.internal.test','mode':'internal'})
    prior = (root/'Caddyfile').read_text()
    for body, profile in [({'domain':'PATCHY.INTERNAL.TEST','mode':'internal','enabled':True},'external'),
                          ({'domain':'other.test','aliases':['patchy.internal.test'],'mode':'internal','enabled':True},'external'),
                          ({'domain':'patchy.internal.test','mode':'internal','enabled':False},'internal')]:
        with pytest.raises(ValueError): tls.apply(body, profile)
        assert (root/'Caddyfile').read_text() == prior
    with pytest.raises(ValueError, match='SAN'):
        tls.apply({'domain':'patchy.internal.test','aliases':['missing.test'],'mode':'uploaded',**certificate(['patchy.internal.test'])})
    assert len(calls) == 1


@pytest.mark.parametrize('field,value', [('domain','evil..test'),('aliases',['*.example.test']),('email','x@example.test\n}'),
                                       ('acme_url','https://user:pass@ca.test/directory'),('eab_id','{env.SECRET}'),('https_port',0)])
def test_profile_input_cannot_inject_caddy(configured, field, value):
    _, calls = configured
    with pytest.raises(ValueError): tls.apply({'domain':'patchy.internal.test','mode':'internal',field:value})
    assert not calls


def test_legacy_uploaded_and_custom_ca_migrate_without_changing_primary(configured):
    root, calls = configured
    material = certificate(['legacy.test'])
    (root/'cert.pem').write_text(material['certificate']); (root/'key.pem').write_text(material['private_key'])
    (root/'Caddyfile').write_text('{\n admin 0.0.0.0:2019\n}\nlegacy.test {\n tls '+str(root/'cert.pem')+' '+str(root/'key.pem')+'\n reverse_proxy app:8000\n}\n')
    tls.bootstrap()
    assert not calls
    assert tls.public_state()['profiles']['internal']['domain'] == 'legacy.test'
    assert tls.read_profiles()['internal']['private_key'] == material['private_key']
    before = (root/'Caddyfile').read_text(); tls.bootstrap(); assert (root/'Caddyfile').read_text() == before
    assert tls._legacy('legacy.test {\n tls {\n issuer acme {\n dir "https://ca.test/directory"\n trusted_roots '+str(root/'cert.pem')+'\n }\n }\n}\n')['ca'] == material['certificate']


def test_parallel_profile_updates_do_not_lose_other_profile(configured):
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda name: tls.apply({'domain':name+'.test','mode':'internal','enabled':True}, name), tls.PROFILES))
    state = tls.public_state()['profiles']
    assert state['internal']['domain'] == 'internal.test' and state['external']['domain'] == 'external.test'


def test_profile_port_and_http_disable_are_explicit(configured):
    _, calls = configured
    tls.apply({'domain':'patchy.internal.test','mode':'internal','https_port':9443})
    assert 'https://patchy.internal.test:9443{uri}' in calls[-1]
    tls.apply({'domain':'patchy.internal.test','mode':'internal','redirect_http':False})
    assert 'respond "Use HTTPS" 404' in calls[-1] and 'redir ' not in calls[-1]


def test_profile_api_auth_redaction_and_legacy_endpoint(admin, configured):
    material = certificate(['patchy.internal.test'])
    response = admin.put('/api/tls', json={'domain':'patchy.internal.test','mode':'uploaded',**material})
    assert response.status_code == 200
    assert 'PRIVATE KEY' not in admin.get('/api/tls').text
    assert admin.get('/api/settings').json()['tls']['profiles']['internal']['certificate_configured']
    assert admin.put('/api/tls/unknown', json={'mode':'internal'}).status_code == 400
    assert admin.put('/api/users', json={'username':'viewer','role':'viewer','password':'viewer-password-long'}).status_code == 200
    admin.post('/api/logout'); assert admin.get('/api/tls').status_code == 401
    result = admin.post('/api/login', json={'username':'viewer','password':'viewer-password-long'}).json()
    admin.headers['X-CSRF-Token'] = result['csrf']
    assert admin.get('/api/tls').status_code == 403
    assert admin.put('/api/tls/external',json={'mode':'internal','domain':'external.test'}).status_code == 403


def test_native_caddy_adapts_both_issuers_and_redirect_ports(configured):
    binary = os.getenv('CADDY_BIN')
    if not binary: pytest.skip('CADDY_BIN is set for native adapter validation')
    root, _ = configured
    ca = certificate(['ca.example.test'])['certificate']
    tls.apply({'domain':'patchy.internal.test','mode':'acme','acme_url':'https://ca.internal.test/directory','ca':ca,
               'email':'ops@example.test','eab_id':'account','eab_key':'YWJj','challenge':'http'})
    tls.apply({'domain':'patchy.external.test','mode':'acme','enabled':True,'acme_url':tls.DEFAULT_ACME,'challenge':'tlsalpn'}, 'external')
    result = subprocess.run([binary,'adapt','--config',str(root/'Caddyfile'),'--adapter','caddyfile'],capture_output=True,text=True,check=True)
    config = json.loads(result.stdout)
    policies = config['apps']['tls']['automation']['policies']
    by_host = {p['subjects'][0]:p['issuers'][0] for p in policies}
    assert by_host['patchy.internal.test']['ca'] == 'https://ca.internal.test/directory'
    assert by_host['patchy.internal.test']['external_account']['mac_key'] == 'YWJj'
    assert by_host['patchy.external.test']['ca'] == tls.DEFAULT_ACME
    assert 'external_account' not in by_host['patchy.external.test']
    assert 'trusted_roots_pem_files' not in by_host['patchy.external.test']
    assert 'https://patchy.external.test:8443{http.request.uri}' in result.stdout


def test_uploaded_certificate_cannot_override_automatic_profile(configured):
    _, calls = configured
    with pytest.raises(ValueError, match='overlaps'):
        tls.apply({'domain':'external.test','enabled':True,'mode':'uploaded',
                   **certificate(['external.test','patchy.internal.test'])}, 'external')
    assert not calls


def test_native_caddy_pins_overlapping_manual_certificates_to_each_profile(configured):
    binary = os.getenv('CADDY_BIN')
    if not binary: pytest.skip('CADDY_BIN is set for native adapter validation')
    root, _ = configured
    tls.apply({'domain':'patchy.internal.test','mode':'uploaded',**certificate(['patchy.internal.test','external.test'])})
    tls.apply({'domain':'external.test','mode':'uploaded','enabled':True,**certificate(['patchy.internal.test','external.test'])}, 'external')
    result = subprocess.run([binary,'adapt','--config',str(root/'Caddyfile'),'--adapter','caddyfile'],capture_output=True,text=True,check=True)
    config = json.loads(result.stdout)
    server = next(s for s in config['apps']['http']['servers'].values() if ':443' in s['listen'])
    policies = {p['match']['sni'][0]:p['certificate_selection']['any_tag'] for p in server['tls_connection_policies'] if 'match' in p}
    assert policies['patchy.internal.test'] != policies['external.test']
