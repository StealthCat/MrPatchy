"""Real Docker bindings, nonstandard redirects and independent SNI certificates."""
import http.client
import json
import os
import socket
import ssl
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

COMPOSE = ['docker', 'compose', '--env-file', '.env.ci']
PASSWORD = 'ci-disposable-password-only'


def cert_for(hosts):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc)+timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hosts]), False)
            .sign(key, hashes.SHA256()))
    return {'certificate':cert.public_bytes(serialization.Encoding.PEM).decode(),
            'private_key':key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()}


def sni_request(host, material):
    context = ssl.create_default_context(cadata=material['certificate'])
    with socket.create_connection(('127.0.0.1', 18443), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=host) as connection:
            connection.sendall(('GET /healthz HTTP/1.1\r\nHost: '+host+':18443\r\nConnection: close\r\n\r\n').encode())
            response = http.client.HTTPResponse(connection); response.begin()
            assert response.status == 200
            assert json.loads(response.read()) == {'status':'ok'}
            expected = x509.load_pem_x509_certificate(material['certificate'].encode()).public_bytes(serialization.Encoding.DER)
            assert connection.getpeercert(binary_form=True) == expected


env = Path('.env.ci'); original = env.read_text()
try:
    env.write_text(original+'\nBIND_IP=127.0.0.1\nHTTP_PORT=18080\nHTTPS_PORT=18443\nPUBLIC_URL=https://localhost:18443\n')
    config = json.loads(subprocess.check_output([*COMPOSE,'config','--format','json'],text=True))
    ports = config['services']['caddy']['ports']
    assert {(p['host_ip'],str(p['published']),p['target'],p['protocol']) for p in ports} == {
        ('127.0.0.1','18080',80,'tcp'),('127.0.0.1','18443',443,'tcp'),('127.0.0.1','18443',443,'udp')}
    assert 'ports' not in config['services']['app']
    overrides = json.loads(subprocess.check_output([*COMPOSE,'config','--format','json'],text=True,
        env={**os.environ,'BIND_IP':'::','HTTP_BIND_IP':'127.0.0.1','HTTPS_BIND_IP':'::1'}))
    for port in overrides['services']['caddy']['ports']:
        assert port['host_ip'] == ('127.0.0.1' if port['target'] == 80 else '::1')
    subprocess.run([*COMPOSE,'up','-d','--wait'],check=True)
    # Docker's effective bindings agree with Compose; no all-interface publication.
    container = subprocess.check_output([*COMPOSE,'ps','-q','caddy'],text=True).strip()
    bindings = json.loads(subprocess.check_output(['docker','inspect',container],text=True))[0]['HostConfig']['PortBindings']
    assert bindings['443/tcp'] == [{'HostIp':'127.0.0.1','HostPort':'18443'}]
    root = ssl.create_default_context(cafile='/tmp/mrpatchy-ci-root.crt')
    with httpx.Client(verify=root,trust_env=False,timeout=15) as client:
        for attempt in range(30):
            try:
                client.get('https://localhost:18443/healthz').raise_for_status(); break
            except (httpx.TransportError, httpx.HTTPStatusError):
                if attempt == 29: raise
                time.sleep(.5)
        redirect = client.get('http://localhost:18080/a/path?test=yes',follow_redirects=False)
        assert redirect.status_code == 308 and redirect.headers['location'] == 'https://localhost:18443/a/path?test=yes'
        assert client.get('https://localhost:18443/healthz').headers['alt-svc'] == 'h3=":18443"; ma=86400'
        login = client.post('https://localhost:18443/api/login',json={'password':PASSWORD}); login.raise_for_status()
        client.headers['X-CSRF-Token'] = login.json()['csrf']
        external = cert_for(['external.example.test'])
        response = client.put('https://localhost:18443/api/tls/external',json={'domain':'external.example.test','enabled':True,'mode':'uploaded',**external})
        response.raise_for_status()
        sni_request('external.example.test',external)
        assert client.get('https://localhost:18443/healthz').status_code == 200
        internal = cert_for(['localhost','internal.example.test'])
        response = client.put('https://localhost:18443/api/tls/internal',json={'domain':'localhost','aliases':['internal.example.test'],'mode':'uploaded',**internal})
        response.raise_for_status()
        assert 'PRIVATE KEY' not in response.text
    sni_request('localhost',internal); sni_request('internal.example.test',internal); sni_request('external.example.test',external)
    subprocess.run([*COMPOSE,'restart','caddy'],check=True)
    for attempt in range(30):
        try:
            sni_request('external.example.test',external); break
        except (OSError, http.client.HTTPException):
            if attempt == 29: raise
            time.sleep(.5)
    sni_request('internal.example.test',internal)
    with httpx.Client(verify=ssl.create_default_context(cadata=internal['certificate']),trust_env=False,timeout=15) as client:
        login = client.post('https://localhost:18443/api/login',json={'password':PASSWORD}); login.raise_for_status()
        state = client.get('https://localhost:18443/api/tls'); state.raise_for_status()
        assert state.json()['profiles']['external']['certificate_configured']
        assert state.json()['profiles']['internal']['certificate_configured']
        assert 'PRIVATE KEY' not in state.text
    print('Real loopback/custom-port bindings, redirect, independent TLS profiles and restart persistence passed')
finally:
    env.write_text(original)
