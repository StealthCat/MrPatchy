"""Real APT/GPG integration against a temporary signed HTTP repository."""
import base64
import functools
import gzip
import hashlib
import http.server
import os
import re
from pathlib import Path
import shutil
import subprocess
import threading
import ssl
import ipaddress
from datetime import datetime,timezone,timedelta
from email.utils import format_datetime
import pytest
from app import apt

@pytest.mark.skipif(not shutil.which('gpg'),reason='GnuPG required')
@pytest.mark.parametrize('private',['public','https-auth-mirror'])
def test_central_apt_verifies_signatures_and_package_hashes(tmp_path,monkeypatch,private):
    from pgpy import PGPKey, PGPUID, PGPMessage
    from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
    signing=PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign,2048)
    signing.add_uid(PGPUID.new('Mr Patchy Test',email='test@example.invalid'),usage={KeyFlags.Sign},hashes=[HashAlgorithm.SHA256],ciphers=[SymmetricKeyAlgorithm.AES256],compression=[CompressionAlgorithm.ZLIB])
    key=bytes(signing.pubkey)
    repo=tmp_path/'repo';dist=repo/'dists/stable';binary=dist/'main/binary-arm64';binary.mkdir(parents=True)
    packages=b'Package: patchy-test\nVersion: 2.0-1\nArchitecture: arm64\nMaintainer: Test <test@example.invalid>\nDescription: Integration fixture\nFilename: pool/patchy-test.deb\nSize: 1\nSHA256: '+b'0'*64+b'\n\n'
    (binary/'Packages').write_bytes(packages);(binary/'Packages.gz').write_bytes(gzip.compress(packages))
    release='Origin: Patchy Test\nLabel: Patchy Test\nSuite: stable\nCodename: stable\nArchitectures: arm64\nComponents: main\nDate: '+format_datetime(datetime.now(timezone.utc))+'\nValid-Until: '+format_datetime(datetime.now(timezone.utc)+timedelta(days=1))+'\nSHA256:\n'
    for name in ['Packages','Packages.gz']:
        data=(binary/name).read_bytes();release+=f' {hashlib.sha256(data).hexdigest()} {len(data)} main/binary-arm64/{name}\n'
    (dist/'Release').write_text(release)
    message=PGPMessage.new(release,cleartext=True)
    message |= signing.sign(message,hash=HashAlgorithm.SHA256)
    (dist/'InRelease').write_text(str(message))
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_GET(self):
            if private=='https-auth-mirror' and self.headers.get('Authorization')!='Basic '+base64.b64encode(b'test:secret').decode():
                self.send_response(401);self.end_headers();return
            super().do_GET()
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Quiet,directory=str(repo)))
    access={}
    if private=='https-auth-mirror':
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes,serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        tlskey=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        subject=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'Local test CA')])
        cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(tlskey.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1))
              .not_valid_after(datetime.now(timezone.utc)+timedelta(days=1))
              .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
              .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
              .sign(tlskey,hashes.SHA256()))
        ca=cert.public_bytes(serialization.Encoding.PEM).decode()
        (tmp_path/'cert.pem').write_text(ca)
        (tmp_path/'key.pem').write_bytes(tlskey.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(tmp_path/'cert.pem',tmp_path/'key.pem')
        server.socket=context.wrap_socket(server.socket,server_side=True)
        uri='https://127.0.0.1:'+str(server.server_port)
        access={'ca':ca,'mirrors':{'file:/fixture':uri},'credentials':[{'machine':uri,'login':'test','password':'secret'}]}
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    monkeypatch.setattr(apt,'DATA',tmp_path/'central')
    inv={'architecture':'arm64','foreign_architectures':[],'machine_id':'a'*32,'status':'Package: patchy-test\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1.0-1\nMaintainer: Test <test@example.invalid>\nDescription: Integration fixture\n\n','keys':{'/etc/apt/keyrings/test.gpg':base64.b64encode(key).decode()},'files':{'/etc/apt/sources.list':f'deb [signed-by=/etc/apt/keyrings/test.gpg] http://127.0.0.1:{server.server_port} stable main\n'}}
    if private=='https-auth-mirror':
        inv['files']['/etc/apt/sources.list']=inv['files']['/etc/apt/sources.list'].replace(f'http://127.0.0.1:{server.server_port}','file:/fixture')
    try:
        rows,log=apt.refresh('signed-test',inv,access)
        assert rows[0]['candidate']=='2.0-1',rows
        # Tamper with a signed index. APT must reject, not silently use the old candidate.
        (binary/'Packages.gz').write_bytes(gzip.compress(packages.replace(b'2.0-1',b'9.0-1')))
        shutil.rmtree(tmp_path/'central/apt/signed-test/var/lib/apt/lists')
        with pytest.raises(RuntimeError,match='Hash Sum mismatch|unexpected size'):
            apt.refresh('signed-test',inv,access)
        # Tamper with signature itself: no successful refresh permitted.
        (dist/'InRelease').write_text((dist/'InRelease').read_text().replace('Origin: Patchy Test','Origin: Forged Test'))
        shutil.rmtree(tmp_path/'central/apt/signed-test/var/lib/apt/lists')
        with pytest.raises(RuntimeError): apt.refresh('signed-test',inv,access)
        # Authenticated but expired metadata must also fail closed.
        expired=re.sub(r'^Valid-Until:.*$', 'Valid-Until: '+format_datetime(datetime.now(timezone.utc)-timedelta(days=1)), release, flags=re.M)
        signed_expired=PGPMessage.new(expired,cleartext=True);signed_expired |= signing.sign(signed_expired,hash=HashAlgorithm.SHA256)
        (dist/'InRelease').write_text(str(signed_expired))
        shutil.rmtree(tmp_path/'central/apt/signed-test/var/lib/apt/lists')
        with pytest.raises(RuntimeError,match='expired'):apt.refresh('signed-test',inv,access)
    finally: server.shutdown();server.server_close()

@pytest.mark.parametrize('separator',[' ', '\t'])
def test_native_apt_trusted_whitespace_bypass_is_blocked(tmp_path,monkeypatch,separator):
    """Native APT accepts the dangerous spelling; our trust boundary must not."""
    repo=tmp_path/'repo';dist=repo/'dists/stable';binary=dist/'main/binary-amd64';binary.mkdir(parents=True)
    (binary/'Packages').write_bytes(b'')
    (dist/'Release').write_text('Suite: stable\nCodename: stable\nArchitectures: amd64\nComponents: main\nDate: '+format_datetime(datetime.now(timezone.utc))+'\nSHA256:\n '+hashlib.sha256(b'').hexdigest()+' 0 main/binary-amd64/Packages\n')
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self,*args):pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Quiet,directory=str(repo)))
    threading.Thread(target=server.serve_forever,daemon=True).start()
    monkeypatch.setattr(apt,'DATA',tmp_path/'central')
    source=f'Types: deb\nURIs: http://127.0.0.1:{server.server_port}\nSuites: stable\nComponents: main\n'
    name='/etc/apt/sources.list.d/test.sources'
    inv={'architecture':'amd64','foreign_architectures':[],'status':'','files':{name:source},'keys':{}}
    try:
        root,cfg=apt.prepare('whitespace',inv)
        with pytest.raises(RuntimeError,match='not signed'):apt.run(cfg,['apt-get','update'])
        malicious=source+'Trusted'+separator+': yes\n'
        # Write directly to the native fixture to demonstrate APT's interpretation.
        (root/name.lstrip('/')).write_text(malicious)
        apt.run(cfg,['apt-get','update'])
        inv['files'][name]=malicious
        with pytest.raises(ValueError,match='Deb822 field'):apt.prepare('whitespace',inv)
    finally:server.shutdown();server.server_close()
