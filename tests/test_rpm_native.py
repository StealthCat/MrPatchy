"""Real libdnf/libRPM: HTTPS metadata, EVR epochs, advisories and corruption.

Requires system python3-dnf/python3-rpm (CI runs this with system Python).
"""
import functools
import gzip
import hashlib
import http.server
import ipaddress
import json
import shutil
import ssl
import threading
from datetime import datetime, timedelta, timezone

import pytest
from target import rpm_support


def test_native_rpm_metadata_and_policy(tmp_path):
    pytest.importorskip('dnf');pytest.importorskip('rpm')
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'Local test CA')])
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1))
          .not_valid_after(datetime.now(timezone.utc)+timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
          .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
          .sign(key,hashes.SHA256()))
    ca=cert.public_bytes(serialization.Encoding.PEM).decode();(tmp_path/'ca.pem').write_text(ca)
    (tmp_path/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    repo=tmp_path/'repo';metadata=repo/'repodata';metadata.mkdir(parents=True)
    primary='''<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="1">
<package type="rpm"><name>Patchy_test</name><arch>noarch</arch><version epoch="2" ver="1.0" rel="1"/>
<checksum type="sha256" pkgid="YES">'''+('a'*64)+'''</checksum><summary>Fixture</summary><description>Fixture</description><packager>Test</packager><url/>
<time file="1700000000" build="1700000000"/><size package="123" installed="4" archive="4"/><location href="Patchy_test.rpm"/>
<format><rpm:license>MIT</rpm:license><rpm:vendor>Test</rpm:vendor><rpm:group>System</rpm:group><rpm:buildhost>test</rpm:buildhost><rpm:sourcerpm>Patchy_test-1.0-1.src.rpm</rpm:sourcerpm><rpm:header-range start="0" end="100"/><rpm:provides><rpm:entry name="Patchy_test" flags="EQ" epoch="2" ver="1.0" rel="1"/></rpm:provides></format></package></metadata>'''
    updateinfo='''<?xml version="1.0"?><updates><update from="test" status="stable" type="security" version="1"><id>PATCHY-1</id><title>Critical fixture</title><severity>Critical</severity><issued date="2026-01-01 00:00:00"/><description>Test</description><pkglist><collection short="fixture"><name>Fixture</name><package name="Patchy_test" epoch="2" version="0.9" release="1" arch="noarch" src=""><filename>Patchy_test.rpm</filename></package></collection></pkglist></update></updates>'''
    def publish(primary):
        entries=[]
        for kind,content in [('primary',primary),('updateinfo',updateinfo)]:
            raw=content.encode();data=gzip.compress(raw);(metadata/(kind+'.xml.gz')).write_bytes(data)
            entries.append(f'<data type="{kind}"><checksum type="sha256">{hashlib.sha256(data).hexdigest()}</checksum><open-checksum type="sha256">{hashlib.sha256(raw).hexdigest()}</open-checksum><location href="repodata/{kind}.xml.gz"/><timestamp>1700000000</timestamp><size>{len(data)}</size><open-size>{len(raw)}</open-size></data>')
        (metadata/'repomd.xml').write_text('<?xml version="1.0"?><repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision>'+''.join(entries)+'</repomd>')
    publish(primary)
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            if 'If-Modified-Since' in self.headers:del self.headers['If-Modified-Since']
            super().do_GET()
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Quiet,directory=str(repo)))
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(tmp_path/'ca.pem',tmp_path/'key.pem')
    server.socket=context.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    source=f'[fixture]\nname=Fixture\nbaseurl=https://127.0.0.1:{server.server_port}\ngpgcheck=1\n'
    inv={'architecture':'x86_64','rpm_vars':{'basearch':'x86_64','releasever':'44'},'keys':{},
         'files':{'/etc/yum.repos.d/test.repo':source},'rpm_packages':[
             {'name':'Patchy_test','arch':'noarch','evr':'1:99.0-1','held':False},
             {'name':'Patchy_test','arch':'noarch','evr':'1:90.0-1','held':False}]}
    try:
        assert rpm_support.compare('2:1.0-1','1:99.0-1')>0
        assert rpm_support.compare('1.0~rc1-1','1.0-1')<0
        assert rpm_support.compare('1.0^git1-1','1.0-1')>0
        rows=rpm_support.discover(inv,tmp_path/'central',{'ca':ca})
        assert rows[0]['candidate']=='2:1.0-1',rows
        # The latest update inherits a security fix shipped in an earlier RPM.
        assert rows[0]['priority']=='critical',rows
        checked={**inv,'rpm_packages':[{'name':'Patchy_test','arch':'noarch','evr':'2:0.95-1','held':False}]}
        assert rpm_support.discover(checked,tmp_path/'already-fixed',{'ca':ca})[0]['priority']=='normal'
        assert len(rows[0]['installed_versions'])==2
        mirror_uri=f'https://127.0.0.1:{server.server_port}/mirrors'
        (repo/'mirrors').write_text('# Fixture mirror list\nhttp://insecure.invalid\n'+mirror_uri.rsplit('/',1)[0]+'\n')
        assert rpm_support.secure_mirrors(mirror_uri,tmp_path/'ca.pem')==[mirror_uri.rsplit('/',1)[0]]
        (repo/'mirrors').write_text('http://insecure.invalid\n')
        with pytest.raises(ValueError,match='no verified HTTPS'):rpm_support.secure_mirrors(mirror_uri,tmp_path/'ca.pem')
        (tmp_path/'central/cache/stale-keyring').touch()
        inv['keys']['/etc/pki/rpm-gpg/removed.asc']=''
        rpm_support.discover(inv,tmp_path/'central',{'ca':ca})
        assert not (tmp_path/'central/cache/stale-keyring').exists()
        inv['files']['/etc/yum.repos.d/test.repo']=source+'exclude=Patchy_test\n'
        assert not rpm_support.discover(inv,tmp_path/'excluded',{'ca':ca})[0]['candidate']
        inv['files']['/etc/yum.repos.d/test.repo']=source
        inv['rpm_packages'][0]['held']=True
        assert not rpm_support.discover(inv,tmp_path/'held',{'ca':ca})[0]['candidate']
        inv['rpm_packages'][0]['held']=False
        primary=primary.replace('ver="1.0"','ver="2.0"')
        publish(primary)
        assert rpm_support.discover(inv,tmp_path/'central',{'ca':ca})[0]['candidate']=='2:2.0-1'
        with pytest.raises(Exception):rpm_support.discover(inv,tmp_path/'untrusted-tls',{})
        (metadata/'primary.xml.gz').write_bytes(gzip.compress(primary.replace('2.0','9.0').encode()))
        with pytest.raises(Exception,match='checksum|Downloading|download|repodata'):
            rpm_support.discover(inv,tmp_path/'tampered',{'ca':ca})
    finally:server.shutdown();server.server_close()
