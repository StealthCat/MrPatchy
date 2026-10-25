"""Real APT/GPG integration against a temporary signed HTTP repository."""
import base64
import functools
import gzip
import hashlib
import http.server
import os
from pathlib import Path
import shutil
import subprocess
import threading
from datetime import datetime,timezone,timedelta
from email.utils import format_datetime
import pytest
from app import apt

@pytest.mark.skipif(not shutil.which('gpg'),reason='GnuPG required')
def test_central_apt_verifies_signatures_and_package_hashes(tmp_path,monkeypatch):
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
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Quiet,directory=str(repo)))
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    monkeypatch.setattr(apt,'DATA',tmp_path/'central')
    inv={'architecture':'arm64','foreign_architectures':[],'machine_id':'a'*32,'status':'Package: patchy-test\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1.0-1\nMaintainer: Test <test@example.invalid>\nDescription: Integration fixture\n\n','keys':{'/etc/apt/keyrings/test.gpg':base64.b64encode(key).decode()},'files':{'/etc/apt/sources.list':f'deb [signed-by=/etc/apt/keyrings/test.gpg] http://127.0.0.1:{server.server_port} stable main\n'}}
    try:
        rows,log=apt.refresh('signed-test',inv)
        assert rows[0]['candidate']=='2.0-1',rows
        # Tamper with a signed index. APT must reject, not silently use the old candidate.
        (binary/'Packages.gz').write_bytes(gzip.compress(packages.replace(b'2.0-1',b'9.0-1')))
        shutil.rmtree(tmp_path/'central/apt/signed-test/var/lib/apt/lists')
        with pytest.raises(RuntimeError,match='Hash Sum mismatch|unexpected size'):
            apt.refresh('signed-test',inv)
        # Tamper with signature itself: no successful refresh permitted.
        (dist/'InRelease').write_text((dist/'InRelease').read_text().replace('Origin: Patchy Test','Origin: Forged Test'))
        shutil.rmtree(tmp_path/'central/apt/signed-test/var/lib/apt/lists')
        with pytest.raises(RuntimeError): apt.refresh('signed-test',inv)
    finally: server.shutdown();server.server_close()
