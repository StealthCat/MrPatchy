"""Real offline enrollment/SSH/sudo test. Systemd service control is stubbed."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
workspace=Path(tempfile.mkdtemp(prefix='patchy-ssh-integration-'))
os.environ['DATA_DIR']=str(workspace)
from app import ssh

def run(*args):
    return subprocess.check_output(list(args),text=True).strip()

def main():
    image=os.getenv('TARGET_IMAGE','mrpatchy-ssh-test:latest')
    name='patchy-target-'+uuid.uuid4().hex[:10]
    run('docker','run','-d','--name',name,'-p','127.0.0.1::22',image)
    try:
        host=SimpleNamespace(id='integration-host',name='Disposable target',address='127.0.0.1',port=int(run('docker','port',name,'22/tcp').rsplit(':',1)[1]),fingerprint='')
        ssh.create_key(host.id)
        installer=workspace/'enroll.sh';installer.write_text(ssh.bootstrap(host))
        run('docker','cp',str(installer),name+':/tmp/enroll.sh')
        run('docker','exec',name,'bash','/tmp/enroll.sh')
        host.fingerprint=run('docker','exec',name,'ssh-keygen','-lf','/etc/ssh/ssh_host_ed25519_key.pub','-E','sha256').split()[1]
        ssh.deploy(host)
        verification=ssh.call(host,{'action':'verify'})
        assert verification['files']['/usr/local/lib/mrpatchy/release.py']=={'uid':0,'gid':0,'mode':0o644,'sha256':ssh.hashlib.sha256((ssh.TARGET/'release.py').read_bytes()).hexdigest()}
        assert verification['active'] and verification['files']['/usr/local/lib/mrpatchy/agent.py']['uid']==0
        run('docker','exec','-d',name,'/usr/bin/python3','-I','/usr/local/lib/mrpatchy/agent.py')
        snapshot={}
        for _ in range(30):
            snapshot=ssh.call(host,{'action':'snapshot'},timeout=5)
            if snapshot.get('telemetry') and snapshot.get('inventory'): break
            time.sleep(.5)
        assert snapshot.get('inventory',{}).get('status'), snapshot.get('collector-error', snapshot)
        assert snapshot['telemetry']['managed']['/usr/local/lib/mrpatchy/agent.py']==ssh.hashlib.sha256((ssh.TARGET/'agent.py').read_bytes()).hexdigest()
        assert snapshot['events'] and snapshot['spool']['pending']>0
        ids=[event['id'] for event in snapshot['events']]
        ssh.call(host,{'action':'ack','ids':ids})
        assert not set(ids)&{event['id'] for event in ssh.call(host,{'action':'snapshot'})['events']}
        key=next(iter(snapshot['inventory']['keys'].values()))
        ssh.call(host,{'action':'key','name':'review-fixture.gpg','data':key})
        ssh.call(host,{'action':'repository','path':'/etc/apt/sources.list.d/review.sources','content':'Types: deb\nURIs: https://example.invalid\nSuites: stable\nComponents: main\nEnabled: no\n'})
        ssh.call(host,{'action':'repository','path':'/etc/apt/sources.list.d/review.sources','content':''})
        backups=ssh.call(host,{'action':'backups'})['backups']
        assert backups and backups[0]['path']=='/etc/apt/sources.list.d/review.sources'
        assert 'Enabled: no' in backups[0]['content']
        ssh.call(host,{'action':'repository','path':backups[0]['path'],'content':backups[0]['content']})
        for path in ['/etc/apt/keyrings/review-fixture.gpg','/etc/apt/sources.list.d/review.sources','/usr/local/lib/mrpatchy/agent.py']:
            assert run('docker','exec',name,'stat','-c','%a:%u',path)=='644:0'
        # Re-enrollment must replace old user-owned files with root-owned files.
        run('docker','exec',name,'chown','drpatch:drpatch','/usr/local/lib/mrpatchy/bridge.py')
        run('docker','exec',name,'bash','/tmp/enroll.sh')
        assert run('docker','exec',name,'stat','-c','%a:%u','/usr/local/lib/mrpatchy/bridge.py')=='644:0'
        # A real flock held by an installation must not block the snapshot path.
        locker="import fcntl,time,pathlib; f=open('/opt/drpatch/bridge.lock','w'); fcntl.flock(f,fcntl.LOCK_EX); pathlib.Path('/opt/drpatch/lock-ready').touch(); time.sleep(20)"
        run('docker','exec','-d',name,'python3','-c',locker)
        for _ in range(20):
            if run('docker','exec',name,'python3','-c',"from pathlib import Path; print(Path('/opt/drpatch/lock-ready').exists())")=='True': break
            time.sleep(.1)
        assert ssh.call(host,{'action':'snapshot'},timeout=3)['telemetry']
        assert ssh.call(host,{'action':'release-status','job_id':str(uuid.uuid4())},timeout=3)=={'state':'absent'}
        old_key=workspace/'old-identity.key';old_key.write_bytes(ssh.key_path(host.id).read_bytes());old_key.chmod(0o600)
        old_public=ssh.public_key(host.id)
        rotated=ssh.rotate(host)
        assert rotated['authorized_keys_sha256'] and ssh.public_key(host.id)!=old_public
        assert ssh.call(host,{'action':'snapshot'})['telemetry']
        try:ssh.call(host,{'action':'snapshot'},key_file=old_key)
        except ssh.paramiko.AuthenticationException:pass
        else:raise AssertionError('Old identity still authorized after rotation')
        assert ssh.public_key(host.id) in ssh.bootstrap(host)
        host.fingerprint='SHA256:'+'a'*43
        try: ssh.call(host,{'action':'snapshot'},timeout=3)
        except ssh.paramiko.SSHException: pass
        else: raise AssertionError('Unverified host key was accepted')
        print('Offline enrollment, real SSH/sudo, ownership, key permissions, pinning, and nonblocking snapshots passed for '+image)
    finally:
        subprocess.run(['docker','rm','-f',name],check=False,stdout=subprocess.DEVNULL)

if __name__=='__main__': main()
