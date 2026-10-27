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
from app.db import init
init()

def run(*args):
    return subprocess.check_output(list(args),text=True).strip()

def main():
    image=os.getenv('TARGET_IMAGE','mrpatchy-ssh-test:latest')
    name='patchy-target-'+uuid.uuid4().hex[:10]
    run('docker','run','-d','--name',name,'-p','127.0.0.1::22','-p','127.0.0.1::8443',image)
    try:
        host=SimpleNamespace(id='integration-host',name='Disposable target',address='127.0.0.1',port=int(run('docker','port',name,'22/tcp').rsplit(':',1)[1]),fingerprint='')
        ssh.create_key(host.id)
        installer=workspace/'enroll.sh';installer.write_text(ssh.bootstrap(host))
        run('docker','cp',str(installer),name+':/tmp/enroll.sh')
        # Obsolete/malformed public key files must not abort successful enrollment.
        run('docker','exec',name,'sh','-c','printf "not a public key\\n" > /etc/ssh/ssh_host_dsa_key.pub')
        enrolled=run('docker','exec',name,'bash','/tmp/enroll.sh')
        host.fingerprint=run('docker','exec',name,'ssh-keygen','-lf','/etc/ssh/ssh_host_ed25519_key.pub','-E','sha256').split()[1]
        assert host.fingerprint in enrolled and enrolled.count('SHA256:')==1
        assert 'then click Finish installation' in enrolled
        ssh.deploy(host)
        verification=ssh.call(host,{'action':'verify'})
        assert verification['files']['/usr/local/lib/mrpatchy/release.py']=={'uid':0,'gid':0,'mode':0o644,'sha256':ssh.hashlib.sha256((ssh.TARGET/'release.py').read_bytes()).hexdigest()}
        assert verification['active'] and verification['files']['/usr/local/lib/mrpatchy/agent.py']['uid']==0
        # Independent health action must work even when the collector is modified.
        from app import agent_maintenance
        host.baseline={}
        host.baseline=ssh.expected_files(host)
        health=ssh.call(host,{'action':'agent-status'})
        assert agent_maintenance.assess(host,health)['state']=='current',health
        run('docker','exec',name,'sh','-c',"printf '# drift fixture\\n' >> /usr/local/lib/mrpatchy/agent.py")
        run('docker','exec',name,'chmod','666','/usr/local/lib/mrpatchy/agent.py')
        health=ssh.call(host,{'action':'agent-status'})
        assert agent_maintenance.assess(host,health)['state']=='drifted',health
        ssh.deploy(host)
        assert agent_maintenance.assess(host,ssh.call(host,{'action':'agent-status'}))['state']=='current'
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
        assert isinstance(ssh.call(host,{'action':'events'})['events'],list)
        original=ssh.call(host,{'action':'patch-inspect'},timeout=120)
        assert original['version']==1 and original['configs']
        assert ssh.call(host,{'action':'patch-restored','original':original},timeout=120)['original_state_verified']
        run('docker','exec',name,'sh','-c','printf changed > /etc/mrpatchy-recovery-fixture')
        try:ssh.call(host,{'action':'patch-restored','original':original},timeout=120)
        except RuntimeError as error:assert 'not restored' in str(error)
        else:raise AssertionError('Changed configuration was accepted as restored')
        run('docker','exec',name,'rm','/etc/mrpatchy-recovery-fixture')
        assert ssh.call(host,{'action':'patch-restored','original':original},timeout=120)['original_state_verified']
        rpm=snapshot['inventory'].get('package_manager')=='rpm'
        # Real package verifiers over the deployed root bridge, on every distro.
        package='patchy-fixture:noarch' if rpm else 'patchy-fixture'
        request={'action':'security-inspect','packages':[package],'persistence':False}
        def inspected():
            report=ssh.call(host,request,timeout=210)
            assert report['trust_basis']=='target_local_package_database',report
            assert report['state']=='collected',report
            return report['packages'][0]
        assert inspected()['state']=='no_reported_differences'
        fixture_path='/usr/share/patchy-fixture/version'
        run('docker','exec',name,'sh','-c','printf changed > '+fixture_path)
        changed=inspected()
        assert changed['state']=='differences' and changed['findings'][0]['path']==fixture_path,changed
        run('docker','exec',name,'rm',fixture_path)
        missing=inspected()
        assert missing['findings'][0]['status']=='missing',missing
        run('docker','exec',name,'sh','-c',"printf '1\\n' > "+fixture_path)
        restored=inspected()
        assert not any('5' in finding['checks'] for finding in restored['findings']),restored
        if not rpm:
            vendor_manifest={'package':'patchy-fixture','version':'1.0-1','architecture':'all',
                             'entries':[{'path':fixture_path,'sha256':ssh.hashlib.sha256(b'1\n').hexdigest(),'size':2}]}
            vendor_request={'action':'vendor-inspect','manifest':vendor_manifest}
            assert ssh.call(host,vendor_request,timeout=150)['state']=='matches_artifact_bytes'
            run('docker','exec',name,'sh','-c','printf changed > '+fixture_path)
            assert ssh.call(host,vendor_request,timeout=150)['state']=='differences'
            run('docker','exec',name,'rm',fixture_path)
            assert ssh.call(host,vendor_request,timeout=150)['findings'][0]['status']=='missing'
            run('docker','exec',name,'sh','-c',"printf '1\\n' > "+fixture_path)
            vendor_manifest['version']='999'
            rejected=ssh.call(host,vendor_request,timeout=150)
            assert rejected['state']=='incomplete' and rejected['examined']==0,rejected
        assert run('docker','exec',name,'python3','-c',"from pathlib import Path; print(Path('/tmp/patchy-verifyscript-executed').exists())")=='False'
        absent=ssh.call(host,{'action':'security-inspect','packages':['patchy-package-does-not-exist'],'persistence':False},timeout=210)
        assert absent['state']=='incomplete' and absent['packages'][0]['gaps'],absent
        startup='/etc/cron.d/patchy-inventory-fixture'
        run('docker','exec',name,'sh','-c',"mkdir -p /etc/cron.d; printf '# inventory fixture only\\n' > "+startup)
        inventory=ssh.call(host,{'action':'security-inspect','packages':[],'persistence':True},timeout=210)
        entry=next(row for row in inventory['persistence']['entries'] if row['path']==startup)
        assert entry['kind']=='regular' and len(entry['sha256'])==64,entry
        assert 'inventory fixture only' not in json.dumps(inventory)
        run('docker','exec',name,'rm',startup)
        print('Native integrity checks passed: unchanged, modified, missing, restored, absent package, persistence and no verification scripts')
        key=next(iter(snapshot['inventory']['keys'].values()))
        ssh.call(host,{'action':'key','name':'review-fixture.gpg','data':key})
        source_path='/etc/yum.repos.d/review.repo' if rpm else '/etc/apt/sources.list.d/review.sources'
        content='[review]\nname=Review\nbaseurl=https://example.invalid\nenabled=0\n' if rpm else 'Types: deb\nURIs: https://example.invalid\nSuites: stable\nComponents: main\nEnabled: no\n'
        ssh.call(host,{'action':'repository','path':source_path,'content':content})
        ssh.call(host,{'action':'repository','path':source_path,'content':''})
        backups=ssh.call(host,{'action':'backups'})['backups']
        assert backups and backups[0]['path']==source_path
        assert backups[0]['content']==content
        ssh.call(host,{'action':'repository','path':source_path,'content':content})
        key_path='/etc/pki/rpm-gpg/review-fixture.gpg' if rpm else '/etc/apt/keyrings/review-fixture.gpg'
        for path in [key_path,source_path,'/usr/local/lib/mrpatchy/agent.py','/usr/local/lib/mrpatchy/rpm_support.py']:
            assert run('docker','exec',name,'stat','-c','%a:%u',path)=='644:0'
        if rpm:
            from app import packages
            run('docker','exec','-d',name,'python3','/tmp/serve-fixture.py')
            ca=run('docker','exec',name,'cat','/etc/pki/fixture-ca.pem')
            repo_port=run('docker','port',name,'8443/tcp').rsplit(':',1)[1]
            inv=ssh.call(host,{'action':'inventory'})
            assert inv['package_manager']=='rpm'
            rows,_=packages.refresh(host.id,inv,{'ca':ca,'mirrors':{'https://127.0.0.1:8443':'https://127.0.0.1:'+repo_port}})
            fixture=next(p for p in rows if p['name']=='patchy-fixture:noarch')
            assert fixture['candidate']=='1:2.0-1',fixture
            result=ssh.call(host,{'action':'patch','packages':['patchy-fixture:noarch=1:2.0-1']},timeout=120)
            assert 'DNF completed' in result['output'],result
            assert run('docker','exec',name,'rpm','-q','--qf','%{VERSION}','patchy-fixture')=='2.0'
            # Unsigned newer RPM must never be installed, even with valid HTTPS metadata.
            run('docker','exec',name,'cp','/tmp/fixture-build/RPMS/noarch/patchy-fixture-3.0-1.noarch.rpm','/tmp/fixture-repo/')
            run('docker','exec',name,'createrepo_c','--update','/tmp/fixture-repo')
            rows,_=packages.refresh(host.id,ssh.call(host,{'action':'inventory'}),{'ca':ca,'mirrors':{'https://127.0.0.1:8443':'https://127.0.0.1:'+repo_port}})
            assert next(p for p in rows if p['name']=='patchy-fixture:noarch')['candidate']=='1:3.0-1'
            try:ssh.call(host,{'action':'patch','packages':['patchy-fixture:noarch=1:3.0-1']},timeout=120)
            except RuntimeError as error:assert 'signature' in str(error).lower(),error
            else:raise AssertionError('Unsigned RPM accepted')
            assert run('docker','exec',name,'rpm','-q','--qf','%{VERSION}','patchy-fixture')=='2.0'
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
        except RuntimeError as error:
            assert isinstance(error.__cause__,ssh.paramiko.AuthenticationException),error
            assert 'SSH authentication rejected' in str(error),error
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
