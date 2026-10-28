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
        if rpm:
            from app import vendor
            bundle=workspace/'vendor-packages'/'rpm-fixture';bundle.mkdir(parents=True)
            source='/tmp/fixture-build/RPMS/noarch/patchy-fixture-1.0-1.noarch.rpm'
            run('docker','cp',name+':'+source,str(bundle/'package.rpm'))
            run('docker','cp',name+':/etc/pki/rpm-gpg/fixture.asc',str(bundle.parent/'rpm-trustedkeys.asc'))
            vendor_manifest,proof=vendor.authenticate('rpm-fixture')
            assert vendor_manifest['version']=='1:1.0-1' and proof['signature_key_ids'],proof
            assert sorted(vendor_manifest['entries'],key=lambda e:e['path'])==[{'path':'/srv/patchy-vendor-fixture/data','sha256':ssh.hashlib.sha256(b'1\n').hexdigest(),'size':2},{'path':fixture_path,'sha256':ssh.hashlib.sha256(b'1\n').hexdigest(),'size':2}],vendor_manifest
            vendor_request={'action':'vendor-inspect','manifest':vendor_manifest}
            receipt=ssh.call(host,vendor_request,timeout=150)
            vendor.validate_receipt(vendor_manifest,receipt)
            assert receipt['state']=='matches_artifact_bytes',receipt
            run('docker','exec',name,'sh','-c','printf changed > '+fixture_path)
            assert ssh.call(host,vendor_request,timeout=150)['state']=='differences'
            run('docker','exec',name,'rm',fixture_path)
            assert ssh.call(host,vendor_request,timeout=150)['findings'][0]['status']=='missing'
            run('docker','exec',name,'sh','-c',"printf '1\\n' > "+fixture_path)
            vendor_manifest['version']='2:1.0-1'
            receipt=ssh.call(host,vendor_request,timeout=150)
            assert receipt['state']=='incomplete' and receipt['examined']==0,receipt
            artifact=(bundle/'package.rpm').read_bytes()
            for invalid in (artifact[:-1]+bytes([artifact[-1]^1]),b'not an rpm'):
                (bundle/'package.rpm').write_bytes(invalid)
                try:vendor.authenticate('rpm-fixture')
                except (ValueError,RuntimeError):pass
                else:raise AssertionError('Invalid/tampered RPM was authenticated')
            unsigned='/tmp/fixture-build/RPMS/noarch/patchy-fixture-3.0-1.noarch.rpm'
            run('docker','cp',name+':'+unsigned,str(bundle/'package.rpm'))
            try:vendor.authenticate('rpm-fixture')
            except (ValueError,RuntimeError):pass
            else:raise AssertionError('Unsigned RPM was authenticated')
            (bundle/'package.rpm').write_bytes(artifact)
            (bundle.parent/'rpm-trustedkeys.asc').write_text('not a signing key')
            try:vendor.authenticate('rpm-fixture')
            except (ValueError,RuntimeError):pass
            else:raise AssertionError('An untrusted RPM signing key was accepted')
            print('Native vendor RPM authentication passed: signed header/payload, exact epoch, bytes, tampering, unsigned and invalid trust')
        assert run('docker','exec',name,'python3','-c',"from pathlib import Path; print(Path('/tmp/patchy-verifyscript-executed').exists())")=='False'
        absent=ssh.call(host,{'action':'security-inspect','packages':['patchy-package-does-not-exist'],'persistence':False},timeout=210)
        assert absent['state']=='incomplete' and absent['packages'][0]['gaps'],absent
        startup='/etc/cron.d/patchy-inventory-fixture'
        run('docker','exec',name,'sh','-c',"mkdir -p /etc/cron.d; printf '# inventory fixture only\\n' > "+startup)
        inventory=ssh.call(host,{'action':'security-inspect','packages':[],'persistence':True},timeout=210)
        entry=next(row for row in inventory['persistence']['entries'] if row['path']==startup)
        assert entry['kind']=='regular' and len(entry['sha256'])==64,entry
        assert 'inventory fixture only' not in json.dumps(inventory)
        custom='/srv/patchy-custom-fixture'
        run('docker','exec',name,'sh','-c',"mkdir -p "+custom+"; printf 'custom metadata only\\n' > "+custom+"/config")
        custom_request={'action':'security-inspect-custom','packages':[],'persistence':True,'custom_paths':[custom]}
        custom_report=ssh.call(host,custom_request,timeout=210)
        assert custom in custom_report['persistence']['scope'],custom_report
        entry=next(e for e in custom_report['persistence']['entries'] if e['path']==custom+'/config')
        assert entry['sha256']==ssh.hashlib.sha256(b'custom metadata only\n').hexdigest(),entry
        assert 'custom metadata only' not in json.dumps(custom_report)
        run('docker','exec',name,'rm',custom+'/config')
        missing=ssh.call(host,custom_request,timeout=210)
        assert not any(e['path']==custom+'/config' for e in missing['persistence']['entries']),missing
        print('Custom integrity scope passed: declared root, SHA256, no contents and removed file')
        source=custom+'/evidence-source'
        run('docker','exec',name,'sh','-c',"printf evidence-fixture > "+source+"; chmod 755 "+source)
        identity=json.loads(run('docker','exec',name,'python3','-c',"import os,json; s=os.stat('"+source+"'); print(json.dumps({'device':s.st_dev,'inode':s.st_ino}))"))
        expected={**identity,'path':source,'sha256':ssh.hashlib.sha256(b'evidence-fixture').hexdigest()}
        vault_snapshot=ssh.call(host,{'action':'evidence-prepare','expected':expected},timeout=60)
        operation=str(uuid.uuid4());request={'action':'evidence-preserve','id':operation,'snapshot':vault_snapshot,'approved_until':time.time()+240}
        receipt=ssh.call(host,request,timeout=180)
        assert receipt['state']=='preserved' and receipt['original_unchanged'],receipt
        assert run('docker','exec',name,'cat',source)=='evidence-fixture'
        assert ssh.call(host,request,timeout=180)==receipt
        assert ssh.call(host,{'action':'evidence-status','id':operation},timeout=60)==receipt
        assert run('docker','exec',name,'stat','-c','%a','/var/lib/mrpatchy-evidence/'+operation+'/content')=='600'
        print('Evidence preservation passed: guarded vault, source unchanged, copy verification and idempotent recovery receipt')
        export_request={'action':'evidence-export','id':operation,'snapshot':vault_snapshot,'approved_until':time.time()+240}
        try:ssh.call(host,{**export_request,'approved_until':time.time()-1},timeout=60)
        except RuntimeError as error:assert 'approval' in str(error).lower(),str(error)
        else:raise AssertionError('Expired acquisition approval was accepted')
        acquired=ssh.call(host,export_request,timeout=150)
        assert acquired['snapshot']==vault_snapshot and base64.b64decode(acquired['content_base64'],validate=True)==b'evidence-fixture'
        from app import evidence_archive
        from app.db import Session,Job
        from app.evidence_vault import EvidenceCopy,EvidenceArchive
        archive_id=str(uuid.uuid4())
        with Session() as session:
            session.add(EvidenceCopy(id=operation,host_id=host.id,incident_id='native-fixture',state='preserved',snapshot=vault_snapshot,evidence_digest='a'*64))
            session.add(EvidenceArchive(id=archive_id,host_id=host.id,copy_id=operation,created=time.time(),state='queued',snapshot=vault_snapshot,fingerprint=host.fingerprint,actor='native-test',reason='Exercise the real SSH evidence acquisition.',expires=time.time()+240));session.commit()
            result=evidence_archive.execute(session,host,Job(id=str(uuid.uuid4()),action='evidence-acquire',payload={'archive_id':archive_id}));session.commit()
            assert result['state']=='verified' and result['bytes']==len(b'evidence-fixture'),result
            assert evidence_archive.verify(session.get(EvidenceArchive,archive_id))=='verified'
        assert (workspace/'evidence-archive'/archive_id/'content').read_bytes()==b'evidence-fixture'
        assert run('docker','exec',name,'cat',source)=='evidence-fixture'
        print('Controller acquisition passed: expired approval rejected, real pinned SSH transfer, private archive and independent hash verification')

        from app import quarantine,incidents,worker,operations
        from app.db import Host
        init() # Register worker-owned models before exercising its real job path.
        evidence_digest=incidents.digest(expected)
        with Session() as session:
            session.add(Host(id=host.id,name=host.name,address=host.address,port=host.port,fingerprint=host.fingerprint,state='online',baseline=host.baseline))
            session.add(incidents.Incident(id='native-fixture',host_id=host.id,scan_id='native-scan',evidence=expected))
            session.get(EvidenceCopy,operation).evidence_digest=evidence_digest
            response_job=worker.enqueue(session,host.id,'quarantine-prepare',{'archive_id':archive_id,'evidence_digest':evidence_digest,'_actor':'native-test'})
        worker.execute(response_job)
        def queue_response(action):
            with Session() as session:
                q_record=session.query(quarantine.Quarantine).one()
                if action!='quarantine-status':
                    review=quarantine.Approval(id=str(uuid.uuid4()),quarantine_id=q_record.id,action='restore' if action=='quarantine-restore' else 'quarantine',expires=time.time()+240,plan_digest=incidents.digest(q_record.plan),actor='native-test',reason='Approved harmless native response fixture.',before_state=q_record.state,before_hold=q_record.hold)
                    session.add(review);q_record.approval_id=review.id;q_record.state='restore_queued' if action=='quarantine-restore' else 'queued';q_record.hold=True
                return worker.enqueue(session,host.id,action,{'quarantine_id':q_record.id,'_actor':'native-test'})
        # A harmless target process retains a descriptor across the namespace move.
        holder_code="import os,sys,time; f=open(sys.argv[1],'rb'); open(sys.argv[2],'w').write(os.readlink('/proc/self')); time.sleep(300)"
        holder_ready=custom+'/reference-holder.pid'
        run('docker','exec','-d',name,'python3','-c',holder_code,source,holder_ready)
        for attempt in range(100):
            holder_result=subprocess.run(['docker','exec',name,'cat',holder_ready],capture_output=True,text=True)
            if holder_result.returncode==0 and holder_result.stdout.strip():break
            time.sleep(.05)
        else:raise AssertionError('Reference holder did not become ready')
        holder_pid=int(holder_result.stdout.strip())
        response_job=queue_response('quarantine-apply');worker.execute(response_job)
        with Session() as session:
            q_record=session.query(quarantine.Quarantine).one();q_id=q_record.id
            assert session.get(Job,response_job).state=='complete',session.get(Job,response_job).output
            assert q_record.state=='quarantined' and q_record.hold and operations.host_quarantined(session,host.id)
        assert run('docker','exec',name,'stat','-c','%a','/var/lib/mrpatchy-quarantine/'+q_id+'/held')=='600'
        run('docker','exec',name,'test','!','-e',source)
        from app import response_processes
        def inspect_process_references():
            with Session() as session:
                response=session.get(quarantine.Quarantine,q_id)
                check=worker.enqueue(session,host.id,'quarantine-processes',{'quarantine_id':q_id,'fingerprint':host.fingerprint,'plan_digest':incidents.digest(response.plan),'_actor':'native-test'})
            worker.execute(check)
            with Session() as session:
                assert session.get(Job,check).state=='complete',session.get(Job,check).output
                assert session.get(quarantine.Quarantine,q_id).hold
                return session.get(response_processes.Observation,check).report
        process_report=inspect_process_references()
        assert process_report['held_verified'],process_report
        assert any(m['pid']==holder_pid and m['references'].get('descriptor',0)>0 for m in process_report['observation']['matches']),process_report
        run('docker','exec',name,'kill','-0',str(holder_pid))
        run('docker','exec',name,'kill',str(holder_pid))
        # Wait only for our fixture's descriptor to close, never retry a mutation.
        for attempt in range(100):
            holder_result=subprocess.run(['docker','exec',name,'test','-d','/proc/'+str(holder_pid)+'/fd'],capture_output=True)
            if holder_result.returncode:break
            time.sleep(.05)
        process_report=inspect_process_references()
        assert not process_report['observation']['matches'],process_report
        print('Process references passed: real restricted bridge and held descriptor across quarantine, no signals from inspector, durable receipts and unchanged hold')
        from app import response_monitor
        from app.db import Setting
        with Session() as session:
            session.add(Setting(key='response-monitor:'+host.id,value={'enabled':True,'interval_minutes':5,'pause_on_problem':True,'revision':str(uuid.uuid4())}));session.commit()
        def audit_retained():
            response_monitor.schedule_tick(time.time()+601)
            with Session() as session:check_job=session.query(Job).filter_by(action='quarantine-audit',state='queued').one().id
            worker.execute(check_job)
            with Session() as session:return session.get(response_monitor.Check,check_job).state
        assert audit_retained()=='verified'
        run('docker','exec',name,'sh','-c',"printf concurrent-deployment > "+source)
        assert audit_retained()=='path_occupied'
        worker.execute(queue_response('quarantine-status'))
        with Session() as session:
            q_record=session.get(quarantine.Quarantine,q_id)
            assert q_record.state=='uncertain' and not q_record.receipt['restore_ready'] and q_record.hold
        assert run('docker','exec',name,'cat',source)=='concurrent-deployment'
        run('docker','exec',name,'rm',source)
        worker.execute(queue_response('quarantine-status'))
        restore_job=queue_response('quarantine-restore');worker.execute(restore_job)
        with Session() as session:
            q_record=session.get(quarantine.Quarantine,q_id)
            assert session.get(Job,restore_job).state=='complete',session.get(Job,restore_job).output
            assert q_record.state=='restored' and not q_record.hold and not operations.host_quarantined(session,host.id)
        assert run('docker','exec',name,'cat',source)=='evidence-fixture'
        assert run('docker','exec',name,'stat','-c','%a',source)=='755'
        assert ssh.call(host,{'action':'quarantine-status','id':q_id,'plan':q_record.plan},timeout=90)['state']=='restored'
        assert ssh.call(host,{'action':'quarantine-audit','id':q_id,'plan':q_record.plan},timeout=90)['state']=='restored'
        with Session() as session:
            assert session.query(response_monitor.Check).count()==2
            assert response_monitor.assessment(session,host.id)['watched']==0
        print('Retained response monitoring passed: real scheduled worker checks, retained hash, occupied source alert, separate pause policy and completed-restoration scope')
        print('Reviewed quarantine passed: verified independent archive, durable hold, root-only move, destination conflict, no overwrite and exact original restoration')
        # A second full evidence/quarantine workflow retains a running executable.
        # Coreutils single-binary installations expose sleep as a shebang
        # wrapper. Quarantine the actual ELF copy, not its interpreter script.
        executable=custom+'/sleep'
        image_code=Path(__file__).with_name('fixture_process.py').read_text()
        native_image=run('docker','exec',name,'python3','-c',image_code,'/usr/bin/sleep')
        run('docker','exec',name,'cp',native_image,executable)
        run('docker','exec',name,'chmod','755',executable)
        executable_expected=json.loads(run('docker','exec',name,'python3','-c',"import os,json,hashlib; p='"+executable+"'; s=os.stat(p); print(json.dumps({'path':p,'device':s.st_dev,'inode':s.st_ino,'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()}))"))
        executable_snapshot=ssh.call(host,{'action':'evidence-prepare','expected':executable_expected},timeout=90)
        executable_copy=str(uuid.uuid4());executable_archive=str(uuid.uuid4())
        ssh.call(host,{'action':'evidence-preserve','id':executable_copy,'snapshot':executable_snapshot,'approved_until':time.time()+240},timeout=180)
        executable_digest=incidents.digest(executable_expected)
        with Session() as session:
            session.add(incidents.Incident(id='native-process-fixture',host_id=host.id,scan_id='native-process-scan',evidence=executable_expected))
            session.add(EvidenceCopy(id=executable_copy,host_id=host.id,incident_id='native-process-fixture',state='preserved',snapshot=executable_snapshot,evidence_digest=executable_digest))
            session.add(EvidenceArchive(id=executable_archive,host_id=host.id,copy_id=executable_copy,created=time.time(),state='queued',snapshot=executable_snapshot,fingerprint=host.fingerprint,actor='native-test',reason='Retain a harmless running executable independently.',expires=time.time()+240));session.commit()
            evidence_archive.execute(session,host,Job(id=str(uuid.uuid4()),action='evidence-acquire',payload={'archive_id':executable_archive}));session.commit()
            executable_prepare=worker.enqueue(session,host.id,'quarantine-prepare',{'archive_id':executable_archive,'evidence_digest':executable_digest,'_actor':'native-test'})
        run('docker','exec','-d',name,executable,'300')
        ready_code="""import os,json,sys
source=os.stat(sys.argv[1]);matches=[]
for entry in os.scandir('/proc'):
    if not entry.name.isdecimal():continue
    try:
        target=os.stat(entry.path+'/exe')
        if (target.st_dev,target.st_ino)==(source.st_dev,source.st_ino):matches.append(int(entry.name))
    except OSError:pass
print(json.dumps(matches))"""
        for attempt in range(50):
            executable_pids=json.loads(run('docker','exec',name,'python3','-c',ready_code,executable))
            if executable_pids:break
            time.sleep(.05)
        else:raise AssertionError('Harmless executable fixture did not become ready')
        worker.execute(executable_prepare)
        with Session() as session:
            assert session.get(Job,executable_prepare).state=='complete',session.get(Job,executable_prepare).output
            executable_response=session.query(quarantine.Quarantine).filter_by(archive_id=executable_archive).one();executable_qid=executable_response.id
        def native_file_action(quarantine_id,restore=False):
            with Session() as session:
                record=session.get(quarantine.Quarantine,quarantine_id)
                approval=quarantine.Approval(id=str(uuid.uuid4()),quarantine_id=record.id,action='restore' if restore else 'quarantine',expires=time.time()+240,plan_digest=incidents.digest(record.plan),actor='native-test',reason='Reviewed harmless running executable file response.',before_state=record.state,before_hold=record.hold)
                session.add(approval);record.approval_id=approval.id;record.hold=True;record.state='restore_queued' if restore else 'queued'
                identifier=worker.enqueue(session,host.id,'quarantine-restore' if restore else 'quarantine-apply',{'quarantine_id':record.id,'_actor':'native-test'})
            worker.execute(identifier)
            with Session() as session:assert session.get(Job,identifier).state=='complete',session.get(Job,identifier).output
        native_file_action(executable_qid)
        with Session() as session:
            record=session.get(quarantine.Quarantine,executable_qid)
            observed_job=worker.enqueue(session,host.id,'quarantine-processes',{'quarantine_id':record.id,'fingerprint':host.fingerprint,'plan_digest':incidents.digest(record.plan),'_actor':'native-test'})
        worker.execute(observed_job)
        from app import process_response
        with Session() as session:
            observation=session.get(response_processes.Observation,observed_job)
            assert observation.state=='references_found',observation.report
            process_match=next(m for m in observation.report['observation']['matches'] if m['references'].get('executable')==1)
            process_prepare_job=worker.enqueue(session,host.id,'process-prepare',{'quarantine_id':executable_qid,'observation_id':observation.id,'pid':process_match['pid'],'plan_digest':observation.report['plan_digest'],'fingerprint':host.fingerprint,'_actor':'native-test'})
        worker.execute(process_prepare_job)
        with Session() as session:
            assert session.get(Job,process_prepare_job).state=='complete',session.get(Job,process_prepare_job).output
            process_record=session.query(process_response.ProcessResponse).one();process_id=process_record.id
        def process_action(action):
            with Session() as session:
                record=session.get(process_response.ProcessResponse,process_id)
                if action!='status':
                    approval=process_response.Approval(id=str(uuid.uuid4()),process_id=record.id,action=action,expires=time.time()+240,plan_digest=incidents.digest(record.plan),actor='native-test',reason='Reviewed harmless process fixture and explicit recovery.',before_state=record.state,before_hold=record.hold)
                    session.add(approval);record.approval_id=approval.id;record.state='resume_queued' if action=='resume' else 'queued';record.hold=True
                identifier=worker.enqueue(session,host.id,'process-'+action,{'process_id':record.id,'quarantine_id':record.quarantine_id,'_actor':'native-test'})
            worker.execute(identifier)
            with Session() as session:
                assert session.get(Job,identifier).state=='complete',session.get(Job,identifier).output
                return session.get(process_response.ProcessResponse,process_id).state
        assert process_action('suspend')=='suspended'
        assert run('docker','exec',name,'python3','-c',"v=open('/proc/"+str(process_match['pid'])+"/stat').read(); print(v[v.rfind(') ')+2:].split()[0])")=='T'
        assert process_action('status')=='suspended'
        with Session() as session:assert operations.host_quarantined(session,host.id) and session.get(process_response.ProcessResponse,process_id).hold
        assert process_action('resume')=='resumed'
        with Session() as session:
            assert not session.get(process_response.ProcessResponse,process_id).hold
            assert session.get(quarantine.Quarantine,executable_qid).hold
            assert session.query(process_response.Approval).count()==2
        run('docker','exec',name,'kill',str(process_match['pid']))
        native_file_action(executable_qid,True)
        print('Reviewed process response passed: independent evidence, executable match, real stable-pidfd suspension, read-only reconciliation, separate recovery approval and independent file hold')
        # Authenticate a separately supplied replacement, but publish no bytes.
        from app import repair_preparation,vendor
        repair_path='/srv/patchy-vendor-fixture/data'
        if rpm:
            repair_bundle='rpm-fixture';bundle=workspace/'vendor-packages'/repair_bundle
            run('docker','cp',name+':/etc/pki/rpm-gpg/fixture.asc',str(bundle.parent/'rpm-trustedkeys.asc'))
        else:
            from email.utils import formatdate
            repair_bundle='deb-fixture';bundle=workspace/'vendor-packages'/repair_bundle;bundle.mkdir(parents=True)
            run('docker','cp',name+':/tmp/patchy-fixture.deb',str(bundle/'package.deb'))
            artifact=(bundle/'package.deb').read_bytes()
            index=('Package: patchy-fixture\nVersion: 1.0-1\nArchitecture: all\nSize: '+str(len(artifact))+'\nSHA256: '+vendor.sha(artifact)+'\n\n').encode()
            (bundle/'Packages').write_bytes(index);(bundle/'index-path').write_text('main/binary-all/Packages\n')
            (bundle/'Release').write_text('Origin: Native test\nDate: '+formatdate(time.time(),usegmt=True)+'\nSHA256:\n '+vendor.sha(index)+' '+str(len(index))+' main/binary-all/Packages\n')
            keys=workspace/'vendor-test-keys';keys.mkdir(mode=0o700)
            run('gpg','--homedir',str(keys),'--batch','--pinentry-mode','loopback','--passphrase','','--quick-generate-key','Patchy native vendor fixture <fixture@example.invalid>','rsa2048','sign','0')
            run('gpg','--homedir',str(keys),'--batch','--output',str(bundle.parent/'trustedkeys.gpg'),'--export')
            run('gpg','--homedir',str(keys),'--batch','--pinentry-mode','loopback','--passphrase','','--output',str(bundle/'Release.gpg'),'--detach-sign',str(bundle/'Release'))
        (bundle/'replacement').write_bytes(b'1\n')
        selected,authentication=vendor.replacement(repair_bundle,repair_path)
        assert selected['entries']==[{'path':repair_path,'sha256':vendor.sha(b'1\n'),'size':2}]
        run('docker','exec',name,'sh','-c',"printf changed > "+repair_path)
        repair_expected=json.loads(run('docker','exec',name,'python3','-c',"import os,json,hashlib; p='"+repair_path+"'; s=os.stat(p); print(json.dumps({'path':p,'device':s.st_dev,'inode':s.st_ino,'sha256':hashlib.sha256(open(p,'rb').read()).hexdigest()}))"))
        repair_snapshot=ssh.call(host,{'action':'evidence-prepare','expected':repair_expected},timeout=90)
        repair_copy=str(uuid.uuid4());repair_archive=str(uuid.uuid4());repair_digest=incidents.digest(repair_expected)
        ssh.call(host,{'action':'evidence-preserve','id':repair_copy,'snapshot':repair_snapshot,'approved_until':time.time()+240},timeout=180)
        with Session() as session:
            session.add(incidents.Incident(id='native-repair-fixture',host_id=host.id,scan_id='native-repair-scan',evidence=repair_expected))
            session.add(EvidenceCopy(id=repair_copy,host_id=host.id,incident_id='native-repair-fixture',state='preserved',snapshot=repair_snapshot,evidence_digest=repair_digest))
            session.add(EvidenceArchive(id=repair_archive,host_id=host.id,copy_id=repair_copy,created=time.time(),state='queued',snapshot=repair_snapshot,fingerprint=host.fingerprint,actor='native-test',reason='Retain original before read-only trusted repair preparation.',expires=time.time()+240));session.commit()
            evidence_archive.execute(session,host,Job(id=str(uuid.uuid4()),action='evidence-acquire',payload={'archive_id':repair_archive}));session.commit()
            preparation_job=worker.enqueue(session,host.id,'quarantine-prepare',{'archive_id':repair_archive,'evidence_digest':repair_digest,'_actor':'native-test'})
        worker.execute(preparation_job)
        with Session() as session:
            assert session.get(Job,preparation_job).state=='complete',session.get(Job,preparation_job).output
            repair_response=session.query(quarantine.Quarantine).filter_by(archive_id=repair_archive).one();repair_qid=repair_response.id
        native_file_action(repair_qid)
        def trusted_preparation():
            with Session() as session:
                record=session.get(quarantine.Quarantine,repair_qid)
                prepared=repair_preparation.Preparation(id=str(uuid.uuid4()),host_id=host.id,quarantine_id=record.id,bundle_id=repair_bundle,path=repair_path,actor='native-test',fingerprint=host.fingerprint,response_plan_digest=incidents.digest(record.plan))
                session.add(prepared)
                identifier=worker.enqueue(session,host.id,'trusted-repair-prepare',{'preparation_id':prepared.id,'quarantine_id':record.id,'_actor':'native-test'});preparation_id=prepared.id
            worker.execute(identifier)
            with Session() as session:
                assert session.get(Job,identifier).state=='complete',session.get(Job,identifier).output
                record=session.get(repair_preparation.Preparation,preparation_id)
                assert session.get(quarantine.Quarantine,repair_qid).hold
                return record.state,record.report
        state,prepared_report=trusted_preparation()
        assert state=='ready' and all(v is True for v in prepared_report['target']['facts'].values()),prepared_report
        run('docker','exec',name,'test','!','-e',repair_path)
        assert run('docker','exec',name,'cat','/var/lib/mrpatchy-quarantine/'+repair_qid+'/held')=='changed'
        run('docker','exec',name,'sh','-c',"printf deployment > "+repair_path)
        state,prepared_report=trusted_preparation()
        assert state=='blocked' and 'destination_occupied' in prepared_report['target']['gaps'],prepared_report
        assert run('docker','exec',name,'cat',repair_path)=='deployment'
        assert run('docker','exec',name,'python3','-c',"from pathlib import Path; print(Path('/tmp/patchy-verifyscript-executed').exists())")=='False'
        run('docker','exec',name,'rm',repair_path)
        # Existing original-file restoration is a separate fixture cleanup action.
        with Session() as session:
            original_check=worker.enqueue(session,host.id,'quarantine-status',{'quarantine_id':repair_qid,'_actor':'native-test'})
        worker.execute(original_check);native_file_action(repair_qid,True)
        run('docker','exec',name,'sh','-c',"printf '1\\n' > "+repair_path)
        print('Trusted replacement preparation passed: real signed artifact and replacement authentication, exact installed package/owner, retained bytes, empty destination, occupied-path refusal, unchanged holds and no publication or package scripts')
        owned=custom+'/user-owned-response'
        run('docker','exec',name,'sh','-c',"printf owner-fixture > "+owned+"; chmod 644 "+owned)
        run('docker','exec',name,'chown','65534:65534',owned)
        owned_identity=json.loads(run('docker','exec',name,'python3','-c',"import os,json; s=os.stat('"+owned+"'); print(json.dumps({'device':s.st_dev,'inode':s.st_ino}))"))
        owned_snapshot=ssh.call(host,{'action':'evidence-prepare','expected':{**owned_identity,'path':owned,'sha256':ssh.hashlib.sha256(b'owner-fixture').hexdigest()}},timeout=90)
        try:ssh.call(host,{'action':'quarantine-prepare','snapshot':owned_snapshot},timeout=90)
        except RuntimeError as error:assert 'root-owned' in str(error),str(error)
        else:raise AssertionError('Quarantine accepted a file owned by an unprivileged user')
        assert run('docker','exec',name,'cat',owned)=='owner-fixture'
        print('Quarantine source ownership guard passed: unprivileged file refused without mutation')

        if not rpm:
            from target.agent import validate_yara_rules
            rules={'source':'rule PatchyFixture { strings: $a = "PATCHY_YARA_TEST" condition: $a }', 'issued':time.time()-60,'expires':time.time()+3600}
            rules['sha256']=ssh.hashlib.sha256(rules['source'].encode()).hexdigest();validate_yara_rules(rules)
            run('docker','exec',name,'sh','-c',"printf PATCHY_YARA_TEST > "+custom+"/yara-fixture")
            result=ssh.call(host,{'action':'yara-scan','paths':[custom],'rules':rules},timeout=300)
            assert result['engine']=='YARA' and result['state']=='completed_with_findings',result
            assert result['signatures']['database_version']==rules['sha256']
            assert result['findings'][0]['evidence']=='YARA rules: PatchyFixture',result
            run('docker','exec',name,'sh','-c',"printf harmless > "+custom+"/yara-fixture")
            result=ssh.call(host,{'action':'yara-scan','paths':[custom],'rules':rules},timeout=300)
            assert result['state']=='no_detections' and not result['findings'],result
            print('Native YARA source scanning passed: match, benign bytes, bound rule hash')

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
