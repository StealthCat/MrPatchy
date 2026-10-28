import concurrent.futures
import hashlib
import json
import logging
import threading
import time
import uuid
import math
import re
import subprocess
from sqlalchemy import select, delete, update, func
from .db import Session, Host, Package, Behavior, Job, Setting, InventoryRevision, Observation, config, audit
from . import incidents, apt, ssh, operations, releases, scheduling, ai, ai_runs, package_history, update_scores, packages as package_backend
from target.agent import MANAGED
from .security import unseal
import httpx
from .coordination import Lock
log=logging.getLogger(__name__)
stop=threading.Event()
host_locks={}; locks_guard=threading.Lock()
def host_lock(host_id):
    with locks_guard: return host_locks.setdefault(host_id,Lock("host:"+host_id))
def enqueue(s,host_id,action,payload=None):
    if len(list(s.scalars(select(Job.id).where(Job.host_id==host_id,Job.state.in_(['queued','running']))).all()))>=50: raise ValueError('Server queue is full (50 operations)')
    job=Job(id=str(uuid.uuid4()),host_id=host_id,action=action,payload=payload or {})
    s.add(job); audit(s,'queue '+action,host_id); s.commit(); return job.id

def save_inventory(s,h,inv):
    items=package_backend.installed(inv)
    if h.inventory and any(h.inventory.get(key)!=inv.get(key) for key in ('status','files','keys','architecture','foreign_architectures','machine_id','package_manager','rpm_vars','module_platform_id')):
        h.last_repo=0
    previous={k:v for k,v in h.inventory.items() if k!='collected'}
    current={k:v for k,v in inv.items() if k!='collected'}
    old={p.name:p for p in s.scalars(select(Package).where(Package.host_id==h.id))}
    package_history.record(s,h,inv,old,items)
    if previous!=current or not s.scalar(select(InventoryRevision.id).where(InventoryRevision.host_id==h.id).limit(1)):
        s.add(InventoryRevision(id=uuid.uuid4().hex,host_id=h.id,inventory=inv))
    h.inventory=inv
    changed=[(item,old[item['name']]) for item in items if item['name'] in old and old[item['name']].candidate]
    newer=package_backend.newer_flags(inv,[(p.candidate,item['installed']) for item,p in changed])
    still_newer={item['name']:flag for (item,_),flag in zip(changed,newer)}
    names=set()
    for item in items:
        names.add(item['name']); p=old.get(item['name'])
        if not p:
            p=Package(id=h.id+':'+item['name'],host_id=h.id,**item); s.add(p)
            if old: audit(s,'package installed',h.name+' '+item['name']+' '+item['installed'])
        else:
            if p.installed!=item['installed']: audit(s,'package version changed',h.name+' '+p.name+' '+p.installed+' → '+item['installed'])
            p.installed=item['installed']; p.held=item['held']; p.dpkg_state=item['dpkg_state']
            if p.candidate and not still_newer.get(item['name'],False):
                p.candidate=''; p.available_since=0
    for name,p in old.items():
        if name not in names:
            audit(s,'package removed',h.name+' '+p.name+' '+p.installed); s.delete(p)

def update_repos(s,h):
    # Repository resolution does not depend on a live SSH connection.
    inv=h.inventory
    if not inv: raise ValueError('Finish enrollment to obtain a package/source inventory')
    if h.state!='offline':
        try:
            inv=ssh.call(h,{'action':'inventory'})
        except Exception as e:
            s.rollback();h=s.get(Host,h.id);inv=h.inventory
            audit(s,'repository check uses cached inventory',h.id+' '+type(e).__name__)
        else:
            save_inventory(s,h,inv);s.commit()
    packages,output=package_backend.refresh(h.id,inv,repository_access(s,h.id))
    for item in packages:
        p=s.get(Package,h.id+':'+item['name'])
        if not p: continue
        # Superseding a still-outstanding update must not postpone its deadline.
        if not item['candidate']: p.available_since=0
        elif not p.candidate or not p.available_since: p.available_since=time.time()
        for key in ['candidate','origin']: setattr(p,key,item[key])
        if not p.priority_manual: p.priority=item['priority']
    h.last_repo=time.time(); h.repo_error=''; s.commit(); return output

def repository_access(s,host_id):
    item=s.get(Setting,'repository-access:'+host_id)
    return json.loads(unseal(item.value['encrypted'])) if item else {}

def record_behavior(s,h,p,observed):
    e=behavior_evidence(p)
    key=hashlib.sha256((h.id+json.dumps(e,sort_keys=True)).encode()).hexdigest()
    row=s.get(Behavior,key)
    if row:
        row.last_seen=max(row.last_seen,observed);row.first_seen=min(row.first_seen,observed)
    else:
        s.add(Behavior(id=key,host_id=h.id,evidence=e,first_seen=observed,last_seen=observed))
        s.flush()

def ingest_events(s,h,snapshot):
    ids=[]
    events=snapshot.get('events',[])
    if not isinstance(events,list) or len(events)>8: raise ValueError('Invalid event batch')
    for event in events:
        eid=str(uuid.UUID(event['id']));observed=event['observed']
        if not isinstance(observed,(int,float)) or not math.isfinite(observed) or observed>time.time()+120: raise ValueError('Invalid event time')
        key=hashlib.sha256((h.id+eid).encode()).hexdigest()
        if not s.get(Observation,key):
            for process in event.get('processes',[]): record_behavior(s,h,process,observed)
            s.add(Observation(id=key,host_id=h.id,observed=observed,evidence=event))
            s.flush()
        ids.append(eid)
    return ids

def behavior_evidence(p):
    # Exclude PID and ephemeral client ports so expected reconnects do not flood the queue.
    connections=[]
    for c in p.get('connections',[]):
        connections.append({'protocol':c['protocol'],'remote':c['remote'],'remote_port':c['remote_port'], 'listen_port':c['local_port'] if c['state']=='0A' or c['remote_port']==0 else None, 'bind_address':c['local'] if c['state']=='0A' or c['remote_port']==0 else None})
    connections=sorted({json.dumps(c,sort_keys=True) for c in connections})
    evidence={'executable':p['executable'],'sha256':p['sha256'],'uid':p['uid'],'network_namespace':p.get('network_namespace'),'provenance':p.get('provenance',[]),'capture':p.get('capture','sample'),'connections':[json.loads(c) for c in connections]}
    if p.get('capture')=='ebpf' or 'identity_verified' in p:
        evidence['identity_verified']=p.get('identity_verified') is True
    return evidence

def ingest(s,h,snapshot,include_inventory=True):
    if include_inventory and 'inventory' in snapshot and snapshot['inventory'].get('collected',0)>h.inventory.get('collected',0): save_inventory(s,h,snapshot['inventory'])
    t=snapshot.get('telemetry',{})
    if not t: raise RuntimeError('Collector has not produced telemetry yet')
    for name in ('collected','hashed_at'):
        value=t.get(name,0)
        if not isinstance(value,(int,float)) or not math.isfinite(value):
            raise ValueError('Invalid telemetry timestamp: '+name)
    if t.get('collected',0)>time.time()+120: raise RuntimeError('Target clock is ahead; cannot verify telemetry freshness')
    if t.get('collected',0)<h.telemetry.get('collected',0):
        raise RuntimeError('Collector snapshot timestamp moved backwards')
    issues=[]
    if time.time()-t.get('collected',0)>120: issues.append({'path':'collector','issue':'Telemetry older than 120 seconds'})
    if time.time()-t.get('hashed_at',0)>360: issues.append({'path':'integrity','issue':'Hash sweep is overdue'})
    if t.get('hashed_at',0)>time.time()+120: issues.append({'path':'integrity','issue':'Hash sweep timestamp is in the future'})
    for error in t.get('errors',[]): issues.append({'path':'collector','issue':str(error)[:1000]})
    for name,expected in h.baseline.items():
        if t.get('managed',{}).get(name)!=expected: issues.append({'path':name,'issue':'SHA-256 differs from enrolled version or file is missing'})
        if name in MANAGED or name=='/etc/systemd/system/mrpatchy-agent.service.d/observability.conf':
            expected_mode=0o440 if name=='/etc/sudoers.d/mrpatchy' else 0o644
            if t.get('managed_metadata',{}).get(name)!={'uid':0,'gid':0,'mode':expected_mode}:
                issues.append({'path':name,'issue':'Managed file ownership/permissions changed or metadata is missing; upgrade the collector if needed'})
    if not h.baseline: issues.append({'path':'baseline','issue':'Managed baseline missing; finish installation'})
    ingest_events(s,h,snapshot)
    for p in t.get('processes',[]): record_behavior(s,h,p,t['collected'])
    if snapshot.get('spool',{}).get('dropped',0):
        issues.append({'path':'event spool','issue':str(snapshot['spool']['dropped'])+' observation batches lost to the target size limit'})
    t=dict(t);t['spool']=snapshot.get('spool',{})
    if snapshot.get('ebpf-diagnostic'):issues.append({'path':'eBPF diagnostics','issue':str(snapshot['ebpf-diagnostic'])})
    if snapshot.get('ebpf-status',{}).get('state') in ('error','warning','unavailable'):issues.append({'path':'eBPF','issue':str(snapshot['ebpf-status'])})
    if snapshot.get('collector-error'): issues.append({'path':'collector','issue':str(snapshot['collector-error'])})
    h.integrity=issues; h.telemetry=t; h.last_seen=time.time(); h.state='attention' if issues else 'online'; h.error=''
    s.commit()

def drain_events(s,h,snapshot,max_batches=32,budget=10):
    """Commit before acknowledgement; bounded catch-up without full inventories."""
    deadline=time.monotonic()+budget
    for index in range(max_batches):
        events=snapshot.get('events',[])
        if not events:return
        ids=ingest_events(s,h,snapshot);s.commit()
        ssh.call(h,{'action':'ack','ids':ids},timeout=max(1,deadline-time.monotonic()))
        if snapshot.get('spool',{}).get('pending',len(events))<=len(events):return
        if index+1==max_batches or time.monotonic()>=deadline:return
        snapshot=ssh.call(h,{'action':'events'},timeout=max(1,deadline-time.monotonic()))


def poll_host(host_id):
    lock=host_lock(host_id)
    locked=lock.acquire(False)
    try:
        with Session() as s:
            h=s.get(Host,host_id)
            if not h or h.state=='enrolling': return
            # Snapshot/events may import the collector. Check independently first,
            # and never consume it after a known failed health/trust assessment.
            if h.baseline:
                from . import agent_maintenance
                saved=s.get(Setting,'agent-status:'+host_id)
                status=saved.value if saved else None
                if locked and not operations.host_quarantined(s,host_id) and (not status or time.time()-status.get('checked',0)>=300):
                    status=agent_maintenance.inspect(s,h)
                if status and status['state'] not in ('current','outdated'):
                    h.state='attention';h.error='Agent verification '+status['state']+'; telemetry ingestion paused. Review Agent health.';s.commit()
                    return
            try:
                snapshot=ssh.call(h,{'action':'snapshot'})
                ingest(s,h,snapshot,include_inventory=locked)
                drain_events(s,h,snapshot)
            except Exception as e:
                s.rollback()
                h=s.get(Host,host_id)
                if h: h.state='offline'; h.error=str(e)[:4000]; s.commit()
            if locked and h and not h.baseline and not operations.host_quarantined(s,host_id):
                from . import agent_maintenance
                status=s.get(Setting,'agent-status:'+host_id)
                if not status or time.time()-status.value.get('checked',0)>=300:
                    agent_maintenance.inspect(s,h)
    finally:
        if locked: lock.release()

class RecoveryTimeout(RuntimeError):pass


def wait_for_reboot(host,result,job_id,timeout=600,original=None):
    if result.get('outcome')=='rollback_pending' and (not isinstance(original,dict) or original.get('version')!=1):
        raise ValueError('Original recovery evidence is missing; reconcile target state')
    deadline=time.monotonic()+timeout;last_error='Waiting for a changed boot ID'
    while time.monotonic()<deadline:
        time.sleep(5)
        try:
            status=ssh.call(host,{'action':'recovery-status'},timeout=15)
            if status['boot_id']==result['boot_before']:continue
            health=ssh.call(host,{'action':'health'},timeout=15)
            if health.get('failed_units') or not health.get('collector_active'):
                last_error='Services are not healthy yet';continue
            if result.get('outcome')=='rollback_pending':
                # A root filesystem rollback can also revert the target journal.
                # The centrally persisted rollback receipt survives that rollback.
                verified=verify_patch_recovery(host,original)
                return {**result,**verified,'reboot_verified':True,'health':health}
            return ssh.call(host,{'action':'complete-recovery','job_id':job_id},timeout=15)
        except (OSError,ssh.paramiko.SSHException,RuntimeError,ValueError) as error:
            last_error=str(error)[:1000]
    raise RecoveryTimeout('Reboot/health not verified within the recovery window: '+last_error)


def verify_patch_recovery(host,original):
    if not isinstance(original,dict) or original.get('version')!=1:
        raise ValueError('Original recovery evidence is missing; reconcile target state')
    verified=ssh.call(host,{'action':'patch-restored','original':original},timeout=120)
    if verified.get('outcome')!='rolled_back' or verified.get('original_state_verified') is not True:
        raise ValueError('Original target state has not been verified')
    return verified


def finish_recovery(s,host,job,result,policy):
    original=job.payload.get('_patch_original')
    if not result.get('reboot_scheduled'):
        if result.get('outcome')=='rolled_back':result={**result,**verify_patch_recovery(host,original)}
        return result
    job.output=json.dumps(result);s.commit() # Persist receipt before the target can reboot.
    try:return wait_for_reboot(host,result,job.id,original=original)
    except RecoveryTimeout:
        if not policy.get('rollback') or result.get('outcome')=='rollback_pending':raise
        # The target refuses this if it has not rebooted, has no snapshot, or
        # rollback was already attempted. Never repeat a snapshot rollback.
        recovery=ssh.call(host,{'action':'rollback-patch','job_id':job.id},timeout=1900)
        job.output=json.dumps(recovery);s.commit()
        if recovery.get('reboot_scheduled'):return wait_for_reboot(host,recovery,job.id,original=original)
        return {**recovery,**verify_patch_recovery(host,original)}


def submit_job(pool,job,active,busy):
    if job.id in active or job.host_id in busy:return False
    lock=host_lock(job.host_id)
    if not lock.acquire(False):return False
    try:future=pool.submit(execute,job.id,lock)
    except BaseException:
        lock.release();raise
    active[job.id]=(future,job.host_id);busy.add(job.host_id)
    return True


def execute(job_id,reserved_lock=None):
    lock=reserved_lock
    if lock is None:
        with Session() as s:
            job=s.get(Job,job_id)
            if not job:return
            lock=host_lock(job.host_id)
        if not lock.acquire(False):return
    try:return execute_locked(job_id)
    finally:lock.release()


def execute_locked(job_id):
    with Session() as s:
        job=s.get(Job,job_id)
        if not job or (job.state!='queued' and not (job.action=='release-upgrade' and job.state=='running')):return
        # End a pre-lock MySQL REPEATABLE READ snapshot before quarantine checks.
        s.rollback()
        s.refresh(job)
        resuming=job.action=='release-upgrade' and job.state=='running'
        if job.state!='queued' and not resuming:return
        from . import quarantine,process_response
        response_id=job.payload.get('quarantine_id') if job.action in quarantine.RECOVERY_ACTIONS else None
        process_id=job.payload.get('process_id') if job.action in process_response.RECOVERY_ACTIONS else None
        read_only_response_id=job.payload.get('quarantine_id') if job.action=='trusted-repair-prepare' else None
        if operations.host_quarantined(s,job.host_id,exclude=job.id,response_id=response_id,process_id=process_id,read_only_response_id=read_only_response_id,local_observation=job.action=='evidence-archive-status'):return
        if not resuming and not operations.eligible(s,job): return
        claimed=1 if resuming else s.execute(update(Job).where(Job.id==job_id,Job.state=='queued').values(state='running')).rowcount
        s.commit()
        if claimed!=1:return
        s.refresh(job)
        h=s.get(Host,job.host_id);protected=job.action=='release-upgrade';result={}
        try:
            if not h: raise ValueError('Host no longer exists')
            health=s.get(Setting,'agent-status:'+h.id)
            # File responses perform a mandatory fresh independent check before
            # importing a helper. Let that check recover a stale cached outage.
            if not resuming and health and health.value.get('state') in ('blocked','drifted','unavailable') and job.action not in ('agent-check','agent-update','deploy','security-plan','startup-plan','evidence-archive-status',*quarantine.ACTIONS):
                raise ValueError('Agent verification failed; review Agent health before executing remote operations')
            if job.action=='release-plan':result=releases.build(s,h,job.payload['plan_id']);job.output=json.dumps(result)
            elif job.action=='release-upgrade':
                result=releases.execute(s,h,job)
                job.output=json.dumps(result)
                token=package_history.operation.set({'job_id':job.id,'actor':job.payload.get('_actor','system')})
                try:save_inventory(s,h,ssh.call(h,{'action':'inventory'}));h.last_repo=0;s.commit()
                finally:package_history.operation.reset(token)
            elif job.action=='deploy':
                result=ssh.deploy(h)
                expected_files=ssh.expected_files(h)
                from . import agent_maintenance
                verification=ssh.call(h,{'action':'agent-status'})
                old_baseline=h.baseline;h.baseline=expected_files
                try:
                    status=agent_maintenance.assess(h,verification)
                    if status['state']!='current':raise ValueError('Installation verification failed; review independent agent status')
                except Exception:
                    h.baseline=old_baseline
                    raise
                status.update(checked=time.time(),release=agent_maintenance.release_id(h),report=verification)
                s.merge(Setting(key='agent-status:'+h.id,value=status))
                h.state='waiting'; job.output=json.dumps({'deployment':result,'verification':verification})
                save_inventory(s,h,ssh.call(h,{'action':'inventory'}))
            elif job.action in ('agent-check','agent-update'):
                from . import agent_maintenance
                result=agent_maintenance.inspect(s,h,queue=False) if job.action=='agent-check' else agent_maintenance.update(s,h,job)
                job.output=json.dumps(result)
            elif job.action=='rotate-key':
                result=ssh.rotate(h)
                h.baseline={**h.baseline,'/opt/drpatch/.ssh/authorized_keys':result['authorized_keys_sha256']}
                job.output=json.dumps(result)
            elif job.action=='startup-plan':
                from . import startup_ai,incidents
                incident=s.get(incidents.PersistenceIncident,job.payload['incident_id'])
                if not incident or incident.host_id!=h.id:raise ValueError('Startup incident not found')
                plan=startup_ai.generate(s,incident,float(job.payload['expected_updated']))
                job.output=json.dumps({'plan_id':plan.id,'execution':'manual_only'})
            elif job.action=='security-plan':
                from . import incidents
                incident=s.get(incidents.Incident,job.payload['incident_id'])
                if not incident or incident.host_id!=h.id:raise ValueError('Incident not found')
                if job.payload.get('automatic'):
                    policy=s.get(Setting,'security-policy:'+h.id)
                    if not policy or not policy.value.get('auto_ai_plan'):raise ValueError('Automatic AI planning is disabled; no AI call sent')
                    if incident.state!='open' or incident.scan_id!=job.payload.get('scan_id'):raise ValueError('Automatic incident evidence changed; no AI call sent')
                plan=incidents.generate(s,incident)
                job.output=json.dumps({'plan_id':plan.id,'execution':'manual_only'})
            elif job.action=='vendor-inspect':
                from . import vendor,incidents
                manifest,provenance=vendor.authenticate(job.payload['bundle_id'])
                result=ssh.call(h,{'action':'vendor-inspect','manifest':manifest},timeout=150)
                vendor.validate_receipt(manifest,result)
                report={'version':1,'trust_basis':vendor.trust_basis(manifest),'state':'collected' if result['state']!='incomplete' else 'incomplete',
                        'packages':[],'persistence':None,'vendor_verification':result,'vendor_authentication':provenance}
                incidents.record_inspection(s,h.id,job.id,report,vendor_authenticated=True)
                job.output=json.dumps({'state':result['state'],'bundle_id':job.payload['bundle_id'],'examined':result.get('examined')})
            elif job.action=='security-inspect':
                from . import incidents
                from .persistence import monitor_policy
                if '_persistence_policy' in job.payload:
                    policy=monitor_policy(s,h.id)
                    if not policy['enabled'] or policy['revision']!=job.payload['_persistence_policy']:
                        raise ValueError('Persistence monitoring policy changed; scheduled inspection cancelled before remote access')
                request={'action':'security-inspect','packages':job.payload['packages'],'persistence':job.payload['persistence']}
                paths=job.payload.get('custom_paths',[])
                if paths:
                    from target.agent import validate_custom_paths
                    expected_scope=validate_custom_paths(paths)
                    request.update(action='security-inspect-custom',custom_paths=paths)
                result=ssh.call(h,request,timeout=210)
                if paths and set((result.get('persistence') or {}).get('scope',[]))!=set(expected_scope):
                    raise ValueError('Custom inventory scope was not returned; update target helpers')
                incidents.record_inspection(s,h.id,job.id,result)
                job.output=json.dumps({'state':result.get('state'),'packages':len(result.get('packages',[])),
                                       'persistence_entries':len((result.get('persistence') or {}).get('entries',[]))})
            elif job.action in process_response.ACTIONS:
                result=process_response.execute(s,h,job);job.output=json.dumps(result)
            elif job.action=='quarantine-processes':
                from . import response_processes
                result=response_processes.execute(s,h,job);job.output=json.dumps(result)
            elif job.action=='quarantine-audit':
                from . import response_monitor
                result=response_monitor.execute(s,h,job);job.output=json.dumps(result)
            elif job.action=='trusted-repair-prepare':
                from . import repair_preparation
                result=repair_preparation.execute(s,h,job);job.output=json.dumps(result)
            elif job.action in quarantine.ACTIONS:
                result=quarantine.execute(s,h,job);job.output=json.dumps(result)
            elif job.action in ('evidence-acquire','evidence-archive-status'):
                from . import evidence_archive
                job.output=json.dumps(evidence_archive.execute(s,h,job))
            elif job.action in ('evidence-prepare','evidence-preserve','evidence-status'):
                from . import evidence_vault
                job.output=json.dumps(evidence_vault.execute(s,h,job))
            elif job.action=='yara-scan':
                from . import yara_rules,incidents
                rules,proof=yara_rules.authenticate(job.payload['bundle_id'])
                result=ssh.call(h,{'action':'yara-scan','paths':job.payload['paths'],'rules':rules},timeout=300)
                if result.get('engine')!='YARA' or result.get('signatures',{}).get('database_version')!=rules['sha256']:
                    raise ValueError('YARA receipt does not bind authenticated rules; update target helpers')
                incidents.record(s,h.id,job.id,result,rules_provenance=proof)
                job.output=json.dumps({'state':result.get('state'),'findings':len(result.get('findings',[])),'bundle_id':job.payload['bundle_id']})
            elif job.action=='security-scan':
                result=ssh.call(h,{'action':'security-scan','paths':job.payload['paths']},timeout=300)
                from . import incidents
                incidents.record(s,h.id,job.id,result)
                job.output=json.dumps({'state':result.get('state'),'findings':len(result.get('findings',[]))})
            elif job.action=='refresh': job.output=update_repos(s,h)
            elif job.action in ('patch','repository','key','repair'):
                if job.action=='patch':
                    save_inventory(s,h,ssh.call(h,{'action':'inventory'}))
                    s.commit()
                    validate_patch(s,h,job.payload['packages'])
                    if job.payload.get('_schedule'): scheduling.validate_selection(s,h,job)
                policy=operations.recovery_policy(s,h.id)
                if job.action=='patch':
                    approved=job.payload.get('_recovery_policy',{'reboot':False,'rollback':False})
                    if approved!=policy:raise ValueError('Recovery policy changed; review and submit this patch again')
                checked_patch=job.action=='patch' and ('_depends_on' in job.payload or any(policy.values()))
                health_before=None
                if checked_patch:
                    health_before=ssh.call(h,{'action':'health'})
                    existing=operations.failed_unit_names(health_before)
                    if not health_before['collector_active']:
                        raise ValueError('Pre-patch health failed: collector is inactive; no package changes attempted')
                    if any(policy.values()) and existing:
                        raise ValueError('Pre-patch health failed: automatic reboot/rollback requires clean service health; no package changes attempted: '+json.dumps(sorted(existing)))
                    job.payload={**job.payload,'_health_before':health_before};s.commit()
                protected=job.action=='patch' and any(policy.values())
                request={'action':job.action,**{k:v for k,v in job.payload.items() if not k.startswith('_')}}
                if protected:
                    if policy.get('rollback'):
                        original=ssh.call(h,{'action':'patch-inspect'},timeout=120)
                        if original.get('version')!=1 or not original.get('configs'):
                            raise ValueError('Upgrade target helpers before using verified rollback')
                        # This receipt must survive both a target snapshot restore and
                        # a central crash; never store it only in truncated job output.
                        job.payload={**job.payload,'_patch_original':original};s.commit()
                        request['original']=original
                    request.update(action='protected-patch',job_id=job.id,policy=policy)
                result=ssh.call(h,request,timeout=7500 if protected else 3700)
                if protected:result=finish_recovery(s,h,job,result,policy)
                job.output=json.dumps(result)
                token=package_history.operation.set({'job_id':job.id,'actor':job.payload.get('_actor','system')})
                try:save_inventory(s,h,ssh.call(h,{'action':'inventory'}));h.last_repo=0;s.commit()
                finally:package_history.operation.reset(token)
                if job.action=='patch' and '_depends_on' in job.payload:
                    health=ssh.call(h,{'action':'health'})
                    comparison=operations.patch_health_comparison(health_before,health)
                    if not comparison['passed']:raise RuntimeError('Post-patch service health regressed; rollout stopped: '+json.dumps(comparison))
                    job.output+='\nPost-patch health comparison: '+json.dumps(comparison)
            else: raise ValueError('Unsupported job')
            job.output=job.output.encode()[:48000].decode(errors='ignore')
            job.state='failed' if result.get('outcome') in ('rolled_back','response_incomplete') else 'complete'
            audit(s,('rolled back ' if result.get('outcome')=='rolled_back' else 'incomplete ' if result.get('outcome')=='response_incomplete' else 'complete ')+job.action,h.id)
        except Exception as e:
            s.rollback()
            job=s.get(Job,job_id)
            h=s.get(Host,job.host_id)
            job.state='recovery_required' if protected else 'failed'
            if job.action in ('quarantine-apply','quarantine-restore'):quarantine.reject_unstarted(s,job)
            if job.action in ('process-suspend','process-resume'):process_response.reject_unstarted(s,job)
            if job.action=='process-status':
                response=s.get(process_response.ProcessResponse,job.payload.get('process_id'))
                if response and response.host_id==job.host_id and (response.state!='uncertain' or response.receipt):
                    response.state='uncertain';response.hold=True;response.receipt={};response.observed=time.time()
                    process_response.event(s,response,'observation_failed',job.payload.get('_actor','system'),{'job_id':job.id})
            if job.action=='quarantine-status':
                response=s.get(quarantine.Quarantine,job.payload.get('quarantine_id'))
                if response and response.host_id==job.host_id and (response.state!='uncertain' or response.receipt):
                    response.state='uncertain';response.hold=True;response.receipt={};response.observed=time.time()
                    quarantine.event(s,response,'observation_failed',job.payload.get('_actor','system'),{'job_id':job.id})
            if job.action=='evidence-acquire':
                from . import evidence_archive
                from .evidence_vault import EvidenceArchive
                acquisition=s.get(EvidenceArchive,job.payload.get('archive_id'))
                if acquisition and acquisition.host_id==job.host_id and acquisition.state=='queued':
                    acquisition.state='rejected';evidence_archive.observe(s,acquisition,'rejected',job.id)
            if job.action in ('release-plan','release-upgrade'):
                plan=s.get(releases.ReleasePlan,job.payload['plan_id'])
                if plan:plan.state=job.state;plan.error=str(e)[:1000]
            receipt=job.output if protected or job.action=='agent-update' else ''
            job.output=(str(e)+'\n'+receipt).encode()[:48000].decode(errors='ignore')
            if h:
                h.error=str(e)[:4000]
                if job.action=='refresh': h.repo_error=str(e)[:16000]
            audit(s,'failed '+job.action,str(e)[:4000])
        s.commit()

def validate_patch(s,h,specs):
    cfg=config(s)
    if h.repo_error or not h.last_repo or time.time()-h.last_repo>cfg['repo_minutes']*120:
        raise ValueError('Refresh repositories before patching; metadata is stale, changed, or the latest check failed')
    for spec in specs:
        name,version=spec.rsplit('=',1)
        p=s.get(Package,h.id+':'+name)
        if not p or p.held or p.dpkg_state.split()[-1]!='installed' or not p.candidate or p.candidate!=version:
            raise ValueError('Queued patch is no longer valid; review package '+name)


def investigate_one():
    lock=Lock('ai-triage')
    if not lock.acquire(False):return
    try:
        ai_runs.reconcile('triage')
        return _investigate_one()
    finally:lock.release()

def _investigate_one():
    with Session() as s:
        cfg=config(s); secret=s.get(Setting,'openai_key')
        if not cfg['ai_enabled'] or not cfg['ai_model'] or not secret: return
        now=time.time()
        recent=list(s.scalars(select(Behavior).where(Behavior.attempted>now-3600)))
        count=s.scalar(select(func.count()).select_from(ai_runs.AIRun).where(ai_runs.AIRun.purpose=='triage',ai_runs.AIRun.started>now-3600))
        if max(len(recent),count)>=cfg['ai_hourly_limit']: return
        row=s.scalar(select(Behavior).where(Behavior.approved==False,Behavior.verdict.in_(['pending','error']),Behavior.attempted<now-3600).order_by(Behavior.first_seen).limit(1))
        if not row: return
        row.attempted=now; s.commit()
        try:
            with ai_runs.track('triage',cfg['ai_model'],row.host_id,row.id):
                _assess_behavior(s,row,cfg,secret)
        except Exception as e:
            s.rollback();row=s.get(Behavior,row.id)
            row.verdict='error'
            row.analysis='Investigation failed; automatic retry after the one-hour backoff. '+ai_runs.safe_error(e)
        s.commit()

def _assess_behavior(s,row,cfg,secret):
    def assess(evidence):return ai.investigate(evidence,cfg['ai_model'],unseal(secret.value['encrypted']))
    result=assess(row.evidence)
    checks=result.get('requested_checks',[])
    if checks:
        ai_runs.event('ssh_evidence','Collecting the requested allowlisted evidence from the target.')
        host=s.get(Host,row.host_id)
        checksum=row.evidence.get('sha256','')
        if not host or not isinstance(checksum,str) or not re.fullmatch(r'[a-f0-9]{64}',checksum) or row.evidence.get('identity_verified') is False:
            evidence={'identity_verified':False,'checks':list(set(checks)),'reason':'The observed executable has no verified identity or its host is unavailable; no remote evidence request was sent'}
        else:
            try:evidence=ssh.call(host,{'action':'evidence','executable':row.evidence['executable'],'sha256':checksum,'checks':list(set(checks))},timeout=90)
            except Exception as error:raise ai.AIError('SSH evidence collection failed ('+type(error).__name__+'). Verify target connectivity, host pinning and helper installation.') from None
        row.evidence={**row.evidence,'investigation':{'collected':time.time(),'details':evidence}}
        s.commit()
        result=assess(row.evidence)
    row.verdict=result['risk']; row.analysis=result['explanation']+'\n\nRecommended checks: '+result['recommended_checks']
    s.commit()

def ai_cycle():
    # Separate quotas keep score batches from starving process investigations.
    for fn in (investigate_one,update_scores.run_one):
        try:fn()
        except Exception as error:ai_runs.task_failure(error)


def loop():
    # Exactly one scheduler process. Pools isolate slow APT and AI from 30-second SSH collection.
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as polls, concurrent.futures.ThreadPoolExecutor(max_workers=2) as jobs, concurrent.futures.ThreadPoolExecutor(max_workers=1) as ai:
        leader=Lock('scheduler');is_leader=False
        active_polls={}; active_jobs={}; ai_task=None; last_poll=0; last_cleanup=0; notification_task=None; last_schedule=0; last_ai=0
        while not stop.wait(1):
            try:
                now=time.time()
                if is_leader:
                    try:valid=leader.owned()
                    except Exception:valid=False
                    if not valid:
                        try:leader.release()
                        except Exception:pass
                        is_leader=False
                if not is_leader:is_leader=leader.acquire(False)
                if is_leader:ai_runs.heartbeat()
                if ai_task is not None and ai_task.done():
                    try:ai_task.result()
                    except Exception as error:ai_runs.task_failure(error)
                    ai_task=None
                for key,(future,_) in list(active_jobs.items()):
                    if future.done():
                        try: future.result()
                        except Exception: log.exception('Job worker failed outside its operation handler')
                        del active_jobs[key]
                busy_hosts={host_id for _,host_id in active_jobs.values()}
                if is_leader and now-last_schedule>=30:
                    scheduling.tick(now); incidents.schedule_tick(now);
                    from .persistence import schedule_tick as persistence_tick
                    from .response_monitor import schedule_tick as response_tick
                    persistence_tick(now); incidents.auto_plan_tick(now);response_tick(now); last_schedule=now
                with Session() as s:
                    busy_hosts.update(s.scalars(select(Job.host_id).where(Job.state.in_(operations.QUARANTINE_STATES))))
                    if is_leader and now-last_poll>=30:
                        for h in s.scalars(select(Host)):
                            if h.id not in active_polls or active_polls[h.id].done(): active_polls[h.id]=polls.submit(poll_host,h.id)
                            if h.state!='enrolling' and bool(h.inventory) and now-h.last_repo>config(s)['repo_minutes']*60:
                                existing=s.scalar(select(Job).where(Job.host_id==h.id,Job.action=='refresh',Job.state.in_(['queued','running'])))
                                # Failure backoff is independent of last successful refresh.
                                latest=s.scalar(select(Job).where(Job.host_id==h.id,Job.action=='refresh').order_by(Job.created.desc()))
                                if not existing and (not latest or now-latest.created>300): enqueue(s,h.id,'refresh')
                        last_poll=now
                        operations.collect_alerts()
                    # Resume observation, never the package transaction, after worker loss.
                    resume_busy={host_id for _,host_id in active_jobs.values()}
                    for j in s.scalars(select(Job).where(Job.state=='running',Job.action=='release-upgrade')):
                        if len(active_jobs)>=2:break
                        if submit_job(jobs,j,active_jobs,resume_busy):busy_hosts.add(j.host_id)
                    for j in s.scalars(select(Job).where(Job.state=='queued',Job.host_id.not_in(busy_hosts)).order_by(Job.created)):
                        if len(active_jobs)>=2: break
                        from . import quarantine,process_response
                        response_id=j.payload.get('quarantine_id') if j.action in quarantine.RECOVERY_ACTIONS else None
                        process_id=j.payload.get('process_id') if j.action in process_response.RECOVERY_ACTIONS else None
                        read_only_response_id=j.payload.get('quarantine_id') if j.action=='trusted-repair-prepare' else None
                        if operations.host_quarantined(s,j.host_id,exclude=j.id,response_id=response_id,process_id=process_id,read_only_response_id=read_only_response_id,local_observation=j.action=='evidence-archive-status'):continue
                        if j.id not in active_jobs and j.host_id not in busy_hosts and operations.eligible(s,j):
                            submit_job(jobs,j,active_jobs,busy_hosts)
                if is_leader and now-last_cleanup>3600:
                    with Session() as s:
                        cutoff=now-config(s)['history_days']*86400
                        s.execute(delete(Observation).where(Observation.received<cutoff))
                        s.execute(delete(InventoryRevision).where(InventoryRevision.created<cutoff))
                        expired=select(ai_runs.AIRun.id).where(ai_runs.AIRun.started<cutoff,ai_runs.AIRun.state!='running')
                        s.execute(delete(ai_runs.AIEvent).where(ai_runs.AIEvent.run_id.in_(expired)))
                        s.execute(delete(ai_runs.AICall).where(ai_runs.AICall.run_id.in_(expired)))
                        s.execute(delete(ai_runs.AIRunHost).where(ai_runs.AIRunHost.run_id.in_(expired)))
                        s.execute(delete(ai_runs.AIRun).where(ai_runs.AIRun.started<cutoff,ai_runs.AIRun.state!='running'))
                        for entry in s.scalars(select(Setting).where(Setting.key.like('session:%') | Setting.key.like('enroll:%') | Setting.key.like('oidc-state:%'))):
                            if entry.value.get('expires',now+1)<now: s.delete(entry)
                        s.commit()
                    last_cleanup=now
                if is_leader and (notification_task is None or notification_task.done()): notification_task=polls.submit(operations.deliver_one)
                if is_leader and ai_task is None and now-last_ai>=5: ai_task=ai.submit(ai_cycle);last_ai=now
            except Exception: log.exception('Scheduler tick failed')
        if is_leader:leader.release()
def start():
    stop.clear()
    t=threading.Thread(target=loop,daemon=True); t.start(); return t

if __name__=='__main__':
    from . import identity,operations
    from .db import init
    import signal
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(name)s %(message)s')
    from .database_config import runtime_guard
    with runtime_guard():
        init()
        signal.signal(signal.SIGTERM,lambda *args:stop.set())
        signal.signal(signal.SIGINT,lambda *args:stop.set())
        loop()
