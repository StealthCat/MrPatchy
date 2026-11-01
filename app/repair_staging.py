"""Separately approved private payload staging. Never publishes a live file."""
import base64
import time
import uuid
from sqlalchemy import String,Double,JSON,Text,select
from sqlalchemy.orm import Mapped,mapped_column
from .db import Base,audit
from . import incidents,quarantine,repair_preparation,vendor,ssh,operations

ACTIONS=('trusted-repair-stage','trusted-repair-stage-status')
CHUNK_SIZE=1024*1024


class Stage(Base):
    __tablename__='security_repair_stages'
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    quarantine_id:Mapped[str]=mapped_column(String(36),index=True)
    preparation_id:Mapped[str]=mapped_column(String(36),unique=True)
    preparation_digest:Mapped[str]=mapped_column(String(64))
    created:Mapped[float]=mapped_column(Double,default=time.time)
    expires:Mapped[float]=mapped_column(Double)
    actor:Mapped[str]=mapped_column(String(120))
    reason:Mapped[str]=mapped_column(Text)
    fingerprint:Mapped[str]=mapped_column(String(100))
    plan:Mapped[dict]=mapped_column(JSON)
    state:Mapped[str]=mapped_column(String(30),default='queued')
    observed:Mapped[float]=mapped_column(Double,default=0)
    report:Mapped[dict]=mapped_column(JSON,default=dict)


class Event(Base):
    __tablename__='security_repair_stage_events'
    id:Mapped[str]=mapped_column(String(36),primary_key=True,default=lambda:str(uuid.uuid4()))
    stage_id:Mapped[str]=mapped_column(String(36),index=True)
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    created:Mapped[float]=mapped_column(Double,default=time.time)
    actor:Mapped[str]=mapped_column(String(120))
    kind:Mapped[str]=mapped_column(String(40))
    report:Mapped[dict]=mapped_column(JSON,default=dict)


def event(s,row,kind,actor,report=None):
    s.add(Event(stage_id=row.id,host_id=row.host_id,actor=actor,kind=kind,report=report or {}))
    audit(s,'trusted replacement '+kind,row.host_id+' '+row.id+' '+actor)


def preparation(s,host,identifier,expected_digest):
    row=s.get(repair_preparation.Preparation,identifier)
    if not row or row.host_id!=host.id:raise ValueError('Replacement preparation not found')
    original=repair_preparation.source(s,host,row)
    if row.state!='ready' or not row.report.get('scope_current') or incidents.digest(row.report)!=expected_digest or not 0<=time.time()-row.finished<=900 or original.state!='quarantined':raise ValueError('A fresh bound ready preparation is required')
    repair_preparation.validate(row.report['target'],original,row.report['manifest'])
    if vendor.authentication_digest(row.report['manifest'],row.report['authentication'])!=row.report['authentication_digest']:raise ValueError('Preparation authentication changed')
    return row,original


def approve(s,host,identifier,expected_digest,actor,reason):
    prepared,original=preparation(s,host,identifier,expected_digest)
    if s.scalar(select(Stage.id).where(Stage.preparation_id==prepared.id).limit(1)):raise ValueError('This preparation already has a staging approval; review its history')
    plan={'quarantine_id':original.id,'quarantine_plan':original.plan,'manifest':prepared.report['manifest'],
          'authentication_digest':prepared.report['authentication_digest'],'replacement_mode':prepared.report['target']['replacement_mode']}
    row=Stage(id=str(uuid.uuid4()),host_id=host.id,quarantine_id=original.id,preparation_id=prepared.id,preparation_digest=expected_digest,
              expires=time.time()+300,actor=actor,reason=reason,fingerprint=host.fingerprint,plan=plan,state='queued')
    s.add(row);event(s,row,'approved',actor,{'plan_digest':incidents.digest(plan),'expires':row.expires,'reason':reason})
    return row


def source(s,host,row,job,mutation=False):
    original=s.get(quarantine.Quarantine,row.quarantine_id)
    prepared=s.get(repair_preparation.Preparation,row.preparation_id)
    if not original or original.host_id!=host.id or row.fingerprint!=host.fingerprint or original.fingerprint!=host.fingerprint or row.plan['quarantine_id']!=original.id or row.plan['quarantine_plan']!=original.plan or job.payload.get('quarantine_id')!=original.id or not prepared or prepared.host_id!=host.id or incidents.digest(prepared.report)!=row.preparation_digest:raise ValueError('Staging scope or pinned host changed')
    if mutation:
        preparation(s,host,row.preparation_id,row.preparation_digest)
        if time.time()>=row.expires:raise ValueError('Staging approval expired')
        if operations.host_quarantined(s,host.id,exclude=job.id,response_id=original.id,staging_response_id=original.id):raise ValueError('Unrelated response or recovery requires reconciliation')
    return original


def validate(result,row):
    if not isinstance(result,dict) or set(result)!={'version','id','plan_digest','state','received','payload','facts','readiness'} or type(result['version']) is not int or result['version']!=1 or result['id']!=row.id or result['plan_digest']!=incidents.digest(row.plan) or result['state'] not in ('receiving','staged','incomplete','not_found','blocked','capacity_reached'):raise ValueError('Unbound staging receipt')
    entry=row.plan['manifest']['entries'][0];facts=result['facts']
    if type(result['received']) is not int or not 0<=result['received']<=entry['size'] or not isinstance(facts,dict) or set(facts)!={'intent_verified','payload_verified','completion_recorded'} or any(type(value) is not bool for value in facts.values()):raise ValueError('Invalid staging facts')
    payload=result['payload']
    if result['state']=='staged':
        if result['received']!=entry['size'] or not facts['intent_verified'] or not facts['payload_verified'] or not isinstance(payload,dict) or set(payload)!={'sha256','size','identity'} or payload['sha256']!=entry['sha256'] or type(payload['size']) is not int or payload['size']!=entry['size']:raise ValueError('Unverified staged payload')
        identity=payload['identity']
        if not isinstance(identity,dict) or set(identity)!={'dev','ino','size','uid','gid','mode','mtime_ns','nlink'} or any(type(v) is not int or v<0 for v in identity.values()) or identity['uid']!=0 or identity['gid']!=0 or identity['mode']!=0o100600 or identity['nlink']!=1 or identity['size']!=entry['size'] or identity['dev']!=row.plan['quarantine_plan']['vault_device']:raise ValueError('Unsupported staged payload identity')
    elif payload is not None or facts['payload_verified'] or facts['completion_recorded']:raise ValueError('Contradictory staging receipt')
    if result['state'] in ('receiving','staged') and not facts['intent_verified']:raise ValueError('Missing staging intent')
    if result['state']=='not_found' and (result['received'] or any(facts.values())):raise ValueError('Contradictory missing stage')
    if result['state']=='capacity_reached' and (result['received'] or any(facts.values()) or result['readiness'] is None):raise ValueError('Contradictory staging capacity refusal')
    if result['readiness'] is not None:
        class Original:pass
        original=Original();original.id=row.quarantine_id;original.plan=row.plan['quarantine_plan']
        repair_preparation.validate(result['readiness'],original,row.plan['manifest'])
    if result['state']=='blocked' and (not result['readiness'] or result['readiness']['state']!='blocked'):raise ValueError('Missing blocked readiness observation')


def execute(s,host,job):
    row=s.get(Stage,job.payload['stage_id'])
    if not row or row.host_id!=host.id:raise ValueError('Replacement staging not found')
    mutation=job.action==ACTIONS[0]
    if mutation and row.state!='queued':return {'stage_id':row.id,'state':row.state,'outcome':'response_incomplete','replayed':False}
    actor=job.payload.get('_actor','system');phase='scope';sent=False;receipt=None
    report={'version':1,'publication':'not_authorized','scope_current':False,'trust_current':False}
    try:
        source(s,host,row,job,mutation)
        if mutation:
            phase='authentication';prepared=s.get(repair_preparation.Preparation,row.preparation_id)
            manifest,proof,data=vendor.replacement_payload(prepared.bundle_id,prepared.path)
            if manifest!=row.plan['manifest'] or vendor.authentication_digest(manifest,proof)!=row.plan['authentication_digest']:raise ValueError('Approved replacement or trust changed')
            entry=manifest['entries'][0]
            if not isinstance(data,bytes) or len(data)!=entry['size'] or vendor.sha(data)!=entry['sha256']:raise ValueError('Replacement bytes changed before staging')
        phase='helper';quarantine.healthy(s,host)
        s.rollback();s.expire_all();row=s.get(Stage,job.payload['stage_id']);source(s,host,row,job,mutation)
        if mutation:
            phase='authentication_recheck';prepared=s.get(repair_preparation.Preparation,row.preparation_id)
            current,proof=vendor.replacement(prepared.bundle_id,prepared.path)
            if current!=row.plan['manifest'] or vendor.authentication_digest(current,proof)!=row.plan['authentication_digest']:raise ValueError('Approved trust changed during preflight')
            # Commit uncertainty before any target writes; restarting never replays.
            row.state='uncertain';row.report=report;event(s,row,'started',actor,{'job_id':job.id});s.commit()
        def call(action,**extra):
            nonlocal row,sent,phase
            phase='scope';s.rollback();s.expire_all();row=s.get(Stage,job.payload['stage_id']);source(s,host,row,job,mutation)
            phase='remote';sent=True
            result=ssh.call(host,{'action':action,'id':row.id,'plan':row.plan,**extra},timeout=180)
            phase='protocol';validate(result,row)
            return result
        if mutation:
            approval={'id':row.id,'action':'stage','expires':row.expires,'actor':row.actor,'reason':row.reason,'plan_digest':incidents.digest(row.plan)}
            receipt=call('repair-stage-begin',approval=approval)
            if receipt['state']=='receiving' and receipt['received']==0:
                for offset in range(0,len(data),CHUNK_SIZE):
                    receipt=call('repair-stage-chunk',offset=offset,data=base64.b64encode(data[offset:offset+CHUNK_SIZE]).decode('ascii'))
                    if receipt['state']!='receiving' or receipt['received']!=min(offset+CHUNK_SIZE,len(data)):raise ValueError('Incomplete staging chunk; no automatic retry')
                phase='authentication_recheck';prepared=s.get(repair_preparation.Preparation,row.preparation_id)
                current,proof=vendor.replacement(prepared.bundle_id,prepared.path)
                if current!=row.plan['manifest'] or vendor.authentication_digest(current,proof)!=row.plan['authentication_digest']:raise ValueError('Trust changed during transfer')
                receipt=call('repair-stage-finish')
            elif receipt['state'] not in ('blocked','capacity_reached'):raise ValueError('Existing or interrupted staging operation cannot be replayed')
        else:receipt=call('repair-stage-status')
        s.rollback();s.expire_all();row=s.get(Stage,job.payload['stage_id']);phase='scope';source(s,host,row,job,mutation)
        report['scope_current']=True
        # Status can verify historical retained bytes when the offline bundle has
        # since been removed/revoked. It never becomes publication permission.
        phase='authentication_recheck'
        try:
            prepared=s.get(repair_preparation.Preparation,row.preparation_id)
            current,proof=vendor.replacement(prepared.bundle_id,prepared.path)
            report['trust_current']=current==row.plan['manifest'] and vendor.authentication_digest(current,proof)==row.plan['authentication_digest']
        except Exception:
            if mutation:raise
        if mutation and not report['trust_current']:raise ValueError('Trust changed after staging')
        # End the post-I/O MySQL snapshot before accepting current scope.
        s.rollback();s.expire_all();row=s.get(Stage,job.payload['stage_id']);phase='scope';source(s,host,row,job,mutation)
        state='incomplete' if receipt['state']=='receiving' else receipt['state']
    except Exception as error:
        s.rollback();s.expire_all();row=s.get(Stage,job.payload['stage_id'])
        if not row or row.host_id!=host.id:raise ValueError('Staging record removed during operation')
        state='uncertain' if sent or not mutation else 'rejected'
        report['scope_current']=False
        report['failure']={'stage':phase,'type':type(error).__name__}
    if receipt is not None:report['target']=receipt
    row.state=state;row.observed=time.time();row.report=report
    event(s,row,'observed_'+state,actor,{'job_id':job.id,**report})
    return {'stage_id':row.id,'state':state,'publication':'not_authorized','outcome':'response_incomplete' if state in ('uncertain','incomplete','rejected','not_found','capacity_reached') else 'observed'}
