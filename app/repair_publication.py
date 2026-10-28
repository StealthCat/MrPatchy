"""Explicit publication of one authenticated staged inode; no automatic recovery."""
import time
import uuid
from sqlalchemy import String,Double,Boolean,JSON,Text,select,func
from sqlalchemy.orm import Mapped,mapped_column
from .db import Base,Job,audit
from . import incidents,quarantine,repair_staging,repair_preparation,vendor,ssh,operations

ACTIONS=('trusted-repair-publish','trusted-repair-publish-status')
FACTS=('intent_verified','held_verified','parents_match','published_verified','private_present','package_matches','owner_matches','rechecked','completion_recorded')
GAPS=('private_payload_present','retained_original','parent_changed','destination_missing','destination_changed','package_identity','package_owner','changed_during_read','verification_unavailable')


class Publication(Base):
    __tablename__='security_repair_publications'
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    quarantine_id:Mapped[str]=mapped_column(String(36),index=True)
    stage_id:Mapped[str]=mapped_column(String(36),index=True)
    created:Mapped[float]=mapped_column(Double,default=time.time)
    expires:Mapped[float]=mapped_column(Double)
    actor:Mapped[str]=mapped_column(String(120))
    reason:Mapped[str]=mapped_column(Text)
    fingerprint:Mapped[str]=mapped_column(String(100))
    stage_report_digest:Mapped[str]=mapped_column(String(64))
    plan:Mapped[dict]=mapped_column(JSON)
    state:Mapped[str]=mapped_column(String(30),default='queued')
    hold:Mapped[bool]=mapped_column(Boolean,default=True)
    before_state:Mapped[str]=mapped_column(String(30))
    before_hold:Mapped[bool]=mapped_column(Boolean)
    observed:Mapped[float]=mapped_column(Double,default=0)
    receipt:Mapped[dict]=mapped_column(JSON,default=dict)
    report:Mapped[dict]=mapped_column(JSON,default=dict)


class Event(Base):
    __tablename__='security_repair_publication_events'
    id:Mapped[str]=mapped_column(String(36),primary_key=True,default=lambda:str(uuid.uuid4()))
    publication_id:Mapped[str]=mapped_column(String(36),index=True)
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    created:Mapped[float]=mapped_column(Double,default=time.time)
    actor:Mapped[str]=mapped_column(String(120))
    kind:Mapped[str]=mapped_column(String(40))
    details:Mapped[dict]=mapped_column(JSON,default=dict)


def event(s,row,kind,actor,details=None):
    s.add(Event(publication_id=row.id,host_id=row.host_id,kind=kind,actor=actor,details=details or {}))
    audit(s,'replacement publication '+kind,row.host_id+' '+row.id+' '+actor)


def reject_unstarted(s,job,actor=None,kind='rejected'):
    row=s.get(Publication,job.payload.get('publication_id'))
    if row and row.host_id==job.host_id and row.state=='queued':
        row.state='rejected';row.hold=False;row.receipt={};row.observed=time.time()
        row.report={'scope_current':False,'trust_current':False,'not_requested':True,'reason':kind}
        event(s,row,kind,actor or job.payload.get('_actor','system'),{'job_id':job.id})


def active(s,quarantine_id):
    return s.scalar(select(Publication).where(Publication.quarantine_id==quarantine_id,Publication.state.not_in(('rejected','console_recovered'))).order_by(Publication.created.desc(),Publication.id).limit(1))


def latest(s,records):
    if not records:return {}
    host_id=records[0].host_id;ids=[r.id for r in records]
    rank=select(Publication.id,func.row_number().over(partition_by=Publication.quarantine_id,order_by=(Publication.created.desc(),Publication.id)).label('rank')).where(Publication.host_id==host_id,Publication.quarantine_id.in_(ids),Publication.state.not_in(('rejected','console_recovered'))).subquery()
    return {r.quarantine_id:r for r in s.scalars(select(Publication).where(Publication.id.in_(select(rank.c.id).where(rank.c.rank==1))))}


def bound(s,host,row):
    original=s.get(quarantine.Quarantine,row.quarantine_id);staged=s.get(repair_staging.Stage,row.stage_id)
    return bool(original and staged and original.host_id==staged.host_id==row.host_id==host.id and row.fingerprint==original.fingerprint==staged.fingerprint==host.fingerprint
        and staged.quarantine_id==original.id and row.plan['stage_id']==staged.id and row.plan['stage_plan']==staged.plan
        and staged.plan['quarantine_plan']==original.plan and staged.plan['quarantine_id']==original.id)


def approve(s,host,stage_id,expected_digest,actor,reason):
    staged=s.get(repair_staging.Stage,stage_id)
    if not staged or staged.host_id!=host.id:raise ValueError('Same-host staged replacement required')
    original=s.get(quarantine.Quarantine,staged.quarantine_id)
    if not original or original.state!='quarantined' or staged.state!='staged' or staged.fingerprint!=host.fingerprint or original.fingerprint!=host.fingerprint or staged.plan['quarantine_plan']!=original.plan or not 0<=time.time()-staged.observed<=300 or incidents.digest(staged.report)!=expected_digest or not staged.report.get('scope_current') or not staged.report.get('trust_current'):raise ValueError('Fresh verified staging and unchanged original quarantine are required')
    repair_staging.validate(staged.report['target'],staged)
    if staged.report['target']['state']!='staged' or active(s,original.id):raise ValueError('A publication already exists or staging is incomplete')
    row=Publication(id=str(uuid.uuid4()),host_id=host.id,quarantine_id=original.id,stage_id=staged.id,expires=time.time()+300,
        actor=actor,reason=reason,fingerprint=host.fingerprint,stage_report_digest=expected_digest,
        plan={'stage_id':staged.id,'stage_plan':staged.plan,'payload':staged.report['target']['payload']},before_state=original.state,before_hold=original.hold,state='queued',hold=True)
    s.add(row);event(s,row,'approved',actor,{'plan_digest':incidents.digest(row.plan),'expires':row.expires,'reason':reason})
    return row


def validate(receipt,row):
    if not isinstance(receipt,dict) or set(receipt)!={'version','id','stage_id','quarantine_id','response_plan_digest','plan_digest','state','payload','facts','gaps','readiness'} or type(receipt['version']) is not int or receipt['version']!=1 or receipt['id']!=row.id or receipt['stage_id']!=row.stage_id or receipt['quarantine_id']!=row.quarantine_id or receipt['plan_digest']!=incidents.digest(row.plan) or receipt['response_plan_digest']!=incidents.digest(row.plan['stage_plan']['quarantine_plan']) or receipt['state'] not in ('published','uncertain','not_started','blocked'):raise ValueError('Unbound publication receipt')
    facts=receipt['facts'];gaps=receipt['gaps']
    if not isinstance(facts,dict) or set(facts)!=set(FACTS) or any(type(value) is not bool for value in facts.values()) or not isinstance(gaps,list) or len(gaps)>len(GAPS) or any(not isinstance(code,str) or code not in GAPS for code in gaps) or len(set(gaps))!=len(gaps):raise ValueError('Invalid publication facts or gaps')
    expected={**row.plan['payload'],'identity':{**row.plan['payload']['identity'],'mode':0o100000|row.plan['stage_plan']['replacement_mode']}}
    payload=receipt['payload']
    if facts['published_verified']:
        if not isinstance(payload,dict) or payload!=expected or type(payload['size']) is not int or not isinstance(payload['identity'],dict) or any(type(v) is not int for v in payload['identity'].values()):raise ValueError('Unverified publication inode or bytes')
    elif payload is not None:raise ValueError('Unexpected publication payload proof')
    positive=all(facts[k] for k in ('intent_verified','held_verified','parents_match','published_verified','package_matches','owner_matches','rechecked')) and not facts['private_present'] and not gaps
    if (receipt['state']=='published')!=positive:raise ValueError('Contradictory publication completion')
    if receipt['state']=='not_started' and (facts['intent_verified'] or not facts['private_present'] or facts['published_verified'] or facts['completion_recorded'] or gaps):raise ValueError('Unbound unstarted publication')
    if facts['completion_recorded'] and not facts['intent_verified']:raise ValueError('Missing publication intent')
    if receipt['readiness'] is not None:
        from . import repair_preparation
        class Original:pass
        original=Original();original.id=row.quarantine_id;original.plan=row.plan['stage_plan']['quarantine_plan']
        repair_preparation.validate(receipt['readiness'],original,row.plan['stage_plan']['manifest'])
    if receipt['state']=='blocked' and (facts['intent_verified'] or not receipt['readiness'] or receipt['readiness']['state']!='blocked'):raise ValueError('Unbound blocked publication')


def trust(s,row):
    staged=s.get(repair_staging.Stage,row.stage_id)
    prepared=s.get(repair_preparation.Preparation,staged.preparation_id)
    manifest,proof=vendor.replacement(prepared.bundle_id,prepared.path)
    if manifest!=row.plan['stage_plan']['manifest'] or vendor.authentication_digest(manifest,proof)!=row.plan['stage_plan']['authentication_digest']:raise ValueError('Approved publisher trust or replacement changed')


def source(s,host,row,job,mutation=False):
    if not bound(s,host,row) or job.payload.get('quarantine_id')!=row.quarantine_id:raise ValueError('Publication identity or pinned host changed')
    if mutation:
        staged=s.get(repair_staging.Stage,row.stage_id);original=s.get(quarantine.Quarantine,row.quarantine_id)
        if row.state not in ('queued','uncertain') or time.time()>=row.expires or incidents.digest(staged.report)!=row.stage_report_digest or original.state not in ('quarantined','replacement_uncertain'):raise ValueError('Publication approval expired or source changed')
    if operations.host_quarantined(s,host.id,exclude=job.id,response_id=row.quarantine_id,publication_id=row.id,publication_response_id=row.quarantine_id):raise ValueError('Unrelated operation or response requires reconciliation')


def apply(s,host,row,receipt,report,pause=True):
    """Update current proof, retaining approval/observation history and all holds."""
    original=s.get(quarantine.Quarantine,row.quarantine_id)
    current=bound(s,host,row) and original.state in ('quarantined','replacement_uncertain','replaced');positive=bool(receipt and receipt['state']=='published')
    row.state=receipt['state'] if receipt else 'uncertain';row.receipt=receipt or {};row.report={**report,'scope_current':current};row.observed=time.time()
    if not positive and pause:row.hold=True
    if current:
        original=s.get(quarantine.Quarantine,row.quarantine_id);staged=s.get(repair_staging.Stage,row.stage_id)
        original.state='replaced' if positive else 'replacement_uncertain';original.receipt=receipt if positive else {};original.observed=row.observed
        staged.state='published' if positive else 'publication_uncertain'
        if not positive and pause:original.hold=True


def execute(s,host,job):
    row=s.get(Publication,job.payload['publication_id'])
    if not row or row.host_id!=host.id:raise ValueError('Publication not found')
    mutation=job.action==ACTIONS[0];actor=job.payload.get('_actor','system')
    if mutation and row.state!='queued':return {'publication_id':row.id,'state':row.state,'outcome':'response_incomplete','replayed':False}
    phase='scope';sent=False;started=False;receipt=None;report={'scope_current':False,'trust_current':False}
    try:
        source(s,host,row,job,mutation)
        if mutation:phase='authentication';trust(s,row)
        phase='helper';quarantine.healthy(s,host)
        s.rollback();s.expire_all();row=s.get(Publication,job.payload['publication_id']);phase='scope';source(s,host,row,job,mutation)
        if mutation:
            phase='authentication_recheck';trust(s,row)
            s.rollback();s.expire_all();row=s.get(Publication,job.payload['publication_id']);phase='scope';source(s,host,row,job,True)
            row.state='uncertain';row.hold=True;original=s.get(quarantine.Quarantine,row.quarantine_id)
            original.state='replacement_uncertain';original.hold=True;original.receipt={};s.get(repair_staging.Stage,row.stage_id).state='publication_uncertain'
            event(s,row,'started',actor,{'job_id':job.id});s.commit();started=True
        s.rollback();s.expire_all();row=s.get(Publication,job.payload['publication_id']);source(s,host,row,job,mutation)
        request={'action':'repair-publish' if mutation else 'repair-publish-status','id':row.id,'plan':row.plan}
        if mutation:request['approval']={'id':row.id,'action':'publish','expires':row.expires,'actor':row.actor,'reason':row.reason,'plan_digest':incidents.digest(row.plan)}
        phase='remote';sent=True;result=ssh.call(host,request,timeout=300)
        phase='protocol';validate(result,row);receipt=result
        phase='authentication_recheck'
        try:trust(s,row);report['trust_current']=True
        except Exception:
            if mutation:raise
        s.rollback();s.expire_all();row=s.get(Publication,job.payload['publication_id']);phase='scope';source(s,host,row,job,mutation)
        apply(s,host,row,receipt,report)
    except Exception as error:
        s.rollback();s.expire_all();row=s.get(Publication,job.payload['publication_id'])
        if not row or row.host_id!=host.id:raise ValueError('Publication removed during operation')
        report['failure']={'stage':phase,'type':type(error).__name__};report['scope_current']=False
        if row.state=='console_recovered':
            event(s,row,'superseded_observation',actor,{'job_id':job.id,'receipt':receipt,**report})
            return {'publication_id':row.id,'state':row.state,'outcome':'response_incomplete'}
        if mutation and not sent:
            row.state='rejected';row.hold=False;row.receipt={};row.report=report;row.observed=time.time()
            if started and bound(s,host,row):
                original=s.get(quarantine.Quarantine,row.quarantine_id);original.state=row.before_state;original.hold=row.before_hold
                s.get(repair_staging.Stage,row.stage_id).state='staged'
        else:
            # Historical receipts remain in events, never current positive proof.
            apply(s,host,row,None,report)
    event(s,row,'observed_'+row.state,actor,{'job_id':job.id,'receipt':receipt,'report':row.report})
    quarantine.event(s,s.get(quarantine.Quarantine,row.quarantine_id),'publication_observed',actor,{'publication_id':row.id,'state':row.state})
    return {'publication_id':row.id,'state':row.state,'publication_hold':row.hold,'outcome':'observed' if row.state=='published' else 'response_incomplete'}


def positive(original,row):
    if not row or row.state!='published' or original.state!='replaced' or row.fingerprint!=original.fingerprint or row.quarantine_id!=original.id or row.plan['stage_plan']['quarantine_plan']!=original.plan or original.receipt!=row.receipt:return False
    try:validate(row.receipt,row)
    except (ValueError,KeyError,TypeError):return False
    return row.receipt['state']=='published'
