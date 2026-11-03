"""Opt-in, read-only verification of retained quarantine material."""
from . import host_lifecycle
import time
from sqlalchemy import String,Double,JSON,Index,select,func
from sqlalchemy.orm import Mapped,mapped_column
from .db import Base,Session,Setting,Host,Job
from . import quarantine,incidents,ssh

DEFAULT={'enabled':False,'interval_minutes':15,'pause_on_problem':False,'revision':''}
STATES=('quarantined','uncertain','not_found','console_recovered','not_moved','replaced','replacement_uncertain')
PROBLEMS=('path_occupied','held_unverified','parent_changed','missing','uncertain','not_quarantined','unavailable')
GOOD=('verified','restored','replacement_verified')
LIMIT=500

class Check(Base):
    __tablename__='security_response_checks'
    __table_args__=(Index('ix_response_checks_q_created','quarantine_id','created'),)
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    quarantine_id:Mapped[str]=mapped_column(String(36),index=True)
    created:Mapped[float]=mapped_column(Double,default=time.time)
    state:Mapped[str]=mapped_column(String(30))
    report:Mapped[dict]=mapped_column(JSON)


def policy(s,host_id):
    setting=s.get(Setting,'response-monitor:'+host_id)
    return {**DEFAULT,**(setting.value if setting else {})}


def watch(s,row):
    setting=s.get(Setting,'response-watch:'+row.id)
    return {'enabled':True,'revision':'',**(setting.value if setting else {})}


def eligible(row):return row.state in STATES


def recent(s,row):
    return s.scalar(select(Check).where(Check.host_id==row.host_id,Check.quarantine_id==row.id,Check.state!='skipped').order_by(Check.created.desc(),Check.id).limit(1))


def context(s,records):
    """Bounded bulk reads; history size does not grow the returned result set."""
    if not records:return {},{},{}
    ids=[r.id for r in records];host_id=records[0].host_id
    settings={r.key:r.value for r in s.scalars(select(Setting).where(Setting.key.in_(['response-watch:'+i for i in ids])))}
    watches={i:{'enabled':True,'revision':'',**settings.get('response-watch:'+i,{})} for i in ids}
    last=select(Check.quarantine_id,func.max(Check.created).label('stamp')).where(Check.host_id==host_id,Check.quarantine_id.in_(ids),Check.state!='skipped').group_by(Check.quarantine_id).subquery()
    selected=select(func.max(Check.id)).join(last,(Check.quarantine_id==last.c.quarantine_id)&(Check.created==last.c.stamp)).where(Check.host_id==host_id,Check.state!='skipped').group_by(Check.quarantine_id)
    latest={}
    for check in s.scalars(select(Check).where(Check.id.in_(selected))):
        latest.setdefault(check.quarantine_id,check)
    attempts=dict(s.execute(select(Check.quarantine_id,func.max(Check.created)).where(Check.host_id==host_id,Check.quarantine_id.in_(ids)).group_by(Check.quarantine_id)).all())
    return watches,latest,attempts


def rows(s,host_id):
    retired=select(Setting.key).where(Setting.key.like('response-watch:%'),Setting.value['enabled'].as_boolean()==False)
    return list(s.scalars(select(quarantine.Quarantine).where(quarantine.Quarantine.host_id==host_id,quarantine.Quarantine.state.in_(STATES),('response-watch:'+quarantine.Quarantine.id).not_in(retired)).order_by(quarantine.Quarantine.created,quarantine.Quarantine.id).limit(LIMIT+1)))


def assessment(s,host_id,now=None):
    from . import repair_publication
    now=time.time() if now is None else now;cfg=policy(s,host_id);records=rows(s,host_id)
    truncated=len(records)>LIMIT;records=records[:LIMIT]
    watches,latest,_=context(s,records);watched=[r for r in records if watches[r.id]['enabled']]
    rotation=cfg['interval_minutes']*len(watched);budget=(rotation+cfg['interval_minutes'])*60
    problems=[];overdue=[];host=s.get(Host,host_id)
    publications=repair_publication.latest(s,records)
    for row in watched:
        publication=publications.get(row.id) if row.state in ('replaced','replacement_uncertain') else None
        check=latest.get(row.id)
        # A newer manual positive verification can supersede a failed check.
        identity=bool(host and row.fingerprint==host.fingerprint)
        bound=bool(check and check.report.get('plan_digest')==incidents.digest(row.plan) and check.report.get('fingerprint')==row.fingerprint)
        if publication:bound=bound and check.report.get('publication_id')==publication.id and check.report.get('publication_plan_digest')==incidents.digest(publication.plan)
        elif check and check.report.get('publication_id'):bound=False
        positive=identity and row.state=='quarantined' and row.receipt.get('id')==row.id and row.receipt.get('plan')==row.plan and row.receipt.get('state')=='quarantined' and row.receipt.get('restore_ready') is True and row.receipt.get('restore_attempted') is False and 0<row.observed<=now
        positive=positive or bool(identity and publication and repair_publication.positive(row,publication) and 0<row.observed<=now)
        manual_problem=bool(publication and publication.state in ('uncertain','blocked','not_started') and publication.observed and (not check or publication.observed>check.created))
        superseded=positive and check and row.observed>check.created
        if not identity and (cfg['enabled'] or check):problems.append({'id':row.id,'state':'identity_changed','checked':None})
        elif manual_problem:problems.append({'id':row.id,'state':'uncertain','checked':publication.observed})
        elif check and not bound and not superseded:problems.append({'id':row.id,'state':'evidence_binding_changed','checked':check.created})
        elif check and check.state in PROBLEMS and not superseded:
            problems.append({'id':row.id,'state':check.state,'checked':check.created})
        verified=row.observed if positive else (check.created if check and bound and check.state in GOOD else 0)
        if not identity or manual_problem:verified=0
        if cfg['enabled'] and (not verified or not 0<=now-verified<=budget):overdue.append(row.id)
    pending=s.scalar(select(Job).where(Job.host_id==host_id,Job.action=='quarantine-audit',Job.state.in_(['queued','running'])).order_by(Job.created).limit(1))
    return {'policy':cfg,'watched':len(watched),'rotation_minutes':rotation,'problems':problems[:20],
            'problem_count':len(problems),'overdue_count':len(overdue),'overdue':overdue[:20],'scope_limited':truncated,
            'pending':{'id':pending.id,'state':pending.state} if pending else None}


def valid(s,host,row,payload):
    cfg=policy(s,host.id)
    if not publication_binding(s,row,payload):return False
    return bool(row and row.host_id==host.id and eligible(row) and row.fingerprint==host.fingerprint
        and host.fingerprint==payload.get('fingerprint')
        and incidents.digest(row.plan)==payload.get('plan_digest') and cfg['enabled']
        and cfg['revision']==payload.get('policy_revision') and watch(s,row)['enabled']
        and watch(s,row)['revision']==payload.get('watch_revision'))


def publication_binding(s,row,payload):
    from . import repair_publication
    if row and row.state in ('replaced','replacement_uncertain'):
        publication=repair_publication.active(s,row.id)
        return bool(publication and publication.id==payload.get('publication_id') and incidents.digest(publication.plan)==payload.get('publication_plan_digest'))
    return not payload.get('publication_id')


def validate(report,row):
    if not isinstance(report,dict) or set(report)!={'version','id','plan_digest','state','receipt','facts'} or type(report['version']) is not int or report['version']!=1 or report['id']!=row.id or report['plan_digest']!=incidents.digest(row.plan) or report['state'] not in ('verified','restored',*PROBLEMS):raise ValueError('Unsupported response monitoring report')
    facts=report['facts']
    if not isinstance(facts,dict) or set(facts)!={'journal_verified','parents_match','held_present','source_present','held_verified'}:raise ValueError('Invalid response observation facts')
    if any(type(facts[k]) is not bool for k in ('journal_verified','held_verified')) or any(facts[k] is not None and type(facts[k]) is not bool for k in ('parents_match','held_present','source_present')):raise ValueError('Invalid response observation types')
    receipt=report['receipt'];state=report['state']
    if receipt is not None:
        if not isinstance(receipt,dict) or set(receipt)!={'id','plan','state','restore_ready','restore_attempted'} or receipt['id']!=row.id or receipt['plan']!=row.plan or receipt['state'] not in ('quarantined','restored','not_moved','uncertain') or type(receipt['restore_ready']) is not bool or type(receipt['restore_attempted']) is not bool:raise ValueError('Mismatched response monitoring receipt')
    if state=='verified' and (not receipt or receipt['state']!='quarantined' or not receipt['restore_ready'] or receipt['restore_attempted'] or facts!={'journal_verified':True,'parents_match':True,'held_present':True,'source_present':False,'held_verified':True}):raise ValueError('Contradictory retained-file verification')
    if state=='restored' and (not receipt or receipt['state']!='restored' or receipt['restore_ready'] or not receipt['restore_attempted'] or not facts['journal_verified'] or facts['parents_match'] is not True or facts['held_present'] is not False or facts['source_present'] is not True):raise ValueError('Contradictory restoration verification')
    if state=='path_occupied' and (not facts['held_verified'] or facts['source_present'] is not True or not receipt or receipt['state']!='uncertain'):raise ValueError('Unbound source occupancy observation')
    if state in PROBLEMS and receipt and (receipt['state'] not in ('uncertain','not_moved') or (receipt['restore_ready'] and (receipt['state']!='uncertain' or receipt['restore_attempted']))):raise ValueError('Contradictory problem observation')


def execute(s,host,job):
    from . import repair_publication
    existing=s.get(Check,job.id)
    if existing:return {'check_id':existing.id,'state':existing.state}
    row=s.get(quarantine.Quarantine,job.payload['quarantine_id'])
    if not valid(s,host,row,job.payload):
        s.add(Check(id=job.id,host_id=host.id,quarantine_id=job.payload['quarantine_id'],state='skipped',report={'reason':'policy_watch_identity_or_state_changed'}))
        return {'check_id':job.id,'state':'skipped'}
    stage='helper'
    try:
        quarantine.healthy(s,host)
        # End MySQL snapshots after a potentially slow independent health check.
        s.rollback();s.expire_all();row=s.get(quarantine.Quarantine,job.payload['quarantine_id'])
        if not valid(s,host,row,job.payload):
            s.add(Check(id=job.id,host_id=host.id,quarantine_id=job.payload['quarantine_id'],state='skipped',report={'reason':'policy_watch_identity_or_state_changed'}))
            return {'check_id':job.id,'state':'skipped'}
        stage='remote'
        if job.payload.get('publication_id'):
            publication=s.get(repair_publication.Publication,job.payload['publication_id'])
            result=ssh.call(host,{'action':'repair-publish-status','id':publication.id,'plan':publication.plan},timeout=300)
            stage='protocol';repair_publication.validate(result,publication)
            trust_current=False
            try:repair_publication.trust(s,publication);trust_current=True
            except Exception:pass
            report={'state':'replacement_verified' if result['state']=='published' else 'uncertain','publication':result,'receipt':None,'facts':result['facts'],'trust_current':trust_current}
        else:
            report=ssh.call(host,{'action':'quarantine-audit','id':row.id,'plan':row.plan},timeout=180)
            stage='protocol';validate(report,row)
    except Exception as error:
        # No contents, exception strings or unverified target claims become proof.
        s.rollback()
        report={'state':'unavailable','receipt':None,'facts':{},'failure':{'stage':stage,'type':type(error).__name__}}
    # Observe current policy/state after the remote round trip, including MySQL
    # REPEATABLE READ. Do not overwrite a concurrently changed response scope.
    s.rollback();s.expire_all();row=s.get(quarantine.Quarantine,job.payload['quarantine_id'])
    if not row or row.host_id!=host.id:raise ValueError('Response removed during monitoring')
    cfg=policy(s,host.id);state=report['state'];receipt=report.get('receipt')
    current_watch=watch(s,row)
    applies=eligible(row) and row.fingerprint==host.fingerprint==job.payload['fingerprint'] and incidents.digest(row.plan)==job.payload['plan_digest'] and publication_binding(s,row,job.payload)
    pause=applies and cfg['enabled'] and cfg['pause_on_problem'] and cfg['revision']==job.payload['policy_revision'] and current_watch['enabled'] and current_watch['revision']==job.payload['watch_revision']
    if job.payload.get('publication_id'):
        publication=s.get(repair_publication.Publication,job.payload['publication_id'])
        receipt=report.get('publication')
        if applies:
            repair_publication.apply(s,host,publication,receipt,{'trust_current':report.get('trust_current',False),'failure':report.get('failure')},pause=pause)
            repair_publication.event(s,publication,'automatic_verification','system',{'job_id':job.id,'receipt':receipt,'pause_on_problem':pause})
    elif applies:
        row.state={'verified':'quarantined','restored':'restored','not_quarantined':'not_moved'}.get(state,'uncertain')
        row.receipt=receipt if state in GOOD else {};row.observed=time.time()
        if state=='restored':row.hold=False
        elif state in PROBLEMS and pause:row.hold=True
    summary={'version':1,'plan_digest':job.payload['plan_digest'],'fingerprint':job.payload['fingerprint'],'watch_revision':job.payload['watch_revision'],'facts':report['facts'],'pause_on_problem':pause,'applied_to_response':applies,
             'server_changes_paused':row.hold,'policy_revision':job.payload['policy_revision'],
             'receipt':{k:v for k,v in receipt.items() if k!='plan'} if receipt else None,
             'receipt_digest':incidents.digest(receipt) if receipt else None,'failure':report.get('failure')}
    if job.payload.get('publication_id'):summary.update(publication_id=job.payload['publication_id'],publication_plan_digest=job.payload['publication_plan_digest'])
    s.add(Check(id=job.id,host_id=host.id,quarantine_id=row.id,state=state,report=summary))
    quarantine.event(s,row,'automatic_verification','system',{'check_id':job.id,'state':state})
    return {'check_id':job.id,'state':state,'server_changes_paused':row.hold,'outcome':'response_incomplete' if state in PROBLEMS else 'observed'}


def schedule_tick(now=None):
    from .coordination import Lock
    from .worker import enqueue
    from .process_response import ProcessResponse
    from . import repair_publication
    now=time.time() if now is None else now
    with Lock('response-monitor-queue'),Session() as s:
        for setting in s.scalars(select(Setting).where(Setting.key.like('response-monitor:%'))):
            cfg={**DEFAULT,**setting.value};host_id=setting.key.split(':',1)[1];host=s.get(Host,host_id)
            if not cfg['enabled'] or not host_lifecycle.active(host) or host.state=='enrolling' or not host.fingerprint:continue
            if s.scalar(select(ProcessResponse.id).where(ProcessResponse.host_id==host_id,ProcessResponse.hold==True).limit(1)):continue
            if s.scalar(select(repair_publication.Publication.id).where(repair_publication.Publication.host_id==host_id,repair_publication.Publication.hold==True).limit(1)):continue
            if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.state.in_(['running','recovery_required'])).limit(1)):continue
            if s.scalar(select(Job.id).where(Job.host_id==host_id,Job.action.in_(quarantine.ACTIONS),Job.state.in_(['queued','running'])).limit(1)):continue
            last=s.scalar(select(Job).where(Job.host_id==host_id,Job.action=='quarantine-audit').order_by(Job.created.desc()).limit(1))
            if last and now-last.created<cfg['interval_minutes']*60:continue
            candidates=[];records=rows(s,host_id)[:LIMIT];watches,_,attempts=context(s,records)
            holds=set(s.scalars(select(quarantine.Quarantine.id).where(quarantine.Quarantine.host_id==host_id,quarantine.Quarantine.hold==True)))
            publications=repair_publication.latest(s,records)
            for row in records:
                watched=watches[row.id]
                if not watched['enabled'] or row.fingerprint!=host.fingerprint or holds-{row.id}:continue
                if row.state in ('replaced','replacement_uncertain') and row.id not in publications:continue
                attempt=attempts.get(row.id) or 0
                candidates.append((max(attempt,row.observed),row.id,row,watched))
            if not candidates:continue
            observed,_,row,watched=min(candidates,key=lambda x:x[:2])
            if now-observed<cfg['interval_minutes']*60:continue
            # Normal queued work takes precedence unless this response owns the hold.
            if not row.hold and s.scalar(select(Job.id).where(Job.host_id==host_id,Job.state=='queued').limit(1)):continue
            publication=publications.get(row.id) if row.state in ('replaced','replacement_uncertain') else None
            extra={'publication_id':publication.id,'publication_plan_digest':incidents.digest(publication.plan)} if publication else {}
            try:enqueue(s,host_id,'quarantine-audit',{'quarantine_id':row.id,'policy_revision':cfg['revision'],
                'watch_revision':watched['revision'],'plan_digest':incidents.digest(row.plan),'fingerprint':host.fingerprint,'_actor':'system',**extra})
            except ValueError:continue
