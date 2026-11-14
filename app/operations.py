"""Durable alert outbox, maintenance windows and operator exports."""
import datetime
import hashlib
import json
import logging
import time
import httpx
from sqlalchemy import String,Text,Double,select,func
from sqlalchemy.orm import Mapped,mapped_column
from . import ai_budget,ai_pricing,host_lifecycle,notifications,scoring_block_notifications,triage_block_notifications
from .db import Base,Session,Setting,Host,Package,Job,config
from .security import unseal

class Alert(Base):
    __tablename__='alerts'
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    host_id:Mapped[str]=mapped_column(String(36),index=True)
    kind:Mapped[str]=mapped_column(String(40))
    message:Mapped[str]=mapped_column(Text)
    state:Mapped[str]=mapped_column(String(20),default='open')
    created:Mapped[float]=mapped_column(Double,default=time.time)
    notified:Mapped[float]=mapped_column(Double,default=0)
    attempted:Mapped[float]=mapped_column(Double,default=0)
    attempts:Mapped[int]=mapped_column(default=0)
    error:Mapped[str]=mapped_column(Text,default='')

def in_window(windows,now=None):
    if not windows:return True
    date=datetime.datetime.fromtimestamp(time.time() if now is None else now,datetime.timezone.utc)
    minute=date.hour*60+date.minute
    return any(date.weekday() in w['days'] and w['start']<=minute<w['end'] for w in windows)

QUARANTINE_STATES=('running','recovery_required')

def host_quarantined(s,host_id,exclude=None,response_id=None,local_observation=False,process_id=None,read_only_response_id=None,staging_response_id=None,publication_id=None,publication_response_id=None,service_response_id=None):
    query=select(Job.id).where(Job.host_id==host_id,Job.state.in_(QUARANTINE_STATES))
    if exclude:query=query.where(Job.id!=exclude)
    if s.scalar(query.limit(1)) is not None:return True
    if local_observation:return False
    from .service_monitor import Watch as ServiceWatch
    service_holds=select(ServiceWatch.id).where(ServiceWatch.host_id==host_id,ServiceWatch.hold==True)
    if service_response_id:service_holds=service_holds.where(ServiceWatch.id!=service_response_id)
    if s.scalar(service_holds.limit(1)) is not None:return True
    from .quarantine import Quarantine
    holds=select(Quarantine.id).where(Quarantine.host_id==host_id,Quarantine.hold==True)
    if response_id:holds=holds.where(Quarantine.id!=response_id)
    if s.scalar(holds.limit(1)) is not None:return True
    from .repair_publication import Publication
    publications=select(Publication.id).where(Publication.host_id==host_id,Publication.hold==True)
    if publication_id:publications=publications.where(Publication.id!=publication_id)
    # Explicit read-only service observations can inspect their own response
    # through its publication pause; no live or process action inherits this.
    if service_response_id:publications=publications.where(Publication.quarantine_id!=service_response_id)
    if s.scalar(publications.limit(1)) is not None:return True
    from .process_response import ProcessResponse
    processes=select(ProcessResponse.id).where(ProcessResponse.host_id==host_id,ProcessResponse.hold==True)
    if process_id:processes=processes.where(ProcessResponse.id!=process_id)
    # Only repair-preparation and service-health reads use this scope: related process holds
    # remain active and no mutation/recovery job inherits this exemption.
    if read_only_response_id:processes=processes.where(ProcessResponse.quarantine_id!=read_only_response_id)
    # Approved staging writes only a private, non-executable payload. Its own
    # file/process holds stay active; no live-file or signal action inherits this.
    if staging_response_id:processes=processes.where(ProcessResponse.quarantine_id!=staging_response_id)
    # Only a separately reviewed publication or its recovery read can coexist
    # with related process pauses. Those pauses are never released or signalled.
    if publication_response_id:processes=processes.where(ProcessResponse.quarantine_id!=publication_response_id)
    return s.scalar(processes.limit(1)) is not None

def quarantined_hosts(s,host_ids):
    """Hosts among host_ids that host_quarantined(s,host_id) would report held, using one query per hold table."""
    from .service_monitor import Watch as ServiceWatch
    from .quarantine import Quarantine
    from .repair_publication import Publication
    from .process_response import ProcessResponse
    host_ids=list(host_ids); held=set()
    for start in range(0,len(host_ids),500):
        chunk=host_ids[start:start+500]
        for column,where in ((Job.host_id,Job.state.in_(QUARANTINE_STATES)),(ServiceWatch.host_id,ServiceWatch.hold==True),
                             (Quarantine.host_id,Quarantine.hold==True),(Publication.host_id,Publication.hold==True),
                             (ProcessResponse.host_id,ProcessResponse.hold==True)):
            held.update(s.scalars(select(column).where(column.in_(chunk),where).distinct()))
    return held

def _recovery_flags(row):
    return {name:bool(row and row.value.get(name)) for name in ('reboot','rollback')}

def recovery_policy(s,host_id):
    return _recovery_flags(s.get(Setting,'recovery:'+host_id))

def recovery_policies(s,host_ids):
    """Recovery policies for many hosts using one Setting query."""
    host_ids=list(host_ids)
    rows={row.key:row for row in s.scalars(select(Setting).where(Setting.key.in_(['recovery:'+h for h in host_ids])))} if host_ids else {}
    return {h:_recovery_flags(rows.get('recovery:'+h)) for h in host_ids}

def eligible(s,job,window_cache=None):
    if job.payload.get('_schedule'):
        from .scheduling import job_guard
        return job_guard(s,job)
    if job.action not in ('patch','repair','release-upgrade'): return True
    dependencies=job.payload.get('_depends_on',[])
    for dep in dependencies:
        previous=s.get(Job,dep)
        if not previous or previous.state in ('failed','blocked','interrupted','cancelled'):
            job.state='blocked';job.output='Canary/dependency did not complete successfully';s.commit();return False
        if previous.state=='recovery_required':
            job.state='blocked';job.output='Canary requires recovery reconciliation';s.commit();return False
        if previous.state!='complete':return False
    from . import freezes
    if window_cache is None:frozen=freezes.blocked(s)
    else:
        if '*freeze' not in window_cache:window_cache['*freeze']=freezes.blocked(s)
        frozen=window_cache['*freeze']
    if frozen:return False
    if window_cache is not None and job.host_id in window_cache:return window_cache[job.host_id]
    row=s.get(Setting,'window:'+job.host_id)
    result=in_window(row.value['windows'] if row else [])
    if window_cache is not None:window_cache[job.host_id]=result
    return result

AI_PRICING_CATALOG_WARNING_SECONDS=7*86400
AI_PRICING_CATALOG_SUBJECT='bundled-public-prices'

def _pricing_catalog_alert(s,cfg,record,now):
    """Publish safe controller-wide lifecycle state for capped AI pricing."""
    status=ai_pricing.catalog_status(now)
    capped=cfg['ai_enabled'] and cfg['ai_control_mode'] in ai_pricing.CAP_MODES
    warning=capped and status['state']=='fresh' and now>=status['expires_at']-AI_PRICING_CATALOG_WARNING_SECONDS
    unavailable=capped and status['state'] in ('expired','not_yet_valid')
    if warning or unavailable:
        expiry=datetime.datetime.fromtimestamp(status['expires_at'],datetime.timezone.utc).isoformat().replace('+00:00','Z')
        if warning:
            severity='medium'
            message='AI public-price catalog '+status['version']+' expires at '+expiry+'. Review and deploy a verified catalog update before capped AI admission stops.'
        else:
            severity='high'
            message='AI public-price catalog '+status['version']+' is '+status['state'].replace('_',' ')+'. Capped AI admission is blocked until a verified catalog update or controller clock correction is deployed.'
        record('controller','AI pricing catalog',message,reopen_on_change=True)
        notifications.publish(s,source='ai-budget',kind='pricing-catalog',subject_type='pricing-catalog',
            subject_id=AI_PRICING_CATALOG_SUBJECT,subject_revision=status['version']+':'+status['state']+':'+str(status['expires_at']),
            severity=severity,reason=message,deep_link='#settings/ai',minimum_role='admin',now=now)
        return
    event=s.scalar(select(notifications.NotificationEvent).where(
        notifications.NotificationEvent.source=='ai-budget',
        notifications.NotificationEvent.kind=='pricing-catalog',
        notifications.NotificationEvent.subject_type=='pricing-catalog',
        notifications.NotificationEvent.subject_id==AI_PRICING_CATALOG_SUBJECT))
    if event:
        notifications.publish(s,source='ai-budget',kind='pricing-catalog',subject_type='pricing-catalog',
            subject_id=AI_PRICING_CATALOG_SUBJECT,subject_revision=status['version']+':resolved:'+str(status['expires_at']),
            severity='info',reason='The AI public-price catalog no longer needs administrator attention.',
            deep_link='#settings/ai',minimum_role='admin',lifecycle='resolved',now=now)

REPOSITORY_REFRESH_MESSAGE=('Repository metadata refresh is failing and no refresh has succeeded within two refresh '
    'intervals. Package updates and scheduled patching on this server are blocked until a refresh succeeds. Review '
    'Repositories and the latest refresh operation in Activity.')

# Human-attention server alerts mirrored into in-app notifications:
# alert kind -> (notification kind, severity, server tab for the deep link).
# Messages for these kinds are composed from counts, states and record IDs only.
# Routine or raw-endpoint-text kinds (stale, integrity, repository, overdue,
# server disabled) stay SMTP/webhook-only so endpoint text and polling noise
# never reach the bell.
OPERATIONAL_NOTIFICATIONS={
    'recovery':('recovery-required','high','history'),
    'disabled server recovery':('disabled-server-recovery','high','security'),
    'file response hold':('file-response-hold','high','security'),
    'process response hold':('process-response-hold','high','security'),
    'publication hold':('publication-hold','high','security'),
    'service hold':('service-hold','high','security'),
    'response integrity':('response-integrity','high','security'),
    'response verification':('response-verification','medium','security'),
    # Notification-only (no outbox Alert): agent_integrity_notifications classifies controller-written
    # managed-file findings into counts, so raw endpoint text never reaches the bell.
    'agent integrity':('agent-integrity','high','agent'),
    'service health':('service-health','medium','security'),
    'service coverage':('service-coverage','medium','security'),
    'execution scan coverage':('execution-scan-coverage','medium','security'),
    'scheduled patching':('scheduled-patching','medium','patching'),
    # Notification-only: keep raw repository errors out of the in-app notification.
    'repository refresh':('repository-refresh','medium','repositories'),
    'agent health':('agent-health','medium','agent'),
    'startup baseline':('startup-baseline','medium','integrity'),
}
OPERATIONAL_NOTIFICATION_SOURCE='operations'
OPERATIONAL_NOTIFICATION_SUBJECT='server'

def _operational_notification(s,host_id,kind,message,now):
    """Publish one allowlisted server alert as a durable active notification."""
    notification_kind,severity,tab=OPERATIONAL_NOTIFICATIONS[kind]
    notifications.publish(s,source=OPERATIONAL_NOTIFICATION_SOURCE,kind=notification_kind,
        subject_type=OPERATIONAL_NOTIFICATION_SUBJECT,subject_id=host_id,host_id=host_id,
        subject_revision='message-sha256:'+hashlib.sha256(message.encode()).hexdigest(),
        severity=severity,reason=message[:2000],deep_link='#servers/'+host_id+'/'+tab,
        minimum_role='admin',now=now)

def _resolve_operational_notifications(s,published,now):
    """Resolve active operations notifications whose alert condition cleared."""
    current=s.execute(select(notifications.NotificationEvent.id,notifications.NotificationEvent.kind,
        notifications.NotificationEvent.host_id)
        .join(notifications.NotificationRevision,(notifications.NotificationRevision.event_id==notifications.NotificationEvent.id)
              &(notifications.NotificationRevision.revision==notifications.NotificationEvent.revision))
        .where(notifications.NotificationEvent.source==OPERATIONAL_NOTIFICATION_SOURCE,
               notifications.NotificationEvent.subject_type==OPERATIONAL_NOTIFICATION_SUBJECT,
               notifications.NotificationRevision.lifecycle=='active')).all()
    tabs={notification_kind:tab for notification_kind,_,tab in OPERATIONAL_NOTIFICATIONS.values()}
    for _,notification_kind,host_id in current:
        if (host_id,notification_kind) in published or notification_kind not in tabs:continue
        notifications.publish(s,source=OPERATIONAL_NOTIFICATION_SOURCE,kind=notification_kind,
            subject_type=OPERATIONAL_NOTIFICATION_SUBJECT,subject_id=host_id,host_id=host_id,
            subject_revision='resolved',severity='info',
            reason='This server condition no longer needs administrator attention.',
            deep_link='#servers/'+host_id+'/'+tabs[notification_kind],
            minimum_role='admin',lifecycle='resolved',now=now)

def collect_alerts(now=None):
    with Session() as s:
        now=time.time() if now is None else now;cfg=config(s);active=set();published=set()
        # One fleet read fills the identity map, so per-alert publish lookups issue no queries.
        _operational_events=s.scalars(select(notifications.NotificationEvent).where(
            notifications.NotificationEvent.source==OPERATIONAL_NOTIFICATION_SOURCE)).all()
        def record(host,kind,message,reopen_on_change=False):
            host_id=host if isinstance(host,str) else host.id
            key=hashlib.sha256((host_id+kind).encode()).hexdigest();active.add(key)
            alert=s.get(Alert,key)
            if not alert:s.add(Alert(id=key,host_id=host_id,kind=kind,message=message,created=now))
            else:
                changed=alert.message!=message
                alert.message=message
                if alert.state=='resolved' or (reopen_on_change and changed):
                    alert.state='open';alert.notified=0;alert.attempts=0;alert.attempted=0;alert.created=now
            if kind in OPERATIONAL_NOTIFICATIONS and not isinstance(host,str):
                published.add((host_id,OPERATIONAL_NOTIFICATIONS[kind][0]))
                # publish() validates before adding rows, so a rejected payload
                # leaves the session untouched and never blocks SMTP/webhook alerts.
                try:_operational_notification(s,host_id,kind,message,now)
                except ValueError:logging.getLogger(__name__).warning('Skipped in-app notification for %s alert on %s',kind,host_id)
        ai_budget.publish_unpriced_model_notification(s,cfg,now)
        _pricing_catalog_alert(s,cfg,record,now)
        ai_budget.publish_cap_notification(s,cfg,now)
        # In-app only: blocked triage already shows on the Investigations status card.
        triage_block_notifications.publish(s,cfg,now)
        scoring_block_notifications.publish(s,cfg,now)
        from .scheduling import PatchRun
        from . import service_monitor
        from .quarantine import Quarantine
        from .process_response import ProcessResponse
        from .repair_publication import Publication
        hosts=[host for host in s.scalars(select(Host)) if not host.deleted_at]
        ids=[host.id for host in hosts]
        # Per-table lookups run once for the fleet instead of once per host.
        def first_by_host(column,*conditions):
            found={}
            for start in range(0,len(ids),500):
                for owner,row_id in s.execute(select(column.class_.host_id,column).where(column.class_.host_id.in_(ids[start:start+500]),*conditions).order_by(column)):found.setdefault(owner,row_id)
            return found
        service_holds=first_by_host(service_monitor.Watch.id,service_monitor.Watch.hold==True)
        file_holds=first_by_host(Quarantine.id,Quarantine.hold==True)
        process_holds=first_by_host(ProcessResponse.id,ProcessResponse.hold==True)
        publication_holds=first_by_host(Publication.id,Publication.hold==True)
        failed_counts={};recoveries={};overdue_hosts=set()
        for start in range(0,len(ids),500):
            chunk=ids[start:start+500]
            failed_counts.update(s.execute(select(PatchRun.host_id,func.count()).where(PatchRun.host_id.in_(chunk),PatchRun.state.in_(('failed','blocked','skipped')),PatchRun.due>now-86400).group_by(PatchRun.host_id)).all())
            for owner,job_id in s.execute(select(Job.host_id,Job.id).where(Job.host_id.in_(chunk),Job.state=='recovery_required')):recoveries.setdefault(owner,[]).append(job_id)
            overdue_hosts.update(s.scalars(select(Package.host_id).where(Package.host_id.in_(chunk),Package.candidate!='',Package.available_since>0,
                Package.available_since<now- min(cfg['deadlines'].values())*3600).distinct()))
        settings={row.key:row for row in s.scalars(select(Setting).where(Setting.key.in_([prefix+owner for owner in ids for prefix in ('agent-status:','persistence-baseline:')])))} if ids else {}
        from . import agent_integrity_notifications
        agent_integrity_notifications.publish(hosts,now,lambda *args:_operational_notification(s,*args),published)
        for host in hosts:
            if not host_lifecycle.active(host):
                record(host,'server disabled','Server management is intentionally disabled. Polling, scheduled work and host AI requests are suspended.')
                if host_quarantined(s,host.id):record(host,'disabled server recovery','This disabled server retains response or recovery holds. Re-enable management to review them; deletion is blocked until reconciled.')
                continue
            from . import execution_scans
            execution_policy=execution_scans.policy(s,host.id)
            if execution_policy['enabled'] and execution_scans.coverage(s,host.id,execution_policy,now)['limited']:
                record(host,'execution scan coverage','Execution-triggered scan coverage is limited by dropped, expired, skipped or failed work. Review Security → Execution-triggered scans and scan history. No clean-host conclusion is available.')
            from . import response_monitor
            monitored=response_monitor.assessment(s,host.id)
            from . import service_monitor
            services=service_monitor.assessment(s,host.id)
            if services['problem_count']:
                record(host,'service health',str(services['problem_count'])+' selected service watch(es) have problems or changed scope. Review Security service watches.')
            if services['overdue_count'] or services['scope_limited']:
                record(host,'service coverage',str(services['overdue_count'])+' service watch(es) lack timely positive checks. '+('The 500-watch scope limit was reached. ' if services['scope_limited'] else '')+'Review Security, pending jobs and agent health; unavailable coverage is not healthy service proof.')
            service_hold=service_holds.get(host.id)
            if service_hold:record(host,'service hold','Server changes paused for selected services on response '+service_hold+'. Run a manual service check and separately review the service pause in Security.')
            if monitored['problem_count']:
                record(host,'response integrity',str(monitored['problem_count'])+' retained response(s) have unresolved verification problems. Review Security: '+', '.join(r['id']+' '+r['state'] for r in monitored['problems']))
            if monitored['policy']['enabled'] and (monitored['overdue_count'] or monitored['scope_limited']):
                record(host,'response verification',str(monitored['overdue_count'])+' retained response(s) lack timely positive verification. '+('The 500-response monitoring scope limit was reached. ' if monitored['scope_limited'] else '')+'Review Security monitoring, pending jobs and agent health; missing verification is not a clean-host verdict.')
            response=file_holds.get(host.id)
            if response:record(host,'file response hold','Server changes paused for reviewed file response '+response+'. Reconcile quarantine state or record reviewed console recovery in Security.')
            process=process_holds.get(host.id)
            if process:record(host,'process response hold','Server changes paused for process response '+process+'. Review suspension, recovery and affected services in Security.')
            publication=publication_holds.get(host.id)
            if publication:record(host,'publication hold','Server changes paused for replacement publication '+publication+'. Verify the published inode and retained original, review service impact or record trusted-console recovery in Security.')
            failed_runs=failed_counts.get(host.id,0)
            if failed_runs:record(host,'scheduled patching',str(failed_runs)+' scheduled run(s) failed, were blocked, or missed their start window in the last 24 hours. Review Patch schedules and Activity.')
            recovery=recoveries.get(host.id,[])
            if recovery:record(host,'recovery',str(len(recovery))+' operation(s) require console recovery/reconciliation. See Activity: '+', '.join(recovery[:10]))
            if host.state=='enrolling':continue
            if now-host.last_seen>120:record(host,'stale','Telemetry has not arrived within 120 seconds')
            if host.integrity:record(host,'integrity',json.dumps(host.integrity)[:8000])
            agent=settings.get('agent-status:'+host.id)
            if agent and agent.value.get('state') not in ('current','outdated'):
                record(host,'agent health','Independent agent verification '+str(agent.value.get('state'))+'. Review Agent health; telemetry ingestion may be paused.')
            if 'persistence-baseline:'+host.id in settings:
                from . import persistence
                assessment=persistence.status(s,host.id)
                if assessment['state']!='matches':
                    record(host,'startup baseline','Startup inventory '+assessment['state']+' against the reviewed baseline. Review File integrity; differences are not a malware verdict.')
            if host.repo_error:record(host,'repository',host.repo_error[:8000])
            if host.repo_error and (not host.last_repo or now-host.last_repo>cfg['repo_minutes']*120):
                published.add((host.id,OPERATIONAL_NOTIFICATIONS['repository refresh'][0]))
                try:_operational_notification(s,host.id,'repository refresh',REPOSITORY_REFRESH_MESSAGE,now)
                except ValueError:logging.getLogger(__name__).warning('Skipped in-app notification for repository refresh on %s',host.id)
            if host.id in overdue_hosts:
                count=sum(now>p.available_since+cfg['deadlines'][p.priority]*3600 for p in s.scalars(select(Package).where(Package.host_id==host.id,Package.candidate!='')))
                if count:record(host,'overdue',str(count)+' packages passed their deadline')
        # In-app only: the raw integrity alert carries endpoint text; publish fixed controller-classified wording.
        from . import integrity_sweep_notifications
        try:integrity_sweep_notifications.publish(s,hosts,now)
        except ValueError:logging.getLogger(__name__).warning('Skipped in-app hash-sweep notifications')
        # In-app only: scheduled malware-scan coverage has no SMTP/webhook alert.
        from . import scan_coverage_notifications
        try:scan_coverage_notifications.publish(s,hosts,now)
        except ValueError:logging.getLogger(__name__).warning('Skipped in-app scheduled-scan coverage notifications')
        # In-app only: lifecycle text comes from the reviewed catalog, never endpoint text.
        from . import os_lifecycle_notifications
        try:os_lifecycle_notifications.publish(s,hosts,now,cfg['repo_minutes']*120)
        except ValueError:logging.getLogger(__name__).warning('Skipped in-app OS lifecycle notifications')
        # In-app only: stored advisory applicability; counts only, never advisory or package text.
        from . import advisory_exposure_notifications
        try:advisory_exposure_notifications.publish(s,hosts,now)
        except ValueError:logging.getLogger(__name__).warning('Skipped in-app advisory exposure notifications')
        # In-app only: the shared provider floor never had an SMTP/webhook alert.
        from . import ai_provider_backoff
        ai_provider_backoff.publish_notification(s,cfg,now)
        for alert in s.scalars(select(Alert).where(Alert.state!='resolved')):
            if alert.id not in active:alert.state='resolved'
        _resolve_operational_notifications(s,published,now)
        # This producer observes the resolved outbox; it never sends or retries alerts.
        from . import alert_delivery_notifications
        alert_delivery_notifications.publish(s,now)
        s.commit()

def delivery_error(error):
    """Sanitized, bounded delivery failure reason: class plus HTTP status or SMTP code only."""
    reason=type(error).__name__
    status=getattr(getattr(error,'response',None),'status_code',None)
    if isinstance(status,int):reason+=' (HTTP %d)'%status
    code=getattr(error,'smtp_code',None)
    if isinstance(code,int):reason+=' (SMTP %d)'%code
    return reason[:120]

def deliver_one():
    # Administrators explicitly configure/enable delivery. Never send in tests.
    with Session() as s:
        setting=s.get(Setting,'notifications')
        if not setting:return
        # An unreadable configuration cannot be delivered; alert_delivery_notifications
        # raises the in-app notice. Count no attempt and never raise into the poll executor.
        try:cfg=json.loads(unseal(setting.value['encrypted']))
        except Exception:return
        if not isinstance(cfg,dict) or not cfg.get('enabled'):return
        alert=next((row for row in s.scalars(select(Alert).where(Alert.state=='open',Alert.notified==0).order_by(Alert.attempted).limit(200)) if time.time()-row.attempted>=min(3600,30*2**min(row.attempts,7))),None)
        if not alert:return
        alert.attempted=time.time();alert.attempts+=1;s.commit()
        try:
            if cfg.get('channel')=='smtp':
                from .mail import send
                send(cfg,alert)
            else:
                response=httpx.post(cfg['url'],headers={'Authorization':'Bearer '+cfg['token']} if cfg.get('token') else {},
                json={'id':alert.id,'event_id':hashlib.sha256((alert.id+str(alert.created)).encode()).hexdigest(),'host_id':alert.host_id,'kind':alert.kind,'message':alert.message,'created':alert.created},timeout=10,follow_redirects=False)
                response.raise_for_status()
            alert.notified=time.time();alert.error=''
        except Exception as e:alert.error=delivery_error(e)
        s.commit()


def failed_unit_names(health):
    """Normalize legacy systemctl tables and structured lists; reject uncertain data."""
    import re
    if not isinstance(health,dict) or type(health.get('collector_active')) is not bool:
        raise ValueError('Unable to verify collector health')
    raw=health.get('failed_units')
    if isinstance(raw,str):rows=raw.splitlines()
    elif isinstance(raw,list):rows=raw
    else:raise ValueError('Unable to verify failed-unit health')
    if len(rows)>4096:raise ValueError('Failed-unit health exceeds limit')
    names=set()
    for row in rows:
        if not isinstance(row,str):raise ValueError('Invalid failed-unit health entry')
        if not row.strip():continue
        parts=row.split()
        if len(parts)!=1 and (len(parts)<4 or parts[2]!='failed'):
            raise ValueError('Unrecognized failed-unit health output')
        name=parts[0]
        if len(name)>255 or not re.fullmatch(r'[A-Za-z0-9_.:@\\-]+\.(?:service|socket|target|device|mount|automount|swap|timer|path|slice|scope)',name):
            raise ValueError('Invalid failed-unit name')
        names.add(name)
    return names


def patch_health_comparison(before,after):
    previous=failed_unit_names(before);current=failed_unit_names(after)
    if before['collector_active'] is not True:raise ValueError('Collector was inactive before patching')
    return {'new_failed_units':sorted(current-previous),'pre_existing_failed_units':sorted(previous),
            'remaining_failed_units':sorted(current),'recovered_units':sorted(previous-current),
            'collector_active':after['collector_active'],
            'passed':not (current-previous) and after['collector_active'] is True}
