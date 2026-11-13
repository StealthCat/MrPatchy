"""Read-only agent event-spool health derived from already collected telemetry.

Only validated numeric counters are returned; observation payloads, paths and
arbitrary supplied keys never leave this module. No remote call is made.
"""
import math
import time

WARNING_PERCENT=70
CRITICAL_PERCENT=90
STALE_SECONDS=15*60
REASONS=('oversize','capacity')
UNAVAILABLE='unavailable'


def count(value):
    """Return a non-negative finite integer, or None when the value is unusable."""
    if isinstance(value,bool) or not isinstance(value,(int,float)):return None
    if isinstance(value,float) and (not math.isfinite(value) or not value.is_integer()):return None
    if value<0 or value>2**53:return None
    return int(value)


def pressure(utilization):
    if utilization is None:return UNAVAILABLE
    if utilization>=CRITICAL_PERCENT:return 'critical'
    if utilization>=WARNING_PERCENT:return 'warning'
    return 'ok'


def lifecycle(host):
    if getattr(host,'deleted_at',0):return 'deleted'
    return 'enabled' if getattr(host,'enabled',True) else 'disabled'


def health(host,now=None):
    now=time.time() if now is None else now
    telemetry=host.telemetry if isinstance(host.telemetry,dict) else {}
    spool=telemetry.get('spool')
    collected=telemetry.get('collected')
    collected=collected if isinstance(collected,(int,float)) and not isinstance(collected,bool) and math.isfinite(collected) else None
    result={'host_id':host.id,'lifecycle':lifecycle(host),'collected':collected,
            'unavailable_metrics':['oldest_observation_age','ingest_rate','flush_rate','delivery_latency','retries']}
    if not isinstance(spool,dict) or not spool:
        return {**result,'status':UNAVAILABLE,'reason':'No spool counters have been collected from this server.','pressure':UNAVAILABLE}
    pending,queued,capacity=count(spool.get('pending')),count(spool.get('queued_bytes')),count(spool.get('capacity_bytes'))
    if None in (pending,queued) or not capacity:
        return {**result,'status':UNAVAILABLE,'reason':'Collected spool counters are malformed.','pressure':UNAVAILABLE}
    utilization=round(min(100.0,queued*100/capacity),1)
    reasons=spool.get('drop_reasons') if isinstance(spool.get('drop_reasons'),dict) else {}
    loss={}
    for name in REASONS:
        item=reasons.get(name) if isinstance(reasons.get(name),dict) else {}
        loss[name]={'batches':count(item.get('batches')),'observations':count(item.get('observations'))}
    dropped=count(spool.get('dropped'))
    lost_observations=count(spool.get('dropped_observations'))
    unclassified=count(reasons.get('unclassified_batches'))
    stale=collected is None or now-collected>STALE_SECONDS
    return {**result,'status':'stale' if stale else 'fresh','pressure':pressure(utilization),
            'thresholds':{'warning_percent':WARNING_PERCENT,'critical_percent':CRITICAL_PERCENT},
            'queue':{'pending_batches':pending,'queued_bytes':queued,'capacity_bytes':capacity,'utilization_percent':utilization,
                     'batch_limit_bytes':count(spool.get('batch_limit_bytes'))},
            'loss':{'dropped_batches':dropped,'lost_observations':lost_observations,'by_reason':loss,'unclassified_batches':unclassified}}


FLEET_LIMIT=10
_RANK={'critical':0,'warning':1}


def fleet(hosts,now=None):
    """Roll up per-server spool health for enabled, non-deleted servers.

    Counts are exhaustive; only the most urgent servers are listed. Servers that
    never reported counters are counted as unavailable, never as healthy.
    """
    counts={'total':0,'ok':0,'warning':0,'critical':0,'stale':0,'unavailable':0}
    batches=observations=with_loss=0
    listed=[]
    for host in hosts:
        if lifecycle(host)!='enabled':continue
        item=health(host,now);counts['total']+=1
        if item['status']==UNAVAILABLE:counts['unavailable']+=1;continue
        if item['status']=='stale':counts['stale']+=1
        elif item['pressure']=='ok':counts['ok']+=1
        if item['pressure'] in ('warning','critical') and item['status']!='stale':counts[item['pressure']]+=1
        loss=item['loss'];lost_b,lost_o=loss['dropped_batches'] or 0,loss['lost_observations'] or 0
        batches+=lost_b;observations+=lost_o;with_loss+=bool(lost_b or lost_o)
        if item['pressure'] in _RANK or item['status']=='stale' or lost_b or lost_o:
            listed.append({'host_id':host.id,'name':host.name,'status':item['status'],'pressure':item['pressure'],
                           'utilization_percent':item['queue']['utilization_percent'],'dropped_batches':lost_b,'lost_observations':lost_o})
    listed.sort(key=lambda row:(_RANK.get(row['pressure'],2),row['status']!='stale',-row['lost_observations'],-row['dropped_batches'],row['name'] or '',row['host_id']))
    return {'counts':counts,'loss':{'dropped_batches':batches,'lost_observations':observations,'servers_with_loss':with_loss},
            'servers':listed[:FLEET_LIMIT],'more':max(0,len(listed)-FLEET_LIMIT),
            'unavailable_metrics':['oldest_observation_age','ingest_rate','flush_rate','delivery_latency','retries']}


# In-app attention for spool pressure and newly observed loss (roadmap J, #108).
NOTIFY_SOURCE='agent-spool'
NOTIFY_KIND='spool-health'
NOTIFY_SUBJECT='server'
_NOTIFY_PARTS=('critical','loss')
_NOTIFY_TEXT={
    'critical':'The agent event spool on this server is at least '+str(CRITICAL_PERCENT)+'% full. Further observations may be lost if it fills; check the agent and its connection.',
    'loss':'The agent reported newly lost observation batches, so monitoring coverage for this server is incomplete for that period. Cumulative counts are on the server summary.',
}
_RESOLVED_TEXT=('Agent event spool use on this server is back below '+str(WARNING_PERCENT)+
                '% and no new loss was reported. Earlier cumulative loss stays visible on the server summary.')
_DELETED_TEXT='The server was deleted; its agent event spool no longer needs attention here.'
_DISABLED_TEXT=('Server management was disabled, so agent event spool monitoring is paused. If spool pressure '
                'or new loss is still present after the server is re-enabled, this notification reopens.')
_ENDED={'server-deleted':_DELETED_TEXT,'server-disabled':_DISABLED_TEXT}


def _link(host_id):
    return '#servers/'+host_id+'/summary'


def notification_transition(active,pressure,new_loss):
    """Pure episode state machine: return ``(action, state)``.

    ``active`` is the current unresolved episode state ('' when none), e.g.
    'critical', 'loss' or 'critical+loss'. An episode opens on critical pressure
    or newly lost batches, grows (escalates) at most once more, holds while use
    stays at warning or above, while loss continues or while counters are
    unusable, and resolves only after a usable reading below warning with no new
    loss. Unchanged conditions never republish, so polling cannot flood users.
    """
    observed={part for part,present in (('critical',pressure=='critical'),('loss',bool(new_loss))) if present}
    current={part for part in active.split('+') if part in _NOTIFY_PARTS} if active else set()
    if observed:
        merged=current|observed
        if merged==current:return 'hold',active
        return 'publish','+'.join(part for part in _NOTIFY_PARTS if part in merged)
    if not current:return 'none',''
    if pressure=='ok':return 'resolve',''
    return 'hold',active


def _active_state(session,host_id):
    from sqlalchemy import select
    from . import notifications
    N=notifications.NotificationEvent;R=notifications.NotificationRevision
    row=session.execute(select(R.subject_revision,R.lifecycle).join(N,(R.event_id==N.id)&(R.revision==N.revision)).where(
        N.id==notifications._event_id(NOTIFY_SOURCE,NOTIFY_KIND,NOTIFY_SUBJECT,host_id,host_id))).first()
    return row[0] if row and row[1]=='active' else ''


def publish_notification(session,host,new_loss,now=None):
    """Publish/resolve the admin-only spool attention event for freshly ingested telemetry.

    Advisory only: it never acknowledges, restarts, drains or remediates anything
    and does not change response authorization. The caller owns the transaction.
    Returns the action taken.
    """
    from . import notifications
    item=health(host,now)
    pressure=item['pressure'] if item['status']=='fresh' else UNAVAILABLE
    action,state=notification_transition(_active_state(session,host.id),pressure,new_loss)
    if action=='publish':
        notifications.publish(session,source=NOTIFY_SOURCE,kind=NOTIFY_KIND,subject_type=NOTIFY_SUBJECT,
            subject_id=host.id,host_id=host.id,subject_revision=state,severity='high' if 'loss' in state else 'medium',
            reason=' '.join(_NOTIFY_TEXT[part] for part in state.split('+')),deep_link=_link(host.id),
            minimum_role='admin',now=now)
    elif action=='resolve':
        notifications.publish(session,source=NOTIFY_SOURCE,kind=NOTIFY_KIND,subject_type=NOTIFY_SUBJECT,
            subject_id=host.id,host_id=host.id,subject_revision='resolved',severity='info',reason=_RESOLVED_TEXT,
            deep_link=_link(host.id),minimum_role='admin',lifecycle='resolved',now=now)
    return action


def resolve_host_notification(session,host_id,cause='server-deleted'):
    """Resolve a still-active spool attention event when its server is deleted or disabled.

    Neither a deleted nor a disabled server is polled, so no fresh telemetry could
    resolve the episode. Returns ``True`` when a resolved revision was added.
    """
    from . import notifications
    reason=_ENDED[cause]
    if not _active_state(session,host_id):return False
    notifications.publish(session,source=NOTIFY_SOURCE,kind=NOTIFY_KIND,subject_type=NOTIFY_SUBJECT,
        subject_id=host_id,host_id=host_id,subject_revision=cause,severity='info',reason=reason,
        deep_link=_link(host_id),minimum_role='admin',lifecycle='resolved')
    return True
