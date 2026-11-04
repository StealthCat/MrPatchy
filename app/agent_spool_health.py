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
