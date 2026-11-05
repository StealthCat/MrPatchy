"""Pure agent-spool capacity admission contract (first slice of issue #107).

No I/O, no clock and no target access. Callers pass measured sizes; the module
returns a decision with an explicit, countable reason. Physical disk use
(journal/WAL/checkpoint/compaction files) is accounted separately from logical
queued payload bytes, and a free-space reserve is always honoured.
"""
import math

WARNING_PERCENT=70
CRITICAL_PERCENT=90
PRIORITIES=('security','normal','low')   # most to least important
ADMIT='admit'
REFUSE='refuse'
REASONS=('invalid','oversize','free_space_reserve','capacity','critical_pressure')
COUNTER_MAX=2**53   # loss counters saturate here (largest exactly-representable JSON/float integer bound)


def _count(value):
    if isinstance(value,bool) or not isinstance(value,(int,float)):return None
    if isinstance(value,float) and (not math.isfinite(value) or not value.is_integer()):return None
    if value<0 or value>2**53:return None
    return int(value)


def pressure(logical,physical,capacity):
    """Pressure level from the larger of logical and physical utilization."""
    logical,physical,capacity=_count(logical),_count(physical),_count(capacity)
    if None in (logical,physical) or not capacity:return 'unavailable'
    percent=max(logical,physical)*100/capacity
    if percent>=CRITICAL_PERCENT:return 'critical'
    if percent>=WARNING_PERCENT:return 'warning'
    return 'ok'


def _refuse(reason,level):
    return {'decision':REFUSE,'reason':reason,'pressure':level,'counted_loss':True}


def admit(record_bytes,priority,*,logical_bytes,physical_bytes,capacity_bytes,free_disk_bytes,reserve_bytes,
          overhead_bytes=0,max_record_bytes=None):
    """Decide whether one record may be appended.

    Rules: invalid input refuses (never admits by default); a record larger than
    max_record_bytes is refused as 'oversize'; admission must leave at least
    reserve_bytes of free disk after the record and its journal overhead; the
    logical and physical totals may not exceed capacity; at critical pressure
    only 'security' records are admitted, lower priorities are refused with a
    counted loss rather than evicting stored records.
    """
    size,logical,physical=_count(record_bytes),_count(logical_bytes),_count(physical_bytes)
    capacity,free,reserve=_count(capacity_bytes),_count(free_disk_bytes),_count(reserve_bytes)
    overhead=_count(overhead_bytes)
    limit=None if max_record_bytes is None else _count(max_record_bytes)
    if priority not in PRIORITIES or None in (size,logical,physical,free,reserve,overhead) or not capacity or (max_record_bytes is not None and limit is None):
        return _refuse('invalid','unavailable')
    level=pressure(logical,physical,capacity)
    if limit is not None and size>limit:return _refuse('oversize',level)
    written=size+overhead
    if free-written<reserve:return _refuse('free_space_reserve',level)
    if logical+size>capacity or physical+written>capacity:return _refuse('capacity',level)
    # The priority gate uses the projected post-append pressure as well as the
    # current one, so a lower-priority record cannot cross from warning into the
    # critical headroom (or fill the spool) that is reserved for security records.
    projected=pressure(logical+size,physical+written,capacity)
    if priority!='security' and 'critical' in (level,projected):return _refuse('critical_pressure',level)
    return {'decision':ADMIT,'reason':None,'pressure':level,'counted_loss':False}


def _counter(value):
    """Previous ledger counter: non-negative integer, clamped to COUNTER_MAX.

    Unlike _count, a value at or above the bound is kept (saturated) rather than
    rejected, so the ledger never resets its own earlier output within an epoch.
    """
    if isinstance(value,bool) or not isinstance(value,(int,float)):return 0
    if isinstance(value,float) and (not math.isfinite(value) or not value.is_integer()):return 0
    if value<0:return 0
    return min(int(value),COUNTER_MAX)


def _add(current,n):
    return min(_counter(current)+n,COUNTER_MAX)


def loss_ledger(ledger,decision,priority,observations=1):
    """Return a new cumulative loss ledger including a refused decision.

    The ledger carries an epoch so a reset database is distinguishable from
    zero historical loss. Admitted decisions return the ledger unchanged.
    Counters are monotonic within an epoch and saturate at COUNTER_MAX; once
    any counter saturates the ledger carries 'saturated': True.
    """
    base=ledger if isinstance(ledger,dict) else {}
    epoch=base.get('epoch') if isinstance(base.get('epoch'),str) and base.get('epoch') else 'unknown'
    by=dict(base.get('by_reason',{})) if isinstance(base.get('by_reason'),dict) else {}
    out={'epoch':epoch,'by_reason':by,'by_priority':dict(base.get('by_priority',{})) if isinstance(base.get('by_priority'),dict) else {}}
    if base.get('saturated') is True:out['saturated']=True
    if not isinstance(decision,dict) or decision.get('decision')!=REFUSE:return out
    n=_count(observations)
    n=1 if n is None else n
    reason=decision.get('reason') if decision.get('reason') in REASONS else 'invalid'
    by[reason]=_add(by.get(reason),n)
    key=priority if priority in PRIORITIES else 'invalid'
    out['by_priority'][key]=_add(out['by_priority'].get(key),n)
    if COUNTER_MAX in (by[reason],out['by_priority'][key]):out['saturated']=True
    return out
