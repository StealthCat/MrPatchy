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
    if level=='critical' and priority!='security':return _refuse('critical_pressure',level)
    return {'decision':ADMIT,'reason':None,'pressure':level,'counted_loss':False}


def loss_ledger(ledger,decision,priority,observations=1):
    """Return a new cumulative loss ledger including a refused decision.

    The ledger carries an epoch so a reset database is distinguishable from
    zero historical loss. Admitted decisions return the ledger unchanged.
    """
    base=ledger if isinstance(ledger,dict) else {}
    epoch=base.get('epoch') if isinstance(base.get('epoch'),str) and base.get('epoch') else 'unknown'
    by=dict(base.get('by_reason',{})) if isinstance(base.get('by_reason'),dict) else {}
    out={'epoch':epoch,'by_reason':by,'by_priority':dict(base.get('by_priority',{})) if isinstance(base.get('by_priority'),dict) else {}}
    if decision.get('decision')!=REFUSE:return out
    n=_count(observations)
    n=1 if n is None else n
    reason=decision.get('reason') if decision.get('reason') in REASONS else 'invalid'
    by[reason]=(_count(by.get(reason)) or 0)+n
    key=priority if priority in PRIORITIES else 'invalid'
    out['by_priority'][key]=(_count(out['by_priority'].get(key)) or 0)+n
    return out
