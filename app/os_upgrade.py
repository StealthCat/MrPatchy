"""Bounded report-only OS upgrade snapshots; no target or provider operations."""
import math
import time
from sqlalchemy import select
from .db import Host, Setting
from target import release

STALE_AFTER=7*86400
PREFIX='os-upgrade:'
_UNSET=object()
TIMESTAMP_LIMIT=2**53   # far beyond any real epoch second; larger values are malformed


def _timestamp(value):
    """Return a finite, bounded numeric timestamp or None.

    Integers are range-checked before any float conversion, so arbitrarily
    large legacy JSON integers (e.g. 10**400) are malformed rather than raising
    OverflowError.
    """
    if type(value) is int:return value if -TIMESTAMP_LIMIT<=value<=TIMESTAMP_LIMIT else None
    if type(value) is float:return value if math.isfinite(value) and -TIMESTAMP_LIMIT<=value<=TIMESTAMP_LIMIT else None
    return None


def snapshot(inventory):
    inv=inventory if isinstance(inventory,dict) else {}
    result={'version':1,'has_os':bool(inv.get('os')),'valid':False,'collected':0}
    collected=_timestamp(inv.get('collected') or 0);files=inv.get('files',{})
    if (collected is None
            or not isinstance(inv.get('os',''),str) or not isinstance(inv.get('status',''),str)
            or not isinstance(files,dict) or not all(isinstance(k,str) and isinstance(v,str) for k,v in files.items())):
        return result
    result.update(valid=True,collected=collected)
    if not result['has_os']:return result
    try:target=release.transition(inv)
    except ValueError as error:
        result['detected']={'status':'unsupported','message':str(error)[:512]}
    except Exception:
        result['detected']={'status':'unknown','message':'Upgrade availability could not be determined from this inventory.'}
    else:
        item={'distribution':target['distribution'],'from_version':target['from_version'],'to_version':target['version']}
        if target['distribution']=='debian':
            item.update(status='available',message=f"Debian {target['from_version']} can move to Debian {target['version']} ({target['suite']}) through a reviewed release plan.")
        else:
            item.update(status='supported',message=f"Ubuntu {target['from_version']} to {target['version']} is a supported path, but Ubuntu's offer is only verified when a plan is prepared.")
        result['detected']=item
    return result


def store(session,host,inventory):
    session.merge(Setting(key=PREFIX+host.id,value=snapshot(inventory)))


def backfill(connection):
    """One-time startup work, at most 100 inventories materialized per batch.

    New snapshots are refreshed in the same transaction as inventory ingestion.
    API list requests never perform a fallback full-inventory read.
    """
    while True:
        rows=connection.execute(select(Host.id,Host.inventory).outerjoin(Setting,Setting.key==PREFIX+Host.id)
            .where(Setting.key.is_(None)).order_by(Host.id).limit(100)).all()
        if not rows:return
        connection.execute(Setting.__table__.insert(),[{'key':PREFIX+hid,'value':snapshot(inv)} for hid,inv in rows])


def status(host,now=None,*,saved=_UNSET):
    now=time.time() if now is None else now
    # Explicit missing/corrupt persisted snapshots stay unknown. Only callers
    # that already own an inventory may use the standalone detector path.
    value=snapshot(host.inventory) if saved is _UNSET else saved
    if getattr(host,'deleted_at',0) or not getattr(host,'enabled',True):
        return {'status':'unknown','message':'Management is disabled; upgrade availability is not tracked.'}
    if not isinstance(value,dict) or type(value.get('version')) is not int or value['version']!=1:
        return {'status':'unknown','message':'Upgrade inventory summary is unavailable; await an inventory refresh.'}
    if not value.get('has_os'):
        return {'status':'unknown','message':'No operating-system inventory has been collected yet.'}
    collected=_timestamp(value.get('collected'))
    if value.get('valid') is not True or collected is None:
        return {'status':'unknown','message':'Inventory is malformed; upgrade availability is not asserted.'}
    result={'checked':collected or None}
    if not collected or now-collected>STALE_AFTER or collected>now+3600:
        return {**result,'status':'stale','message':'Inventory is older than 7 days; upgrade availability is not asserted.'}
    if host.state!='online':
        return {**result,'status':'unknown','message':'Server is not online; upgrade availability is not asserted.'}
    detected=value.get('detected')
    if not isinstance(detected,dict) or detected.get('status') not in ('available','supported','unsupported','unknown'):
        return {**result,'status':'unknown','message':'Upgrade inventory summary is malformed.'}
    if not isinstance(detected.get('message'),str) or len(detected['message'])>512:
        return {**result,'status':'unknown','message':'Upgrade inventory summary is malformed.'}
    if detected['status'] in ('available','supported'):
        kind=detected.get('distribution');version=detected.get('from_version')
        if not isinstance(kind,str) or not isinstance(version,str):
            return {**result,'status':'unknown','message':'Upgrade inventory summary is malformed.'}
        target=release.TRANSITIONS.get(kind,{}).get(version)
        if (not target or target[0]!=detected.get('to_version') or
                detected['status']!=('available' if kind=='debian' else 'supported')):
            return {**result,'status':'unknown','message':'Upgrade inventory summary is malformed.'}
    return {**result,**{k:detected[k] for k in ('status','message','distribution','from_version','to_version') if k in detected}}
