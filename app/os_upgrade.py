"""Report-only distribution/major-OS upgrade availability for a managed server.

One source of truth for the API and every UI location. Detection never starts
an upgrade and never calls the target; it reads the saved inventory and the
same adjacent-release table the reviewed release planner uses.
"""
import time
from target import release

STALE_AFTER=7*86400

def status(host,now=None):
    """Return {'status','message', ...}; only status 'available' may raise an alert or badge."""
    now=time.time() if now is None else now
    inv=host.inventory if isinstance(host.inventory,dict) else {}
    if getattr(host,'deleted_at',0) or not getattr(host,'enabled',True):
        return {'status':'unknown','message':'Management is disabled; upgrade availability is not tracked.'}
    if not inv.get('os'):
        return {'status':'unknown','message':'No operating-system inventory has been collected yet.'}
    collected=inv.get('collected') or 0
    result={'checked':collected or None}
    if not collected or now-collected>STALE_AFTER or collected>now+3600:
        return {**result,'status':'stale','message':'Inventory is older than 7 days; upgrade availability is not asserted.'}
    if host.state!='online':
        return {**result,'status':'unknown','message':'Server is not online; upgrade availability is not asserted.'}
    try:target=release.transition(inv)
    except ValueError as error:
        return {**result,'status':'unsupported','message':str(error)}
    result.update(distribution=target['distribution'],from_version=target['from_version'],to_version=target['version'])
    if target['distribution']=='debian':
        result.update(status='available',message=f"Debian {target['from_version']} can move to Debian {target['version']} ({target['suite']}) through a reviewed release plan.")
    else:
        # Ubuntu offers the next LTS only when its own upgrader says so; that
        # is verified at planning time, not assumed from the release table.
        result.update(status='supported',message=f"Ubuntu {target['from_version']} to {target['version']} is a supported path, but Ubuntu's offer is only verified when a plan is prepared.")
    return result
