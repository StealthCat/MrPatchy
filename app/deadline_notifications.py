"""In-app notifications for pending package updates past their patch deadline.

The SMTP/webhook ``overdue`` alert carries a package count that changes as
updates arrive or install, so mirroring it would create a new unread revision
on every change. This producer instead publishes one admin-only event per
server whose fixed text names only the highest overdue priority: count changes
are no-ops and only a change of that priority appends a revision. Resolution
uses the shared operational path, so it needs the kind registered in
``operations.OPERATIONAL_NOTIFICATIONS``. Nothing here installs packages,
acknowledges alerts or changes any deadline or authorization.
"""
import logging

from sqlalchemy import and_, or_, select

from . import host_lifecycle
from .db import Package

ALERT_KIND = 'patch deadline'
ORDER = ('critical', 'high', 'normal', 'low')
SEVERITY = {'critical': 'critical', 'high': 'high', 'normal': 'medium', 'low': 'low'}
CHUNK = 500


def message(priority):
    return (f'At least one {priority}-priority package update on this server has passed its configured patch '
            'deadline. Review pending updates and the Patching timeline. Holds, freezes and failed operations '
            'can keep updates pending; this notification does not install anything.')


def highest_overdue(s, host_ids, deadlines, now):
    """Return {host_id: highest overdue priority} with one grouped read per chunk."""
    windows = [(priority, hours) for priority, hours in deadlines.items() if priority in SEVERITY]
    if not host_ids or not windows:
        return {}
    overdue = or_(*(and_(Package.priority == priority, Package.available_since < now - hours * 3600)
                    for priority, hours in windows))
    found = {}
    for start in range(0, len(host_ids), CHUNK):
        chunk = host_ids[start:start + CHUNK]
        rows = s.execute(select(Package.host_id, Package.priority).where(
            Package.host_id.in_(chunk), Package.candidate != '', Package.available_since > 0, overdue).distinct())
        for host_id, priority in rows:
            current = found.get(host_id)
            if current is None or ORDER.index(priority) < ORDER.index(current):
                found[host_id] = priority
    return found


def publish(s, hosts, cfg, now, notify, published):
    """Publish for every eligible server and add its key to ``published``.

    ``notify(host_id, alert_kind, message, now, severity)`` is the operational publisher;
    servers left out of ``published`` are resolved by the caller.
    """
    from .operations import OPERATIONAL_NOTIFICATIONS
    kind = OPERATIONAL_NOTIFICATIONS[ALERT_KIND][0]
    eligible = [h.id for h in hosts if not h.deleted_at and host_lifecycle.active(h) and h.state != 'enrolling']
    for host_id, priority in sorted(highest_overdue(s, eligible, cfg['deadlines'], now).items()):
        # Keep the key even if publishing is rejected, so an active event is never resolved by mistake.
        published.add((host_id, kind))
        try:
            notify(host_id, ALERT_KIND, message(priority), now, SEVERITY[priority])
        except ValueError:
            logging.getLogger(__name__).warning('Skipped in-app patch deadline notification on %s', host_id)
