"""Administrator notice when a saved server AI policy needs repair."""

import json
from urllib.parse import quote

from sqlalchemy import Text, cast, select

from . import ai_policy, host_lifecycle, notifications
from .db import Host, Setting


SOURCE = 'ai-policy'
KIND = 'malformed-server-policy'
REPAIR = (
    'The saved AI policy for this server is malformed, so its AI work is paused. '
    'Review and repair the policy in the server Security tab. '
    'Non-AI inventory, patching, scanning and monitoring can continue.'
)
RESOLVED = (
    'This server no longer needs an active AI policy repair notice. Its policy '
    'was repaired, central AI was disabled, or the server left active management.'
)


def _malformed_policy(raw):
    # Inspect stored JSON as text so one invalid SQLite value cannot stop
    # collection for the rest of the fleet.
    try:
        value = json.loads(raw)
    except (TypeError, ValueError, RecursionError):
        return True
    explicitly_paused = isinstance(value, dict) and value.get('paused') is True
    return ai_policy.stored_paused(value) and not explicitly_paused


def _record(session, host_id, *, active, now):
    notifications.publish(
        session, source=SOURCE, kind=KIND, subject_type='server',
        subject_id=host_id, host_id=host_id, minimum_role='admin',
        subject_revision='malformed' if active else 'resolved',
        lifecycle='active' if active else 'resolved',
        reason=REPAIR if active else RESOLVED,
        severity='medium' if active else 'info',
        deep_link='#servers/' + quote(host_id, safe='') + '/security', now=now,
    )


def publish(session, cfg, now):
    """Synchronize one durable event per affected server in the collector transaction."""
    affected = set()
    if cfg['ai_enabled']:
        policies = session.execute(select(Host.id, cast(Setting.value, Text))
            .join(Setting, Setting.key == ai_policy.PREFIX + Host.id)
            .where(Host.id.in_(host_lifecycle.active_ids())))
        affected = {host_id for host_id, raw in policies if _malformed_policy(raw)}

    event, revision = notifications.NotificationEvent, notifications.NotificationRevision
    active = set(session.scalars(select(event.host_id)
        .join(revision, (revision.event_id == event.id) & (revision.revision == event.revision))
        .where(event.source == SOURCE, event.kind == KIND, revision.lifecycle == 'active')))
    for host_id in sorted(affected - active):
        _record(session, host_id, active=True, now=now)
    for host_id in sorted(active - affected):
        _record(session, host_id, active=False, now=now)
