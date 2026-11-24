"""In-app notifications for low disk, inodes, memory or an unsynchronized clock on managed agents (#1257).

The endpoint-agent view (``agent_fleet_health.resources``) already derives advisory
attention codes from the agent's own retained telemetry. This producer mirrors them
into one admin-only notification per server so administrators are told without
opening Activity → Workers. It is a #342 alert-producer slice and a roadmap J
health producer.

- Only **fresh** telemetry is evaluated. Stale, missing, future-dated or malformed
  telemetry, and a metric that is now unknown, leave an active event unchanged:
  unknown is not recovery. Telemetry loss has its own producer.
- The reason text is fixed and names only the affected categories, so changing
  percentages add no revisions; a changed category set adds one.
- Hysteresis: a capacity category already in the active event stays until its
  available share rises above ``CLEAR_AVAILABLE_PERCENT``, so values hovering
  around the trigger threshold do not flap the event.

Resolution uses the shared operational path, which needs the kind registered in
``operations.OPERATIONAL_NOTIFICATIONS``. It is notification-only: there is no
SMTP/webhook outbox alert. Nothing here changes agent health classification, makes
an AI call, repairs anything or authorizes any response.
"""
import itertools
import logging

from sqlalchemy import select

from . import agent_fleet_health, host_lifecycle, notifications

ALERT_KIND = 'resource attention'
TRIGGER_AVAILABLE_PERCENT = agent_fleet_health.LOW_AVAILABLE_PERCENT
CLEAR_AVAILABLE_PERCENT = 15
# Display order and fixed wording. Capacity categories map to the resources() key.
CAPACITY = (('disk-space-low', 'disk', 'free disk space on the root file system'),
            ('disk-inodes-low', 'inodes', 'free inodes on the root file system'),
            ('memory-low', 'memory', 'available memory'))
CLOCK = 'clock-unsynchronized'
CODES = tuple(code for code, _, _ in CAPACITY) + (CLOCK,)
_LABELS = {code: label for code, _, label in CAPACITY}


def message(codes):
    """Fixed text for a non-empty set of attention codes. No live numbers or endpoint text."""
    ordered = [code for code in CODES if code in codes]
    if not ordered:
        raise ValueError('No resource attention codes')
    parts = []
    low = [_LABELS[code] for code in ordered if code in _LABELS]
    if low:
        parts.append('The agent reports low ' + ', '.join(low) + f' ({TRIGGER_AVAILABLE_PERCENT}% or less available).')
    if CLOCK in ordered:
        parts.append('The agent reports that the kernel clock is not synchronized.')
    return (' '.join(parts) + ' Patching, logging and evidence collection can fail or record wrong times. Review '
            'Agent health on this server and Activity → Workers. These are the agent\'s own advisory observations. '
            'This notification does not change agent health, free disk space or memory, adjust the clock or '
            'authorize any response.')


# Every possible reason text, so an active event's categories can be recovered exactly.
_BY_MESSAGE = {message(set(combo)): frozenset(combo)
               for size in range(1, len(CODES) + 1) for combo in itertools.combinations(CODES, size)}


def evaluate(resources, previous):
    """Return the attention codes for one server's fresh resources summary.

    ``previous`` is the code set of the server's active event (empty when none).
    A metric that is unknown keeps its previous state; a capacity category that
    was already active stays until it is above ``CLEAR_AVAILABLE_PERCENT``.
    """
    codes = set()
    for code, key, _ in CAPACITY:
        value = resources.get(key) if isinstance(resources, dict) else None
        if not isinstance(value, dict) or value.get('available_percent') is None:
            if code in previous:
                codes.add(code)
            continue
        limit = CLEAR_AVAILABLE_PERCENT if code in previous else TRIGGER_AVAILABLE_PERCENT
        if value['available_percent'] <= limit:
            codes.add(code)
    clock = resources.get('clock') if isinstance(resources, dict) else None
    if not isinstance(clock, dict) or not isinstance(clock.get('synchronized'), bool):
        if CLOCK in previous:
            codes.add(CLOCK)
    elif not clock['synchronized']:
        codes.add(CLOCK)
    return codes


def _active(session, source, subject_type, kind):
    """Map host_id -> code set of the currently active resource-attention event.

    An active event whose text is not recognised maps to an empty set.
    """
    event, revision = notifications.NotificationEvent, notifications.NotificationRevision
    rows = session.execute(select(event.host_id, revision.reason).join(
        revision, (revision.event_id == event.id) & (revision.revision == event.revision)).where(
        event.source == source, event.kind == kind, event.subject_type == subject_type,
        revision.lifecycle == 'active')).all()
    return {host_id: _BY_MESSAGE.get(reason, frozenset()) for host_id, reason in rows}


def publish(session, hosts, now, notify, published):
    """Publish for every affected eligible server and add its key to ``published``.

    ``notify(host_id, alert_kind, message, now)`` is the operational publisher;
    servers left out of ``published`` are resolved by the caller.
    """
    from .operations import (OPERATIONAL_NOTIFICATION_SOURCE, OPERATIONAL_NOTIFICATION_SUBJECT,
                             OPERATIONAL_NOTIFICATIONS)
    kind = OPERATIONAL_NOTIFICATIONS[ALERT_KIND][0]
    active = _active(session, OPERATIONAL_NOTIFICATION_SOURCE, OPERATIONAL_NOTIFICATION_SUBJECT, kind)
    for host in sorted(hosts, key=lambda h: h.id):
        if host.deleted_at or not host_lifecycle.active(host) or host.state == 'enrolling':
            continue
        previous = active.get(host.id)
        summary = None
        try:
            state, _ = agent_fleet_health.telemetry_state(host.telemetry, now)
            summary = agent_fleet_health.resources(host.telemetry, state) if state == 'fresh' else None
            codes = evaluate(summary, previous or frozenset()) if summary is not None else set(previous or ())
        except (ArithmeticError, TypeError, ValueError):
            codes = set(previous or ())  # uninterpretable telemetry is unknown, not recovery
        if previous is not None and not previous and not codes:
            # An active event whose text is unrecognised (e.g. written by another version): keep it until
            # fresh known values are available, rather than resolving on an unknown.
            if summary is None:
                published.add((host.id, kind))
            continue
        if not codes:
            continue
        # Keep the key even if publishing is rejected, so an active event is never resolved by mistake.
        published.add((host.id, kind))
        try:
            notify(host.id, ALERT_KIND, message(codes), now)
        except ValueError:
            logging.getLogger(__name__).warning('Skipped in-app resource attention notification on %s', host.id)
