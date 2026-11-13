"""Administrator notification when a server's file-integrity hash sweep stalls.

``worker.ingest`` flags a sweep older than 360 seconds (or dated in the future)
in ``host.integrity``. That puts the server in attention and blocks automatic and
scheduled patching, but the only external signal is the raw-text ``integrity``
SMTP/webhook alert, which the bell excludes because it carries endpoint text.

This producer publishes one admin-only in-app event per server while telemetry
is fresh but the sweep has been stalled for a sustained period, and resolves it
when the sweep recovers, telemetry goes stale (the telemetry-loss producer owns
that case) or the server is disabled, deleted or re-enrolling.

It only reads state. Reason text is fixed per category and never carries
endpoint-supplied paths, errors or timestamps. It changes no patching state and
acknowledges, remediates or authorizes nothing.
"""
import math

from sqlalchemy import select

from . import host_lifecycle, notifications

SOURCE = 'integrity-sweep'
KIND = 'hash-sweep-stalled'
SUBJECT = 'server'
FRESH_SECONDS = 120
STALLED_SECONDS = 1800
FUTURE_SECONDS = 120
MESSAGES = {
    'overdue': ('File-integrity monitoring has not completed a hash sweep on this server for at least 30 minutes, '
                'although telemetry is still arriving. Managed-file and file-integrity coverage is missing, and '
                'automatic and scheduled patching wait while this persists. Review the Overview integrity findings '
                'and Agent health. Missing coverage is not a clean-host or compromise verdict.'),
    'future': ('This server reports a file-integrity hash sweep time in the future, so sweep freshness cannot be '
               'verified. Check the server clock and the agent. Managed-file and file-integrity coverage is '
               'unverified, and automatic and scheduled patching wait while this persists. This is not a '
               'clean-host or compromise verdict.'),
}
RESOLVED = 'The file-integrity hash sweep on this server no longer needs administrator attention.'


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def classify(host, now):
    """Return ``'overdue'``, ``'future'`` or ``None`` for one server's stored snapshot."""
    if host.deleted_at or not host_lifecycle.active(host) or host.state == 'enrolling':
        return None
    if not _number(host.last_seen) or now - host.last_seen > FRESH_SECONDS:
        return None
    telemetry = host.telemetry if isinstance(host.telemetry, dict) else {}
    if not telemetry:
        return None
    hashed = telemetry.get('hashed_at', 0)
    if not _number(hashed):
        return 'overdue'
    if hashed > now + FUTURE_SECONDS:
        return 'future'
    if now - hashed > STALLED_SECONDS:
        return 'overdue'
    return None


def _link(host_id):
    return '#servers/' + host_id + '/overview'


def publish(session, hosts, now):
    """Publish or resolve sweep events in the caller's transaction. Returns the stalled host IDs."""
    stalled = {}
    for host in hosts:
        category = classify(host, now)
        if category:
            stalled[host.id] = category
    for host_id, category in stalled.items():
        notifications.publish(session, source=SOURCE, kind=KIND, subject_type=SUBJECT, subject_id=host_id,
                              host_id=host_id, subject_revision=category, severity='medium',
                              reason=MESSAGES[category], deep_link=_link(host_id), minimum_role='admin', now=now)
    N, R = notifications.NotificationEvent, notifications.NotificationRevision
    active = session.execute(select(N.subject_id).join(R, (R.event_id == N.id) & (R.revision == N.revision)).where(
        N.source == SOURCE, N.kind == KIND, N.subject_type == SUBJECT, R.lifecycle == 'active')).scalars().all()
    for host_id in active:
        if host_id in stalled:
            continue
        notifications.publish(session, source=SOURCE, kind=KIND, subject_type=SUBJECT, subject_id=host_id,
                              host_id=host_id, subject_revision='resolved', severity='info', reason=RESOLVED,
                              deep_link=_link(host_id), minimum_role='admin', lifecycle='resolved', now=now)
    return set(stalled)
