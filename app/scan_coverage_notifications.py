"""Administrator notification when scheduled malware scanning has no current conclusion (#816).

Servers with scheduled scanning enabled (``security-policy:<host>``) are scanned
by ``incidents.schedule_tick``. When the latest scheduled-engine scan fails,
finishes with incomplete coverage, loses its receipt or stops arriving, the
fleet Security coverage page shows it, but nothing reached the bell or the
SMTP/webhook outbox. Administrators who rely on scheduled scans only learned of
the gap by opening that page.

This producer runs on the coordinator alert tick and publishes one admin-only
in-app event per server. It classifies the latest ``security-scan`` job and its
own receipt with ``security_coverage.assessment``, the same assessment the
coverage page uses:

- ``failed``: the latest scan job failed, was blocked or was interrupted.
- ``incomplete``: the receipt is missing, or it records gaps, an unavailable
  engine, stale or unverifiable signatures, or malformed coverage metadata.
- ``overdue``: no scan has completed for longer than the configured interval
  plus the notification grace period (one hour unless the policy sets
  ``notify_grace_hours``, 1 to 168, #1182), for example because the scheduler is paused by
  a response hold, a recovery-required operation or a full queue.
- ``stalled``: the latest scan job has been queued or running for longer than
  the configured interval plus the grace period (#839). The scheduler does not
  enqueue another scan while one is pending, so a stuck job would otherwise
  hold the event silent indefinitely.
- A server that has never been scanned is ``overdue`` once scheduled scanning has
  been enabled (``enabled_since``, recorded when the policy is saved) for longer
  than the interval plus the grace period (#841). Otherwise a scheduler blocker
  present from enablement onward, such as a quarantine, a recovery-required job
  or a full queue, would leave the server silent. Legacy policies saved before
  ``enabled_since`` existed use the time this producer first saw them enabled and
  never scanned instead (#883). That time lives in its own server-managed
  ``security-scan-legacy-since:<host>`` setting, so the administrator's policy row
  is never rewritten, and it is never earlier than that first observation.
- Re-enabling scheduled scanning restarts ``enabled_since``, and a server that
  returns to the active set after being disabled or re-enrolling restarts its own
  server-managed ``security-scan-resumed:<host>`` clock (#1043). ``overdue`` then
  waits for the interval plus the grace period from the later of the two, so an
  old last scan does not publish while the scheduler is held right after the
  return. A missing clock (upgrades, continuously active servers) adds no delay.

A younger pending scan leaves an existing event unchanged. Recorded scans resolve it,
and so do scans with findings, because the ``malware-detection`` incident
producer owns those. Disabling scheduled scanning, or disabling, deleting or
re-enrolling the server, also resolves the event.

Apart from that legacy first-observed marker, it only reads state. Reason text is fixed per category and never carries paths,
rule names, engine output, errors or timestamps. It never enqueues, retries or
cancels scans, changes patching state, or acknowledges, remediates or
authorizes anything.
"""
import math
from fractions import Fraction

from sqlalchemy import func, select

from . import host_lifecycle, notifications
from .db import Job, Setting
from .incidents import Scan
from .security_coverage import assessment

SOURCE = 'security-scan'
KIND = 'scheduled-scan-coverage'
SUBJECT = 'server'
GRACE_SECONDS = 3600
DEFAULT_GRACE_HOURS = 1
MAX_GRACE_HOURS = 168
DEFAULT_INTERVAL_HOURS = 24
CHUNK = 500
# Server-managed first observation of an enabled, never-scanned legacy policy (#883). The prefix must not start
# with ``security-policy:``, which the scheduler and coverage page enumerate.
LEGACY_PREFIX = 'security-scan-legacy-since:'
# Server-managed resume clock (#1043): ``{"inactive": true}`` while a server with an enabled policy is outside the
# active set, then ``{"active_since": <epoch>}`` for one interval plus grace after it returns. Same prefix rule.
RESUME_PREFIX = 'security-scan-resumed:'
MESSAGES = {
    'failed': ('The latest scheduled malware scan on this server failed, was blocked or was interrupted, so there is '
               'no current scan conclusion. Review the scan operation in Security and Activity. Missing coverage is '
               'not a clean-host or compromise verdict.'),
    'incomplete': ('The latest scheduled malware scan on this server finished without complete coverage. The receipt '
                   'is missing or reports skipped paths, an unavailable scanner, stale signatures or invalid coverage '
                   'metadata. Review Security scan coverage. Missing coverage is not a clean-host or compromise '
                   'verdict.'),
    'stalled': ('A scheduled malware scan on this server has been queued or running for longer than its configured '
                'interval plus one hour, and no new scheduled scan starts while it is pending. Workers may be '
                'unavailable or the operation may need recovery. Review Activity and Security. Missing coverage is '
                'not a clean-host or compromise verdict.'),
    'overdue': ('Scheduled malware scanning on this server has not completed a scan within its configured interval '
                'plus one hour. Response holds, operations awaiting recovery or a full queue can pause the scheduler. '
                'Review Security and Activity. Missing coverage is not a clean-host or compromise verdict.'),
}
RESOLVED = 'Scheduled malware scanning on this server no longer needs administrator attention.'
# Assessment states that keep an existing event unchanged instead of resolving it.
WAITING = {'pending'}
CATEGORIES = {'attempt_failed': 'failed', 'incomplete': 'incomplete', 'receipt_missing': 'incomplete'}


def _interval_hours(policy):
    hours = policy.get('interval_hours', DEFAULT_INTERVAL_HOURS)
    return hours if type(hours) is int and 1 <= hours <= 720 else DEFAULT_INTERVAL_HOURS


def _grace_hours(policy):
    """Return the administrator's notification grace in hours (#1182); anything invalid keeps one hour."""
    hours = policy.get('notify_grace_hours', DEFAULT_GRACE_HOURS)
    return hours if type(hours) is int and 1 <= hours <= MAX_GRACE_HOURS else DEFAULT_GRACE_HOURS


def _limit(policy):
    """Return the configured interval plus the notification grace, in seconds."""
    return _interval_hours(policy) * 3600 + _grace_hours(policy) * 3600


def message(category, policy):
    """Return the fixed reason for ``category``. The default grace keeps the original text byte for byte."""
    text = MESSAGES[category]
    hours = _grace_hours(policy)
    if hours == DEFAULT_GRACE_HOURS or category not in ('stalled', 'overdue'):
        return text
    return text.replace('plus one hour', 'plus its %d-hour notification grace period' % hours)


def classify(scan, attempt, policy, now):
    """Return ``'failed'``, ``'incomplete'``, ``'overdue'``, ``'stalled'``, ``'pending'`` or ``None``."""
    hours = _interval_hours(policy)
    limit = _limit(policy)
    result = assessment(scan, attempt, now, hours * 3600)
    state = result['state']
    if state in WAITING:
        return 'stalled' if now - attempt.created > limit else 'pending'
    if state in CATEGORIES:
        return CATEGORIES[state]
    if state == 'overdue' and result['age_seconds'] is not None and result['age_seconds'] > limit:
        # A valid clock that started within the limit (scanning or the server was just re-enabled, #1043) holds
        # the old scan's overdue state until the scheduler has had the same interval plus grace.
        if not 0 <= _enabled_age(policy, now) <= limit:
            return 'overdue'
        return None
    if state == 'never_scanned' and _enabled_age(policy, now) > limit:
        return 'overdue'
    # A recently enabled never_scanned policy (the scheduler has not started yet), legacy policies without
    # ``enabled_since`` or a first-observed marker, recorded scans and findings need no coverage event.
    return None


def _valid_time(value, now):
    return type(value) in (int, float) and math.isfinite(value) and value <= now


def _enabled_age(policy, now):
    since = policy.get('enabled_since')
    if not _valid_time(since, now):
        return -1
    return now - since


def whole_microseconds(seconds):
    """Return ``seconds`` truncated to whole microseconds, never later than ``seconds`` (#942).

    ``math.floor(seconds * 1_000_000)`` is not safe at epoch magnitudes: the product is near 1.8e15, where doubles
    are 0.25 apart, so it can round up to the next microsecond and store a marker after ``now``. The exact rational
    product avoids that, and dividing the integer by 10**6 gives the nearest double to that decimal, at most ``seconds``.
    """
    return math.floor(Fraction(seconds) * 1_000_000) / 1_000_000


def _legacy_markers(session, policies, attempts, now):
    """Return policies with a conservative ``enabled_since`` for enabled, never-scanned legacy policies (#883).

    The first tick that sees such a policy records ``now`` under its own key, so the administrator's policy row is
    never rewritten and a concurrent policy save cannot be lost. Markers are removed once the policy carries its
    own ``enabled_since``, is disabled or removed, the server gets a scan attempt, or the server leaves the active
    set. A marker with an invalid or future time is replaced by ``now``.
    """
    legacy = [host_id for host_id, policy in policies.items()
              if host_id not in attempts and not _valid_time(policy.get('enabled_since'), now)]
    wanted = {LEGACY_PREFIX + host_id: host_id for host_id in legacy}
    existing = {row.key: row for row in session.scalars(select(Setting).where(Setting.key.like(LEGACY_PREFIX + '%')))}
    for key, row in existing.items():
        if key not in wanted:
            session.delete(row)
    effective = dict(policies)
    for key, host_id in wanted.items():
        row = existing.get(key)
        since = row.value.get('first_seen') if row and isinstance(row.value, dict) else None
        if not _valid_time(since, now):
            # Whole microseconds keep the stored JSON double exact on MySQL, as for ``enabled_since``.
            since = whole_microseconds(now)
            if row:
                row.value = {'first_seen': since}
            else:
                session.add(Setting(key=key, value={'first_seen': since}))
        effective[host_id] = {**policies[host_id], 'enabled_since': since}
    return effective


def _active(host):
    return host_lifecycle.active(host) and host.state != 'enrolling'


def _enabled_policies(session, hosts):
    """Return ``(active, inactive)`` enabled policies for non-deleted servers."""
    by_id = {host.id: host for host in hosts if not host.deleted_at}
    active, inactive = {}, {}
    ids = list(by_id)
    for start in range(0, len(ids), CHUNK):
        keys = ['security-policy:' + host_id for host_id in ids[start:start + CHUNK]]
        for row in session.scalars(select(Setting).where(Setting.key.in_(keys))):
            if isinstance(row.value, dict) and row.value.get('enabled') is True:
                host_id = row.key.split(':', 1)[1]
                (active if _active(by_id[host_id]) else inactive)[host_id] = row.value
    return active, inactive


def _resume_markers(session, policies, inactive, now):
    """Apply each returning server's resume clock to its policy's ``enabled_since`` (#1043).

    A server with an enabled policy outside the active set is marked inactive. When it is next seen active the
    marker becomes ``active_since = now``, and the later of that and ``enabled_since`` starts the coverage clock.
    Markers are written only on these transitions and removed once the clock is older than the interval plus
    grace, or when the policy is disabled or removed or the server is deleted. A server never seen inactive has
    no marker, so upgrades and continuously active servers keep the existing schedule.
    """
    existing = {row.key: row for row in session.scalars(select(Setting).where(Setting.key.like(RESUME_PREFIX + '%')))}
    effective = dict(policies)
    for key, row in existing.items():
        host_id = key[len(RESUME_PREFIX):]
        if host_id in inactive:
            continue
        value = row.value if isinstance(row.value, dict) else {}
        if host_id not in policies:
            session.delete(row)
            continue
        since = value.get('active_since')
        if value.get('inactive') is True or not _valid_time(since, now):
            since = whole_microseconds(now)
            row.value = {'active_since': since}
        policy = policies[host_id]
        if now - since > _limit(policy):
            session.delete(row)
            continue
        enabled = policy.get('enabled_since')
        if _valid_time(enabled, now) and enabled >= since:
            continue
        effective[host_id] = {**policy, 'enabled_since': since}
    for host_id in inactive:
        row = existing.get(RESUME_PREFIX + host_id)
        if not row:
            session.add(Setting(key=RESUME_PREFIX + host_id, value={'inactive': True}))
        elif row.value != {'inactive': True}:
            row.value = {'inactive': True}
    return effective


def _latest_attempts(session, ids):
    latest = {}
    for start in range(0, len(ids), CHUNK):
        chunk = ids[start:start + CHUNK]
        ranked = select(Job.id, func.row_number().over(
            partition_by=Job.host_id, order_by=(Job.created.desc(), Job.id)).label('rank')).where(
            Job.host_id.in_(chunk), Job.action == 'security-scan').subquery()
        for job in session.scalars(select(Job).where(Job.id.in_(select(ranked.c.id).where(ranked.c.rank == 1)))):
            latest[job.host_id] = job
    return latest


def _link(host_id):
    return '#servers/' + host_id + '/security'


def publish(session, hosts, now):
    """Publish or resolve coverage events in the caller's transaction. Returns ``{host_id: category}``."""
    policies, inactive = _enabled_policies(session, hosts)
    attempts = _latest_attempts(session, list(policies))
    policies = _legacy_markers(session, policies, attempts, now)
    policies = _resume_markers(session, policies, inactive, now)
    scans = {}
    scan_ids = [job.id for job in attempts.values()]
    for start in range(0, len(scan_ids), CHUNK):
        for scan in session.scalars(select(Scan).where(Scan.id.in_(scan_ids[start:start + CHUNK]))):
            scans[scan.id] = scan
    attention, waiting = {}, set()
    for host_id, policy in policies.items():
        attempt = attempts.get(host_id)
        category = classify(scans.get(attempt.id) if attempt else None, attempt, policy, now)
        if category == 'pending':
            waiting.add(host_id)
        elif category:
            attention[host_id] = category
    for host_id, category in attention.items():
        notifications.publish(session, source=SOURCE, kind=KIND, subject_type=SUBJECT, subject_id=host_id,
                              host_id=host_id, subject_revision=category, severity='medium',
                              reason=message(category, policies[host_id]), deep_link=_link(host_id), minimum_role='admin', now=now)
    N, R = notifications.NotificationEvent, notifications.NotificationRevision
    active = session.execute(select(N.subject_id).join(R, (R.event_id == N.id) & (R.revision == N.revision)).where(
        N.source == SOURCE, N.kind == KIND, N.subject_type == SUBJECT, R.lifecycle == 'active')).scalars().all()
    for host_id in active:
        if host_id in attention or host_id in waiting:
            continue
        notifications.publish(session, source=SOURCE, kind=KIND, subject_type=SUBJECT, subject_id=host_id,
                              host_id=host_id, subject_revision='resolved', severity='info', reason=RESOLVED,
                              deep_link=_link(host_id), minimum_role='admin', lifecycle='resolved', now=now)
    return attention
