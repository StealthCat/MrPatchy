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
  plus a one-hour grace period, for example because the scheduler is paused by
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
  ``enabled_since`` existed stay silent until the policy is saved again.

A younger pending scan leaves an existing event unchanged. Recorded scans resolve it,
and so do scans with findings, because the ``malware-detection`` incident
producer owns those. Disabling scheduled scanning, or disabling, deleting or
re-enrolling the server, also resolves the event.

It only reads state. Reason text is fixed per category and never carries paths,
rule names, engine output, errors or timestamps. It never enqueues, retries or
cancels scans, changes patching state, or acknowledges, remediates or
authorizes anything.
"""
import math

from sqlalchemy import func, select

from . import host_lifecycle, notifications
from .db import Job, Setting
from .incidents import Scan
from .security_coverage import assessment

SOURCE = 'security-scan'
KIND = 'scheduled-scan-coverage'
SUBJECT = 'server'
GRACE_SECONDS = 3600
DEFAULT_INTERVAL_HOURS = 24
CHUNK = 500
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


def classify(scan, attempt, policy, now):
    """Return ``'failed'``, ``'incomplete'``, ``'overdue'``, ``'stalled'``, ``'pending'`` or ``None``."""
    hours = _interval_hours(policy)
    limit = hours * 3600 + GRACE_SECONDS
    result = assessment(scan, attempt, now, hours * 3600)
    state = result['state']
    if state in WAITING:
        return 'stalled' if now - attempt.created > limit else 'pending'
    if state in CATEGORIES:
        return CATEGORIES[state]
    if state == 'overdue' and result['age_seconds'] is not None and result['age_seconds'] > limit:
        return 'overdue'
    if state == 'never_scanned' and _enabled_age(policy, now) > limit:
        return 'overdue'
    # A recently enabled never_scanned policy (the scheduler has not started yet), legacy policies without
    # ``enabled_since``, recorded scans and findings need no coverage event.
    return None


def _enabled_age(policy, now):
    since = policy.get('enabled_since')
    if type(since) not in (int, float) or not math.isfinite(since) or since > now:
        return -1
    return now - since


def _enabled_policies(session, hosts):
    by_id = {host.id: host for host in hosts if not host.deleted_at and host_lifecycle.active(host)
             and host.state != 'enrolling'}
    policies = {}
    ids = list(by_id)
    for start in range(0, len(ids), CHUNK):
        keys = ['security-policy:' + host_id for host_id in ids[start:start + CHUNK]]
        for row in session.scalars(select(Setting).where(Setting.key.in_(keys))):
            if isinstance(row.value, dict) and row.value.get('enabled') is True:
                policies[row.key.split(':', 1)[1]] = row.value
    return policies


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
    policies = _enabled_policies(session, hosts)
    attempts = _latest_attempts(session, list(policies))
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
                              reason=MESSAGES[category], deep_link=_link(host_id), minimum_role='admin', now=now)
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
