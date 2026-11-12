"""In-app notifications for failed server-changing operations (roadmap J, #731).

The producer runs in the transaction that records the job's final state, so a
rolled-back state change never announces anything. Payloads carry only fixed
text and identifiers: job output and errors may contain endpoint text, so they
stay on the escaped operation detail page behind the deep link.

Policy:

- A ``failed`` operator-initiated patch, repository, signing-key, repair,
  release-upgrade or agent-update job publishes an active event, one per
  server and action. A later failure of the same action appends a revision, so
  it is unread again and links to the newest failed operation.
- A later ``complete`` job of the same action on that server resolves an active
  event. A success with no active event publishes nothing.
- Scheduled patch runs are covered by the ``scheduled patching`` operational
  alert, and ``recovery_required`` jobs by the ``recovery`` alert, so neither
  publishes here. Other actions publish nothing.

Notifications never retry, acknowledge, reconcile or authorize anything.
"""
import logging

from . import notifications

SOURCE = 'operations'
SUBJECT_TYPE = 'operation'
MINIMUM_ROLE = 'operator'
ACTIONS = {
    'patch': 'Package update',
    'repository': 'Repository configuration change',
    'key': 'Repository signing-key change',
    'repair': 'Package repair',
    'release-upgrade': 'OS release upgrade',
    'agent-update': 'Agent update',
}

log = logging.getLogger(__name__)


def _link(job):
    return '#activity/jobs/' + job.id


def _active(session, job):
    event = session.get(notifications.NotificationEvent, notifications._event_id(
        SOURCE, job.action, SUBJECT_TYPE, job.host_id, job.host_id))
    if not event:
        return None
    current = session.get(notifications.NotificationRevision, (event.id, event.revision))
    return current if current and current.lifecycle == 'active' else None


def eligible(job):
    return bool(job and job.host_id and job.action in ACTIONS
                and not (job.action == 'patch' and (job.payload or {}).get('_schedule')))


def publish_outcome(session, job, *, now=None):
    """Publish or resolve the failure event for one finished job.

    Returns whether a revision was created. The caller owns the transaction.
    """
    from .db import Host
    if not eligible(job) or session.get(Host, job.host_id) is None:
        return False
    label = ACTIONS[job.action]
    common = dict(source=SOURCE, kind=job.action, subject_type=SUBJECT_TYPE,
                  subject_id=job.host_id, host_id=job.host_id,
                  deep_link=_link(job), minimum_role=MINIMUM_ROLE, now=now)
    if job.state == 'failed':
        _, created = notifications.publish(
            session, subject_revision='failed:' + job.id, severity='medium',
            reason=label + ' failed on this server. Open the operation for its error and any '
                   'receipt. Nothing is retried automatically.', **common)
        return created
    if job.state == 'complete' and _active(session, job):
        _, created = notifications.publish(
            session, subject_revision='complete:' + job.id, severity='info',
            reason='A later ' + label[0].lower() + label[1:] + ' completed on this server.',
            lifecycle='resolved', **common)
        return created
    return False


def publish_outcome_safely(session, job):
    """Never let a notification problem change the job's recorded outcome."""
    try:
        with session.begin_nested():
            return publish_outcome(session, job)
    except Exception:
        log.exception('Operation outcome notification failed for job %s', getattr(job, 'id', '?'))
        return False
