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
- A ``failed`` AI response-plan job (``security-plan``/``startup-plan``,
  #806) follows the same failure/resolution rules, but only administrators
  see it, because only administrators request and review plans. A controlled
  AI wait (budget, pacing, provider backoff or pause) keeps the job queued and
  publishes nothing. An automatic proposal that the worker skips before any AI
  call, because the policy was turned off or the incident evidence changed,
  is a superseded attempt rather than a failure and publishes nothing.

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
PLAN_ACTIONS = {
    'security-plan': 'AI security incident response planning',
    'startup-plan': 'AI startup-change response planning',
}
PLAN_MINIMUM_ROLE = 'admin'
# Fixed worker refusals for automatic proposals that never reach the provider.
AUTOMATIC_PLAN_DISABLED = 'Automatic AI planning is disabled; no AI call sent'
AUTOMATIC_PLAN_STALE = 'Automatic incident evidence changed; no AI call sent'

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


def _skipped_automatic_plan(job):
    return ((job.payload or {}).get('automatic') is True
            and (job.output or '').startswith((AUTOMATIC_PLAN_DISABLED, AUTOMATIC_PLAN_STALE)))


def eligible(job):
    if not job or not job.host_id:
        return False
    if job.action in PLAN_ACTIONS:
        return not _skipped_automatic_plan(job)
    return job.action in ACTIONS and not (job.action == 'patch' and (job.payload or {}).get('_schedule'))


def publish_outcome(session, job, *, now=None):
    """Publish or resolve the failure event for one finished job.

    Returns whether a revision was created. The caller owns the transaction.
    """
    from .db import Host
    if not eligible(job) or session.get(Host, job.host_id) is None:
        return False
    plan = job.action in PLAN_ACTIONS
    label = PLAN_ACTIONS[job.action] if plan else ACTIONS[job.action]
    common = dict(source=SOURCE, kind=job.action, subject_type=SUBJECT_TYPE,
                  subject_id=job.host_id, host_id=job.host_id, deep_link=_link(job),
                  minimum_role=PLAN_MINIMUM_ROLE if plan else MINIMUM_ROLE, now=now)
    if job.state == 'failed':
        reason = (label + ' failed on this server, so no response plan was proposed. Nothing ran '
                  'on the server. Open the operation for its error, then request a new plan after '
                  'fixing the cause; automatic planning only retries for new incident evidence.'
                  if plan else
                  label + ' failed on this server. Open the operation for its error and any '
                  'receipt. Nothing is retried automatically.')
        _, created = notifications.publish(
            session, subject_revision='failed:' + job.id, severity='medium', reason=reason, **common)
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
