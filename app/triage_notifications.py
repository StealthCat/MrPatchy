"""In-app notifications for significant AI process-triage verdicts.

The producer runs inside the transaction that persists the verdict, so a
rolled-back save never announces anything. Payloads carry only fixed text and
identifiers: executable paths and model output stay on the Investigations
page, where they are rendered with escaping and full context.

Significance policy (advisory only):

- ``high`` and ``medium`` provider verdicts publish an active event with the
  matching severity. An unchanged risk adds no revision; a change in risk adds
  one, so escalations resurface as unread.
- ``low`` (provider or exact known-good reuse) resolves an existing active
  event and otherwise publishes nothing, so safe cache hits cause no storm.
- ``unknown`` and any other state leave the event unchanged.
- An administrator approval resolves an active event in the approval's own
  transaction. Revoking that approval while the verdict is still significant
  re-publishes the event as active.

Notifications never approve a behavior, acknowledge anything or authorize a
response.
"""

from . import notifications

SOURCE = 'ai-triage'
KIND = 'process-verdict'
SUBJECT_TYPE = 'behavior'
SIGNIFICANT = {'high': 'high', 'medium': 'medium'}


def _link(host_id):
    return '#servers/' + host_id + '/investigations'


def _active(session, behavior):
    event = session.get(notifications.NotificationEvent, notifications._event_id(
        SOURCE, KIND, SUBJECT_TYPE, behavior.id, behavior.host_id))
    if not event:
        return None
    current = session.get(notifications.NotificationRevision, (event.id, event.revision))
    return current if current and current.lifecycle == 'active' else None


def publish_verdict(session, behavior, *, now=None):
    """Publish or resolve the triage notification for ``behavior``'s verdict.

    The caller owns the surrounding transaction. Returns ``True`` when a new
    notification revision was added.
    """
    risk = behavior.verdict
    common = dict(source=SOURCE, kind=KIND, subject_type=SUBJECT_TYPE,
                  subject_id=behavior.id, host_id=behavior.host_id,
                  deep_link=_link(behavior.host_id), minimum_role='viewer', now=now)
    if risk in SIGNIFICANT:
        _, created = notifications.publish(
            session, subject_revision='risk:' + risk, severity=SIGNIFICANT[risk],
            reason=('AI triage rated an observed process behavior as ' + risk
                    + ' risk. The assessment is advisory: review the evidence on the '
                    'server Investigations tab. It does not approve the behavior or '
                    'authorize any response.'),
            **common)
        return created
    if risk == 'low' and _active(session, behavior):
        _, created = notifications.publish(
            session, subject_revision='risk:low', severity='info',
            reason=('A later AI triage rated this behavior as low risk. The earlier '
                    'significant verdict no longer needs attention; the assessment '
                    'remains advisory.'),
            lifecycle='resolved', **common)
        return created
    return False


def publish_approval(session, behavior, *, now=None):
    """Reflect an administrator approval change in the triage notification.

    The approval itself is the source of the change; the notification never
    grants or withdraws it. The caller owns the surrounding transaction.
    Returns ``True`` when a new notification revision was added.
    """
    if not behavior.approved:
        return publish_verdict(session, behavior, now=now)
    if not _active(session, behavior):
        return False
    _, created = notifications.publish(
        session, source=SOURCE, kind=KIND, subject_type=SUBJECT_TYPE,
        subject_id=behavior.id, host_id=behavior.host_id,
        deep_link=_link(behavior.host_id), minimum_role='viewer', now=now,
        subject_revision='approved', severity='info',
        reason=('An administrator approved this exact behavior. The earlier '
                'significant AI verdict no longer needs attention; the assessment '
                'remains advisory and this notification authorizes nothing.'),
        lifecycle='resolved')
    return created
