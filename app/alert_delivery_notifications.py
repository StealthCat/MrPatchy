"""Administrator notification while external SMTP/webhook alert delivery keeps failing.

``operations.deliver_one()`` retries each open alert with backoff and keeps only a
sanitized error class. If the configured channel is broken, nothing outside the
Operations panel shows it, so administrators who rely on email or a webhook can
miss every alert. This producer publishes one admin-only in-app event while open,
undelivered alerts have repeatedly failed, and resolves it when that clears.

It only reads state. It never sends, retries, changes backoff or acknowledges
alerts. It adds no ``Alert`` row of its own, so a broken channel cannot recurse.
The reason text is fixed per channel and never carries alert text, URLs, tokens,
recipients or error strings.
"""
import json

from sqlalchemy import func, select

from . import notifications
from .db import Setting
from .security import unseal

FAILED_ATTEMPTS = 3
IDENTITY = dict(source='alert-delivery', kind='delivery-failing',
                subject_type='alert-delivery', subject_id='external')
CHANNELS = {
    'smtp': 'SMTP email',
    'webhook': 'webhook',
}
MESSAGE = ('External {channel} alert delivery keeps failing: at least one open alert has failed {attempts} or more '
           'delivery attempts and has not been delivered. Administrators may not be receiving server alerts outside '
           'Mr Patchy. Review Account → Operations for the per-alert delivery error and the delivery configuration. '
           'Delivery is still retried with backoff; this notice does not send, acknowledge or resolve any alert.')
RESOLVED = 'External alert delivery no longer has repeatedly failing undelivered alerts.'


def delivery_channel(session):
    """Return ``'smtp'``, ``'webhook'``, ``None`` (disabled or absent) or ``'unknown'`` (unreadable)."""
    setting = session.get(Setting, 'notifications')
    if not setting:
        return None
    try:
        cfg = json.loads(unseal(setting.value['encrypted']))
    except Exception:  # Any local decryption/format failure means the configuration is unreadable.
        return 'unknown'
    if not isinstance(cfg, dict) or not cfg.get('enabled'):
        return None
    return 'smtp' if cfg.get('channel') == 'smtp' else 'webhook'


def failing_count(session):
    """Open alerts not yet delivered whose repeated attempts all recorded an error."""
    from .operations import Alert
    return session.scalar(select(func.count()).select_from(Alert).where(
        Alert.state == 'open', Alert.notified == 0, Alert.attempts >= FAILED_ATTEMPTS, Alert.error != ''))


def publish(session, now):
    """Publish or resolve the admin event in the caller's transaction. Returns True while failing."""
    channel = delivery_channel(session)
    if channel is not None and failing_count(session):
        label = CHANNELS.get(channel, 'SMTP/webhook')
        notifications.publish(session, **IDENTITY, subject_revision='failing:' + (channel if channel in CHANNELS else 'unknown'),
                              severity='high', reason=MESSAGE.format(channel=label, attempts=FAILED_ATTEMPTS),
                              minimum_role='admin', now=now)
        return True
    event = session.scalar(select(notifications.NotificationEvent).where(
        *(getattr(notifications.NotificationEvent, key) == value for key, value in IDENTITY.items())))
    if event is not None:
        current = session.get(notifications.NotificationRevision, (event.id, event.revision))
        if current is None or current.lifecycle != 'resolved':
            notifications.publish(session, **IDENTITY, subject_revision='resolved', severity='info',
                                  reason=RESOLVED, minimum_role='admin', lifecycle='resolved', now=now)
    return False
