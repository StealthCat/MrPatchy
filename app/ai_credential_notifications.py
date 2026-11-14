"""Administrator notification while the saved AI API key cannot be used locally.

Every paid AI path (process triage, update scoring, plans, release planning and
model tests) decrypts the saved key immediately before sending a request. When
AI is enabled but that key row is missing, malformed or cannot be decrypted with
the current controller encryption key (for example after restoring a database
onto a different ``secret.key``), each path fails before any provider request
and before any spend reservation. Without this producer, triage reported the
failure as a provider-side rejection and update scoring failed silently.

This producer reads state only. It never retries, unblocks, reserves spend,
calls a provider or changes authorization, and it adds no SMTP/webhook alert.
The notification text is fixed: no ciphertext, plaintext, exception text, path
or evidence is recorded.
"""
import hashlib

from sqlalchemy import select

from . import notifications
from .db import Setting
from .security import unseal

IDENTITY = dict(source='ai-credential', kind='unreadable-key',
                subject_type='ai-credential', subject_id='saved-ai-key')
LINK = '#settings/ai'
MISSING = ('Central AI is enabled, but no API key is saved. Every paid AI call, including triage, update scoring '
           'and plans, stops before sending. No provider request is sent and no spend is reserved. Save the API key '
           'in Settings → AI & models, or disable AI.')
UNREADABLE = ('Central AI is enabled, but the saved API key cannot be decrypted with this controller\'s encryption '
              'key, for example after restoring a database without its matching secret.key. Every paid AI call, '
              'including triage, update scoring and plans, stops before sending. No provider request is sent and no '
              'spend is reserved. Restore the matching encryption key, or save the API key again in Settings → '
              'AI & models. A key saved again is encrypted with the current key.')
RESOLVED = 'The saved AI API key is readable again, or central AI is disabled.'


def state(session):
    """Return ``(code, revision)`` for the saved key: ``ok``, ``missing`` or ``unreadable``.

    The revision is a re-hashed digest of the stored ciphertext, never the
    ciphertext itself, so a newly saved key that also fails is distinguishable.
    """
    row = session.get(Setting, 'openai_key')
    if row is None:
        return 'missing', 'missing'
    value = row.value
    encrypted = value.get('encrypted') if isinstance(value, dict) else None
    if not isinstance(encrypted, str) or not encrypted:
        return 'unreadable', 'malformed'
    digest = hashlib.sha256(('ai-credential-notification-v1\0' + encrypted).encode()).hexdigest()[:32]
    try:
        plaintext = unseal(encrypted)
    except Exception:  # noqa: BLE001 - any local decryption failure means the key is unusable
        return 'unreadable', digest
    if not plaintext:
        return 'unreadable', digest
    return 'ok', digest


def publish(session, cfg, now):
    """Publish or resolve the admin event in the caller's transaction. Returns True while unusable."""
    code, revision = state(session) if cfg.get('ai_enabled') else ('ok', '')
    if code != 'ok':
        notifications.publish(session, **IDENTITY, subject_revision=code + ':' + revision, severity='high',
                              reason=MISSING if code == 'missing' else UNREADABLE, deep_link=LINK,
                              minimum_role='admin', now=now)
        return True
    event = session.scalar(select(notifications.NotificationEvent).where(
        *(getattr(notifications.NotificationEvent, key) == value for key, value in IDENTITY.items())))
    if event is not None:
        current = session.get(notifications.NotificationRevision, (event.id, event.revision))
        if current is None or current.lifecycle != 'resolved':
            notifications.publish(session, **IDENTITY, subject_revision='resolved', severity='info',
                                  reason=RESOLVED, deep_link=LINK, minimum_role='admin',
                                  lifecycle='resolved', now=now)
    return False
