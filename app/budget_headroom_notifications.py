"""In-app notice when daily-cap headroom is below the smallest possible paid call (#819).

In a capped AI mode, counted spend can stay below the cap while the remaining
headroom is too small for any Mr Patchy provider call. Capped admission then
defers every paid AI call until the reset, but the exhausted notification needs
counted spend to reach the cap and the advance warning needs a fixed fraction of
it, so with a small cap nothing explained the stall.

``minimum_call_reservation`` quotes a payload that is never larger than a real
billable request: the smallest bounded output any path uses (the process
investigation), an empty input and the default tier, which every current path
uses. ``ai_pricing.reservation`` is monotonic in input bytes and output tokens,
so every real call's conservative quote is at least this amount. A path that
adds a smaller output bound or a cheaper processing tier must lower this floor.

Read-only: this never reserves, releases or authorizes spend, never changes
admission and adds no SMTP/webhook alert. It runs in the caller's transaction.
"""
from datetime import datetime, timezone
from decimal import Decimal
import hashlib

from sqlalchemy import select

from . import ai_budget, ai_pricing, notifications
from .notifications import NotificationEvent, NotificationRevision

NOTIFICATION = dict(source='ai-budget', kind='daily-cap-headroom', subject_type='daily-cap',
                    subject_id='shared-daily-ai-spend')
RESOLVED = ('Remaining shared daily AI spend headroom no longer blocks every paid call: the headroom fits, the '
            'window reset, the cap or mode changed, AI was disabled, the cap was reached (its own notification '
            'applies) or the saved model cannot be priced (its own notification applies).')


def minimum_call_reservation(model, now=None):
    """Return the ``ai_pricing.reservation`` result for the smallest possible paid call."""
    from .ai import INVESTIGATION_TOKENS
    return ai_pricing.reservation({'model': model, 'max_output_tokens': INVESTIGATION_TOKENS, 'input': ''}, now)


def _current(session):
    event = session.scalar(select(NotificationEvent).where(
        *(getattr(NotificationEvent, key) == value for key, value in NOTIFICATION.items())))
    return session.get(NotificationRevision, (event.id, event.revision)) if event is not None else None


def publish(session, cfg, now):
    """Publish or resolve the headroom notice. Returns True while it is active."""
    model = cfg.get('ai_model') or ''
    if cfg.get('ai_enabled') and model and cfg['ai_control_mode'] in ai_pricing.CAP_MODES:
        floor = minimum_call_reservation(model, now)
        enabled, name, _start, reset, _groups, counted, cap, _rec = ai_budget._state(session, cfg, now)
        # An unpriced model or stale catalog has its own notification; a reached cap has its own.
        if enabled and floor['ok'] and counted < cap and cap - counted < floor['amount_usd']:
            binding = '\n'.join((name, repr(float(reset)), ai_budget._money(cap), ai_pricing.VERSION,
                                 hashlib.sha256(model.encode('utf-8')).hexdigest()))
            subject_revision = 'headroom:' + hashlib.sha256(binding.encode('utf-8')).hexdigest()
            current = _current(session)
            # Amounts are recorded when the notice is raised; an active notice for the same
            # window, cap, catalog and model is left unchanged rather than republished.
            if current is None or current.lifecycle != 'active' or current.subject_revision != subject_revision:
                reset_text = datetime.fromtimestamp(reset, timezone.utc).isoformat().replace('+00:00', 'Z')
                remaining = max(cap - counted, Decimal(0))
                message = ('Only $' + ai_budget._money(remaining) + ' of the shared daily AI spend cap of $' +
                    ai_budget._money(cap) + ' (' + name + ' day) remains, less than the smallest conservative '
                    'reservation of $' + ai_budget._money(floor['amount_usd']) + ' that any paid AI call with the '
                    'saved model needs. Every new paid AI call, including triage, scoring and plans, is deferred, '
                    'not discarded, until the reset at ' + reset_text + ' or until an administrator changes the cap '
                    'or mode. These amounts were recorded when this notice was raised; Settings shows current totals. '
                    'Counted spend conservatively includes reserved and uncertain charges; it is a local estimate, '
                    'not a provider invoice.')
                notifications.publish(session, **NOTIFICATION, subject_revision=subject_revision,
                                      severity='medium', reason=message, deep_link='#settings/ai',
                                      minimum_role='admin', now=now)
            return True
    current = _current(session)
    if current is not None and current.lifecycle != 'resolved':
        notifications.publish(session, **NOTIFICATION, subject_revision='resolved', severity='info',
                              reason=RESOLVED, deep_link='#settings/ai', minimum_role='admin',
                              lifecycle='resolved', now=now)
    return False
