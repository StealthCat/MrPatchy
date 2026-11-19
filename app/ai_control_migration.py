"""One-time unattended migration of never-reviewed legacy AI admission controls (#1039).

Installations whose stored configuration predates ``ai_control_mode`` are read as
``legacy`` by :func:`app.db.config`. They keep the hidden burst-then-stop hourly
allowances (process triage, update scoring and the fixed automatic-plan allowance).
At startup this module moves such an installation once to the shared smooth
``rate`` mode at :func:`app.ai_control_preview.legacy_migration`'s proposal: the
lowest enabled legacy per-purpose ceiling. That proposal is applied only when the same
comparison used by Settings and the save audit reports no expansion, so no purpose
can start more work per hour than before and no spend control is relaxed.

An administrator who explicitly saved ``legacy`` (the key is present) keeps it.
Fresh installations with no stored configuration already default to ``rate``.
Stored legacy limits are preserved; only the mode and shared rate are written.

Both outcomes also publish an admin-only in-app notification (#1178): an ``info``
record when the migration is applied, written in the migration transaction, and a
``medium`` event when the proposal is refused, which :func:`publish` resolves once an
administrator saves an explicit mode. Notifications never change admission, spend or
authorization, call no provider and add no SMTP/webhook alert.
"""
import logging

from sqlalchemy import select

from . import ai_control_preview, notifications
from .db import Session, Setting, audit, config

log = logging.getLogger(__name__)

ACTION = 'migrate AI admission controls'
LINK = '#settings/ai'
MIGRATED = dict(source='ai-admission', kind='legacy-migrated', subject_type='ai-admission',
                subject_id='legacy-migration')
REFUSED = dict(source='ai-admission', kind='legacy-migration-refused', subject_type='ai-admission',
               subject_id='legacy-migration')
REFUSED_REASON = ('Mr Patchy did not migrate this installation\'s never-reviewed legacy AI admission controls, '
                  'because the suggested shared rate would expand admission or spend. Nothing was changed: the '
                  'hidden burst-then-stop hourly allowances remain in effect. Review the suggestion in Settings → '
                  'AI & models, preview it, and save an explicit admission mode.')
RESOLVED_REASON = ('An explicit AI admission mode is now saved, by an administrator or a later startup migration; '
                   'the refused legacy migration no longer applies.')


def _notify(session, identity, **fields):
    """Publish in the caller's transaction; a rejected payload never blocks the migration.

    ``notifications.publish`` validates before adding rows, so a rejection leaves the
    session untouched.
    """
    try:
        notifications.publish(session, **identity, deep_link=LINK, minimum_role='admin', **fields)
    except ValueError:
        log.warning('Skipped the in-app notification for the AI admission migration')


def publish(session, now=None):
    """Resolve an active refused-migration event once the stored config has an explicit mode.

    Called from each ``collect_alerts`` pass. Reads state only; it never migrates,
    expands admission, reserves spend or calls a provider.
    """
    event = session.scalar(select(notifications.NotificationEvent).where(
        *(getattr(notifications.NotificationEvent, key) == value for key, value in REFUSED.items())))
    if event is None:
        return False
    current = session.get(notifications.NotificationRevision, (event.id, event.revision))
    if current is not None and current.lifecycle == 'resolved':
        return False
    item = session.get(Setting, 'config')
    stored = item.value if item is not None and isinstance(item.value, dict) else None
    if stored is not None and 'ai_control_mode' not in stored:
        return True  # still implicit legacy: keep the refusal visible
    _notify(session, REFUSED, subject_revision='resolved', severity='info', reason=RESOLVED_REASON,
            lifecycle='resolved', now=now)
    return False


def _ceilings(values):
    starts = ai_control_preview.ceilings(values)['hourly_starts']
    return ', '.join(f'{key.replace("_", " ")} {value}/hour' for key, value in starts.items())


def migrate_implicit_legacy():
    """Apply the non-expanding shared-rate migration once; return what happened.

    Returns ``'migrated'``, ``'refused'`` (the proposal would expand admission or spend,
    so nothing was written) or ``None`` when there is nothing to migrate. Runs under the
    ``settings-config`` lock that settings saves use and re-reads the stored value, so
    concurrent controllers/workers and racing saves cannot double-apply or clobber it.
    """
    from .coordination import Lock
    with Lock('settings-config'):
        with Session() as s:
            item = s.get(Setting, 'config')
            stored = dict(item.value or {}) if item else None
            if stored is None or 'ai_control_mode' in stored:
                return None
            current = config(s)
            plan = ai_control_preview.legacy_migration(current)
            if plan['proposal_expands']:
                # Defensive: never silently expand. Nothing is written, so the Settings
                # suggestion with explicit preview/confirmation remains the only path.
                log.warning('Legacy AI admission left unchanged: the suggested shared rate would expand: %s',
                            ' '.join(plan['proposal_expansions']))
                _notify(s, REFUSED, subject_revision='refused', severity='medium', reason=REFUSED_REASON)
                s.commit()
                return 'refused'
            proposed = current | plan['proposal']
            s.merge(Setting(key='config', value=stored | plan['proposal']))
            audit(s, ACTION, 'Automatically moved never-reviewed legacy AI admission to the shared smooth rate of '
                  f'{plan["proposal"]["ai_rate_per_hour"]}/hour; hourly start ceilings before: {_ceilings(current)}; '
                  f'after: {_ceilings(proposed)}. No admission or spend control was expanded; '
                  'stored legacy limits are retained and no provider call was made')
            rate = plan['proposal']['ai_rate_per_hour']
            _notify(s, MIGRATED, subject_revision=f'rate:{rate}', severity='info',
                    reason='Mr Patchy moved this installation\'s never-reviewed legacy AI admission controls to the '
                           f'shared smooth rate of {rate} AI starts per hour. No purpose can start more work per '
                           'hour than before, no spend control was relaxed and stored legacy limits are retained. '
                           'Review or change the rate in Settings → AI & models; the audit log lists the '
                           'before and after ceilings.')
            s.commit()
            log.info('Migrated legacy AI admission to shared rate %s/hour', plan['proposal']['ai_rate_per_hour'])
            return 'migrated'
