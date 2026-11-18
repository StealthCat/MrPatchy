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
"""
import logging

from . import ai_control_preview
from .db import Session, Setting, audit, config

log = logging.getLogger(__name__)

ACTION = 'migrate AI admission controls'


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
                return 'refused'
            proposed = current | plan['proposal']
            s.merge(Setting(key='config', value=stored | plan['proposal']))
            audit(s, ACTION, 'Automatically moved never-reviewed legacy AI admission to the shared smooth rate of '
                  f'{plan["proposal"]["ai_rate_per_hour"]}/hour; hourly start ceilings before: {_ceilings(current)}; '
                  f'after: {_ceilings(proposed)}. No admission or spend control was expanded; '
                  'stored legacy limits are retained and no provider call was made')
            s.commit()
            log.info('Migrated legacy AI admission to shared rate %s/hour', plan['proposal']['ai_rate_per_hour'])
            return 'migrated'
