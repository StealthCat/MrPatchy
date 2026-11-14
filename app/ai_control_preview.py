"""Pure before/after comparison of the shared AI admission and spend controls.

Settings uses this to show what a proposed AI settings change would do before it is
saved, and to record any expansion in the audit trail. It reads nothing, writes
nothing and never contacts a provider. It describes the ceilings Mr Patchy's own
controls enforce; provider limits, finite concurrency, pause, lifecycle, roles and
data sharing apply in every mode and are not modelled here.
"""
from decimal import Decimal, InvalidOperation

from .ai_control_status import AUTO_PLAN_HOURLY_LIMIT

FIELDS = ('ai_control_mode', 'ai_rate_per_hour', 'ai_daily_cap_usd', 'ai_budget_timezone',
          'ai_hourly_limit', 'ai_update_hourly_limit', 'ai_updates_enabled')
RATE_MODES = ('rate', 'rate_and_daily')
CAP_MODES = ('daily_cap', 'rate_and_daily')
MODE_LABELS = {
    'legacy': 'Legacy separate hourly limits',
    'rate': 'Shared smooth rate throttle',
    'daily_cap': 'Daily spend cap',
    'rate_and_daily': 'Rate throttle + daily spend cap',
    'unthrottled': 'Unthrottled by Mr Patchy',
}
PURPOSES = (
    ('triage', 'Process triage'),
    ('update_scoring', 'Update scoring'),
    ('automatic_plans', 'Automatic incident/startup plans'),
)
LIMITATION = ('Preview compares Mr Patchy rate and spend ceilings only. Provider limits, finite concurrency, '
              'global and per-server pause, lifecycle, roles and data sharing still apply in every mode. '
              'Saving through the API without previewing is still accepted and audited.')


def _money(value):
    try:
        return Decimal(str(value)).quantize(Decimal('0.01'))
    except (InvalidOperation, TypeError, ValueError):
        return None


def ceilings(values):
    """Return per-purpose hourly start ceilings and the daily spend ceiling.

    ``None`` means Mr Patchy itself sets no ceiling; ``0`` means the purpose is off.
    In the rate modes every purpose draws from one shared rate, so the combined
    ceiling is that rate rather than the sum of the per-purpose figures.
    """
    mode = values['ai_control_mode']
    scoring_on = bool(values['ai_updates_enabled'])
    if mode == 'legacy':
        per = {'triage': int(values['ai_hourly_limit']),
               'update_scoring': int(values['ai_update_hourly_limit']) if scoring_on else 0,
               'automatic_plans': AUTO_PLAN_HOURLY_LIMIT}
        combined = sum(per.values())
    elif mode in RATE_MODES:
        rate = int(values['ai_rate_per_hour'])
        per = {'triage': rate, 'update_scoring': rate if scoring_on else 0, 'automatic_plans': rate}
        combined = rate
    else:
        per = {'triage': None, 'update_scoring': None if scoring_on else 0, 'automatic_plans': None}
        combined = None
    cap = _money(values['ai_daily_cap_usd']) if mode in CAP_MODES else None
    return {'mode': mode, 'mode_label': MODE_LABELS.get(mode, mode), 'hourly_starts': per,
            'combined_hourly_starts': combined, 'daily_cap_usd': None if cap is None else str(cap),
            'budget_timezone': values['ai_budget_timezone'] if mode in CAP_MODES else None}


def _more(after, before):
    """True when ``after`` admits more than ``before``; ``None`` is unlimited."""
    if after == before:
        return False
    if after is None:
        return True
    if before is None:
        return False
    return after > before


def _fmt_rate(value):
    return 'no Mr Patchy limit' if value is None else 'off' if value == 0 else f'{value}/hour'


def _fmt_cap(value):
    return 'no daily cap' if value is None else f'${value}/day'


def compare(stored, proposed):
    """Compare stored and proposed AI controls without side effects."""
    before_values = {key: stored[key] for key in FIELDS}
    after_values = before_values | {key: proposed[key] for key in FIELDS if key in proposed}
    before, after = ceilings(before_values), ceilings(after_values)
    effects = []

    def add(text, expands):
        effects.append({'text': text, 'expands': bool(expands)})

    if before['mode'] != after['mode']:
        expands = after['mode'] == 'unthrottled'
        text = f"Admission mode changes from {before['mode_label']} to {after['mode_label']}."
        if after['mode'] == 'unthrottled':
            text += ' Mr Patchy rate and spend controls are removed.'
        elif before['mode'] == 'legacy':
            text += ' Hidden per-purpose hourly allowances are replaced by the controls below.'
        add(text, expands)
    if not before_values['ai_updates_enabled'] and after_values['ai_updates_enabled']:
        add('Automatic update scoring is enabled and starts making paid provider calls.', True)
    elif before_values['ai_updates_enabled'] and not after_values['ai_updates_enabled']:
        add('Automatic update scoring is disabled.', False)
    for key, label in PURPOSES:
        old, new = before['hourly_starts'][key], after['hourly_starts'][key]
        if old != new:
            if key == 'update_scoring' and \
                    bool(before_values['ai_updates_enabled']) != bool(after_values['ai_updates_enabled']):
                continue  # already explained by the enable/disable effect
            add(f'{label} start ceiling changes from {_fmt_rate(old)} to {_fmt_rate(new)}.', _more(new, old))
    old, new = before['combined_hourly_starts'], after['combined_hourly_starts']
    if old != new:
        add(f'Combined AI work start ceiling changes from {_fmt_rate(old)} to {_fmt_rate(new)}.', _more(new, old))
    old_cap, new_cap = before['daily_cap_usd'], after['daily_cap_usd']
    if old_cap != new_cap:
        old_d = None if old_cap is None else Decimal(old_cap)
        new_d = None if new_cap is None else Decimal(new_cap)
        add(f'Daily spend ceiling changes from {_fmt_cap(old_cap)} to {_fmt_cap(new_cap)}.', _more(new_d, old_d))
    if before['mode'] in CAP_MODES and after['mode'] in CAP_MODES and \
            before_values['ai_budget_timezone'] != after_values['ai_budget_timezone']:
        add(f"Daily budget reset timezone changes from {before_values['ai_budget_timezone']} to "
            f"{after_values['ai_budget_timezone']}. The budget window moves, so more spend may be admitted "
            'around the change.', True)
    expansions = [item['text'] for item in effects if item['expands']]
    return {'before': before, 'after': after, 'effects': effects, 'changed': bool(effects),
            'expands': bool(expansions), 'expansions': expansions, 'limitation': LIMITATION}


def audit_suffix(stored, proposed):
    """Return the audit detail suffix naming every expansion, or an empty string."""
    expansions = compare(stored, proposed)['expansions']
    return ('; expands AI admission or spend: ' + ' '.join(expansions)) if expansions else ''
