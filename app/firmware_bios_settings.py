"""Pure BIOS/UEFI settings redaction, drift and change-binding contract (first slice of #401).

Read-only helpers: no database, network, route, UI or runtime-authorization
effects, and nothing imports this module yet. Previewing or binding a change
never applies it; applying a setting needs a separate explicit authorization
that this contract only gates, never grants.
"""
from __future__ import annotations

import hashlib
import json
import re

SECRET_NAME = re.compile(r'(password|passwd|passphrase|secret|token|recovery.?key|credential|pin\b)', re.IGNORECASE)
SETTING_TYPES = {'enumeration', 'integer', 'string', 'boolean'}
REDACTED = '[redacted]'


def _is_sensitive(setting: dict) -> bool:
    return bool(setting.get('sensitive')) or bool(SECRET_NAME.search(str(setting.get('id') or '')))


def redact(settings: list) -> list:
    """Return copies of settings with sensitive values removed; inputs are untouched."""
    out = []
    for s in settings or []:
        item = dict(s)
        if _is_sensitive(s):
            for k in ('current', 'pending', 'default', 'allowed'):
                if k in item:
                    item[k] = REDACTED
            item['redacted'] = True
        out.append(item)
    return out


def validate_value(setting: dict, value) -> str | None:
    """Return a reason string if value is invalid for the setting's native type, else None."""
    kind = setting.get('type')
    if kind not in SETTING_TYPES:
        return 'unknown_type'
    if kind == 'boolean':
        return None if isinstance(value, bool) else 'type_mismatch'
    if kind == 'integer':
        if isinstance(value, bool) or not isinstance(value, int):
            return 'type_mismatch'
        lo, hi = setting.get('min'), setting.get('max')
        if (lo is not None and value < lo) or (hi is not None and value > hi):
            return 'out_of_range'
        return None
    if not isinstance(value, str):
        return 'type_mismatch'
    if kind == 'enumeration' and value not in (setting.get('allowed') or []):
        return 'not_allowed_value'
    return None


def drift(settings: list, baseline: dict) -> list:
    """Compare current values with an approved baseline {setting_id: value}.

    Missing settings are `unknown`, never `ok`. Sensitive values are never echoed.
    """
    by_id = {str(s.get('id')): s for s in settings or []}
    rows = []
    for sid, expected in sorted((baseline or {}).items()):
        s = by_id.get(sid)
        if s is None or 'current' not in s:
            rows.append({'id': sid, 'state': 'unknown'})
            continue
        row = {'id': sid, 'state': 'ok' if s['current'] == expected else 'drifted'}
        if row['state'] == 'drifted' and not _is_sensitive(s):
            row.update(expected=expected, current=s['current'])
        if s.get('pending') is not None and s.get('pending') != s['current']:
            row['reboot_pending'] = True
        rows.append(row)
    return rows


def _fingerprint(setting: dict) -> dict:
    return {k: setting.get(k) for k in ('id', 'type', 'current', 'pending', 'read_only', 'locked')}


def preview(setting: dict, proposed, privileged: bool) -> dict:
    """Preview one proposed change. `ready` is eligibility evidence, never authorization."""
    reasons = []
    if setting.get('read_only') or setting.get('locked'):
        reasons.append('setting_locked')
    if not privileged:
        reasons.append('missing_privileges')
    if _is_sensitive(setting):
        reasons.append('sensitive_setting_manual_only')
    bad = validate_value(setting, proposed)
    if bad:
        reasons.append(bad)
    if not reasons and setting.get('current') == proposed:
        reasons.append('no_change')
    result = {'state': 'blocked' if reasons else 'ready', 'reasons': reasons,
              'reboot_required': bool(setting.get('reboot_required', True))}
    if not reasons:
        fields = {'setting': _fingerprint(setting), 'proposed': proposed}
        result['binding'] = {**fields, 'binding_sha256': hashlib.sha256(
            json.dumps(fields, sort_keys=True, separators=(',', ':'), default=str).encode()).hexdigest()}
    return result


def recheck(bound: dict, setting: dict, privileged: bool) -> dict:
    """Re-verify at use. Changed values, locks or privileges require re-review."""
    proposed = (bound.get('binding') or {}).get('proposed')
    current = preview(setting, proposed, privileged)
    if current['state'] != 'ready':
        return {'state': 'rereview', 'reasons': current['reasons']}
    if current['binding']['binding_sha256'] != bound['binding']['binding_sha256']:
        return {'state': 'rereview', 'reasons': ['setting_changed']}
    return {'state': 'ready', 'reasons': [], 'binding': current['binding']}
