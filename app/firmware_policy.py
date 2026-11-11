"""Pure firmware policy contract (first slice of #400).

Resolves effective firmware policy from layered scopes (broadest first, for
example fleet -> group -> host -> device class), evaluates a device's installed
version against it and decides whether an unattended firmware operation is
authorized. It performs no I/O, persistence, scheduling or execution and never
authorizes a firmware change by itself. Missing, expired or malformed input
always resolves to the more restrictive outcome, and an unrecognized version
is never treated as meeting a minimum.
"""
from __future__ import annotations

import math
import re
from typing import Any

CONTRACT_VERSION = 1
MAX_LAYERS = 16
MAX_ITEMS = 64
MAX_TEXT = 128
UNATTENDED_ACTIONS = ('stage', 'install')

STATES = ('compliant', 'noncompliant', 'unknown_version', 'excluded',
          'deferred', 'excepted')
_VERSION = re.compile(r'^v?\d+(\.\d+){0,5}$')
_SCALARS = ('min_version', 'pin_version', 'deferred_until', 'exception',
            'reboot_rule')
REBOOT_RULES = ('allow', 'manual', 'forbid')


def parse_version(value: Any) -> tuple[int, ...] | None:
    """Return a comparable tuple for plain dotted numeric versions, else None."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not _VERSION.match(text):
        return None
    parts = tuple(int(p) for p in text.lstrip('v').split('.'))
    while len(parts) > 1 and parts[-1] == 0:
        parts = parts[:-1]
    return parts


def _checked_text_list(value: Any) -> tuple[list[str], str | None]:
    """Return ``(items, problem)``; items are never truncated or silently capped.

    ``problem`` is ``'overlong_id'`` when any item exceeds ``MAX_TEXT``,
    ``'too_many_ids'`` when there are more than ``MAX_ITEMS`` items and
    ``'malformed_ids'`` for a non-list or a non-string/blank item. Callers
    must fail closed on any problem instead of using a narrowed or
    prefix-matched list, so a long ID can never authorize a different ID
    that shares its prefix.
    """
    if not isinstance(value, (list, tuple, set, frozenset)):
        return [], 'malformed_ids'
    out = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            return [], 'malformed_ids'
        text = item.strip()
        if len(text) > MAX_TEXT:
            return [], 'overlong_id'
        out.append(text)
    if len(set(out)) > MAX_ITEMS:
        return [], 'too_many_ids'
    return sorted(set(out)), None


def _is_num(value: Any) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def _exception(raw: Any, now: float) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    expires = raw.get('expires_at')
    if not _is_num(expires):
        return None  # exceptions must expire
    reason = raw.get('reason')
    return {
        'expires_at': float(expires),
        'reason': reason.strip()[:MAX_TEXT] if isinstance(reason, str) else '',
        'active': float(expires) > now,
    }


def normalize_unattended(raw: Any, now: float) -> dict[str, Any]:
    """An unattended opt-in is valid only with bounded, unexpired scope."""
    off = {'enabled': False, 'reason': 'not_opted_in', 'devices': [],
           'actions': [], 'releases': []}
    if not isinstance(raw, dict) or raw.get('enabled') is not True:
        return off
    scope = {}
    for key in ('devices', 'releases', 'actions'):
        if key not in raw:
            return {**off, 'reason': 'unbounded_scope'}
        items, problem = _checked_text_list(raw.get(key))
        if problem:
            return {**off, 'reason': f'{key}_{problem}'}
        scope[key] = items
    devices, releases = scope['devices'], scope['releases']
    actions = [a for a in scope['actions'] if a in UNATTENDED_ACTIONS]
    if not devices or not actions or not releases:
        return {**off, 'reason': 'unbounded_scope'}
    expires = raw.get('expires_at')
    if not _is_num(expires) or float(expires) <= now:
        return {**off, 'reason': 'expired_or_missing_expiry'}
    return {'enabled': True, 'reason': 'opted_in', 'devices': devices,
            'actions': actions, 'releases': releases,
            'expires_at': float(expires)}


def resolve_effective_policy(layers: Any, now: float) -> dict[str, Any]:
    """Merge layers broadest -> narrowest; narrower scalar values win.

    Exclusion is sticky (any layer excluding the device excludes it).
    Unattended opt-in is never inherited: it counts only when the narrowest
    layer present declares it, so a broader opt-in does not apply to a
    narrower layer that is silent. Contradictions and malformed values are
    reported as conflicts (which block compliance and unattended work), not
    silently resolved or dropped. More than ``MAX_LAYERS`` layers is a
    blocking ``too_many_layers`` conflict that also disables unattended work;
    an exclusion in any supplied layer still applies.
    """
    if not isinstance(layers, (list, tuple)):
        layers = []
    layers = [l for l in layers if isinstance(l, dict)]
    values: dict[str, Any] = {}
    sources: dict[str, str] = {}
    excluded_by: list[str] = []
    conflicts: list[str] = []
    over_cap = len(layers) > MAX_LAYERS
    if over_cap:
        # Fail closed instead of silently truncating: report a blocking
        # conflict, keep exclusion sticky across every supplied layer and
        # keep the narrowest layers (never the broadest) for merging, so a
        # dropped narrow layer cannot hand authority to a broader one.
        conflicts.append('too_many_layers')
        for layer in layers[:-MAX_LAYERS]:
            if layer.get('excluded') is True:
                excluded_by.append(str(layer.get('scope') or 'unknown')[:MAX_TEXT])
        layers = layers[-MAX_LAYERS:]
    channels: list[str] | None = None
    unattended_raw: Any = None
    unattended_src = None
    for layer in layers:
        scope = str(layer.get('scope') or 'unknown')[:MAX_TEXT]
        for key in _SCALARS:
            if layer.get(key) is not None:
                values[key] = layer[key]
                sources[key] = scope
        excluded = layer.get('excluded')
        if excluded is True:
            excluded_by.append(scope)
        elif excluded is not None and excluded is not False:
            conflicts.append('excluded_invalid')
        if layer.get('approved_channels') is not None:
            channels, problem = _checked_text_list(layer['approved_channels'])
            if problem:
                conflicts.append(f'approved_channels_{problem}')
            sources['approved_channels'] = scope
    narrowest = layers[-1] if layers else {}
    if 'unattended' in narrowest:
        unattended_raw = narrowest['unattended']
        unattended_src = str(narrowest.get('scope') or 'unknown')[:MAX_TEXT]

    minimum = values.get('min_version')
    pin = values.get('pin_version')
    min_t, pin_t = parse_version(minimum), parse_version(pin)
    if minimum is not None and min_t is None:
        conflicts.append('min_version_unparseable')
    if pin is not None and pin_t is None:
        conflicts.append('pin_version_unparseable')
    if min_t and pin_t and pin_t < min_t:
        conflicts.append('pin_below_minimum')
    rule = values.get('reboot_rule')
    if rule is not None and rule not in REBOOT_RULES:
        conflicts.append('reboot_rule_invalid')
        rule = 'manual'
    deferred = values.get('deferred_until')
    if deferred is not None and not _is_num(deferred):
        conflicts.append('deferred_until_invalid')
    deferred = float(deferred) if _is_num(deferred) else None
    unattended = normalize_unattended(unattended_raw, now)
    if over_cap:
        unattended = {'enabled': False, 'reason': 'too_many_layers',
                      'devices': [], 'actions': [], 'releases': []}
    return {
        'contract_version': CONTRACT_VERSION,
        'min_version': minimum if min_t else None,
        'pin_version': pin if pin_t else None,
        'approved_channels': channels or [],
        'reboot_rule': rule or 'manual',
        'deferred_until': deferred,
        'deferred_active': deferred is not None and deferred > now,
        'exception': _exception(values.get('exception'), now),
        'excluded': bool(excluded_by),
        'excluded_by': excluded_by,
        'unattended': unattended,
        'unattended_source': unattended_src,
        'sources': sources,
        'conflicts': list(dict.fromkeys(conflicts)),
    }


def evaluate_device(policy: dict[str, Any], installed_version: Any,
                    now: float) -> dict[str, Any]:
    """Classify one device against an effective policy.

    Unknown or unparseable versions are reported separately and never count
    as compliant. A policy with conflicts is never reported compliant.
    """
    reasons: list[str] = []
    if policy.get('excluded'):
        return {'state': 'excluded', 'compliant': False, 'reasons': ['excluded']}
    exc = policy.get('exception')
    exc_active = bool(exc) and exc['expires_at'] > now
    deferred_until = policy.get('deferred_until')
    deferred_active = deferred_until is not None and deferred_until > now
    if exc_active:
        return {'state': 'excepted', 'compliant': False,
                'reasons': ['exception_active'],
                'exception_expires_at': exc['expires_at']}
    if exc and not exc_active:
        reasons.append('exception_expired')
    if deferred_active:
        return {'state': 'deferred', 'compliant': False,
                'reasons': reasons + ['deferred']}
    installed = parse_version(installed_version)
    needs = policy.get('min_version') or policy.get('pin_version')
    if needs and installed is None:
        return {'state': 'unknown_version', 'compliant': False,
                'reasons': reasons + ['installed_version_unrecognized']}
    ok = True
    if policy.get('min_version') and installed < parse_version(policy['min_version']):
        ok = False
        reasons.append('below_minimum')
    if policy.get('pin_version') and installed != parse_version(policy['pin_version']):
        ok = False
        reasons.append('differs_from_pin')
    if policy.get('conflicts'):
        ok = False
        reasons.append('policy_conflict')
    if not needs:
        ok = False
        reasons.append('no_requirement_defined')
    return {'state': 'compliant' if ok else 'noncompliant', 'compliant': ok,
            'reasons': reasons}


def authorize_unattended(policy: dict[str, Any], device_id: str, action: str,
                         release_id: str, now: float) -> dict[str, Any]:
    """Decide whether the policy's opt-in covers exactly this operation.

    A False result only means the policy does not authorize it; a True
    result is necessary but never sufficient (jobs, windows and approvals
    still apply) and never substitutes a different release.
    """
    blockers: list[str] = []
    opt = policy.get('unattended') or {}
    if not opt.get('enabled'):
        blockers.append(opt.get('reason') or 'not_opted_in')
    else:
        if opt.get('expires_at', 0) <= now:
            blockers.append('opt_in_expired')
        if device_id not in opt.get('devices', []):
            blockers.append('device_not_in_scope')
        if action not in opt.get('actions', []):
            blockers.append('action_not_in_scope')
        if release_id not in opt.get('releases', []):
            blockers.append('release_not_in_scope')
    if policy.get('excluded'):
        blockers.append('excluded')
    until = policy.get('deferred_until')
    if until is not None and until > now:
        blockers.append('deferred')
    if policy.get('conflicts'):
        blockers.append('policy_conflict')
    if policy.get('reboot_rule') == 'forbid' and action == 'install':
        blockers.append('reboot_forbidden')
    return {'allowed': not blockers, 'blockers': blockers}
