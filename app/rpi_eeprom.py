"""Pure, read-only Raspberry Pi boot-EEPROM status contract (first slice of #402).

Parses captured ``rpi-eeprom-update`` text into typed records and classifies
the result without ever treating a missing tool, empty output, an unsupported
board or an unrecognized report as healthy. It never runs a tool, stages or
flashes an update, changes the release stream, or touches the auto-update
service; it performs no I/O and never authorizes a firmware change.
"""
from __future__ import annotations

import re
import time
from typing import Any

CONTRACT_VERSION = 1
MAX_OUTPUT = 16384
DEFAULT_MAX_AGE = 7 * 24 * 3600
# Streams that may be proposed implicitly. Anything else needs a reviewed plan.
SAFE_RELEASES = frozenset({'default', 'stable', 'critical'})
STATUSES = (
    'verified_current', 'update_available', 'pending_reboot', 'unsupported_model',
    'missing_tool', 'collection_failed', 'stale_unknown',
)
HEALTHY_STATUSES = frozenset({'verified_current'})
OPERATIONS = {
    'enumerate': True, 'discover': True, 'status': True, 'history': False,
    'plan': False, 'stage': False, 'execute': False, 'verify': False,
    'recovery': False, 'settings': False, 'security': False, 'trust': False,
}
_STATE_RE = re.compile(r'^\s*(BOOTLOADER|VL805):\s*(.+?)\s*$', re.IGNORECASE)
_STAMP_RE = re.compile(r'^\s*(CURRENT|LATEST):\s*(.*?)\s*(?:\((\d{1,12})\))?\s*$', re.IGNORECASE)
_RELEASE_RE = re.compile(r'^\s*RELEASE:\s*([A-Za-z0-9_.-]{1,64})\b')
_PENDING_RE = re.compile(r'(update pending|installing eeprom|reboot to apply|reboot to complete)', re.IGNORECASE)
_UNSUPPORTED_RE = re.compile(r'(unsupported|not supported|does not have a boot eeprom|no boot eeprom)', re.IGNORECASE)


def provider_capabilities() -> dict[str, bool]:
    return dict(OPERATIONS)


def parse_status(output: Any) -> dict[str, Any]:
    """Parse rpi-eeprom-update text; unknown lines are ignored, never trusted."""
    text = output[:MAX_OUTPUT] if isinstance(output, str) else ''
    out: dict[str, Any] = {
        'bootloader_state': None, 'vl805_state': None, 'current_epoch': None,
        'latest_epoch': None, 'release': None, 'pending': False, 'unsupported': False,
    }
    section = None
    for line in text.splitlines():
        if _PENDING_RE.search(line):
            out['pending'] = True
        if _UNSUPPORTED_RE.search(line):
            out['unsupported'] = True
        m = _STATE_RE.match(line)
        if m:
            section = m.group(1).upper()
            if section == 'BOOTLOADER':
                out['bootloader_state'] = m.group(2).lower()[:64]
            else:
                out['vl805_state'] = m.group(2).lower()[:64]
            continue
        m = _RELEASE_RE.match(line)
        if m:
            out['release'] = m.group(1).lower()
            continue
        m = _STAMP_RE.match(line)
        # Only the bootloader block's timestamps decide the bootloader result.
        if m and section == 'BOOTLOADER' and m.group(3):
            out['current_epoch' if m.group(1).upper() == 'CURRENT' else 'latest_epoch'] = int(m.group(3))
    return out


def classify_collection(result: Any, *, now: float | None = None,
                        max_age: float = DEFAULT_MAX_AGE) -> dict[str, Any]:
    """Classify one capture.

    ``result`` keys: ``tool_present`` (bool), ``exit_code`` (int), ``output``
    (str), ``observed_at`` (epoch seconds), ``service_active`` (bool|None),
    ``timed_out`` (bool). Anything unrecognized is never healthy.
    """
    now = time.time() if now is None else now
    base = {'contract_version': CONTRACT_VERSION, 'provider': 'rpi-eeprom',
            'status': 'collection_failed', 'healthy': False, 'reason': None,
            'auto_update_service_active': None, 'release_requires_review': False,
            'detail': None}
    if not isinstance(result, dict) or result.get('tool_present') is not True:
        return {**base, 'status': 'missing_tool', 'reason': 'rpi-eeprom-update is not installed'}
    svc = result.get('service_active')
    base['auto_update_service_active'] = svc if isinstance(svc, bool) else None
    exit_code = result.get('exit_code')
    output = result.get('output')
    if result.get('timed_out') or not isinstance(exit_code, int) or isinstance(exit_code, bool):
        return {**base, 'reason': 'collection timed out or returned no exit status'}
    parsed = parse_status(output)
    base['detail'] = parsed
    if parsed['unsupported']:
        return {**base, 'status': 'unsupported_model', 'reason': 'board has no supported boot EEPROM'}
    if not isinstance(output, str) or not output.strip() or exit_code not in (0, 1, 2) \
            or parsed['bootloader_state'] is None:
        return {**base, 'reason': 'empty, unrecognized or failed rpi-eeprom-update output'}
    release = parsed['release']
    base['release_requires_review'] = release is not None and release not in SAFE_RELEASES
    observed = result.get('observed_at')
    if not isinstance(observed, (int, float)) or isinstance(observed, bool) \
            or not 0 <= now - observed <= max_age:
        return {**base, 'status': 'stale_unknown', 'reason': 'observation is missing or too old'}
    if parsed['pending']:
        return {**base, 'status': 'pending_reboot', 'reason': 'a staged update awaits reboot'}
    cur, lat = parsed['current_epoch'], parsed['latest_epoch']
    state = parsed['bootloader_state']
    if cur is not None and lat is not None:
        if lat > cur:
            return {**base, 'status': 'update_available', 'reason': 'newer bootloader in the release stream'}
        if 'up to date' in state:
            return {**base, 'status': 'verified_current', 'healthy': True}
    if 'update available' in state:
        return {**base, 'status': 'update_available', 'reason': 'tool reports an update'}
    return {**base, 'status': 'stale_unknown', 'reason': 'versions could not be compared'}
