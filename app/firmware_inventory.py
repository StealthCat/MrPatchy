"""Pure, read-only firmware provider contract (first slice of #397).

Normalizes machine-readable ``fwupdmgr --json`` output into typed device and
release records, classifies firmware state without ever treating missing tools,
empty output or unsupported hardware as healthy, and declares which provider
operations exist. It performs no collection, installation, catalog refresh,
persistence or I/O and never authorizes a firmware change.
"""
from __future__ import annotations

import time
from typing import Any

CONTRACT_VERSION = 1
MAX_DEVICES = 512
MAX_RELEASES = 64
MAX_GUIDS = 32
MAX_FLAGS = 64
MAX_TEXT = 256
DEFAULT_MAX_AGE = 7 * 24 * 3600

STATUSES = (
    'verified_current', 'update_available', 'missing_tool', 'no_vendor_support',
    'no_matching_release', 'blocked_requirements', 'disconnected',
    'collection_failed', 'stale_unknown',
)
HEALTHY_STATUSES = frozenset({'verified_current'})

# Operations every provider may implement; support is advertised explicitly and
# execution-class operations are delivered by later slices.
OPERATIONS = (
    'enumerate', 'discover', 'plan', 'stage', 'execute', 'status', 'verify',
    'history', 'recovery', 'settings', 'security', 'trust',
)
PROVIDERS = {
    'fwupd': {
        'enumerate': True, 'discover': True, 'history': True, 'status': True,
        'plan': False, 'stage': False, 'execute': False, 'verify': False,
        'recovery': False, 'settings': False, 'security': False, 'trust': False,
    },
}
SENSITIVE_DEVICE_FIELDS = ('serial',)
_BLOCKED_RELEASE_FLAGS = frozenset({
    'blocked-version', 'blocked-approval', 'trusted-report-missing',
})


def provider_capabilities(provider: str) -> dict[str, bool]:
    """Return a full operation map; unknown providers support nothing."""
    declared = PROVIDERS.get(provider, {})
    return {op: bool(declared.get(op, False)) for op in OPERATIONS}


def _text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:MAX_TEXT] if value else None


def _strings(value: Any, limit: int) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    out = []
    for item in value:
        item = _text(item)
        if item and item not in out:
            out.append(item)
        if len(out) >= limit:
            break
    return out


def _flags(value: Any) -> list[str]:
    return sorted({f.lower() for f in _strings(value, MAX_FLAGS)})


def normalize_release(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    version = _text(raw.get('Version'))
    if not version:
        return None
    return {
        'version': version,
        'summary': _text(raw.get('Summary')),
        'remote': _text(raw.get('RemoteId')) or _text(raw.get('Remote')),
        'branch': _text(raw.get('Branch')),
        'checksums': _strings(raw.get('Checksum'), 8),
        'uri': _text(raw.get('Uri')),
        'urgency': _text(raw.get('Urgency')),
        'flags': _flags(raw.get('TrustFlags')) + _flags(raw.get('Flags')),
        'requires_reboot': 'needs-reboot' in _flags(raw.get('Flags')),
        'install_duration': raw.get('InstallDuration') if isinstance(raw.get('InstallDuration'), int) else None,
    }


def normalize_device(raw: Any, *, include_private: bool = False) -> dict[str, Any] | None:
    """Normalize one fwupd device; unknown fields are ignored, not trusted."""
    if not isinstance(raw, dict):
        return None
    device_id = _text(raw.get('DeviceId'))
    guids = _strings(raw.get('Guid'), MAX_GUIDS)
    if not device_id and not guids:
        return None
    flags = _flags(raw.get('Flags'))
    releases = [r for r in (normalize_release(x) for x in
                (raw.get('Releases') or [])[:MAX_RELEASES]) if r]
    device = {
        'device_id': device_id,
        'guids': guids,
        'name': _text(raw.get('Name')),
        'vendor': _text(raw.get('Vendor')),
        'plugin': _text(raw.get('Plugin')),
        'version': _text(raw.get('Version')),
        'version_format': _text(raw.get('VersionFormat')),
        'version_lowest': _text(raw.get('VersionLowest')),
        'parent_id': _text(raw.get('ParentDeviceId')),
        'flags': flags,
        'updatable': 'updatable' in flags,
        'unreachable': 'unreachable' in flags,
        'releases': releases,
    }
    if include_private:
        for field in SENSITIVE_DEVICE_FIELDS:
            device[field] = _text(raw.get(field.capitalize()))
    return device


def _device_list(payload: Any, *, include_private: bool = False) -> list[dict[str, Any]] | None:
    """Return devices from a fwupd JSON payload or None when malformed."""
    if not isinstance(payload, dict) or not isinstance(payload.get('Devices'), list):
        return None
    devices = [d for d in (normalize_device(x, include_private=include_private)
               for x in payload['Devices'][:MAX_DEVICES]) if d]
    return devices


def classify_collection(result: Any, *, now: float | None = None,
                        max_age: int = DEFAULT_MAX_AGE) -> dict[str, Any]:
    """Classify one passive collection result for a host.

    ``result`` keys: ``tool_present`` (bool), ``exit_code``, ``devices`` and
    ``updates`` (parsed JSON payloads or None), ``observed_at`` (epoch seconds),
    ``catalog_refreshed_at`` (epoch seconds, optional) and ``error``.
    Returns ``{'status', 'devices': [...], 'reason'}`` where each device carries
    its own ``status``. An empty or unparseable result is never healthy.
    """
    now = time.time() if now is None else now
    if not isinstance(result, dict):
        return {'status': 'collection_failed', 'devices': [], 'reason': 'invalid result'}
    if result.get('tool_present') is False:
        return {'status': 'missing_tool', 'devices': [], 'reason': 'fwupdmgr is not installed'}
    devices = _device_list(result.get('devices'))
    if devices is None:
        return {'status': 'collection_failed', 'devices': [],
                'reason': _text(result.get('error')) or 'device list missing or malformed'}
    if not devices:
        return {'status': 'no_vendor_support', 'devices': [],
                'reason': 'no firmware-capable devices reported'}
    observed = result.get('observed_at')
    fresh = isinstance(observed, (int, float)) and 0 <= now - observed <= max_age
    updates = result.get('updates')
    updates_known = updates is not None
    update_ids = {}
    if updates_known:
        listed = _device_list(updates)
        if listed is None:
            updates_known = False
        else:
            for dev in listed:
                update_ids[dev['device_id']] = dev['releases']
    refreshed = result.get('catalog_refreshed_at')
    catalog_fresh = isinstance(refreshed, (int, float)) and 0 <= now - refreshed <= max_age
    out = []
    for dev in devices:
        out.append({**dev, 'status': classify_device(
            dev, update_ids.get(dev['device_id']) if updates_known else None,
            fresh=fresh, updates_known=updates_known, catalog_fresh=catalog_fresh)})
    statuses = {d['status'] for d in out}
    for status in ('collection_failed', 'blocked_requirements', 'update_available',
                   'stale_unknown', 'disconnected', 'no_matching_release',
                   'no_vendor_support'):
        if status in statuses:
            overall = status
            break
    else:
        overall = 'verified_current'
    return {'status': overall, 'devices': out, 'reason': None}


def classify_device(device: dict[str, Any], update_releases: list[dict[str, Any]] | None,
                    *, fresh: bool, updates_known: bool, catalog_fresh: bool) -> str:
    """Classify a single device. ``update_releases`` are applicable upgrades from
    the update listing only; historical releases never imply an update."""
    if device.get('unreachable'):
        return 'disconnected'
    if not fresh:
        return 'stale_unknown'
    if not device.get('updatable'):
        return 'no_vendor_support'
    if not updates_known:
        return 'stale_unknown'
    if update_releases:
        if any(set(r['flags']) & _BLOCKED_RELEASE_FLAGS for r in update_releases):
            return 'blocked_requirements'
        return 'update_available'
    # No applicable upgrade: only current when a fresh catalog lists the
    # installed version itself. Otherwise the catalog may simply lack the device.
    if catalog_fresh and any(r['version'] == device.get('version')
                             for r in device.get('releases', [])):
        return 'verified_current'
    return 'no_matching_release'


def reconcile_disconnected(previous_ids: set[str], devices: list[dict[str, Any]]) -> set[str]:
    """Device ids seen before but absent now. Identity (and any approval) is
    never transferred to a different device that appears under a new id."""
    current = {d['device_id'] for d in devices if d.get('device_id')}
    return set(previous_ids) - current
