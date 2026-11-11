"""Pure CVE applicability and verified exposure-window contract (roadmap D, #672).

This module performs no I/O apart from the optional native Debian comparator. It
does not store results, call AI providers or authorize any response action. A
vulnerable version, an advisory match or an AI assertion is never evidence of
exploitation, and nothing here can trigger quarantine or process termination.
"""
from functools import cmp_to_key
import math

from .debian_versions import newer_flags

AFFECTED = 'affected'
FIXED = 'fixed'
UNAFFECTED = 'unaffected'
UNCERTAIN = 'uncertain'

NOT_APPLICABLE = 'not_applicable'
OPEN = 'open'
PENDING_ACTIVATION = 'pending_activation'
CLOSED = 'closed'

EVENT_KINDS = frozenset({
    'applicable', 'fix_available', 'fix_installed', 'install_failed', 'activated', 'reintroduced',
})
_RANGE_EVENT_KEYS = frozenset({'introduced', 'fixed', 'last_affected', 'limit'})
MAX_AFFECTED_ENTRIES = 64
MAX_RANGE_EVENTS = 256


def native_compare(left, right):
    """Return -1, 0 or 1 using the native ``dpkg --compare-versions`` ordering."""
    if left == right:
        return 0
    greater, lesser = newer_flags([(left, right), (right, left)])
    return 1 if greater else -1 if lesser else 0


def _cve_ids(vuln):
    ids = [vuln.get('id')] + list(vuln.get('aliases') or [])
    return sorted({value for value in ids if isinstance(value, str) and value.startswith('CVE-')})


def _result(vuln, status, reason, fixed_version=None):
    return {
        'advisory_id': vuln.get('id') if isinstance(vuln.get('id'), str) else None,
        'cve_ids': _cve_ids(vuln),
        'status': status,
        'reason': reason,
        'fixed_version': fixed_version,
        'fix_available': fixed_version is not None,
    }


def _parse_events(events):
    if not isinstance(events, list) or not events or len(events) > MAX_RANGE_EVENTS:
        raise ValueError('range events are missing, malformed or exceed the bound')
    parsed = []
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise ValueError('range event must contain exactly one key')
        (key, value), = event.items()
        if key not in _RANGE_EVENT_KEYS or not isinstance(value, str) or not value:
            raise ValueError('range event has an unknown key or a non-string version')
        if key == 'limit':
            raise ValueError('limit events are not supported for ecosystem ranges')
        if key != 'introduced' and value == '0':
            raise ValueError('only introduced events may use the zero version')
        parsed.append((key, value))
    if not any(key == 'introduced' for key, _ in parsed):
        raise ValueError('range has no introduced event')
    return parsed


def _evaluate_range(parsed, installed, compare):
    """Apply the OSV ECOSYSTEM range algorithm to one validated event list.

    Returns ``(status, fixed_version)`` where status is AFFECTED, FIXED or
    UNAFFECTED. ``fixed_version`` is the next fix at or after the installed
    version for an affected result, or the fix that ended exposure otherwise.
    """
    def order(left, right):
        if left[1] == right[1]:
            return 0
        if left[1] == '0':
            return -1
        if right[1] == '0':
            return 1
        return compare(left[1], right[1])

    events = sorted(parsed, key=cmp_to_key(order))
    affected = False
    passed_fix = None
    for key, value in events:
        if key == 'introduced':
            if value == '0' or compare(installed, value) >= 0:
                affected = True
        elif key == 'fixed':
            if compare(installed, value) >= 0:
                if affected:
                    passed_fix = value
                affected = False
        elif compare(installed, value) > 0:  # last_affected
            affected = False
    if affected:
        following = [value for key, value in events if key == 'fixed' and compare(value, installed) > 0]
        return AFFECTED, following[0] if following else None
    if passed_fix is not None:
        return FIXED, passed_fix
    return UNAFFECTED, None


def classify(vuln, ecosystem, package, installed_version, compare=native_compare):
    """Classify one installed source package against one OSV vulnerability record.

    Only entries for the exact ``ecosystem`` and ``package`` are used: another
    distribution's range data, a generic upstream range or a CVE ID alone never
    establishes applicability. Every unsupported, malformed or uncomparable input
    yields UNCERTAIN, which callers must not treat as UNAFFECTED.
    """
    if not isinstance(vuln, dict):
        return _result({}, UNCERTAIN, 'Advisory record is malformed')
    if not isinstance(installed_version, str) or not installed_version:
        return _result(vuln, UNCERTAIN, 'Installed version is unknown')
    affected = vuln.get('affected')
    if not isinstance(affected, list) or len(affected) > MAX_AFFECTED_ENTRIES:
        return _result(vuln, UNCERTAIN, 'Advisory affected data is missing, malformed or exceeds the bound')
    entries = [
        entry for entry in affected
        if isinstance(entry, dict) and isinstance(entry.get('package'), dict)
        and entry['package'].get('ecosystem') == ecosystem and entry['package'].get('name') == package
    ]
    if not entries:
        return _result(vuln, UNCERTAIN, 'Advisory has no vendor data for this distribution release and package')
    affected_fixes = []
    fixed_by = []
    problems = []
    for entry in entries:
        versions = entry.get('versions')
        ranges = entry.get('ranges')
        if versions is not None and not isinstance(versions, list):
            problems.append('explicit version list is malformed')
            versions = None
        if ranges is not None and not isinstance(ranges, list):
            problems.append('range list is malformed')
            ranges = None
        if not versions and not ranges:
            problems.append('vendor entry lists no versions or ranges')
            continue
        if versions and installed_version in versions:
            affected_fixes.append(None)
        for item in ranges or []:
            if not isinstance(item, dict) or item.get('type') != 'ECOSYSTEM':
                problems.append('unsupported range type for distribution version ordering')
                continue
            try:
                status, fixed_version = _evaluate_range(_parse_events(item.get('events')), installed_version, compare)
            except (ValueError, TypeError, OSError) as exc:
                problems.append(str(exc) or 'version comparison failed')
                continue
            except Exception:  # noqa: BLE001 - an unknown comparator failure is uncertainty, never safety
                problems.append('version comparison failed')
                continue
            if status == AFFECTED:
                affected_fixes.append(fixed_version)
            elif status == FIXED:
                fixed_by.append(fixed_version)
    if affected_fixes:
        known = [value for value in affected_fixes if value is not None]
        fix = None
        if known:
            try:
                fix = sorted(known, key=cmp_to_key(compare))[0]
            except Exception:  # noqa: BLE001
                fix = None
        reason = 'Installed version is inside a vendor-listed affected range'
        if fix is None:
            reason += '; no fixed version is published for this release'
        return _result(vuln, AFFECTED, reason, fix)
    if problems:
        return _result(vuln, UNCERTAIN, 'Applicability could not be established: ' + '; '.join(sorted(set(problems))))
    if fixed_by:
        try:
            fix = sorted(fixed_by, key=cmp_to_key(compare))[-1]
        except Exception:  # noqa: BLE001
            return _result(vuln, UNCERTAIN, 'Applicability could not be established: version comparison failed')
        return _result(vuln, FIXED, 'Installed version is at or beyond the vendor fix', fix)
    return _result(vuln, UNAFFECTED, 'Installed version is outside every vendor-listed affected range')


def _timestamp(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError(name + ' must be a finite non-negative timestamp')
    return float(value)


def exposure_window(published_at, events, now, monitoring_started_at=None, offline_periods=()):
    """Compute one endpoint's exposure window for one CVE from recorded evidence.

    ``events`` are dictionaries with ``kind`` (see ``EVENT_KINDS``) and ``at``.
    ``fix_installed`` events close the window only when ``verified`` is true;
    when ``activation_required`` is true the window stays ``pending_activation``
    until a later ``activated`` event records the restart or reboot. Rollback or
    reinstallation of an affected version (``reintroduced``) reopens a closed or
    pending window. Monitoring gaps are disclosed and never imply coverage.
    """
    published = _timestamp(published_at, 'published_at')
    current = _timestamp(now, 'now')
    if published > current:
        raise ValueError('published_at is after now')
    if not isinstance(events, (list, tuple)):
        raise ValueError('events must be a list')
    ordered = []
    for index, event in enumerate(events):
        if not isinstance(event, dict) or event.get('kind') not in EVENT_KINDS:
            raise ValueError('event has an unknown kind')
        at = _timestamp(event.get('at'), 'event time')
        if at > current:
            raise ValueError('event time is after now')
        ordered.append((at, index, event))
    ordered.sort(key=lambda item: (item[0], item[1]))

    result = {
        'state': NOT_APPLICABLE, 'published_at': published, 'applicable_at': None,
        'fix_available_at': None, 'fix_installed_at': None, 'effective_at': None,
        'closed_at': None, 'reopened': 0, 'duration_seconds': None, 'gaps': [], 'notes': [],
        'monitoring_complete': None,
    }
    state = NOT_APPLICABLE
    for at, _, event in ordered:
        kind = event['kind']
        if kind == 'applicable':
            if result['applicable_at'] is None:
                result['applicable_at'] = at
                if at < published:
                    result['notes'].append('Applicability was recorded before publication; exposure starts at publication')
            if state == NOT_APPLICABLE:
                state = OPEN
        elif kind == 'fix_available':
            if result['fix_available_at'] is None:
                result['fix_available_at'] = at
        elif state == NOT_APPLICABLE:
            continue
        elif kind == 'install_failed':
            if state != CLOSED:
                result['notes'].append('A fix installation failed; the exposure window stays open')
        elif kind == 'fix_installed':
            if state == CLOSED:
                continue
            if event.get('verified') is not True:
                result['notes'].append('An unverified or partial fix installation does not close the window')
                continue
            result['fix_installed_at'] = at
            if event.get('activation_required') is True:
                state = PENDING_ACTIVATION
            else:
                state = CLOSED
                result['effective_at'] = result['closed_at'] = at
        elif kind == 'activated':
            if state == PENDING_ACTIVATION:
                state = CLOSED
                result['effective_at'] = result['closed_at'] = at
        elif kind == 'reintroduced':
            if state in (CLOSED, PENDING_ACTIVATION):
                if state == CLOSED:
                    result['reopened'] += 1
                state = OPEN
                result['fix_installed_at'] = result['effective_at'] = result['closed_at'] = None
                result['notes'].append('An affected version was reintroduced; the exposure window reopened')
    result['state'] = state
    if state == NOT_APPLICABLE:
        return result

    end = result['closed_at'] if state == CLOSED else current
    result['duration_seconds'] = max(0.0, end - published)
    if monitoring_started_at is None:
        result['gaps'].append({'kind': 'no_monitoring', 'start': published, 'end': end})
    else:
        started = _timestamp(monitoring_started_at, 'monitoring_started_at')
        if started > published:
            result['gaps'].append({'kind': 'late_enrollment', 'start': published, 'end': min(started, end)})
    for period in offline_periods or ():
        if not isinstance(period, (list, tuple)) or len(period) != 2:
            raise ValueError('offline period must be a (start, end) pair')
        start = _timestamp(period[0], 'offline start')
        stop = _timestamp(period[1], 'offline end')
        if stop < start:
            raise ValueError('offline period ends before it starts')
        start, stop = max(start, published), min(stop, end)
        if stop > start:
            result['gaps'].append({'kind': 'offline', 'start': start, 'end': stop})
    result['gaps'].sort(key=lambda gap: (gap['start'], gap['end'], gap['kind']))
    result['monitoring_complete'] = not result['gaps']
    return result
