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


_REVISION_CHARS = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.+~')
_UPSTREAM_CHARS = _REVISION_CHARS | frozenset('-:')


def valid_debian_version(value):
    """Return whether ``value`` has valid Debian version syntax (as ``dpkg --validate-version``).

    ``dpkg --compare-versions`` only warns about many malformed strings and still
    orders them (``v2.0`` sorts above every numeric version), so the native
    comparator must reject them itself to keep malformed advisories UNCERTAIN.
    """
    if not isinstance(value, str) or not value or value != value.strip() or any(ch.isspace() for ch in value):
        return False
    rest = value
    if ':' in rest:
        epoch, rest = rest.split(':', 1)
        if not epoch or not epoch.isascii() or not epoch.isdigit() or not rest:
            return False
    upstream = rest
    if '-' in rest:
        upstream, revision = rest.rsplit('-', 1)
        if not revision or not set(revision) <= _REVISION_CHARS:
            return False
    return bool(upstream) and upstream[0] in '0123456789' and set(upstream) <= _UPSTREAM_CHARS


def native_compare(left, right):
    """Return -1, 0 or 1 using the native ``dpkg --compare-versions`` ordering.

    Raises ValueError for any version without valid Debian syntax, so callers
    report UNCERTAIN instead of trusting dpkg's warn-and-continue ordering.
    """
    if not valid_debian_version(left) or not valid_debian_version(right):
        raise ValueError(_INVALID_SYNTAX)
    if left == right:
        return 0
    greater, lesser = newer_flags([(left, right), (right, left)])
    return 1 if greater else -1 if lesser else 0


def _cve_ids(vuln):
    aliases = vuln.get('aliases')
    ids = [vuln.get('id')] + (list(aliases) if isinstance(aliases, (list, tuple)) else [])
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


# Fixed, user-facing reasons for an unevaluable range. Range problems are
# reported only from this closed set: raw exception text (dpkg OSError paths,
# interpreter messages) never reaches stored or returned results (#798).
_EVENTS_MALFORMED = 'range events are missing, malformed or exceed the bound'
_EVENT_NOT_SINGLE = 'range event must contain exactly one key'
_EVENT_UNKNOWN = 'range event has an unknown key or a non-string version'
_EVENT_LIMIT = 'limit events are not supported for ecosystem ranges'
_EVENT_ZERO = 'only introduced events may use the zero version'
_EVENT_NO_INTRODUCED = 'range has no introduced event'
_INVALID_SYNTAX = 'version does not have valid Debian version syntax'
_COMPARISON_FAILED = 'version comparison failed'
_UNCERTAIN_PREFIX = 'Applicability could not be established: '
_RANGE_PROBLEMS = frozenset({
    'explicit version list is malformed', 'explicit version list contains non-string entries',
    'range list is malformed', 'vendor entry lists no versions or ranges',
    'unsupported range type for distribution version ordering',
    _EVENTS_MALFORMED, _EVENT_NOT_SINGLE, _EVENT_UNKNOWN, _EVENT_LIMIT, _EVENT_ZERO,
    _EVENT_NO_INTRODUCED, _INVALID_SYNTAX, _COMPARISON_FAILED,
})


def _parse_events(events):
    """Return ``(parsed, problem)``; ``problem`` is a fixed reason or None."""
    if not isinstance(events, list) or not events or len(events) > MAX_RANGE_EVENTS:
        return None, _EVENTS_MALFORMED
    parsed = []
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return None, _EVENT_NOT_SINGLE
        (key, value), = event.items()
        if key not in _RANGE_EVENT_KEYS or not isinstance(value, str) or not value:
            return None, _EVENT_UNKNOWN
        if key == 'limit':
            return None, _EVENT_LIMIT
        if key != 'introduced' and value == '0':
            return None, _EVENT_ZERO
        parsed.append((key, value))
    if not any(key == 'introduced' for key, _ in parsed):
        return None, _EVENT_NO_INTRODUCED
    return parsed, None


def sanitize_reason(reason):
    """Return ``reason`` with any unknown uncertainty detail replaced by a fixed reason.

    Results retained before #798 may carry raw comparator exception text inside
    an ``Applicability could not be established: ...`` reason. Only problems from
    the closed ``_RANGE_PROBLEMS`` set survive; anything else is reported as a
    failed version comparison. Other reasons are returned unchanged.
    """
    if not isinstance(reason, str) or not reason.startswith(_UNCERTAIN_PREFIX):
        return reason
    parts = reason[len(_UNCERTAIN_PREFIX):].split('; ')
    safe = sorted({part if part in _RANGE_PROBLEMS else _COMPARISON_FAILED for part in parts})
    return _UNCERTAIN_PREFIX + '; '.join(safe)


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

    For an AFFECTED result, ``fixed_version`` names the lowest published fix that
    the complete matching vendor data classifies as FIXED or UNAFFECTED. A fix
    that ends one matching range but sits inside another (overlapping ranges, an
    explicit affected version or an unevaluable sibling) is never reported.
    """
    return _classify(vuln, ecosystem, package, installed_version, compare, resolve_fix=True)


def _classify(vuln, ecosystem, package, installed_version, compare, resolve_fix):
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
    is_affected = False
    fix_candidates = []
    fixed_by = []
    problems = []
    for entry in entries:
        versions = entry.get('versions')
        ranges = entry.get('ranges')
        if versions is not None and not isinstance(versions, list):
            problems.append('explicit version list is malformed')
            versions = None
        if versions and not all(isinstance(value, str) and value for value in versions):
            problems.append('explicit version list contains non-string entries')
        if ranges is not None and not isinstance(ranges, list):
            problems.append('range list is malformed')
            ranges = None
        if not versions and not ranges:
            problems.append('vendor entry lists no versions or ranges')
            continue
        # Exact string match: OSV-normalized explicit lists spell each version
        # canonically, so equivalent spellings (an explicit ``0:`` epoch) are not unified.
        if versions and installed_version in versions:
            is_affected = True
        for item in ranges or []:
            if not isinstance(item, dict) or item.get('type') != 'ECOSYSTEM':
                problems.append('unsupported range type for distribution version ordering')
                continue
            parsed, problem = _parse_events(item.get('events'))
            if problem is None and compare is native_compare and not all(
                    valid_debian_version(value) for value in
                    [installed_version, *(value for _key, value in parsed if value != '0')]):
                problem = _INVALID_SYNTAX
            if problem is not None:
                problems.append(problem)
                continue
            try:
                status, fixed_version = _evaluate_range(parsed, installed_version, compare)
                later_fixes = [value for key, value in parsed if key == 'fixed' and compare(value, installed_version) > 0]
            except Exception:  # noqa: BLE001 - any comparator failure is uncertainty, never safety
                # Never report the exception text: it can carry paths or internals (#798).
                problems.append(_COMPARISON_FAILED)
                continue
            fix_candidates.extend(later_fixes)
            if status == AFFECTED:
                is_affected = True
            elif status == FIXED:
                fixed_by.append(fixed_version)
    if is_affected:
        fix = _complete_fix(vuln, ecosystem, package, fix_candidates, compare) if resolve_fix else None
        reason = 'Installed version is inside a vendor-listed affected range'
        if fix is None and resolve_fix:
            if fix_candidates:
                reason += '; no published fixed version clears every matching vendor range'
            else:
                reason += '; no fixed version is published for this release'
        return _result(vuln, AFFECTED, reason, fix)
    if problems:
        return _result(vuln, UNCERTAIN, _UNCERTAIN_PREFIX + '; '.join(sorted(set(problems))))
    if fixed_by:
        try:
            fix = sorted(fixed_by, key=cmp_to_key(compare))[-1]
        except Exception:  # noqa: BLE001
            return _result(vuln, UNCERTAIN, _UNCERTAIN_PREFIX + _COMPARISON_FAILED)
        return _result(vuln, FIXED, 'Installed version is at or beyond the vendor fix', fix)
    return _result(vuln, UNAFFECTED, 'Installed version is outside every vendor-listed affected range')


def _complete_fix(vuln, ecosystem, package, candidates, compare):
    """Return the lowest candidate fix that the whole matching record clears, else None."""
    try:
        ordered = sorted(set(candidates), key=cmp_to_key(compare))
    except Exception:  # noqa: BLE001 - uncomparable fixes are never reported
        return None
    for candidate in ordered:
        status = _classify(vuln, ecosystem, package, candidate, compare, resolve_fix=False)['status']
        if status in (FIXED, UNAFFECTED):
            return candidate
    return None


def _timestamp(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError(name + ' must be a finite non-negative timestamp')
    return float(value)


def _coverage_gaps(published, monitoring_started_at, offline_periods):
    """Return unclipped coverage gaps from publication onward as (kind, start, end|None)."""
    gaps = []
    if monitoring_started_at is None:
        gaps.append(('no_monitoring', published, None))
    else:
        started = _timestamp(monitoring_started_at, 'monitoring_started_at')
        if started > published:
            gaps.append(('late_enrollment', published, started))
    for period in offline_periods or ():
        if not isinstance(period, (list, tuple)) or len(period) != 2:
            raise ValueError('offline period must be a (start, end) pair')
        begin = _timestamp(period[0], 'offline start')
        stop = _timestamp(period[1], 'offline end')
        if stop < begin:
            raise ValueError('offline period ends before it starts')
        begin = max(begin, published)
        if stop > begin:
            gaps.append(('offline', begin, stop))
    return gaps


def exposure_window(published_at, events, now, monitoring_started_at=None, offline_periods=()):
    """Compute one endpoint's exposure history for one CVE from recorded evidence.

    ``events`` are dictionaries with ``kind`` (see ``EVENT_KINDS``) and ``at``.
    ``fix_installed`` events close the window only when ``verified`` is true;
    when ``activation_required`` is true the window stays ``pending_activation``
    until a later ``activated`` event records the restart or reboot.

    Exposure is reported as explicit ``intervals``; ``duration_seconds`` is their
    sum, so a verified-fixed period between a closure and a reopen is never
    counted, and every earlier closure is retained in its interval. Rollback or
    reinstallation of an affected version reopens a closed window. Producers
    should emit ``reintroduced`` for that, but an ``applicable`` event recorded
    after a closure, or while a fix is still pending activation, is treated the
    same way, so a producer that only re-reports applicability can never hide
    renewed exposure.

    Exposure starts at the first ``applicable`` observation only when monitoring
    covered the whole interval from publication to that observation without a
    gap (``start_basis`` = ``first_observed``). Otherwise the earlier state is
    unknown and exposure conservatively starts at publication (``publication``),
    as it also does when applicability was recorded at or before publication.
    Coverage gaps are clipped to the exposed intervals, disclosed, and never
    imply coverage.
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
    raw_gaps = _coverage_gaps(published, monitoring_started_at, offline_periods)

    result = {
        'state': NOT_APPLICABLE, 'published_at': published, 'applicable_at': None, 'start_basis': None,
        'fix_available_at': None, 'fix_installed_at': None, 'effective_at': None,
        'closed_at': None, 'reopened': 0, 'intervals': [], 'duration_seconds': None, 'gaps': [], 'notes': [],
        'monitoring_complete': None,
    }
    intervals = result['intervals']

    def begin(at):
        intervals.append({'start': at, 'end': None, 'state': OPEN,
                          'fix_installed_at': None, 'effective_at': None, 'closed_at': None})

    def close(at):
        window = intervals[-1]
        window['state'] = CLOSED
        window['end'] = window['effective_at'] = window['closed_at'] = at

    def reopen(at, note):
        result['reopened'] += 1
        result['notes'].append(note)
        begin(at)

    state = NOT_APPLICABLE
    for at, _, event in ordered:
        kind = event['kind']
        if kind == 'applicable':
            if state == NOT_APPLICABLE:
                result['applicable_at'] = at
                if at <= published:
                    result['start_basis'] = 'publication'
                    if at < published:
                        result['notes'].append('Applicability was recorded before publication; exposure starts at publication')
                    begin(published)
                elif any(gap_start < at for _, gap_start, _ in raw_gaps):
                    result['start_basis'] = 'publication'
                    result['notes'].append(
                        'Monitoring did not cover the whole interval from publication to the first applicability '
                        'observation; exposure conservatively starts at publication')
                    begin(published)
                else:
                    result['start_basis'] = 'first_observed'
                    begin(at)
                state = OPEN
            elif state == CLOSED:
                state = OPEN
                reopen(max(at, published), 'Applicability was observed again after a verified fix; the exposure window reopened')
            elif state == PENDING_ACTIVATION:
                state = intervals[-1]['state'] = OPEN
                intervals[-1]['fix_installed_at'] = None
                result['notes'].append(
                    'Applicability was observed again before the fix took effect; the window stays open')
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
            intervals[-1]['fix_installed_at'] = at
            if event.get('activation_required') is True:
                state = intervals[-1]['state'] = PENDING_ACTIVATION
            else:
                state = CLOSED
                close(max(at, intervals[-1]['start']))
        elif kind == 'activated':
            if state == PENDING_ACTIVATION:
                state = CLOSED
                close(max(at, intervals[-1]['start']))
        elif kind == 'reintroduced':
            if state == CLOSED:
                state = OPEN
                reopen(max(at, published), 'An affected version was reintroduced; the exposure window reopened')
            elif state == PENDING_ACTIVATION:
                state = intervals[-1]['state'] = OPEN
                intervals[-1]['fix_installed_at'] = None
                result['notes'].append('An affected version was reintroduced before the fix took effect; the window stays open')
    result['state'] = state
    if state == NOT_APPLICABLE:
        return result

    latest = intervals[-1]
    for key in ('fix_installed_at', 'effective_at', 'closed_at'):
        result[key] = latest[key]
    total = 0.0
    for window in intervals:
        end = current if window['end'] is None else window['end']
        total += max(0.0, end - window['start'])
        for kind, gap_start, gap_end in raw_gaps:
            clipped_start = max(gap_start, window['start'])
            clipped_end = min(end if gap_end is None else gap_end, end)
            if clipped_end > clipped_start:
                result['gaps'].append({'kind': kind, 'start': clipped_start, 'end': clipped_end})
    result['duration_seconds'] = total
    result['gaps'].sort(key=lambda gap: (gap['start'], gap['end'], gap['kind']))
    result['monitoring_complete'] = not result['gaps'] and monitoring_started_at is not None
    return result
