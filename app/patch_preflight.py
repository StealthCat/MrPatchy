"""Advisory patch preflight warnings from retained endpoint-agent telemetry (#342).

Pure and read-only. The warnings reuse the validated resource summary and
thresholds of ``agent_fleet_health.resources`` and are shown while an operator
reviews an on-demand patch installation. They never block, change or authorize
a patch, approval, recovery policy or response action, and nothing here uses AI.
Only fresh telemetry can produce warnings; anything else is reported as unknown,
never as an all-clear.
"""
from . import agent_fleet_health as fleet

GAPS = [
    'Warnings come from the agent\'s own last telemetry: root file system, memory and the kernel clock flag. Other file systems such as /boot or /var are not checked.',
    'These warnings are advisory. They do not block or change the installation; the target and repositories are still revalidated at execution.',
]
UNKNOWN_GAP = {
    'missing': 'No telemetry collection time is retained for this server, so disk, memory and clock health before patching is unknown.',
    'stale': f'The last telemetry is older than {fleet.TELEMETRY_STALE_SECONDS} seconds, so current disk, memory and clock health before patching is unknown.',
    'invalid': 'The retained telemetry reports a future collection time, so disk, memory and clock health before patching is unknown.',
}
ABSENT_GAP = 'This server\'s agent has not reported disk, memory or clock health; older agents do not send it. Health before patching is unknown.'
# Fixed, server-authored text only. Endpoint-supplied strings never reach the dialog.
_WARNINGS = {
    'disk-space-low': ('Root file system space is low',
                       'Package downloads and unpacking can fail on a nearly full root file system and leave packages half-configured. Free space or clean the package cache before installing.'),
    'disk-inodes-low': ('Root file system inodes are low',
                        'Packages that add many small files can fail when inodes run out. Remove unneeded files before installing.'),
    'memory-low': ('Available memory is low',
                   'Package scripts and service restarts may be killed under memory pressure. Consider installing when the server is less busy.'),
    'clock-unsynchronized': ('System clock is not synchronized',
                             'Repository metadata and signature checks depend on the clock and can be rejected when it is wrong. Check the server\'s time synchronization before installing.'),
}


def _collected(telemetry, now):
    collected = fleet._timestamp(telemetry.get('collected') if isinstance(telemetry, dict) else None)
    if collected is None:
        return 'missing', None
    if collected > now + fleet.CLOCK_SKEW_SECONDS:
        return 'invalid', None
    return ('stale' if now - collected > fleet.TELEMETRY_STALE_SECONDS else 'fresh'), collected


def assess(telemetry, now):
    """Return the advisory preflight for one server's retained telemetry. Pure and redacted."""
    freshness, collected = _collected(telemetry, now)
    base = {'threshold_percent': fleet.LOW_AVAILABLE_PERCENT, 'collected': collected, 'warnings': [], 'gaps': list(GAPS)}
    if freshness != 'fresh':
        return {**base, 'state': 'unknown', 'gaps': [UNKNOWN_GAP[freshness], *GAPS]}
    summary = fleet.resources(telemetry, 'fresh')
    if summary['state'] != 'present':
        return {**base, 'state': 'unknown', 'gaps': [ABSENT_GAP, *GAPS]}
    unknown = [label for key, label in (('disk', 'root file system space'), ('inodes', 'root file system inodes'),
                                        ('memory', 'available memory'), ('clock', 'clock synchronization'))
               if summary[key] is None]
    warnings = []
    for code in summary['attention']:
        title, guidance = _WARNINGS[code]
        key = {'disk-space-low': 'disk', 'disk-inodes-low': 'inodes', 'memory-low': 'memory'}.get(code)
        warnings.append({'code': code, 'title': title, 'guidance': guidance,
                         'available_percent': summary[key]['available_percent'] if key else None})
    gaps = list(GAPS)
    if unknown:
        gaps.insert(0, 'Not reported or not interpretable: ' + ', '.join(unknown) + '.')
    return {**base, 'state': 'attention' if warnings else ('partial' if unknown else 'clear'),
            'warnings': warnings, 'gaps': gaps}
