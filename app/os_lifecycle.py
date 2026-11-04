"""Conservative, read-only OS support lifecycle evaluation."""
from datetime import datetime, timezone
import re
import math
from target import release as release_rules


CATALOG_REVIEWED = '2026-11-04'
UBUNTU_SOURCE = {'name': 'Ubuntu release cycle', 'url': 'https://ubuntu.com/about/release-cycle', 'reviewed': CATALOG_REVIEWED}
DEBIAN_SOURCE = {'name': 'Debian releases', 'url': 'https://www.debian.org/releases/', 'reviewed': CATALOG_REVIEWED}
DEBIAN_LTS_SOURCE = 'https://wiki.debian.org/LTS'

# Ubuntu publishes lifecycle end months; those are normalized to the inclusive
# last day of that month. Debian publishes exact end dates. Extended Ubuntu
# coverage requires a separately observed entitlement, which this inventory
# does not currently collect.
CATALOG = {
    ('ubuntu', '20.04'): {'label': 'Ubuntu 20.04 LTS', 'standard': '2025-05-31', 'extended': '2030-05-31'},
    ('ubuntu', '22.04'): {'label': 'Ubuntu 22.04 LTS', 'standard': '2027-05-31', 'extended': '2032-05-31'},
    ('ubuntu', '24.04'): {'label': 'Ubuntu 24.04 LTS', 'standard': '2029-05-31', 'extended': '2034-05-31'},
    ('ubuntu', '26.04'): {'label': 'Ubuntu 26.04 LTS', 'standard': '2031-05-31', 'extended': '2036-05-31'},
    ('ubuntu', '26.10'): {'label': 'Ubuntu 26.10', 'standard': '2027-07-31', 'extended': None},
    ('debian', '12'): {
        'label': 'Debian 12 (bookworm)', 'standard': '2026-07-11', 'extended': '2028-06-30',
        'lts_architectures': frozenset({'i386', 'amd64', 'armhf', 'arm64', 'ppc64el'}),
    },
    ('debian', '13'): {
        'label': 'Debian 13 (trixie)', 'standard': '2028-08-09', 'extended': '2030-06-30',
        'lts_architectures': None,
    },
}


def _unknown(coverage, message, *, observed=None, vendor=None, release=None, source=None, gaps=()):
    return {
        'state': 'unknown', 'coverage': coverage, 'vendor': vendor, 'release': release,
        'label': None, 'standard_until': None, 'extended_until': None, 'source': source,
        'coverage_gaps': list(gaps), 'message': message, 'observed_at': observed,
        'catalog_reviewed': CATALOG_REVIEWED,
    }


def _parse_os_release(value):
    if not isinstance(value, str) or len(value) > 65536:
        return {}
    result = {}
    for line in value.splitlines():
        if '=' not in line or line.lstrip().startswith('#'):
            continue
        key, raw = line.split('=', 1)
        key = key.strip()
        if key not in ('ID', 'VERSION_ID'):
            continue
        if key in result:return {}
        item = raw.strip()
        if len(item) >= 2 and item[0] == item[-1] and item[0] in ('"', "'"):
            item = item[1:-1]
        if len(item)>80:return {}
        result[key] = item
    return result


def _timestamp(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:result=float(value)
    except (ValueError,OverflowError):return None
    return result if math.isfinite(result) and 0<=result<=253402300799 else None


def evaluate(inventory, now, max_age_seconds):
    """Return a bounded lifecycle assessment from a stored inventory snapshot."""
    if not isinstance(inventory, dict):
        return _unknown('missing_inventory', 'No stored operating-system inventory is available.')
    observed, current = _timestamp(inventory.get('collected')), _timestamp(now)
    max_age_seconds=_timestamp(max_age_seconds)
    if observed is None or current is None or max_age_seconds is None or max_age_seconds <= 0:
        return _unknown('missing_inventory', 'The inventory collection time is missing or invalid.', observed=observed)
    if observed > current + 300:
        return _unknown('stale_inventory', 'The inventory collection time is in the future; lifecycle coverage cannot be verified.', observed=observed)
    if current - observed > max_age_seconds:
        return _unknown('stale_inventory', 'The operating-system inventory is stale; refresh it before relying on lifecycle status.', observed=observed)

    values = _parse_os_release(inventory.get('os'))
    distro, release = values.get('ID', ''), values.get('VERSION_ID', '')
    if distro not in ('ubuntu', 'debian'):
        return _unknown(
            'unsupported_distribution',
            'No verified lifecycle mapping exists for this exact distribution; derivatives are not treated as Debian or Ubuntu.',
            observed=observed, vendor=distro or None, release=release or None,
        )
    try:derivative=release_rules.is_raspberry_pi(inventory,distro)
    except (TypeError,AttributeError):
        return _unknown('invalid_inventory','Distribution provenance cannot be verified from malformed package/source inventory.',observed=observed)
    if derivative:
        return _unknown('unsupported_distribution','Raspberry Pi vendor inventory does not establish Debian/Ubuntu lifecycle coverage.',observed=observed)
    valid = re.fullmatch(r'\d{2}\.\d{2}', release) if distro == 'ubuntu' else re.fullmatch(r'\d+', release)
    source = UBUNTU_SOURCE if distro == 'ubuntu' else DEBIAN_SOURCE
    vendor = 'Ubuntu' if distro == 'ubuntu' else 'Debian'
    if not valid or (distro, release) not in CATALOG:
        return _unknown('unknown_release', 'This exact release is not in the reviewed lifecycle catalog.', observed=observed, vendor=vendor, release=release or None, source=source)

    record = CATALOG[(distro, release)]
    today = datetime.fromtimestamp(current, timezone.utc).date()
    standard_end = datetime.fromisoformat(record['standard']).date()
    extended_end = datetime.fromisoformat(record['extended']).date() if record['extended'] else None
    common = {
        'vendor': vendor, 'release': release, 'label': record['label'],
        'standard_until': record['standard'], 'extended_until': record['extended'],
        'source': source, 'observed_at': observed, 'catalog_reviewed': CATALOG_REVIEWED,
    }
    if today <= standard_end:
        return {'state': 'standard', 'coverage': 'vendor_standard', **common, 'coverage_gaps': [], 'message': 'The vendor reports this release in standard support.'}
    if extended_end and today <= extended_end:
        if distro == 'ubuntu':
            gap = 'Ubuntu Pro entitlement is not observed by this inventory.'
            return {'state': 'extended', 'coverage': 'subscription_required', **common, 'coverage_gaps': [gap], 'message': 'Standard support has ended. Extended coverage may require an active Ubuntu Pro entitlement.'}
        architectures = record['lts_architectures']
        architecture = inventory.get('architecture')
        if not isinstance(architecture, str) or architectures is None or architecture not in architectures:
            return {
                'state': 'unknown', 'coverage': 'architecture_unverified', **common,
                'coverage_gaps': ['Debian LTS architecture coverage is unverified for this host.', 'Architecture source: '+DEBIAN_LTS_SOURCE],
                'message': 'Standard support has ended, but this host is not verified as eligible for Debian LTS.',
            }
        return {'state': 'extended', 'coverage': 'debian_lts', **common, 'coverage_gaps': [], 'message': 'The release and reported architecture are within Debian LTS coverage.'}
    return {
        'state': 'ended', 'coverage': 'vendor_ended', **common,
        'coverage_gaps': ['No reviewed vendor support phase remains in this catalog.'],
        'message': 'The reviewed vendor support lifecycle has ended for this release.',
    }
