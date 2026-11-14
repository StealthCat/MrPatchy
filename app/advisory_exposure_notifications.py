"""Administrator notification when a stored advisory scan shows version-affected advisories.

An administrator-run OSV advisory scan (``POST /api/operations/{host}/advisories``)
stores per-advisory applicability under the ``advisories:<host>`` setting. Before
this producer an ``affected`` result was visible only while the scan dialog stayed
open. This reconciler publishes one admin-only in-app event per server whose latest
stored scan still has ``affected`` rows for packages installed at the scanned source
version, and resolves it when none remain.

Applicability is version matching against vendor ranges, not exploitation
evidence. The producer only reads: it runs no scan, contacts no advisory service
or AI provider, selects no patches and authorizes no containment or response. The
reason text is fixed and carries only controller-computed counts; advisory text,
package names and other stored strings are never copied.
"""
import hashlib
import json
import re

from sqlalchemy import select

from . import host_lifecycle, notifications
from .apt import paragraphs
from .db import Setting

SOURCE = 'cve-exposure'
KIND = 'affected-advisories'
SUBJECT = 'server'
SETTING_PREFIX = 'advisories:'
AFFECTED = 'affected'
UNCERTAIN = 'uncertain'
# Mirrors advisories._ADVISORY_ID and the source-package parsing in advisories.scan.
_ADVISORY_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}')
_SOURCE = re.compile(r'([a-z0-9+.-]+)(?: \(([^)]+)\))?')
_BATCH = 500
RESOLVED = ('The latest stored advisory scan for this server no longer reports affected advisories for packages '
            'at their scanned versions. This is not a clean-host verdict; re-run Advisory matching after '
            'package changes to refresh the result.')


def _plural(count, word, plural=None):
    return str(count) + ' ' + (word if count == 1 else plural or word + 's')


def reason(matches, packages, fixable, uncertain):
    text = ('The latest stored advisory scan for this server reports '
            + _plural(matches, 'advisory match', 'advisory matches')
            + ' whose vendor version ranges include the installed version of '
            + _plural(packages, 'package') + '; ' + str(fixable) + ' of these name a vendor fix version. '
            'This is version applicability, not evidence of exploitation. Review Patching for available '
            'updates and vendor advisories, then re-run Advisory matching from Operations to confirm.')
    if uncertain:
        text += (' The same scan also has ' + _plural(uncertain, 'uncertain result')
                 + ' that still need review; uncertain is never treated as safe.')
    return text


def installed_sources(inventory):
    """Map ``Package:Architecture`` to its current (source name, source version), or ``None`` if unreadable."""
    if not isinstance(inventory, dict) or not isinstance(inventory.get('status'), str):
        return None
    if inventory.get('package_manager') == 'rpm':
        return None
    found = {}
    for package in paragraphs(inventory['status']):
        if 'Package' not in package or 'Architecture' not in package:
            continue
        match = _SOURCE.fullmatch(package.get('Source', package['Package']))
        if match:
            found[package['Package'] + ':' + package['Architecture']] = (match[1], match[2] or package.get('Version'))
    return found


def exposure(result, installed):
    """Return ``(affected_rows, uncertain_count)`` still current for one stored scan.

    ``installed`` of ``None`` means the current inventory cannot be read, so stored
    rows are kept rather than treated as patched.
    """
    if not isinstance(result, dict) or not isinstance(result.get('results'), list):
        return set(), 0
    affected = set()
    uncertain = 0
    for item in result['results']:
        if not isinstance(item, dict) or not isinstance(item.get('applicability'), list):
            continue
        binary = item.get('binary')
        package = item.get('package') if isinstance(item.get('package'), dict) else {}
        source, version = package.get('name'), item.get('version')
        if not all(isinstance(value, str) and value for value in (binary, source, version)):
            continue
        if installed is not None and installed.get(binary) != (source, version):
            continue  # upgraded, downgraded or removed since the scan: the row no longer describes this host
        for row in item['applicability']:
            if not isinstance(row, dict):
                continue
            status = row.get('status')
            if status == UNCERTAIN:
                uncertain += 1
                continue
            advisory = row.get('advisory_id')
            if status != AFFECTED or not isinstance(advisory, str) or not _ADVISORY_ID.fullmatch(advisory):
                continue
            affected.add((advisory, binary, source, version, row.get('fix_available') is True))
    return affected, uncertain


def _digest(affected):
    material = json.dumps(sorted([list(row[:4]) for row in affected]), separators=(',', ':'))
    return 'advisories-v1:' + hashlib.sha256(material.encode()).hexdigest()


def _link(host_id):
    return '#servers/' + host_id + '/patching'


def _eligible(host):
    return not host.deleted_at and host_lifecycle.active(host) and host.state != 'enrolling'


def publish(session, hosts, now):
    """Publish or resolve exposure events in the caller's transaction. Returns the exposed host IDs."""
    eligible = {host.id: host for host in hosts if _eligible(host)}
    ids = list(eligible)
    stored = {}
    for start in range(0, len(ids), _BATCH):
        keys = [SETTING_PREFIX + host_id for host_id in ids[start:start + _BATCH]]
        for row in session.scalars(select(Setting).where(Setting.key.in_(keys))):
            stored[row.key[len(SETTING_PREFIX):]] = row.value
    exposed = {}
    for host_id, result in stored.items():
        affected, uncertain = exposure(result, installed_sources(eligible[host_id].inventory))
        if affected:
            exposed[host_id] = (affected, uncertain)
    for host_id, (affected, uncertain) in exposed.items():
        unique = {row[:4] for row in affected}
        fixable = len({row[:4] for row in affected if row[4]})
        packages = len({row[1] for row in unique})
        notifications.publish(session, source=SOURCE, kind=KIND, subject_type=SUBJECT, subject_id=host_id,
                              host_id=host_id, subject_revision=_digest(affected), severity='medium',
                              reason=reason(len(unique), packages, fixable, uncertain), deep_link=_link(host_id),
                              minimum_role='admin', now=now)
    N, R = notifications.NotificationEvent, notifications.NotificationRevision
    active = session.execute(select(N.subject_id).join(R, (R.event_id == N.id) & (R.revision == N.revision)).where(
        N.source == SOURCE, N.kind == KIND, N.subject_type == SUBJECT, R.lifecycle == 'active')).scalars().all()
    for host_id in active:
        if host_id in exposed:
            continue
        notifications.publish(session, source=SOURCE, kind=KIND, subject_type=SUBJECT, subject_id=host_id,
                              host_id=host_id, subject_revision='resolved', severity='info', reason=RESOLVED,
                              deep_link=_link(host_id), minimum_role='admin', lifecycle='resolved', now=now)
    return set(exposed)
