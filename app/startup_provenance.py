"""Pure startup-entry provenance classification contract (roadmap F slice, #720).

Takes already-collected evidence about one startup file (a crontab, anacrontab,
systemd unit, drop-in or override, SysV script, ``rc.local`` ...) and returns
exactly one provenance class with its basis, verification strength and explicit
coverage gaps. It performs no I/O, never queries a package manager, never runs
or sources anything and never authorizes a response action.

Classes:

- ``verified_default``: the observed SHA-256 equals an *authenticated* vendor
  artifact for the same package and version as the single installed owner.
- ``modified``: the file is package-owned and its observed bytes differ from the
  authenticated artifact, or from the target's own package-database digest.
- ``unverifiable``: package-owned without an authenticated exact-version
  comparison, or generator output.
- ``custom``: a complete ownership query found no owning package.
- ``unknown``: evidence is missing, malformed, oversized or conflicting, the
  path is diverted or has more than one owner, or the unit is transient.
  When the authenticated artifact *differs* but the target's package database
  matches, the result is ``modified`` (authenticated evidence wins, with a
  ``package_db_disagrees`` gap); a conflict never raises trust.

Fail-closed rules:

- Package ownership alone never yields ``verified_default``. A match against the
  target's own package-database digest is reported as unauthenticated and stays
  ``unverifiable``; the target could have rewritten both file and database.
- An authenticated artifact for another package or version is never used; it
  is recorded as an ``artifact_mismatch`` gap.
- Every result carries ``safety: not_assessed``. Neither ``custom`` nor a
  package origin implies malicious or benign. Administrator baseline acceptance
  is reported in a separate ``baseline`` field and never changes the class.
- A matching entry inside a modified file is ``verified_default`` only when the
  content outside the entries (environment, section headers) has an authenticated
  matching ``context_sha256``. Otherwise it is ``modified`` with a disclosed gap,
  because ``PATH=/tmp:...`` changes what an unchanged job line runs. Matched
  default entries must also keep the authenticated order.
- A drop-in or override is classified on its own bytes. Its ``modifies`` unit
  name is reported, and the vendor unit's own classification is unaffected.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

CONTRACT_VERSION = 1
CLASSES = ('verified_default', 'modified', 'unverifiable', 'custom', 'unknown')
ROLES = ('file', 'drop_in', 'override')
SOURCES = ('file', 'generator', 'transient')
DIGEST_ALGORITHMS = {'sha256': 64, 'md5': 32}
MAX_PATH = 4096
MAX_NAME = 255
MAX_OWNERS = 16
MAX_ENTRIES = 4096
MAX_RECORDS = 4096
MAX_GAPS = 32

_HEX = re.compile(r'[0-9a-f]+')
# C0/C1 controls, DEL and Unicode line/paragraph separators are never valid in
# evidence text: they would let a path or name forge extra lines in later logs,
# JSON consumers or UI rendering.
_CONTROL = re.compile('[\x00-\x1f\x7f-\x9f\u2028\u2029]')
# Debian/RPM package names and versions; anything else is malformed evidence.
_PACKAGE = re.compile(r'[A-Za-z0-9][A-Za-z0-9+._:-]*')
_VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9+.~:_-]*')


def _gap(gaps: list[dict[str, str]], code: str, detail: str) -> None:
    if len(gaps) < MAX_GAPS:
        gaps.append({'code': code, 'detail': detail[:200]})
    elif gaps[-1]['code'] != 'gaps_truncated':
        gaps.append({'code': 'gaps_truncated', 'detail': 'Further gaps were not recorded.'})


def _text(value: Any, limit: int) -> str | None:
    if not isinstance(value, str) or not value or len(value) > limit or _CONTROL.search(value):
        return None
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:  # lone surrogates
        return None
    return value


def _digest(value: Any, algorithm: str = 'sha256') -> str | None:
    if not isinstance(value, str) or len(value) != DIGEST_ALGORITHMS[algorithm]:
        return None
    value = value.lower()
    return value if _HEX.fullmatch(value) else None


def _package(value: Any) -> tuple[str, str] | None:
    """Return (name, version) for a well-formed package identity, else None."""
    if not isinstance(value, dict):
        return None
    name, version = _text(value.get('package'), MAX_NAME), _text(value.get('version'), MAX_NAME)
    if name is None or version is None or not _PACKAGE.fullmatch(name) or not _VERSION.fullmatch(version):
        return None
    return name, version


def _entry_digests(value: Any, gaps: list[dict[str, str]], what: str) -> list[str] | None:
    if value is None:
        return None
    if not isinstance(value, (list, tuple)) or len(value) > MAX_ENTRIES:
        _gap(gaps, 'malformed_evidence', f'{what} must be a list of at most {MAX_ENTRIES} SHA-256 digests.')
        return None
    digests = [_digest(item) for item in value]
    if any(item is None for item in digests):
        _gap(gaps, 'malformed_evidence', f'{what} contains a value that is not a SHA-256 digest.')
        return None
    return digests  # type: ignore[return-value]


def _in_order(sequence: list[str], defaults: list[str]) -> bool:
    """True when ``sequence`` is a subsequence of ``defaults`` in order."""
    iterator = iter(defaults)
    return all(any(item == default for default in iterator) for item in sequence)


def _optional_digest(source: dict[str, Any], key: str, gaps: list[dict[str, str]], what: str) -> str | None:
    value = source.get(key)
    if value is None:
        return None
    digest = _digest(value)
    if digest is None:
        _gap(gaps, 'malformed_evidence', f'{what} is not a SHA-256 digest.')
    return digest


def _result(path: str | None, role: str | None, modifies: str | None) -> dict[str, Any]:
    return {'contract_version': CONTRACT_VERSION, 'path': path, 'role': role, 'modifies': modifies,
            'provenance': 'unknown', 'basis': 'insufficient_evidence', 'verification': 'none',
            'owner': None, 'safety': 'not_assessed',
            'baseline': {'accepted': False, 'affects_provenance': False},
            'entries': [], 'gaps': []}


def _finish(result: dict[str, Any], provenance: str, basis: str, verification: str) -> dict[str, Any]:
    result.update(provenance=provenance, basis=basis, verification=verification)
    return result


def _baseline(value: Any, result: dict[str, Any]) -> None:
    if value is None:
        return
    gaps = result['gaps']
    if isinstance(value, dict) and value.get('accepted') is False:
        return  # an explicit "not accepted" record is valid and changes nothing
    if not isinstance(value, dict) or value.get('accepted') is not True:
        _gap(gaps, 'malformed_baseline', 'Baseline acceptance is not a recorded acceptance; it was ignored.')
        return
    by, at = _text(value.get('by'), MAX_NAME), value.get('at')
    try:
        valid_at = isinstance(at, (int, float)) and not isinstance(at, bool) and math.isfinite(at)
    except OverflowError:  # an int too large for a float
        valid_at = False
    result['baseline'] = {'accepted': True, 'affects_provenance': False, 'by': by,
                          'at': at if valid_at else None}


def _entries(result: dict[str, Any], observed: list[str] | None, defaults: list[str] | None,
             context: str | None = None, default_context: str | None = None) -> None:
    """Classify entries inside one file. Only a modified file with authenticated
    default entries gets per-entry classes; otherwise entries inherit the file's.

    An entry's effective behaviour also depends on the file content outside the
    entries (``PATH``, ``SHELL``, ``MAILTO``, ``CRON_TZ``, anacron's
    ``START_HOURS_RANGE``, a unit's ``[Unit]``/``[Install]`` sections ...). A
    matching entry is therefore ``verified_default`` only when the observed
    context digest equals the authenticated artifact's context digest; otherwise
    it is reported as ``modified`` with the reason and a disclosed gap."""
    if observed is None:
        return
    provenance = result['provenance']
    if provenance == 'modified' and defaults is not None and result['verification'] == 'authenticated':
        remaining = Counter(defaults)
        if context is not None and default_context is not None:
            context_state = 'match' if context == default_context else 'changed'
        else:
            context_state = 'unverified'
        if context_state == 'changed':
            _gap(result['gaps'], 'modified_outside_entries',
                 'Content outside the entries differs from the authenticated artifact; '
                 'default entries may behave differently.')
        elif context_state == 'unverified':
            if Counter(observed) == remaining:
                # Same entries, different file: the change is outside the entries.
                _gap(result['gaps'], 'modified_outside_entries',
                     'The entries equal the authenticated defaults but the file differs, '
                     'so content outside the entries changed.')
            else:
                _gap(result['gaps'], 'entry_context_not_compared',
                     'No authenticated digest of the content outside the entries was compared; '
                     'default entries are not verified.')
        matched = []
        for index, digest in enumerate(observed):
            if remaining[digest] > 0:
                remaining[digest] -= 1
                matched.append(index)
        # Order matters (systemd ExecStartPre/ExecStart sequences, an empty
        # ``ExecStart=`` reset), so matched entries must keep the default order.
        if context_state == 'match' and not _in_order([observed[i] for i in matched], defaults):
            context_state = 'reordered'
            _gap(result['gaps'], 'default_entries_reordered',
                 'Default entries appear in a different order from the authenticated artifact.')
        if context_state == 'match' and Counter(observed) == Counter(defaults):
            _gap(result['gaps'], 'file_differs_outside_compared_content',
                 'Entries and context match the authenticated artifact but the file bytes differ '
                 '(for example comments or whitespace).')
        if context_state == 'match':
            entry_provenance, basis = 'verified_default', 'authenticated_default_entry'
        elif context_state == 'reordered':
            entry_provenance, basis = 'modified', 'default_entry_order_changed'
        else:
            entry_provenance, basis = 'modified', f'default_entry_context_{context_state}'
        matched_set = set(matched)
        for index, digest in enumerate(observed):
            if index in matched_set:
                result['entries'].append({'index': index, 'sha256': digest, 'provenance': entry_provenance,
                                          'basis': basis})
            else:
                result['entries'].append({'index': index, 'sha256': digest, 'provenance': 'custom',
                                          'basis': 'not_in_authenticated_defaults'})
        removed = sum(remaining.values())
        if removed:
            _gap(result['gaps'], 'default_entries_absent',
                 f'{removed} authenticated default entr{"y is" if removed == 1 else "ies are"} not present.')
        return
    basis = 'inherited_from_file'
    for index, digest in enumerate(observed):
        result['entries'].append({'index': index, 'sha256': digest, 'provenance': provenance, 'basis': basis})


def classify(evidence: Any) -> dict[str, Any]:
    """Classify one startup file from collected evidence.

    ``evidence`` keys (all optional unless noted):

    - ``path`` (required): absolute path of the observed file.
    - ``role``: ``file`` (default), ``drop_in`` or ``override``; ``modifies``
      names the unit a drop-in/override applies to.
    - ``source``: ``file`` (default), ``generator`` or ``transient``.
    - ``observed_sha256`` (required): SHA-256 of the observed bytes.
    - ``observed_md5``: MD5 of the same bytes, for comparing a dpkg md5sums value.
    - ``ownership``: ``{'complete': bool, 'owners': [{'package', 'version'}],
      'diverted': bool}`` from the package database query.
    - ``package_db_digest``: ``{'package', 'version', 'algorithm', 'value'}``
      from the target's own package database (unauthenticated).
    - ``authenticated_artifact``: ``{'package', 'version', 'sha256',
      'entry_sha256': [...], 'context_sha256'}`` from controller-verified
      vendor package bytes.
    - ``entry_sha256``: digests of entries parsed from the observed file.
    - ``context_sha256``: SHA-256 of the observed file's content outside its
      entries (environment assignments, section headers ...), canonicalised the
      same way as the artifact's ``context_sha256``. Per-entry
      ``verified_default`` requires both to be present and equal.
    - ``baseline``: ``{'accepted': True, 'by', 'at'}`` administrator acceptance.
    """
    if not isinstance(evidence, dict):
        result = _result(None, None, None)
        _gap(result['gaps'], 'malformed_evidence', 'Evidence is not an object.')
        return result
    path = _text(evidence.get('path'), MAX_PATH)
    role = evidence.get('role', 'file')
    role = role if role in ROLES else None
    modifies = _text(evidence.get('modifies'), MAX_NAME) if role in ('drop_in', 'override') else None
    result = _result(path if path and path.startswith('/') else None, role, modifies)
    gaps = result['gaps']
    if result['path'] is None:
        _gap(gaps, 'malformed_evidence', 'Path is missing, oversized or not absolute.')
    if role is None:
        _gap(gaps, 'malformed_evidence', 'Role is not file, drop_in or override.')
    if role in ('drop_in', 'override') and modifies is None:
        _gap(gaps, 'malformed_evidence', 'A drop-in or override must name the unit it modifies.')
    source = evidence.get('source', 'file')
    if source not in SOURCES:
        _gap(gaps, 'malformed_evidence', 'Source is not file, generator or transient.')
    observed = _digest(evidence.get('observed_sha256'))
    if observed is None:
        _gap(gaps, 'malformed_evidence', 'Observed SHA-256 is missing or malformed.')
    observed_entries = _entry_digests(evidence.get('entry_sha256'), gaps, 'Observed entry digests')
    context = _optional_digest(evidence, 'context_sha256', gaps, 'Observed context digest')
    blocked = bool(gaps)
    # Baseline acceptance is reported alongside, never as evidence: a declined
    # or malformed record is disclosed but cannot block classification.
    _baseline(evidence.get('baseline'), result)
    if blocked:
        return result
    if source == 'transient':
        _gap(gaps, 'transient_unit', 'Transient runtime units have no package or file provenance.')
        return result
    if source == 'generator':
        _gap(gaps, 'generator_output', 'Generator output is produced at boot and cannot be compared to package bytes.')
        result = _finish(result, 'unverifiable', 'generator_output', 'none')
        _entries(result, observed_entries, None)
        return result

    ownership = evidence.get('ownership')
    if not isinstance(ownership, dict):
        _gap(gaps, 'ownership_not_collected', 'No package ownership query result was collected.')
        return result
    owners_raw = ownership.get('owners')
    if not isinstance(owners_raw, (list, tuple)) or len(owners_raw) > MAX_OWNERS:
        _gap(gaps, 'malformed_evidence', 'Ownership owners must be a bounded list.')
        return result
    owners = [_package(item) for item in owners_raw]
    if any(item is None for item in owners):
        _gap(gaps, 'malformed_evidence', 'An owner is not a well-formed package and version.')
        return result
    if ownership.get('diverted') is not False and ownership.get('diverted') is not None:
        _gap(gaps, 'diverted', 'The path is diverted, so the package file is installed elsewhere.')
        return result
    if ownership.get('complete') is not True:
        _gap(gaps, 'ownership_incomplete', 'The ownership query did not complete.')
        return result
    if len(set(owners)) > 1:
        _gap(gaps, 'multiple_owners', 'More than one package claims this path.')
        return result
    if not owners:
        result = _finish(result, 'custom', 'no_owning_package', 'none')
        _entries(result, observed_entries, None)
        return result
    owner = owners[0]
    result['owner'] = {'package': owner[0], 'version': owner[1]}

    # Authenticated comparison, exact package and version only.
    authenticated: str | None = None
    defaults: list[str] | None = None
    default_context: str | None = None
    artifact = evidence.get('authenticated_artifact')
    if artifact is not None:
        identity, digest = _package(artifact), _digest(artifact.get('sha256')) if isinstance(artifact, dict) else None
        if identity is None or digest is None:
            _gap(gaps, 'malformed_evidence', 'Authenticated artifact evidence is malformed.')
            return result
        if identity != owner:
            _gap(gaps, 'artifact_mismatch',
                 f'Authenticated artifact is for {identity[0]} {identity[1]}, not the installed owner.')
        else:
            authenticated = 'match' if digest == observed else 'differ'
            defaults = _entry_digests(artifact.get('entry_sha256'), gaps, 'Authenticated default entry digests')
            if artifact.get('entry_sha256') is not None and defaults is None:
                return result
            if artifact.get('context_sha256') is not None:
                default_context = _optional_digest(artifact, 'context_sha256', gaps,
                                                   'Authenticated context digest')
                if default_context is None:
                    return result

    # The target's own package database, never authenticating on its own.
    database: str | None = None
    record = evidence.get('package_db_digest')
    if record is not None:
        identity = _package(record)
        algorithm = record.get('algorithm') if isinstance(record, dict) else None
        if identity is None or not isinstance(algorithm, str) or algorithm not in DIGEST_ALGORITHMS:
            _gap(gaps, 'malformed_evidence', 'Package database digest evidence is malformed.')
            return result
        value = _digest(record.get('value'), algorithm)
        compare = observed if algorithm == 'sha256' else _digest(evidence.get('observed_md5'), 'md5')
        if value is None:
            _gap(gaps, 'malformed_evidence', 'Package database digest value is malformed.')
            return result
        if identity != owner:
            _gap(gaps, 'package_db_mismatch', 'Package database digest is for another package or version.')
        elif compare is None:
            _gap(gaps, 'package_db_not_compared', f'No observed {algorithm} digest was collected.')
        else:
            database = 'match' if value == compare else 'differ'

    if authenticated == 'match' and database == 'differ':
        # Never raise trust under conflict: the bytes match the vendor artifact
        # but the target's own database says they were changed.
        _gap(gaps, 'conflicting_evidence',
             'The authenticated artifact matches but the package database digest differs.')
        return result
    if authenticated == 'differ' and database == 'match':
        # Authenticated evidence wins: a target that rewrote both the file and
        # its package database must still be reported as modified.
        _gap(gaps, 'package_db_disagrees',
             'The package database digest matches bytes that differ from the authenticated artifact.')
    if authenticated == 'match':
        result = _finish(result, 'verified_default', 'authenticated_artifact_match', 'authenticated')
    elif authenticated == 'differ':
        result = _finish(result, 'modified', 'authenticated_artifact_differs', 'authenticated')
    elif database == 'differ':
        result = _finish(result, 'modified', 'package_db_digest_differs', 'unauthenticated')
    elif database == 'match':
        _gap(gaps, 'unauthenticated_match',
             'Bytes match the target package database only; that database is not authenticated.')
        result = _finish(result, 'unverifiable', 'package_db_digest_match', 'unauthenticated')
    else:
        _gap(gaps, 'no_authenticated_comparison', 'No authenticated exact-version comparison was available.')
        result = _finish(result, 'unverifiable', 'package_owned', 'none')
    _entries(result, observed_entries, defaults, context, default_context)
    return result


def classify_many(evidence: Any) -> dict[str, Any]:
    """Classify a bounded list of files independently. Over-cap input yields no
    records; each record is classified only from its own evidence."""
    if not isinstance(evidence, (list, tuple)):
        return {'contract_version': CONTRACT_VERSION, 'records': [],
                'gaps': [{'code': 'malformed_evidence', 'detail': 'Evidence is not a list.'}]}
    if len(evidence) > MAX_RECORDS:
        return {'contract_version': CONTRACT_VERSION, 'records': [],
                'gaps': [{'code': 'over_limit', 'detail': f'More than {MAX_RECORDS} records.'}]}
    return {'contract_version': CONTRACT_VERSION, 'records': [classify(item) for item in evidence], 'gaps': []}
