#!/usr/bin/env python3
"""Verify a Mr Patchy response record offline using only the standard library."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_BYTES = 16 * 1024 * 1024
SECTIONS = {
    'response', 'incident', 'incident_events', 'advisory_plans', 'preservation',
    'acquisition', 'acquisition_observations', 'file_approvals', 'file_events',
    'monitor_checks', 'process_observations', 'process_responses', 'process_approvals',
    'process_events', 'repair_preparations', 'repair_stages', 'stage_events',
    'repair_publications', 'publication_events',
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def verify(data, expected=None):
    if len(data) > MAX_BYTES:
        raise ValueError('Record exceeds 16 MiB')
    digest = hashlib.sha256(data).hexdigest()
    if expected is not None and (not re.fullmatch('[a-fA-F0-9]{64}', expected) or digest != expected.lower()):
        raise ValueError('Whole-file SHA-256 differs from the separately supplied digest')
    value = json.loads(data, object_pairs_hook=unique_object)
    if not isinstance(value, dict) or set(value) != {'record', 'integrity'}:
        raise ValueError('Unsupported response record envelope')
    record, integrity = value['record'], value['integrity']
    if (not isinstance(record, dict) or set(record) != {'format', 'version', 'export', 'host', 'scope', 'monitoring', 'sections'}
            or record.get('format') != 'mrpatchy-response-record' or type(record.get('version')) is not int or record['version'] not in (1, 2, 3)):
        raise ValueError('Unsupported response record version')
    if (not isinstance(integrity, dict) or set(integrity) != {'algorithm', 'canonicalization', 'record_sha256', 'sections', 'meaning'}
            or integrity.get('algorithm') != 'sha256' or integrity.get('canonicalization') != 'python-json-sort-keys-ascii-compact-v1'):
        raise ValueError('Unsupported integrity scheme')
    if hashlib.sha256(canonical(record)).hexdigest() != integrity.get('record_sha256'):
        raise ValueError('Record content hash mismatch')
    sections, manifests = record.get('sections'), integrity.get('sections')
    expected_sections = SECTIONS | ({'service_observations'} if record['version']>=2 else set()) | ({'service_watch'} if record['version']>=3 else set())
    if not isinstance(sections, dict) or not isinstance(manifests, dict) or set(sections) != set(manifests) or set(sections) != expected_sections:
        raise ValueError('Section manifest mismatch')
    total = 0
    for name, rows in sections.items():
        manifest = manifests[name]
        if not isinstance(rows, list) or not isinstance(manifest, dict) or any(not isinstance(row, dict) for row in rows):
            raise ValueError('Invalid section')
        total += len(rows)
        raw = canonical(rows)
        if (len(rows) > 1000 or total > 5000 or type(manifest.get('records')) is not int
                or type(manifest.get('bytes')) is not int or manifest != {
                    'sha256': hashlib.sha256(raw).hexdigest(), 'records': len(rows), 'bytes': len(raw)}):
            raise ValueError('Section integrity mismatch: ' + name)
    return digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--sha256', help='Whole-file SHA-256 retained through an independently trusted channel')
    args = parser.parse_args()
    try:
        with args.record.open('rb') as stream:
            data = stream.read(MAX_BYTES + 1)
        digest = verify(data, args.sha256)
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        print('Verification failed: ' + str(error), file=sys.stderr)
        return 1
    print('Integrity verified. Whole-file SHA-256: ' + digest)
    print('Hashes do not authenticate the controller, prove historical completeness, or verify current host/file state.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
