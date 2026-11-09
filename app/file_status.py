"""Ordered, read-only file evidence resolution. Authentic bytes are not safe behavior."""
import copy
import re
import time
from collections import Counter

from sqlalchemy import select
from . import ai_assessments, known_good, persistence, vendor
from .db import Behavior
from .incidents import Inspection

ORDER = ['authenticated_repository', 'known_good_database', 'ai']
NOTE = ('Recorded files only, not a full filesystem inventory. Signed artifact matches '
        'do not establish current repository membership, key revocation, safe behavior or a clean host. '
        'AI results are advisory and never approve a baseline.')


def repositories(s, host_id):
    """Newest authenticated receipt for each path wins; never hide a newer mismatch."""
    result = {}
    query = select(Inspection).where(Inspection.host_id == host_id).order_by(
        Inspection.created.desc(), Inspection.id.desc())
    for row in s.scalars(query).yield_per(100):
        report = row.report or {}
        if report.get('trust_basis') not in (
                'controller_authenticated_debian_artifact', 'controller_authenticated_rpm_artifact'):
            continue
        manifest, proof, receipt = (report.get(k) for k in (
            'vendor_manifest', 'vendor_authentication', 'vendor_verification'))
        try:
            binding = vendor.validate_authenticated(manifest, proof, receipt)
        except (TypeError, ValueError):
            continue
        findings = {f['path']: f for f in receipt['findings']}
        for entry in manifest['entries']:
            result.setdefault(entry['path'], {
                'expected_sha256': entry['sha256'], 'inspection_id': row.id,
                'created': row.created, 'package': manifest['package'], 'version': manifest['version'],
                'proof_sha256': binding['proof_sha256'],
                'receipt_state': receipt['state'], 'finding': findings.get(entry['path']),
            })
    return result


def resolve(path, checksum, proofs):
    result = {'status': 'unassessed', 'method': 'none', 'order': ORDER,
              'reason': 'No authenticated artifact match; check exact known-good context before AI.'}
    if not isinstance(checksum, str) or not re.fullmatch('[a-f0-9]{64}', checksum):
        return {**result, 'status': 'unavailable', 'reason': 'No recorded SHA-256 for these file bytes.'}
    proof = proofs.get(path)
    if proof is None:
        return result
    # A signed manifest authenticates expected bytes even when the target receipt
    # is incomplete. The separately recorded observation must match those bytes.
    match = checksum == proof['expected_sha256']
    return {**result, 'status': 'verified' if match else 'changed',
            'method': 'authenticated_repository', 'reference': proof,
            'reason': 'SHA-256 matches authenticated signed artifact bytes.' if match else
            'Recorded SHA-256 differs from the latest authenticated artifact for this path.'}


def before_ai(s, row):
    """Always replace any target-supplied claim with controller-derived evidence."""
    evidence = copy.deepcopy(row.evidence or {})
    from .file_trust import assess
    evidence['file_assessment'] = assess(s, row.host_id, evidence.get('executable'), evidence.get('sha256'),
                                          repositories(s, row.host_id),
                                          observed=getattr(row, 'last_seen', None))
    evidence['file_assessment']['behavior_note'] = (
        'File authenticity does not resolve process behavior. Check the exact known-good '
        'database next; AI may investigate only the remaining behavior uncertainty.')
    return evidence


def page(s, host, offset=0, q='', status='', limit=50):
    from .file_trust import assess, Trust, identity
    proofs = repositories(s, host.id)
    baseline = persistence.status(s, host.id)
    rows = {}

    def add(path, checksum, source, observed, **extra):
        if not isinstance(path, str) or not path.startswith('/'):
            return
        key = (path, checksum if isinstance(checksum, str) else '')
        if key not in rows:
            rows[key] = {'path': path, 'sha256': key[1], 'sources': [],
                         'observed': observed, **assess(s, host.id, path, checksum, proofs, persist=False,
                                                           observed=observed), **extra}
        rows[key]['sources'].append(source)
        rows[key]['observed'] = max(rows[key]['observed'] or 0, observed or 0)
        rows[key].update(extra)

    telemetry = host.telemetry or {}
    for path, checksum in telemetry.get('managed', {}).items():
        add(path, checksum, 'managed_file', telemetry.get('hashed_at'))
    for path, checksum in (host.baseline or {}).items():
        if path not in telemetry.get('managed', {}):
            add(path, None, 'enrollment_baseline', None, baseline_sha256=checksum,
                status='unavailable', reason='Enrollment baseline exists, but no current file observation is recorded.')
    latest = baseline['latest']
    changes = {c['path']: c['kind'] for c in baseline['comparison']['changes']}
    if latest:
        for entry in latest['inventory'].get('entries', []):
            add(entry['path'], entry.get('sha256'), 'startup_inventory', latest['created'],
                baseline_status=changes.get(entry['path'], baseline['state']), kind=entry['kind'])
    for change in baseline['comparison']['changes']:
        if change['kind'] == 'removed':
            add(change['path'], None, 'reviewed_baseline', latest['created'],
                status='missing', reason='Missing from the latest comparable complete startup inventory.')
    # Include files seen only by vendor inspection, including missing/different bytes.
    for path, proof in proofs.items():
        finding = proof['finding'] or {}
        checksum = (finding.get('observed_sha256') if finding else
                    proof['expected_sha256'] if proof['receipt_state'] == 'matches_artifact_bytes' else None)
        add(path, checksum, 'vendor_inspection', proof['created'])
        if finding.get('status') == 'missing':
            rows[(path, '')].update(status='missing', reason='Vendor inspection recorded this file as missing.')
    for behavior in s.scalars(select(Behavior).where(Behavior.host_id == host.id)).yield_per(100):
        evidence = behavior.evidence or {}
        path, checksum = evidence.get('executable'), evidence.get('sha256')
        add(path, checksum, 'process_observation', behavior.last_seen)
        key = (path, checksum if isinstance(checksum, str) else '')
        if key not in rows:
            continue
        item = rows[key]
        assessment = s.scalar(select(ai_assessments.Assessment).where(
            ai_assessments.Assessment.subject == behavior.id,
            ai_assessments.Assessment.state_hash == ai_assessments.state_hash(behavior))
            .order_by(ai_assessments.Assessment.created.desc(), ai_assessments.Assessment.id.desc()).limit(1))
        context = {'id': behavior.id, 'risk': behavior.verdict, 'approved': behavior.approved,
                   'method': assessment.source if assessment else 'not_recorded'}
        if assessment:
            context['assessment_id'] = assessment.id
            if assessment.source == 'known_good':
                context['known_good'] = known_good.assessment(assessment, s)
        item.setdefault('behaviors', []).append(context)
        # AI classifies behavior, never authenticates the file. Retain both facts.
        if item['method'] == 'none' and assessment:
            item['status'] = 'behavior_assessed'
            item['method'] = assessment.source
            item['reason'] = 'Behavior assessment recorded; file authenticity remains unverified.'
            if assessment.source == 'known_good' and context['known_good'].get('published'):
                item.update(status='known_good', method='known_good_database',
                            reason='Exact verified context matches an active retained known-good candidate.')
                trust = s.get(Trust, identity(host.id, path, checksum, 'known_good_database',
                    {'assessment_id': assessment.id, 'fingerprint': context['known_good']['fingerprint']}))
                if trust and trust.reference.get('assessment_id') == assessment.id:
                    item.update(trusted=True, trust_id=trust.id,
                        reason='Automatically trusted and stored: exact active known-good context.')
    all_rows = sorted(rows.values(), key=lambda r: (r['path'], r['sha256']))
    now = time.time()
    for row in all_rows:
        row['stale'] = not row['observed'] or not 0 <= now - row['observed'] <= persistence.MAX_AGE
        row['sources'] = sorted(set(row['sources']))
    filtered = [r for r in all_rows if q.casefold() in r['path'].casefold()
                and (not status or r['status'] == status)]
    return {'items': filtered[offset:offset+limit], 'more': len(filtered) > offset+limit,
            'total': len(filtered), 'recorded': len(all_rows), 'counts': dict(Counter(r['status'] for r in all_rows)),
            'order': ORDER, 'note': NOTE, 'baseline_state': baseline['state'],
            'coverage': latest['inventory'].get('gaps', []) if latest else ['No startup inventory recorded.']}
