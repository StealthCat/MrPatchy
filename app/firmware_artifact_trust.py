"""Pure firmware artifact staging and trust contract (first slice of #398).

Read-only helpers: no database, network, route, UI or runtime-authorization
effects, and nothing imports this module yet. Evaluating or re-checking a
binding never installs, stages or changes source trust; installation needs a
separate explicit authorization that this contract only gates, never grants.
"""
from __future__ import annotations

import hashlib
import json
import re

HEX64 = re.compile(r'^[0-9a-f]{64}$')
SOURCE_KINDS = {'lvfs', 'vendor', 'private', 'local_import'}
MAX_METADATA_AGE = 7 * 86400


def _digest(value) -> str:
    return str(value or '').strip().lower()


def _reasons(*items):
    return [r for r in items if r]


def binding(device: dict, release: dict, source: dict, artifact: dict) -> dict:
    """Exact device/release/source/trust-revision/digest binding for a staged artifact."""
    fields = {
        'device_id': str(device.get('id') or ''),
        'release_id': str(release.get('id') or ''),
        'release_version': str(release.get('version') or ''),
        'source_id': str(source.get('id') or ''),
        'trust_revision': str(source.get('trust_revision') or ''),
        'sha256': _digest(artifact.get('sha256')),
    }
    fields['binding_sha256'] = hashlib.sha256(
        json.dumps(fields, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return fields


def evaluate(device: dict, release: dict, source: dict, artifact: dict,
             policy: dict | None, now: float) -> dict:
    """Decide whether an artifact may appear installable.

    Returns ``state`` of ``installable`` or ``not_installable`` with the
    ``reasons``. Partial, unsigned, digest-mismatched, incompatible, stale-source,
    blocked, testing-remote or unreviewed-source artifacts are never installable.
    A positive result is eligibility evidence only, never authorization.
    """
    policy = policy or {}
    declared = _digest(artifact.get('sha256'))
    observed = _digest(artifact.get('observed_sha256'))
    reasons = []
    if source.get('kind') not in SOURCE_KINDS:
        reasons.append('unknown_source_kind')
    if source.get('trusted') is not True:
        reasons.append('source_not_trusted')
    if source.get('testing') and not policy.get('allow_testing'):
        reasons.append('testing_source_not_enabled')
    verified_at = source.get('metadata_verified_at')
    max_age = policy.get('max_metadata_age', MAX_METADATA_AGE)
    if not isinstance(verified_at, (int, float)) or isinstance(verified_at, bool):
        reasons.append('metadata_unverified')
    elif verified_at > now or now - verified_at > max_age:
        reasons.append('metadata_stale')
    if artifact.get('complete') is not True:
        reasons.append('artifact_incomplete')
    if artifact.get('signature_verified') is not True and not policy.get('allow_unsigned'):
        reasons.append('signature_not_verified')
    if not HEX64.match(declared):
        reasons.append('declared_digest_invalid')
    elif not HEX64.match(observed):
        reasons.append('digest_not_computed')
    elif declared != observed:
        reasons.append('digest_mismatch')
    if str(device.get('id') or '') not in {str(x) for x in release.get('compatible_device_ids') or []}:
        reasons.append('device_incompatible')
    if str(release.get('id') or '') in {str(x) for x in policy.get('blocked_releases') or []}:
        reasons.append('release_blocked')
    approved = {_digest(x) for x in policy.get('approved_checksums') or []}
    if approved and declared not in approved:
        reasons.append('checksum_not_approved')
    allowed = policy.get('allowed_sources')
    if allowed is not None and str(source.get('id') or '') not in {str(x) for x in allowed}:
        reasons.append('source_not_allowed')
    result = {'state': 'not_installable' if reasons else 'installable', 'reasons': reasons}
    if not reasons:
        result['binding'] = binding(device, release, source, artifact)
    return result


def recheck(bound: dict, device: dict, release: dict, source: dict, artifact: dict,
            policy: dict | None, now: float) -> dict:
    """Re-verify at use. Any drift from the staged binding requires replanning."""
    current = evaluate(device, release, source, artifact, policy, now)
    if current['state'] != 'installable':
        return {'state': 'replan', 'reasons': current['reasons']}
    drift = [k for k in ('device_id', 'release_id', 'release_version', 'source_id',
                         'trust_revision', 'sha256')
             if bound.get(k) != current['binding'][k]]
    if drift:
        return {'state': 'replan', 'reasons': [f'{k}_changed' for k in drift]}
    return {'state': 'installable', 'reasons': [], 'binding': current['binding']}
