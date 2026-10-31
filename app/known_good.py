"""Strict candidate fingerprints for future fleet-wide known-good reuse.

This module deliberately does not publish, look up, or trust a cached verdict.
It only creates a host-independent candidate when a completed low-risk AI
assessment carries an explicit, fully verified evidence-manifest contract.
Current partial follow-up receipts therefore remain cache misses.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re


FINGERPRINT_VERSION = 1
CONTEXT_VERSION = 1
MAX_CONTEXT_BYTES = 64 * 1024
COMPONENTS = ('artifact', 'provenance', 'configuration', 'behavior', 'followup', 'coverage')
OBSERVATION_FIELDS = {
    'host_id', 'pid', 'start_ticks', 'boot_id', 'proc_device', 'proc_inode',
    'collected', 'received', 'observed', 'ephemeral_source_ports',
    'vendor_inspection_id', 'authenticated_at',
}
FORBIDDEN_CANONICAL_FIELDS = OBSERVATION_FIELDS | {
    'hostname', 'server_id', 'timestamp', 'mtime', 'ctime', 'source_port',
    'local_ephemeral_port',
}
HEX64 = re.compile(r'^[0-9a-f]{64}$')

REASON_TEXT = {
    'source_not_ai': 'Only a recorded AI assessment can become an automatic safe candidate.',
    'result_not_safe': 'The assessment is not a complete low-risk result.',
    'model_missing': 'The requested model is not recorded.',
    'policy_binding_missing': 'The exact assessment policy is not bound to this result.',
    'snapshot_identity_unverified': 'The original behavior identity is not verified.',
    'followup_identity_unverified': 'Follow-up evidence is not bound to a rechecked process identity.',
    'coverage_incomplete': 'Follow-up evidence still has declared coverage gaps.',
    'recorded_process_not_bound': 'Evidence is not scoped to the recorded process identity.',
    'known_good_context_missing': 'No explicit known-good evidence manifest is recorded.',
    'known_good_context_invalid': 'The known-good evidence manifest is malformed or unsupported.',
    'known_good_context_too_large': 'The known-good evidence manifest exceeds its safety bound.',
    'observation_fields_invalid': 'Host-only observation fields are not isolated from canonical evidence.',
    'artifact_binding_invalid': 'Verified artifact bytes and manifest bindings are incomplete.',
    'provenance_binding_invalid': 'Authenticated provenance bindings are incomplete.',
    'configuration_binding_invalid': 'Complete configuration bindings are missing.',
    'behavior_binding_invalid': 'Effective privilege, startup, network, execution, or memory bindings are incomplete.',
    'followup_binding_invalid': 'Required follow-up evidence and policy bindings are incomplete.',
    'coverage_binding_invalid': 'The complete evidence-coverage manifest is missing.',
}


def _sha(value):
    return isinstance(value, str) and bool(HEX64.fullmatch(value))


def _json_safe(value):
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_json_safe(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _json_safe(item) for key, item in value.items())
    return False


def _contains_forbidden(value):
    if isinstance(value, dict):
        return any(key.lower() in FORBIDDEN_CANONICAL_FIELDS or _contains_forbidden(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_forbidden(item) for item in value)
    return False


def _component(value, marker):
    return isinstance(value, dict) and value.get('version') == CONTEXT_VERSION and value.get(marker) is True


def _manifest(value, fields):
    return all(_sha(value.get(field)) for field in fields)


def _reason(code):
    return {'code': code, 'detail': REASON_TEXT[code]}


def evaluate(snapshot, model, policy_hash, result, source):
    """Return a non-authorizing candidate fingerprint or explicit miss reasons."""
    reasons = []
    if source != 'ai':
        reasons.append('source_not_ai')
    if not isinstance(result, dict) or result.get('risk') != 'low' or not isinstance(result.get('explanation'), str):
        reasons.append('result_not_safe')
    if not isinstance(model, str) or not model.strip():
        reasons.append('model_missing')
    if not _sha(policy_hash):
        reasons.append('policy_binding_missing')
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    if snapshot.get('identity_verified') is not True:
        reasons.append('snapshot_identity_unverified')
    details = snapshot.get('investigation', {}).get('details', {}) if isinstance(snapshot.get('investigation'), dict) else {}
    if not isinstance(details, dict) or details.get('version') != 2 or details.get('identity_verified') is not True:
        reasons.append('followup_identity_unverified')
    context = details.get('context', {}) if isinstance(details, dict) else {}
    coverage = context.get('coverage', {}) if isinstance(context, dict) else {}
    if not isinstance(coverage, dict) or coverage.get('gaps') != []:
        reasons.append('coverage_incomplete')
    if not isinstance(coverage, dict) or coverage.get('scope') != 'recorded_process_identity':
        reasons.append('recorded_process_not_bound')

    contract = details.get('known_good_context') if isinstance(details, dict) else None
    if contract is None:
        reasons.append('known_good_context_missing')
    elif not isinstance(contract, dict) or contract.get('version') != CONTEXT_VERSION or not _json_safe(contract):
        reasons.append('known_good_context_invalid')
    else:
        expected = {'version', *COMPONENTS, 'observation'}
        if set(contract) != expected or not isinstance(contract.get('observation'), dict) or not set(contract['observation']) <= OBSERVATION_FIELDS:
            reasons.append('observation_fields_invalid')
        try:
            encoded = json.dumps(contract, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        except (TypeError, ValueError):
            encoded = b''
            reasons.append('known_good_context_invalid')
        if len(encoded) > MAX_CONTEXT_BYTES:
            reasons.append('known_good_context_too_large')
        canonical_components = {name: contract.get(name) for name in COMPONENTS}
        if _contains_forbidden(canonical_components):
            reasons.append('observation_fields_invalid')

        artifact = contract.get('artifact', {})
        if not (_component(artifact, 'verified') and _manifest(artifact, ('sha256', 'manifest_sha256')) and
                artifact.get('sha256') == snapshot.get('sha256') and artifact.get('path') == snapshot.get('executable')):
            reasons.append('artifact_binding_invalid')
        provenance = contract.get('provenance', {})
        if not (_component(provenance, 'verified') and _manifest(provenance, ('manifest_sha256', 'proof_sha256')) and
                all(isinstance(provenance.get(field), str) and provenance[field] for field in ('scheme', 'subject', 'release'))):
            reasons.append('provenance_binding_invalid')
        configuration = contract.get('configuration', {})
        if not (_component(configuration, 'complete') and _manifest(configuration, ('manifest_sha256',))):
            reasons.append('configuration_binding_invalid')
        behavior = contract.get('behavior', {})
        behavior_fields = ('manifest_sha256', 'privileges_sha256', 'startup_sha256', 'network_sha256', 'execution_sha256', 'memory_sha256')
        if not (_component(behavior, 'complete') and _manifest(behavior, behavior_fields)):
            reasons.append('behavior_binding_invalid')
        followup = contract.get('followup', {})
        if not (_component(followup, 'complete') and _manifest(followup, ('requirements_sha256', 'evidence_sha256')) and
                isinstance(followup.get('policy_version'), str) and followup['policy_version']):
            reasons.append('followup_binding_invalid')
        contract_coverage = contract.get('coverage', {})
        if not (_component(contract_coverage, 'complete') and _manifest(contract_coverage, ('manifest_sha256',)) and contract_coverage.get('gaps') == []):
            reasons.append('coverage_binding_invalid')

    reasons = list(dict.fromkeys(reasons))
    if reasons:
        return {'version': FINGERPRINT_VERSION, 'eligible': False, 'published': False,
            'fingerprint': '', 'reasons': [_reason(code) for code in reasons]}

    canonical = {
        'version': FINGERPRINT_VERSION,
        'assessment': {'classification': 'low', 'classification_source': 'ai',
            'model': model.strip(), 'policy_hash': policy_hash},
        **{name: contract[name] for name in COMPONENTS},
    }
    fingerprint = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    return {'version': FINGERPRINT_VERSION, 'eligible': True, 'published': False,
        'fingerprint': fingerprint, 'reasons': []}


def assessment(row):
    return evaluate(row.snapshot, row.model, row.policy_hash, row.result, row.source)


def bind_vendor_provenance(s, host_id, evidence, collected):
    """Attach exact controller-authenticated artifact provenance, if available."""
    from sqlalchemy import select
    from .incidents import Inspection
    from . import vendor
    value=copy.deepcopy(evidence)
    investigation=value.get('investigation');details=investigation.get('details') if isinstance(investigation,dict) else None
    context=details.get('context') if isinstance(details,dict) else None
    coverage=context.get('coverage') if isinstance(context,dict) else None
    gaps=coverage.get('gaps') if isinstance(coverage,dict) else None
    if (not isinstance(details,dict) or not isinstance(coverage,dict) or details.get('version')!=2
        or details.get('identity_verified') is not True or not isinstance(gaps,list) or not all(isinstance(gap,str) for gap in gaps)
        or coverage.get('scope')!='recorded_process_identity' or 'package_authentication_missing' not in gaps):return value
    path=value.get('executable');checksum=value.get('sha256')
    if not isinstance(path,str) or not re.fullmatch(r'/[^\x00-\x1f]{0,4095}',path) or not _sha(checksum):return value
    rows=s.scalars(select(Inspection).where(Inspection.host_id==host_id).order_by(Inspection.created.desc(),Inspection.id.desc()).limit(50))
    binding=None;inspection_id=''
    for row in rows:
        report=row.report if isinstance(row.report,dict) else {}
        try:binding=vendor.known_good_binding(report.get('vendor_manifest'),report.get('vendor_authentication'),report.get('vendor_verification'),path,checksum)
        except (TypeError,ValueError):continue
        inspection_id=row.id;break
    if binding is None:return value
    artifact,provenance,authenticated_at=binding
    remaining=sorted(gap for gap in gaps if gap!='package_authentication_missing')
    process=context.get('process') if isinstance(context.get('process'),dict) else {}
    observation={key:process[key] for key in ('pid','start_ticks','boot_id','proc_device','proc_inode') if key in process}
    observation.update(host_id=host_id,collected=collected,vendor_inspection_id=inspection_id,authenticated_at=authenticated_at)
    details['known_good_context']={'version':CONTEXT_VERSION,'artifact':artifact,'provenance':provenance,
        'configuration':{'version':CONTEXT_VERSION,'complete':False},
        'behavior':{'version':CONTEXT_VERSION,'complete':False},
        'followup':{'version':CONTEXT_VERSION,'complete':False,'policy_version':'process-followup-v1'},
        'coverage':{'version':CONTEXT_VERSION,'complete':False,'gaps':remaining},'observation':observation}
    coverage['gaps']=remaining
    return value
