"""Strict candidate fingerprints and conservative fleet-wide safe-result reuse.

This module creates and looks up a host-independent candidate only when a
completed low-risk AI assessment carries an explicit, fully verified evidence
manifest. Current partial receipts remain misses. Reuse retains a new per-host
assessment/observation and never implies approval, response authorization or
deterministic-protection suppression.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import time

from sqlalchemy import Boolean, Double, Integer, JSON, String, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base, audit

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
FOLLOWUP_POLICY_VERSION = 'process-followup-v2'
FOLLOWUP_CHECKS = {'package', 'service', 'executable'}
FOLLOWUP_CONTEXT_KEYS = {
    'version', 'process', 'credentials', 'namespaces', 'maps_sha256',
    'cgroup_sha256', 'artifacts', 'executable', 'coverage',
}


class Entry(Base):
    """Minimal durable safe-candidate provenance; never an approval."""
    __tablename__ = 'ai_known_good_entries'
    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[int] = mapped_column(Integer)
    created: Mapped[float] = mapped_column(Double, default=time.time)
    classification_source: Mapped[str] = mapped_column(String(30))
    model: Mapped[str] = mapped_column(String(100))
    policy_hash: Mapped[str] = mapped_column(String(64))
    assessment_id: Mapped[str] = mapped_column(String(36), index=True)
    source_host_id: Mapped[str] = mapped_column(String(36), index=True)
    contract: Mapped[dict] = mapped_column(JSON)
    result: Mapped[dict] = mapped_column(JSON)
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default='1')
    revoked_at: Mapped[float] = mapped_column(Double, default=0, server_default='0')
    revoked_by: Mapped[str] = mapped_column(String(64), default='', server_default='')
    revoked_reason: Mapped[str] = mapped_column(String(1000), default='', server_default='')


class Observation(Base):
    """Per-assessment/host provenance linked to one canonical candidate."""
    __tablename__ = 'ai_known_good_observations'
    assessment_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    host_id: Mapped[str] = mapped_column(String(36), index=True)
    subject: Mapped[str] = mapped_column(String(64), index=True)
    created: Mapped[float] = mapped_column(Double, default=time.time)
    observation: Mapped[dict] = mapped_column(JSON)

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


def _digest(value):
    """Hash one bounded JSON contract without accepting lossy coercions."""
    if not _json_safe(value):
        return None
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    except (TypeError, ValueError):
        return None
    if len(encoded) > MAX_CONTEXT_BYTES:
        return None
    return hashlib.sha256(encoded).hexdigest()


def _followup_binding(details, path, checksum):
    """Bind a complete v2 receipt while excluding only instance observations.

    This completes the follow-up *receipt* component, not evidence coverage. The
    declared configuration/behavior gaps remain authoritative cache misses.
    """
    if not isinstance(details, dict) or details.get('version') != 2 or details.get('identity_verified') is not True:
        return None
    checks = details.get('checks')
    if (not isinstance(checks, list) or not checks or
            any(not isinstance(check, str) or check not in FOLLOWUP_CHECKS for check in checks) or
            len(checks) != len(set(checks))):
        return None
    expected_keys = {'version', 'identity_verified', 'checks', 'context', 'coverage', *checks}
    if set(details) - {'known_good_context'} != expected_keys:
        return None
    context = details.get('context')
    if not isinstance(context, dict) or set(context) != FOLLOWUP_CONTEXT_KEYS or context.get('version') != CONTEXT_VERSION:
        return None
    process = context.get('process')
    positive_identity = ('pid', 'pid_namespace', 'proc_device', 'proc_inode')
    if (not isinstance(process, dict) or set(process) != {*positive_identity, 'start_ticks', 'boot_id'} or
            any(type(process.get(field)) is not int or process[field] <= 0 for field in positive_identity) or
            type(process.get('start_ticks')) is not int or process['start_ticks'] < 0 or
            not isinstance(process.get('boot_id'), str) or
            not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', process['boot_id'])):
        return None
    credentials = context.get('credentials')
    required_credentials = {'Uid', 'Gid', 'CapEff', 'NoNewPrivs', 'Seccomp'}
    if (not isinstance(credentials, dict) or not required_credentials <= set(credentials) or
            any(not isinstance(key, str) or not isinstance(values, list) or not values or
                any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{1,20}', value) for value in values)
                for key, values in credentials.items())):
        return None
    namespaces = context.get('namespaces')
    if (not isinstance(namespaces, dict) or set(namespaces) != {'pid', 'net', 'mnt', 'user'} or
            any(type(value) is not int or value <= 0 for value in namespaces.values())):
        return None
    if not _sha(context.get('maps_sha256')) or not _sha(context.get('cgroup_sha256')):
        return None
    executable = context.get('executable')
    if (not isinstance(executable, dict) or executable.get('sha256') != checksum or not _sha(checksum) or
            not isinstance(path, str) or not path.startswith('/')):
        return None
    artifacts = context.get('artifacts')
    if (not isinstance(artifacts, list) or not artifacts or
            any(not isinstance(item, dict) or item.get('identity_verified') is not True or
                not _sha(item.get('sha256')) or not isinstance(item.get('path'), str)
                for item in artifacts)):
        return None
    coverage = context.get('coverage')
    top_coverage = details.get('coverage')
    gaps = coverage.get('gaps') if isinstance(coverage, dict) else None
    if (not isinstance(coverage, dict) or coverage != top_coverage or
            set(coverage) != {'cache_eligible', 'gaps', 'scope', 'consistency', 'trust'} or
            coverage.get('cache_eligible') is not False or
            coverage.get('scope') != 'recorded_process_identity' or
            coverage.get('consistency') != 'matching_before_after_samples' or
            coverage.get('trust') != 'target_kernel_and_local_files' or
            not isinstance(gaps, list) or
            any(not isinstance(gap, str) or not gap or len(gap) > 200 for gap in gaps) or
            gaps != sorted(set(gaps))):
        return None
    if any(check not in details for check in checks):
        return None

    # Bind every supported receipt field. Only process identity and namespace
    # inode values are observation-specific; namespace coverage is still bound.
    evidence = copy.deepcopy({key: value for key, value in details.items() if key != 'known_good_context'})
    evidence['checks'] = sorted(checks)
    evidence['context'].pop('process')
    evidence['context']['namespaces'] = sorted(namespaces)
    evidence_sha = _digest(evidence)
    requirements_sha = _digest({
        'version': CONTEXT_VERSION,
        'policy_version': FOLLOWUP_POLICY_VERSION,
        'checks': sorted(checks),
        'receipt_version': 2,
        'context_version': CONTEXT_VERSION,
        'scope': 'recorded_process_identity',
        'consistency': 'matching_before_after_samples',
        'trust': 'target_kernel_and_local_files',
        'required_context': sorted(FOLLOWUP_CONTEXT_KEYS),
    })
    if not evidence_sha or not requirements_sha:
        return None
    return {'version': CONTEXT_VERSION, 'complete': True,
        'requirements_sha256': requirements_sha, 'evidence_sha256': evidence_sha,
        'policy_version': FOLLOWUP_POLICY_VERSION}


def evaluate(snapshot, model, policy_hash, result, source):
    """Return a non-authorizing candidate fingerprint or explicit miss reasons."""
    reasons = []
    if source != 'ai':
        reasons.append('source_not_ai')
    if (not isinstance(result, dict) or result.get('risk') != 'low' or
            not isinstance(result.get('explanation'), str) or
            not isinstance(result.get('recommended_checks'), str) or
            result.get('requested_checks') != []):
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


def _canonical_contract(snapshot):
    details = snapshot['investigation']['details']
    value = details['known_good_context']
    return {'version': value['version'],
        **{name: copy.deepcopy(value[name]) for name in COMPONENTS}}


def _insert_once(s, row, model, key):
    """Insert under a savepoint so a uniqueness race cannot poison the unit of work."""
    existing = s.get(model, key)
    if existing is not None:
        return existing, False
    try:
        with s.begin_nested():
            s.add(row)
            s.flush()
        return row, True
    except IntegrityError:
        # MySQL's default repeatable-read snapshot may predate the winning
        # transaction. A locking read is a current read and sees that winner;
        # SQLite safely ignores FOR UPDATE.
        primary_key = model.__mapper__.primary_key[0]
        existing = s.scalar(select(model).where(primary_key == key).with_for_update())
        if existing is None:
            raise
        return existing, False


def _same_entry(row, expected):
    return (row.version == expected.version and
        row.classification_source == expected.classification_source and
        row.model == expected.model and row.policy_hash == expected.policy_hash and
        row.contract == expected.contract)


def _same_observation(row, expected):
    return (row.fingerprint == expected.fingerprint and row.host_id == expected.host_id and
        row.subject == expected.subject and row.observation == expected.observation)


def _safe_probe(snapshot, model, policy_hash):
    """Derive an exact candidate identity without treating a new result as safe."""
    return evaluate(snapshot, model, policy_hash,
        {'risk': 'low', 'explanation': 'Exact-match identity probe',
            'recommended_checks': '', 'requested_checks': []}, 'ai')


def lookup(s, snapshot, model, policy_hashes, bypass=False):
    """Return one fully revalidated active exact match, or ``None``.

    Callers supply every exact policy digest the unchanged pipeline could have
    produced (currently the one- and two-stage variants). No nearest/similar
    match is attempted and explicit administrator refresh always bypasses this
    lookup.
    """
    if bypass or not isinstance(policy_hashes, (list, tuple)):
        return None
    for policy_hash in dict.fromkeys(policy_hashes):
        status = _safe_probe(snapshot, model, policy_hash)
        if not status['eligible']:
            continue
        saved = s.get(Entry, status['fingerprint'])
        if not saved or not saved.active:
            continue
        from .ai_assessments import Assessment
        origin = s.get(Assessment, saved.assessment_id)
        origin_observation = s.get(Observation, saved.assessment_id)
        if (not origin or origin.source != 'ai' or origin.host_id != saved.source_host_id or
                origin.model != saved.model or origin.policy_hash != saved.policy_hash or
                origin.result != saved.result or
                not origin_observation or origin_observation.fingerprint != saved.fingerprint or
                origin_observation.host_id != saved.source_host_id or
                origin_observation.subject != origin.subject):
            continue
        expected = Entry(fingerprint=status['fingerprint'], version=status['version'],
            classification_source='ai', model=model.strip(), policy_hash=policy_hash,
            assessment_id=saved.assessment_id, source_host_id=saved.source_host_id,
            contract=_canonical_contract(snapshot), result=copy.deepcopy(saved.result))
        # Re-evaluate the retained result too: a corrupt/mutated low-risk row is
        # never reusable merely because its primary key still matches.
        retained = evaluate(snapshot, saved.model, saved.policy_hash, saved.result,
            saved.classification_source)
        if (not retained['eligible'] or retained['fingerprint'] != saved.fingerprint or
                not _same_entry(saved, expected) or
                not isinstance(saved.result.get('recommended_checks'), str)):
            continue
        return {'fingerprint': saved.fingerprint, 'version': saved.version,
            'model': saved.model, 'policy_hash': saved.policy_hash,
            'assessment_id': saved.assessment_id,
            'source_subject': origin.subject,
            'source_host_id': saved.source_host_id,
            'created': saved.created, 'result': copy.deepcopy(saved.result)}
    return None


def link_reuse(s, row, hit):
    """Link a retained cache-sourced assessment to its current observation."""
    metadata = row.result.get('known_good_reuse') if isinstance(row.result, dict) else None
    if (row.source != 'known_good' or not isinstance(metadata, dict) or
            metadata.get('fingerprint') != hit.get('fingerprint') or
            metadata.get('source_assessment_id') != hit.get('assessment_id')):
        raise RuntimeError('Known-good reuse provenance is incomplete or inconsistent')
    saved = s.get(Entry, hit['fingerprint'])
    exact = lookup(s, row.snapshot, row.model, [row.policy_hash])
    if not saved or not exact or exact['assessment_id'] != hit['assessment_id']:
        raise RuntimeError('Known-good candidate changed before reuse was retained')
    observation_value = copy.deepcopy(
        row.snapshot['investigation']['details']['known_good_context']['observation'])
    if observation_value.get('host_id', row.host_id) != row.host_id:
        raise RuntimeError('Known-good reuse observation host conflicts with its assessment')
    observation = Observation(assessment_id=row.id, fingerprint=hit['fingerprint'],
        host_id=row.host_id, subject=row.subject, created=row.created,
        observation=observation_value)
    linked, linked_now = _insert_once(s, observation, Observation, observation.assessment_id)
    if not _same_observation(linked, observation):
        raise RuntimeError('Known-good reuse observation conflicts with stored identity')
    if linked_now:
        audit(s, 'reuse known-good candidate',
            f'{observation.fingerprint} {observation.assessment_id} {observation.host_id}')
    return exact


def publish(s, row):
    """Durably record an eligible candidate and its isolated host observation.

    The fingerprint is the uniqueness boundary. A conflicting durable row is
    treated as corruption/collision and fails closed; an inactive row is never
    reactivated by a later assessment.
    """
    status = assessment(row)
    if not status['eligible']:
        return status
    # The retained assessment is the durable provenance anchor. Flush it first
    # so generated timestamps/identities are available before candidate rows.
    s.flush()
    contract = _canonical_contract(row.snapshot)
    candidate = Entry(fingerprint=status['fingerprint'], version=status['version'],
        created=row.created, classification_source=row.source, model=row.model,
        policy_hash=row.policy_hash, assessment_id=row.id, source_host_id=row.host_id,
        contract=contract, result=copy.deepcopy(row.result))
    saved, created = _insert_once(s, candidate, Entry, candidate.fingerprint)
    if not _same_entry(saved, candidate):
        raise RuntimeError('Known-good fingerprint collision or stored candidate corruption')
    observation_value = copy.deepcopy(
        row.snapshot['investigation']['details']['known_good_context']['observation'])
    if observation_value.get('host_id', row.host_id) != row.host_id:
        raise RuntimeError('Known-good observation host conflicts with its retained assessment')
    observation = Observation(assessment_id=row.id, fingerprint=status['fingerprint'],
        host_id=row.host_id, subject=row.subject, created=row.created,
        observation=observation_value)
    linked, linked_now = _insert_once(s, observation, Observation, observation.assessment_id)
    if not _same_observation(linked, observation):
        raise RuntimeError('Known-good assessment observation conflicts with its stored identity')
    if created:
        audit(s, 'publish known-good candidate',
            f'{candidate.fingerprint} {candidate.assessment_id} {candidate.source_host_id}')
    if linked_now:
        audit(s, 'link known-good observation',
            f'{observation.fingerprint} {observation.assessment_id} {observation.host_id}')
    return {**status, 'published': bool(saved.active)}


def _invalidate(s, fingerprint, version, actor, reason, revoked_at, action):
    saved = s.scalar(select(Entry).where(
        Entry.fingerprint == fingerprint).with_for_update())
    if saved is None:
        raise LookupError('Known-good candidate not found')
    if saved.version != version:
        raise ValueError('Known-good candidate version changed; reopen the assessment before submitting')
    if not saved.active:
        raise ValueError('Known-good candidate is already revoked; reopen the assessment to review its current state')
    linked = s.scalar(select(func.count(Observation.assessment_id)).where(
        Observation.fingerprint == fingerprint)) or 0
    saved.active = False
    saved.revoked_at = revoked_at or time.time()
    saved.revoked_by = actor
    saved.revoked_reason = reason
    audit(s, action,
        f'{actor} {fingerprint} linked={linked} reason={reason}')
    return {'fingerprint': fingerprint, 'version': saved.version,
        'active': False, 'review_required': True, 'linked_assessments': linked,
        'revoked_at': saved.revoked_at, 'revoked_by': saved.revoked_by,
        'revoked_reason': saved.revoked_reason}


def revoke(s, fingerprint, version, actor, reason, revoked_at=None):
    """Invalidate one exact candidate without rewriting linked assessment history."""
    return _invalidate(s, fingerprint, version, actor, reason, revoked_at,
        'revoke known-good candidate')


def invalidate_contradiction(s, row, revoked_at=None):
    """Invalidate an exact active candidate after a retained final AI contradiction.

    This is deliberately conservative: only a complete non-low provider result
    for the identical model, policy and verified canonical context can revoke a
    candidate. Incomplete follow-up requests and merely similar context do
    nothing. Revocation changes reuse eligibility only; it authorizes no
    response and never rewrites either assessment.
    """
    result = row.result if isinstance(row.result, dict) else {}
    risk = result.get('risk')
    if (row.source != 'ai' or risk not in {'medium', 'high', 'unknown'} or
            result.get('requested_checks') != [] or
            not isinstance(result.get('explanation'), str) or
            not isinstance(result.get('recommended_checks'), str)):
        return None
    hit = lookup(s, row.snapshot, row.model, [row.policy_hash])
    if not hit:
        return None
    reason = (f'Retained AI assessment {row.id} classified the same exact '
        f'verified context as {risk}; every linked assessment requires review.')
    return _invalidate(s, hit['fingerprint'], hit['version'],
        'assessment:'+row.id, reason, revoked_at,
        'invalidate contradicted known-good candidate')


def _contradiction(s, saved):
    marker = saved.revoked_by or ''
    if not marker.startswith('assessment:'):
        return None
    assessment_id = marker.removeprefix('assessment:')
    if not re.fullmatch(r'[0-9a-f-]{36}', assessment_id):
        return None
    from .ai_assessments import Assessment
    row = s.get(Assessment, assessment_id)
    result = row.result if row and isinstance(row.result, dict) else {}
    if (not row or row.source != 'ai' or row.model != saved.model or
            row.policy_hash != saved.policy_hash or
            result.get('risk') not in {'medium', 'high', 'unknown'} or
            result.get('requested_checks') != []):
        return None
    status = _safe_probe(row.snapshot, row.model, row.policy_hash)
    if not status['eligible'] or status['fingerprint'] != saved.fingerprint:
        return None
    return {'contradiction_assessment_id': row.id,
        'contradiction_subject': row.subject,
        'contradiction_host_id': row.host_id,
        'contradiction_risk': result['risk'],
        'contradiction_created': row.created}


def assessment(row, s=None):
    source = 'ai' if row.source == 'known_good' else row.source
    status = evaluate(row.snapshot, row.model, row.policy_hash, row.result, source)
    if status['eligible'] and s is not None:
        saved = s.get(Entry, status['fingerprint'])
        valid = bool(saved and saved.version == status['version'] and
            saved.classification_source == source and saved.model == row.model and
            saved.policy_hash == row.policy_hash and
            saved.contract == _canonical_contract(row.snapshot))
        active = bool(valid and saved.active)
        status = {**status, 'published': active}
        if valid:
            linked = s.scalar(select(func.count(Observation.assessment_id)).where(
                Observation.fingerprint == saved.fingerprint)) or 0
            contradiction = _contradiction(s, saved) if not active else None
            status = {**status, 'active': active,
                'review_required': not active,
                'linked_assessments': linked,
                'revoked_at': saved.revoked_at if not active else 0,
                'revoked_by': ('AI assessment' if contradiction else saved.revoked_by) if not active else '',
                'revoked_reason': saved.revoked_reason if not active else ''}
            if contradiction:
                status = {**status, **contradiction}
        if row.source == 'known_good':
            metadata = row.result.get('known_good_reuse') if isinstance(row.result, dict) else None
            local_observation = s.get(Observation, row.id)
            origin_observation = s.get(Observation, saved.assessment_id) if saved else None
            reused = bool(valid and isinstance(metadata, dict) and
                metadata.get('fingerprint') == status['fingerprint'] and
                metadata.get('source_assessment_id') == saved.assessment_id and
                metadata.get('source_host_id') == saved.source_host_id and
                origin_observation and
                metadata.get('source_subject') == origin_observation.subject and
                origin_observation.fingerprint == saved.fingerprint and
                origin_observation.host_id == saved.source_host_id and
                local_observation and local_observation.fingerprint == saved.fingerprint and
                local_observation.host_id == row.host_id and
                local_observation.subject == row.subject)
            status = {**status, 'published': bool(reused and active), 'reused': reused,
                'source_assessment_id': saved.assessment_id if reused else '',
                'source_subject': metadata.get('source_subject', '') if reused else '',
                'source_host_id': saved.source_host_id if reused else '',
                'source_created': saved.created if reused else 0}
    return status


def bind_vendor_provenance(s, host_id, evidence, collected):
    """Attach exact controller-authenticated artifact provenance, if available."""
    from sqlalchemy import select
    from .incidents import Inspection
    from . import vendor
    value=copy.deepcopy(evidence)
    investigation=value.get('investigation');details=investigation.get('details') if isinstance(investigation,dict) else None
    context=details.get('context') if isinstance(details,dict) else None
    coverage=context.get('coverage') if isinstance(context,dict) else None
    top_coverage=details.get('coverage') if isinstance(details,dict) else None
    gaps=coverage.get('gaps') if isinstance(coverage,dict) else None
    if (not isinstance(details,dict) or not isinstance(coverage,dict) or details.get('version')!=2
        or details.get('identity_verified') is not True or coverage!=top_coverage
        or not isinstance(gaps,list) or not all(isinstance(gap,str) for gap in gaps)
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
    coverage['gaps']=remaining
    top_coverage['gaps']=list(remaining)
    followup=_followup_binding(details,path,checksum)
    if followup is None:return copy.deepcopy(evidence)
    process=context.get('process') if isinstance(context.get('process'),dict) else {}
    observation={key:process[key] for key in ('pid','start_ticks','boot_id','proc_device','proc_inode') if key in process}
    observation.update(host_id=host_id,collected=collected,vendor_inspection_id=inspection_id,authenticated_at=authenticated_at)
    details['known_good_context']={'version':CONTEXT_VERSION,'artifact':artifact,'provenance':provenance,
        'configuration':{'version':CONTEXT_VERSION,'complete':False},
        'behavior':{'version':CONTEXT_VERSION,'complete':False},
        'followup':followup,
        'coverage':{'version':CONTEXT_VERSION,'complete':False,'gaps':remaining},'observation':observation}
    return value
