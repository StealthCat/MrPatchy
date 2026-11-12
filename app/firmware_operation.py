"""Pure firmware operation contract (first slice of #399).

Defines the operation state model, the preflight blocker evaluation, the
payload/policy binding digest and honest outcome classification for a single
reviewed firmware operation. It performs no execution, persistence, transport
or I/O and never authorizes a firmware change: a plan is only as authoritative
as the explicit approval a later slice binds to its digest.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

CONTRACT_VERSION = 1

ACTIONS = ('upgrade', 'install', 'reinstall', 'downgrade', 'branch_switch', 'stage')
STATES = (
    'queued', 'preflight', 'staged', 'writing', 'pending_activation',
    'verifying', 'succeeded', 'failed', 'recovery_required',
)
TERMINAL_STATES = frozenset({'succeeded', 'failed', 'recovery_required'})
# Staged/pending work must never be reported as completion.
NOT_COMPLETE_STATES = frozenset(STATES) - {'succeeded'}
_TRANSITIONS = {
    'queued': {'preflight', 'failed'},
    'preflight': {'staged', 'writing', 'failed'},
    'staged': {'writing', 'pending_activation', 'failed'},
    'writing': {'pending_activation', 'verifying', 'failed', 'recovery_required'},
    'pending_activation': {'verifying', 'failed', 'recovery_required'},
    'verifying': {'succeeded', 'failed', 'recovery_required'},
    'succeeded': set(),
    'failed': set(),
    'recovery_required': set(),
}
# States in which cancellation is safe: nothing has been written yet.
CANCELLABLE_STATES = frozenset({'queued', 'preflight', 'staged'})
# Flags that must never be silently added to a request.
FORBIDDEN_FLAGS = frozenset({
    'force', 'ignore-power', 'ignore-requirements', 'ignore-vid-pid',
    'allow-older', 'allow-reinstall', 'raw-flash',
})
_REQUIRED_FIELDS = (
    'host_id', 'enrollment_id', 'device_id', 'action', 'release_version',
    'artifact_sha256', 'policy_digest',
)
MAX_TEXT = 256


_ALLOWED_FIELDS = frozenset(_REQUIRED_FIELDS) | {'flags'}
_OVERLONG = object()


def _text(value: Any) -> Any:
    """Return stripped text, ``None`` when absent, or ``_OVERLONG``.

    Overlong values are never truncated: two distinct values sharing a prefix
    must not bind to the same operation or verify as the same version.
    """
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None
    return _OVERLONG if len(value) > MAX_TEXT else value


def bind_operation(request: Any) -> dict[str, Any]:
    """Return ``{'ok', 'errors', 'operation_id'}`` for a requested operation.

    The operation ID is a digest over host/enrollment, device, action, exact
    payload, policy digest and every permitted flag, so any change to those
    invalidates approval. The request schema is strict: unknown keys are
    rejected rather than ignored, overlong values are rejected rather than
    truncated, and force/ignore flags are rejected rather than stripped.
    """
    if not isinstance(request, dict):
        return {'ok': False, 'errors': ['malformed_request'], 'operation_id': None}
    errors = []
    if any(key not in _ALLOWED_FIELDS for key in request):
        errors.append('unknown_field')
    fields: dict[str, Any] = {}
    for name in _REQUIRED_FIELDS:
        value = _text(request.get(name))
        if value is None:
            errors.append(f'missing_{name}')
        elif value is _OVERLONG:
            errors.append(f'overlong_{name}')
            value = None
        fields[name] = value
    if fields['action'] is not None and fields['action'] not in ACTIONS:
        errors.append('unsupported_action')
    raw_flags = request.get('flags', [])
    flags: set[str] = set()
    if not isinstance(raw_flags, list):
        errors.append('malformed_flags')
        raw_flags = []
    for raw in raw_flags:
        flag = _text(raw)
        if flag is None:
            errors.append('malformed_flags')
        elif flag is _OVERLONG:
            errors.append('overlong_flags')
        elif flag.lower() in FORBIDDEN_FLAGS:
            errors.append('forbidden_flag')
        else:
            flags.add(flag)
    if errors:
        return {'ok': False, 'errors': sorted(set(errors)), 'operation_id': None}
    bound: dict[str, Any] = dict(fields)
    # An empty flag list keeps the original digest so existing IDs stay valid.
    if flags:
        bound['flags'] = sorted(flags)
    canonical = json.dumps(bound, sort_keys=True, separators=(',', ':'))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    return {'ok': True, 'errors': [], 'operation_id': digest}


def approval_valid(approved_operation_id: Any, request: Any) -> bool:
    """True only if the request still binds to exactly the approved operation."""
    bound = bind_operation(request)
    return bool(bound['ok'] and isinstance(approved_operation_id, str)
                and approved_operation_id == bound['operation_id'])


def preflight_blockers(facts: Any) -> list[str]:
    """Return sorted blocker codes; an empty list means preflight may proceed.

    Missing or non-boolean facts are blockers: unknown is never treated as safe.
    """
    if not isinstance(facts, dict):
        return ['facts_unavailable']
    blockers = []
    for key, code in (
        ('device_identity_matches', 'device_identity_mismatch'),
        ('signature_trusted', 'signature_untrusted'),
        ('policy_allows', 'policy_blocked'),
        ('power_ok', 'power_insufficient'),
        ('provider_requirements_met', 'provider_requirements_unmet'),
        ('boot_prerequisites_met', 'boot_prerequisites_unmet'),
        ('free_space_ok', 'insufficient_space'),
        ('recovery_requirements_met', 'recovery_requirements_unmet'),
        ('approval_current', 'approval_stale'),
    ):
        if facts.get(key) is not True:
            blockers.append(code)
    if facts.get('anti_rollback_violation') is not False:
        blockers.append('anti_rollback')
    if facts.get('manual_steps_pending') is not False:
        blockers.append('manual_steps_pending')
    return sorted(blockers)


def can_transition(current: Any, new: Any) -> bool:
    return new in _TRANSITIONS.get(current, ())


def can_cancel(state: Any) -> bool:
    """Cancel is limited to unstarted/staged work; never undoes a write."""
    return state in CANCELLABLE_STATES


def classify_outcome(observation: Any) -> dict[str, Any]:
    """Derive an honest state from target-side evidence.

    Exit code and staged images are never completion. Success requires the
    expected running version to be verified after activation. Anything
    uncertain after a write began requires reconciliation.
    """
    if not isinstance(observation, dict):
        return {'state': 'recovery_required', 'reason': 'no_receipt'}
    if observation.get('receipt_valid') is not True:
        return {'state': 'recovery_required' if observation.get('write_started') else 'failed',
                'reason': 'receipt_missing_or_malformed'}
    if observation.get('device_present') is not True:
        return {'state': 'recovery_required', 'reason': 'device_missing'}
    if observation.get('activation_pending') is True:
        return {'state': 'pending_activation', 'reason': 'activation_or_manual_action_pending'}
    expected = _text(observation.get('expected_version'))
    running = _text(observation.get('running_version'))
    if (isinstance(expected, str) and running == expected
            and observation.get('history_confirms') is True):
        return {'state': 'succeeded', 'reason': 'verified'}
    if observation.get('write_started'):
        return {'state': 'recovery_required', 'reason': 'unverified_after_write'}
    return {'state': 'failed', 'reason': 'not_executed'}
