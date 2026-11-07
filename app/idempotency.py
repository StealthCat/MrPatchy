"""Pure idempotency contract for service-submitted mutations (first slice of #337).

No storage, routes, credentials or runtime actions live here. A caller supplies
the stored record (if any) for an identity and key; this module decides whether
the submission is new, an exact replay, or a conflicting reuse of the key.
The fingerprint binds the identity, the sorted target set and the canonical
payload digest, so retries return the original result and changed reuse is
rejected rather than silently executed.
"""
import hashlib
import hmac
import json
import re

KEY_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{7,127}')
NEW, REPLAY, CONFLICT, IN_PROGRESS = 'new', 'replay', 'conflict', 'in_progress'


def valid_key(key):
    """Return the key if it is 8-128 safe characters, else raise ValueError without echoing it."""
    if not isinstance(key, str) or not KEY_PATTERN.fullmatch(key):
        raise ValueError('Idempotency key must be 8-128 letters, digits or . _ : -')
    return key


def payload_digest(payload):
    """SHA-256 of a canonical JSON form: key order and whitespace never change the digest."""
    try:
        data = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError):
        raise ValueError('Payload is not canonical JSON') from None
    return hashlib.sha256(data.encode()).hexdigest()


def fingerprint(identity, targets, payload, action=''):
    """Digest binding identity, action, de-duplicated sorted targets and payload digest."""
    if not isinstance(identity, str) or not identity:
        raise ValueError('Identity is required')
    if isinstance(targets, (str, bytes)):
        raise ValueError('Targets must be a collection of identifiers')
    members = sorted({str(target) for target in targets})
    body = {'identity': identity, 'action': str(action), 'targets': members, 'payload': payload_digest(payload)}
    return payload_digest(body)


def decide(stored, request_fingerprint):
    """Classify a submission against the stored record for the same identity and key.

    stored is None or a mapping with 'fingerprint', optional 'result' and optional
    'complete'. Returns (decision, result): a new submission carries no result, a
    replay returns the original result, a retry of unfinished work reports
    in_progress, and any fingerprint mismatch is a conflict with no result.
    """
    if stored is None:
        return NEW, None
    if not hmac.compare_digest(str(stored.get('fingerprint', '')), request_fingerprint):
        return CONFLICT, None
    if stored.get('complete'):
        return REPLAY, stored.get('result')
    return IN_PROGRESS, None
