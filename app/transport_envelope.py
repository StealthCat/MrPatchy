"""Pure request/receipt envelope contract for cloud-native agent transport (first slice of #359).

No storage, routes, provider calls, credentials or runtime actions live here. A
request is bound to the enrolled host, the immutable provider resource identity,
the enrollment generation, the agent version, the action, the payload digest, the
job id, an expiry and a nonce, so a re-created VM or a replayed message cannot
inherit trust. Provider acceptance never implies that the agent executed anything:
only a receipt that echoes the request binding does.
"""
import hashlib
import hmac
import json

VERSION = 1
BINDING_FIELDS = ('host_id', 'resource_id', 'generation', 'agent_version', 'action', 'payload_digest', 'job_id', 'expires_at', 'nonce')
MAX_LIFETIME = 3600

ACCEPTED, REJECTED, UNKNOWN = 'accepted', 'rejected', 'unknown'
OK, RECOVERY_REQUIRED, FAILED = 'ok', 'recovery_required', 'failed'


def digest(value):
    """SHA-256 of canonical JSON: key order and whitespace never change it."""
    try:
        data = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError):
        raise ValueError('Value is not canonical JSON') from None
    return hashlib.sha256(data.encode()).hexdigest()


def build_request(host_id, resource_id, generation, agent_version, action, payload, job_id, nonce, now, lifetime=300):
    """Return a versioned request envelope; times are epoch seconds."""
    if not 0 < lifetime <= MAX_LIFETIME:
        raise ValueError('Lifetime is outside the allowed range')
    for name, value in (('host_id', host_id), ('resource_id', resource_id), ('agent_version', agent_version),
                        ('action', action), ('job_id', job_id), ('nonce', nonce)):
        if not isinstance(value, (str, int)) or isinstance(value, bool) or value == '':
            raise ValueError(f'{name} is required')
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        raise ValueError('generation must be a positive integer')
    request = {'version': VERSION, 'host_id': str(host_id), 'resource_id': str(resource_id), 'generation': generation,
               'agent_version': str(agent_version), 'action': str(action), 'payload_digest': digest(payload),
               'job_id': str(job_id), 'expires_at': int(now) + int(lifetime), 'nonce': str(nonce)}
    request['binding'] = digest({field: request[field] for field in BINDING_FIELDS})
    return request


def check_replay(seen, request):
    """Raise ValueError if the nonce was already used for this resource; otherwise record it."""
    key = (request['resource_id'], request['nonce'])
    if key in seen:
        raise ValueError('Request nonce was already used')
    seen.add(key)


def verify_receipt(request, receipt):
    """Return (True, '') only when the receipt echoes this exact request and the agent executed it before expiry.

    Reasons are fixed strings; receipt content is never echoed.
    """
    if not isinstance(receipt, dict) or receipt.get('version') != VERSION:
        return False, 'unsupported_version'
    if not hmac.compare_digest(str(receipt.get('binding', '')), request['binding']):
        return False, 'binding_mismatch'
    if any(receipt.get(field) != request[field] for field in BINDING_FIELDS):
        return False, 'binding_mismatch'
    executed = receipt.get('executed_at')
    if not isinstance(executed, int) or isinstance(executed, bool) or executed > request['expires_at']:
        return False, 'expired'
    return True, ''


def route_allowed(matrix, transport, action):
    """Block unsupported transport/action pairs before dispatch; unlisted pairs are unsupported."""
    return action in matrix.get(transport, ())


def classify_submission(provider_state, mutating=True):
    """Decide what a submission's provider-side result permits next.

    Returns (outcome, next_step). An unknown outcome of a mutation stays
    recovery-required: it is never replayed and never moved to another transport.
    """
    if provider_state == ACCEPTED:
        return ACCEPTED, 'await_receipt'
    if provider_state == REJECTED:
        return REJECTED, 'fail'
    if mutating:
        return UNKNOWN, RECOVERY_REQUIRED
    return UNKNOWN, 'retry_read'
