"""Rollout rings, soak gates and availability budgets (pure, no I/O).

First slice of the ring model: validation of a reusable ring definition, the exact
effective target plan, and a deterministic admission decision. Nothing here starts
work, touches the database or a host, drains or rejoins a service. Callers supply
the observed state; the decision is advisory and never overrides approvals or holds.
"""
import hashlib
import json
import re

VERSION = 1
MAX_RINGS = 20
MAX_HOSTS_PER_RING = 1000
MAX_LIMITS = 200
MAX_PARALLEL = 100
MAX_SOAK_SECONDS = 7 * 86400
MAX_FAILURES = 1000
SCOPES = ('service', 'site')
_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')


class RingError(ValueError):
    """The definition or state is invalid; nothing may start."""


def _int(value, label, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise RingError(f'{label} must be an integer from {low} to {high}')
    return value


def _name(value, label):
    if not isinstance(value, str) or not _NAME.match(value):
        raise RingError(f'{label} must be 1-64 letters, digits, dot, dash or underscore')
    return value


def validate(definition):
    """Return a normalized definition or raise RingError (strict, bounded)."""
    if not isinstance(definition, dict) or definition.get('version') != VERSION:
        raise RingError(f'definition must be an object with version {VERSION}')
    rings = definition.get('rings')
    if not isinstance(rings, list) or not 1 <= len(rings) <= MAX_RINGS:
        raise RingError(f'rings must be a list of 1 to {MAX_RINGS} entries')
    seen_rings, seen_hosts, out = set(), set(), []
    for index, ring in enumerate(rings):
        if not isinstance(ring, dict):
            raise RingError('each ring must be an object')
        name = _name(ring.get('name'), 'ring name')
        if name in seen_rings:
            raise RingError(f'duplicate ring name {name}')
        seen_rings.add(name)
        canary = ring.get('canary', False)
        if not isinstance(canary, bool) or (canary and index):
            raise RingError('only the first ring may be marked canary')
        hosts = ring.get('hosts')
        if not isinstance(hosts, list) or not 1 <= len(hosts) <= MAX_HOSTS_PER_RING:
            raise RingError(f'ring {name} needs 1 to {MAX_HOSTS_PER_RING} hosts')
        ordered = []
        for host in hosts:
            _name(host, 'host')
            if host in seen_hosts:
                raise RingError(f'host {host} appears more than once')
            seen_hosts.add(host)
            ordered.append(host)
        out.append({
            'name': name, 'canary': canary, 'hosts': ordered,
            'max_parallel': _int(ring.get('max_parallel', 1), 'max_parallel', 1, MAX_PARALLEL),
            'soak_seconds': _int(ring.get('soak_seconds', 0), 'soak_seconds', 0, MAX_SOAK_SECONDS),
            'max_failures': _int(ring.get('max_failures', 0), 'max_failures', 0, MAX_FAILURES),
        })
    limits = definition.get('limits', [])
    if not isinstance(limits, list) or len(limits) > MAX_LIMITS:
        raise RingError(f'limits must be a list of at most {MAX_LIMITS} entries')
    seen_limits, norm = set(), []
    for limit in limits:
        if not isinstance(limit, dict) or limit.get('scope') not in SCOPES:
            raise RingError('each limit needs scope service or site')
        key = (limit['scope'], _name(limit.get('name'), 'limit name'))
        if key in seen_limits:
            raise RingError(f'duplicate limit {key[0]}:{key[1]}')
        seen_limits.add(key)
        norm.append({'scope': key[0], 'name': key[1],
                     'max_unavailable': _int(limit.get('max_unavailable'), 'max_unavailable', 0, MAX_HOSTS_PER_RING)})
    return {'version': VERSION, 'rings': out, 'limits': norm}


def plan(definition, inventory):
    """Exact effective plan for approval. inventory maps host -> {'service':..,'site':..}.

    Unknown hosts are rejected rather than skipped, so the approved set is explicit.
    """
    normal = validate(definition)
    if not isinstance(inventory, dict):
        raise RingError('inventory must be an object')
    missing = sorted(h for r in normal['rings'] for h in r['hosts'] if h not in inventory)
    if missing:
        raise RingError('hosts not in inventory: ' + ', '.join(missing[:20]))
    members = {}
    for ring in normal['rings']:
        for host in ring['hosts']:
            info = inventory[host] if isinstance(inventory[host], dict) else {}
            members[host] = {s: info.get(s) for s in SCOPES}
    body = {'definition': normal, 'members': members}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {**body, 'digest': digest}


def _hosts(state, key):
    value = state.get(key, [])
    if not isinstance(value, (list, set, tuple)) or not all(isinstance(h, str) for h in value):
        raise RingError(f'{key} must be a list of host names')
    return set(value)


def admit(effective, state, now):
    """Decide the next step. Returns {'action','ring','hosts','reason','blocked'}.

    state: ring (index), done, failed, in_flight, uncertain, unavailable (hosts down
    for any reason, including other rollouts), ring_finished_at (epoch or None).
    Failed, uncertain, in-flight and externally unavailable hosts all consume
    availability budget; capacity is never released on an unknown outcome.
    """
    rings = effective['definition']['rings']
    ring_index = _int(state.get('ring', 0), 'ring', 0, len(rings))
    done, failed = _hosts(state, 'done'), _hosts(state, 'failed')
    flight, uncertain = _hosts(state, 'in_flight'), _hosts(state, 'uncertain')
    down = _hosts(state, 'unavailable') | flight | uncertain | failed

    def result(action, hosts=(), reason='', blocked=()):
        return {'action': action, 'ring': ring_index, 'hosts': list(hosts), 'reason': reason, 'blocked': list(blocked)}

    if ring_index == len(rings):
        return result('complete', reason='all rings finished')
    ring = rings[ring_index]
    in_ring = set(ring['hosts'])
    if len(in_ring & failed) > ring['max_failures']:
        return result('halt', reason=f"ring {ring['name']} exceeded {ring['max_failures']} allowed failures")
    pending = [h for h in ring['hosts'] if h not in done | failed | flight | uncertain]
    active = in_ring & (flight | uncertain)
    if not pending and not active:
        finished = state.get('ring_finished_at')
        if finished is None:
            return result('wait', reason='ring finished; record ring_finished_at to begin soak')
        if isinstance(finished, bool) or not isinstance(finished, (int, float)) or finished > now:
            raise RingError('ring_finished_at must be an epoch not after now')
        remaining = finished + ring['soak_seconds'] - now
        if remaining > 0:
            return result('wait', reason=f'soaking; {int(remaining)}s remaining')
        return result('advance', reason=f"soak complete for ring {ring['name']}")
    if uncertain & in_ring:
        return result('wait', reason='uncertain outcome must be resolved before more work starts')
    slots = ring['max_parallel'] - len(active)
    limits = {(l['scope'], l['name']): l['max_unavailable'] for l in effective['definition']['limits']}
    members = effective['members']
    groups = {}
    for host, info in members.items():
        for scope in SCOPES:
            if info[scope] is not None:
                groups.setdefault((scope, info[scope]), set()).add(host)
    taken, blocked, start = set(), [], []
    for host in pending:
        if len(start) >= slots:
            break
        reason = None
        for scope in SCOPES:
            key = (scope, members[host][scope])
            if key in limits:
                used = len((down | taken) & groups[key])
                already = host in down or host in taken
                if used + (0 if already else 1) > limits[key]:
                    reason = f'{host}: {scope} {key[1]} would exceed {limits[key]} unavailable'
                    break
        if reason:
            blocked.append(reason)
        else:
            start.append(host)
            taken.add(host)
    if start:
        return result('start', start, 'within parallelism and availability limits', blocked)
    if slots <= 0:
        return result('wait', reason='ring parallelism is full')
    return result('wait', reason='availability limits block every pending host', blocked=blocked)
