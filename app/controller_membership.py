"""Pure controller membership and serving-role admission contract (#451, first slice).

Nothing here touches the database, a clock, the network or a lock: callers pass the durable member
records they read (and ``now``) and persist whatever they decide. It authorizes no role change,
failover or target action by itself and fails closed: malformed, stale or ambiguous evidence is
never treated as healthy or eligible. Serving leadership is decided here independently of scheduler
leadership and worker execution, and never from load-balancer reachability alone.

A member record is a dict: ``id``, ``boot`` (generation, int >= 0), ``domain`` (failure domain),
``version`` (``X.Y.Z``), ``protocol``, ``schema``, ``heartbeat`` (epoch seconds), ``desired`` and
``observed`` role (``serving``/``standby``/``draining``) and ``ready`` (bool, standby catch-up).
"""

ROLES = ('serving', 'standby', 'draining')
HEARTBEAT_TTL = 30


def _int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _version(text):
    if not isinstance(text, str):
        return None
    parts = text.strip().split('.')
    if len(parts) != 3 or not all(p.isascii() and p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def member_valid(member):
    return (isinstance(member, dict) and isinstance(member.get('id'), str) and bool(member['id'])
            and _int(member.get('boot')) and isinstance(member.get('domain'), str) and bool(member['domain'])
            and _version(member.get('version')) is not None and _int(member.get('protocol'))
            and _int(member.get('schema')) and isinstance(member.get('heartbeat'), (int, float))
            and not isinstance(member.get('heartbeat'), bool)
            and member.get('desired') in ROLES and member.get('observed') in ROLES
            and isinstance(member.get('ready'), bool))


def is_fresh(member, now, ttl=HEARTBEAT_TTL):
    """A heartbeat from the future or older than ``ttl`` is stale (clock skew is not health)."""
    if not member_valid(member) or not isinstance(now, (int, float)) or isinstance(now, bool):
        return False
    return 0 <= now - member['heartbeat'] <= ttl


def registration_decision(registry, member, now, ttl=HEARTBEAT_TTL):
    """May ``member`` register? Rejects identity collisions and stale boot generations.

    ``registry`` is the list of existing member records. A re-registration of the same id must carry
    a strictly newer boot generation; the same id with the same or older generation from a live
    holder is a collision. Distinct members may share a failure domain, but that is reported via
    ``shared_domain`` so the deployment can refuse to call it redundant.
    """
    if not member_valid(member) or not isinstance(registry, list):
        return {'allowed': False, 'reason': 'invalid_input', 'shared_domain': False}
    if not all(member_valid(m) for m in registry):
        return {'allowed': False, 'reason': 'invalid_registry', 'shared_domain': False}
    shared = False
    for existing in registry:
        if existing['id'] == member['id']:
            if member['boot'] > existing['boot']:
                continue
            if member['boot'] == existing['boot'] and not is_fresh(existing, now, ttl):
                continue
            return {'allowed': False, 'reason': 'identity_collision', 'shared_domain': False}
        if existing['domain'] == member['domain']:
            shared = True
    return {'allowed': True, 'reason': '', 'shared_domain': shared}


def compatible(deployment, member):
    """``deployment`` is ``{'protocol', 'schema'}``; a member must match both exactly."""
    if not (isinstance(deployment, dict) and _int(deployment.get('protocol')) and _int(deployment.get('schema'))
            and member_valid(member)):
        return False
    return member['protocol'] == deployment['protocol'] and member['schema'] == deployment['schema']


def standby_ready(deployment, member, now, ttl=HEARTBEAT_TTL):
    """A standby is promotable only if fresh, compatible, caught up and not draining."""
    return (member_valid(member) and member['observed'] == 'standby' and member['ready']
            and is_fresh(member, now, ttl) and compatible(deployment, member))


def serving_decision(deployment, members, now, ttl=HEARTBEAT_TTL):
    """Pick the single eligible serving controller, or refuse.

    Returns ``{'serving': id|None, 'action': ..., 'quarantine': [ids], 'reason': ...}``. ``action``
    is ``keep`` (exactly one fresh, compatible serving member), ``promote`` (no live serving member
    and exactly one best ready standby) or ``hold`` (never guess: split brain, no candidate, or bad
    evidence). Stale members still claiming ``serving`` are quarantined, never trusted.
    """
    hold = {'serving': None, 'action': 'hold', 'quarantine': [], 'reason': ''}
    if not isinstance(members, list) or not members or not all(member_valid(m) for m in members):
        return {**hold, 'reason': 'invalid_input'}
    if len({m['id'] for m in members}) != len(members):
        return {**hold, 'reason': 'identity_collision'}
    claiming = [m for m in members if m['observed'] == 'serving']
    live = [m for m in claiming if is_fresh(m, now, ttl) and compatible(deployment, m)]
    stale = sorted(m['id'] for m in claiming if m not in live)
    if len(live) > 1:
        return {**hold, 'quarantine': stale, 'reason': 'split_brain'}
    if len(live) == 1:
        return {'serving': live[0]['id'], 'action': 'keep', 'quarantine': stale, 'reason': ''}
    candidates = [m for m in members if standby_ready(deployment, m, now, ttl)]
    if not candidates:
        return {**hold, 'quarantine': stale, 'reason': 'no_eligible_standby'}
    # Prefer an operator-desired serving member, then highest boot generation, then id for stability.
    candidates.sort(key=lambda m: (m['desired'] != 'serving', -m['boot'], m['id']))
    top = candidates[0]
    return {'serving': top['id'], 'action': 'promote', 'quarantine': stale, 'reason': ''}


def missing_expected(expected_ids, members):
    """Expected members absent from the registry are reported, never silently forgotten."""
    if not isinstance(expected_ids, (list, tuple, set)) or not isinstance(members, list):
        return None
    present = {m.get('id') for m in members if isinstance(m, dict)}
    return sorted(i for i in expected_ids if i not in present)
