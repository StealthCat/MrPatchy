"""Pure migration-ownership and version-coexistence contract (#449, first slice).

Nothing here touches the database, a lock, a remote host or a clock: callers pass the durable facts
they read transactionally (deployment record, migration record, live replicas, ``now``) and persist
whatever they decide. It authorizes no migration, drain, rollback or contract step by itself, and it
fails closed: malformed or ambiguous input is always a refusal, never a guess.

Model: the deployment records the schema revision actually applied, the highest release that wrote
its deployment receipt and the wire protocol. Every node declares the schema range it can operate
against, the protocol it speaks and its own release. A migration is one record moving through
expand -> migrate -> contract; only the expand phase is additive, so only it may be resumed or run
while older replicas are present.
"""

PHASES = ('pending', 'expand', 'migrate', 'contract', 'done')
DESTRUCTIVE = ('migrate', 'contract')


def _int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def parse_version(text):
    """``'1.42.31'`` -> ``(1, 42, 31)``; anything else -> ``None`` (never raises)."""
    if not isinstance(text, str):
        return None
    parts = text.strip().split('.')
    if len(parts) != 3 or not all(p.isascii() and p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def _node_ok(node):
    return (isinstance(node, dict) and parse_version(node.get('version')) is not None and _int(node.get('protocol'))
            and _int(node.get('schema_min')) and _int(node.get('schema_max')) and node['schema_min'] <= node['schema_max'])


def _deployment_ok(deployment):
    return (isinstance(deployment, dict) and _int(deployment.get('schema')) and _int(deployment.get('protocol'))
            and (deployment.get('receipt_version') is None or parse_version(deployment.get('receipt_version')) is not None))


def join_decision(deployment, node):
    """May ``node`` serve (or rejoin) this deployment? Returns ``{'allowed', 'reason'}``."""
    if not _deployment_ok(deployment) or not _node_ok(node):
        return {'allowed': False, 'reason': 'invalid_input'}
    if node['protocol'] != deployment['protocol']:
        return {'allowed': False, 'reason': 'protocol_mismatch'}
    if not node['schema_min'] <= deployment['schema'] <= node['schema_max']:
        return {'allowed': False, 'reason': 'schema_unsupported'}
    return {'allowed': True, 'reason': ''}


def receipt_writable(deployment, node):
    """An older node must never overwrite a deployment receipt written by a newer release."""
    if not _deployment_ok(deployment) or not _node_ok(node):
        return False
    recorded = deployment.get('receipt_version')
    return recorded is None or parse_version(node['version']) >= parse_version(recorded)


def new_migration(migration_id, schema_from, schema_to):
    if not isinstance(migration_id, str) or not migration_id or not _int(schema_from) or not _int(schema_to) or schema_to <= schema_from:
        raise ValueError('invalid migration')
    return {'id': migration_id, 'schema_from': schema_from, 'schema_to': schema_to, 'phase': 'pending',
            'owner': None, 'expires_at': 0, 'applied': False}


def _mig_ok(record):
    return (isinstance(record, dict) and record.get('phase') in PHASES and _int(record.get('schema_from'))
            and _int(record.get('schema_to')) and record['schema_to'] > record['schema_from'] and isinstance(record.get('expires_at'), (int, float)))


def resume_decision(record, member, now):
    """What may ``member`` do with this migration record? Never races a live owner.

    MySQL commits DDL implicitly, so a phase whose owner stopped mid-way may be half applied. Only
    the additive ``expand`` phase is assumed idempotent; an interrupted destructive phase blocks for
    an operator instead of being replayed.
    """
    if not _mig_ok(record) or not isinstance(member, str) or not member or isinstance(now, bool) or not isinstance(now, (int, float)):
        return {'action': 'block', 'reason': 'invalid_input'}
    phase = record['phase']
    if phase == 'done':
        return {'action': 'validate', 'reason': ''}
    live = bool(record.get('owner')) and now < record['expires_at']
    if live and record['owner'] != member:
        return {'action': 'wait', 'reason': 'owner_live'}
    if phase == 'pending':
        return {'action': 'start', 'reason': ''}
    if live:  # we are the live owner
        return {'action': 'continue', 'reason': ''}
    if phase == 'expand':
        return {'action': 'restart_phase', 'reason': 'owner_lost_idempotent'}
    return {'action': 'block', 'reason': 'owner_lost_destructive_phase'}


def contract_gate(target_schema, replicas, approved):
    """Destructive change is allowed only when no live replica still needs the old schema.

    ``replicas`` are node dicts for every replica that is, or may be, alive. An empty or malformed
    inventory blocks: absence of evidence is not an empty cluster.
    """
    if not _int(target_schema) or not isinstance(replicas, (list, tuple)) or not replicas or not all(_node_ok(r) for r in replicas):
        return {'allowed': False, 'reason': 'invalid_input', 'blockers': []}
    old = sorted(str(r.get('name', '?')) for r in replicas if r['schema_min'] < target_schema)
    if old:
        return {'allowed': False, 'reason': 'incompatible_replicas_present', 'blockers': old}
    if approved is not True:
        return {'allowed': False, 'reason': 'approval_required', 'blockers': []}
    return {'allowed': True, 'reason': '', 'blockers': []}


def rollback_possible(deployment, node, migration):
    """Can an older ``node`` run again after ``migration``?

    A destructive phase that started (or finished) cannot be undone by running old code, so the
    rollback is refused outright; before that, the normal join rules decide.
    """
    if not _deployment_ok(deployment) or not _node_ok(node) or not _mig_ok(migration):
        return {'possible': False, 'reason': 'invalid_input'}
    if migration['phase'] in DESTRUCTIVE or migration['phase'] == 'done':
        return {'possible': False, 'reason': 'destructive_phase_reached'}
    verdict = join_decision(deployment, node)
    return {'possible': verdict['allowed'], 'reason': verdict['reason']}
