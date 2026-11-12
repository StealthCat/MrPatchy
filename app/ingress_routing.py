"""Pure ingress routing contract: liveness, readiness and role eligibility (#450, first slice).

Nothing here probes a node, reads a clock, edits a proxy or opens a socket. Callers pass the facts they
observed and decide what to do with the verdict. It authorizes no failover, deployment or TLS change, and
it fails closed: malformed or ambiguous input is never routable.

Three independent questions are kept apart so ``/healthz``-style liveness can never imply traffic safety:

* liveness  - the process answers (restart signal only, never a routing signal);
* readiness - its dependencies (database, durable artifacts, schema compatibility) are usable;
* role      - the cluster says this node is ``active`` (or an ``active_active`` member), ``standby``,
  ``fenced`` or ``incompatible``.

Traffic classes: ``read`` (idempotent, safe on any ready serving node), ``mutation`` (non-idempotent;
only a ready, unfenced serving node, and never blindly replayed by the proxy), ``stream`` (long-lived
notification streams; same eligibility as read but flagged for cursor catch-up on reconnect) and ``admin``
(Caddy/ingress administration; never routed publicly).
"""

ROLES = ('active', 'active_active', 'standby', 'fenced', 'incompatible')
MODES = ('active_standby', 'active_active')
TRAFFIC = ('read', 'mutation', 'stream', 'admin')
SERVING = {'active_standby': ('active',), 'active_active': ('active_active',)}


def _facts_ok(node):
    return (isinstance(node, dict) and isinstance(node.get('live'), bool) and isinstance(node.get('ready'), bool)
            and node.get('role') in ROLES)


def eligibility(node, mode):
    """May this node receive production traffic? Returns ``{'serving', 'reason'}``."""
    if mode not in MODES or not _facts_ok(node):
        return {'serving': False, 'reason': 'invalid_input'}
    if not node['live']:
        return {'serving': False, 'reason': 'not_live'}
    if node['role'] in ('fenced', 'incompatible'):
        return {'serving': False, 'reason': node['role']}
    if node['role'] == 'standby':
        return {'serving': False, 'reason': 'standby'}
    if node['role'] not in SERVING[mode]:
        return {'serving': False, 'reason': 'role_mode_mismatch'}
    if not node['ready']:
        return {'serving': False, 'reason': 'not_ready'}
    return {'serving': True, 'reason': ''}


def route_decision(node, mode, traffic):
    """Should the ingress send ``traffic`` to ``node``? Returns ``{'route', 'reason', 'replay_safe'}``.

    ``replay_safe`` says whether the proxy may retry the request on another node after an ambiguous
    failure; only idempotent reads qualify. A failed mutation must surface uncertainty instead.
    """
    if traffic not in TRAFFIC:
        return {'route': False, 'reason': 'invalid_input', 'replay_safe': False}
    if traffic == 'admin':
        return {'route': False, 'reason': 'admin_not_public', 'replay_safe': False}
    verdict = eligibility(node, mode)
    if not verdict['serving']:
        return {'route': False, 'reason': verdict['reason'], 'replay_safe': False}
    return {'route': True, 'reason': '', 'replay_safe': traffic == 'read'}


def pool(nodes, mode, traffic):
    """Names of nodes the ingress may use, with a verdict on whether the pool is safe to serve from.

    ``active_standby`` must have exactly one serving node: two would be split-brain, so the pool is
    refused rather than guessed. ``active_active`` needs at least one. An empty or malformed inventory
    serves nothing: absence of evidence is not a healthy cluster.
    """
    if mode not in MODES or traffic not in TRAFFIC or not isinstance(nodes, (list, tuple)) or not nodes:
        return {'ok': False, 'reason': 'invalid_input', 'members': []}
    names = []
    for item in nodes:
        if not _facts_ok(item) or not isinstance(item.get('name'), str) or not item['name']:
            return {'ok': False, 'reason': 'invalid_input', 'members': []}
        names.append(item['name'])
    if len(set(names)) != len(names):
        return {'ok': False, 'reason': 'duplicate_node', 'members': []}
    members = sorted(n['name'] for n in nodes if route_decision(n, mode, traffic)['route'])
    if not members:
        return {'ok': False, 'reason': 'no_serving_node', 'members': []}
    if mode == 'active_standby':
        claimed = sorted(n['name'] for n in nodes if n['live'] and n['role'] == 'active')
        if len(claimed) > 1:
            return {'ok': False, 'reason': 'multiple_active', 'members': []}
    return {'ok': True, 'reason': '', 'members': members}
