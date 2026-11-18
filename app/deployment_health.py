"""Unified, read-only deployment-health summary (roadmap H slice, issue #843).

Combines the existing controller registrations, expected workers and endpoint-agent health into one
normalized vocabulary. It only reads retained self-reports and receipts: it runs no check, repairs,
drains or authorizes nothing, and every reason is fixed text (reported values are never copied).
"""
import time

from . import agent_fleet_health, controller_registry, worker_registry

STATES = ('offline', 'degraded', 'unknown', 'maintenance', 'healthy')
_RANK = {name: index for index, name in enumerate(STATES)}
# Registry states (controllers and workers share a vocabulary) mapped to the unified one.
REGISTRY_STATE = {
    'missing': 'offline', 'stale': 'offline', 'stopped': 'offline',
    'version_mismatch': 'degraded', 'unknown': 'unknown',
    'draining': 'maintenance', 'drained': 'maintenance', 'reporting': 'healthy',
}
COMPONENT_LABEL = {'controllers': 'Controllers', 'workers': 'Workers', 'endpoint_agents': 'Endpoint agents'}
STATE_TEXT = {
    'offline': 'is offline, missing or stopped',
    'degraded': 'is degraded or reports a different version',
    'unknown': 'has an unknown or unverifiable state',
    'maintenance': 'is draining or drained for maintenance',
    'healthy': 'reports healthy',
}
GAPS = [
    'Summarizes retained self-reports and read-only receipts. HTTP serving, TLS/Caddy routing, readiness and resource metrics are not assessed.',
    'GCP integration nodes are not inventoried yet.',
    'This summary runs no checks and grants no failover, drain, repair or response authority.',
]


def _empty():
    return {name: 0 for name in STATES}


def _component(counts, source, gaps, error=None):
    total = sum(counts.values())
    state = 'unknown' if error else worst(counts)
    return {'counts': counts, 'total': total, 'state': state, 'source': source, 'gaps': gaps, 'error': error}


def worst(counts):
    for name in STATES:
        if counts.get(name):
            return name
    return None


def _registry_counts(items):
    counts = _empty()
    for item in items:
        counts[REGISTRY_STATE.get(item.get('state'), 'unknown')] += 1
    return counts


def workers(now):
    expected, error = worker_registry.expected_workers(now)
    source = 'configuration' if worker_registry.configured() else 'registrations'
    gaps = [] if source == 'configuration' else [
        'Expected workers are inferred from retained registrations; a worker that never registered is not counted.']
    if error:
        return _component(_empty(), source, gaps, 'Expected-worker configuration is invalid or cannot be inferred.')
    return _component(_registry_counts(expected), source, gaps)


def controllers(now):
    expected, error = controller_registry.expected_controllers(now)
    if error:
        return _component(_empty(), 'configuration', [], 'Expected-controller configuration is invalid.')
    if controller_registry._expected_identities():
        return _component(_registry_counts(expected), 'configuration', [])
    # Unconfigured: random identities per start leave stopped/stale history behind, so only count controllers
    # that are currently reporting; never treat retained history as offline.
    items = controller_registry.page(0, now)['items']
    counts = _registry_counts([item for item in items if item.get('state') in ('reporting', 'version_mismatch')])
    return _component(counts, 'registrations', [
        'MRPATCHY_EXPECTED_CONTROLLER_IDS is not configured, so a missing or stopped controller cannot be detected; only currently reporting controllers are counted.'])


def endpoint_agents(now):
    counts = _empty()
    for name, value in agent_fleet_health.page(0, now)['counts'].items():
        counts[name] += value
    return _component(counts, 'servers', ['Only enabled, non-deleted servers are counted.'])


def summary(now=None):
    now = time.time() if now is None else now
    components = {'controllers': controllers(now), 'workers': workers(now), 'endpoint_agents': endpoint_agents(now)}
    ranked = [(name, row['state']) for name, row in components.items() if row['state']]
    if not ranked:
        overall = {'state': 'unknown', 'reason': 'No controllers, workers or endpoint agents are reporting or expected, so deployment health cannot be established.'}
    else:
        name, state = min(ranked, key=lambda pair: (_RANK[pair[1]], list(components).index(pair[0])))
        affected = sum(1 for _, value in ranked if value == state)
        reason = f'{COMPONENT_LABEL[name]}: at least one component {STATE_TEXT[state]}.'
        if state == 'healthy':
            reason = 'Every counted controller, worker and endpoint agent reports healthy. Readiness is not assessed.'
        elif affected > 1:
            reason += f' {affected} component groups share this state.'
        overall = {'state': state, 'reason': reason}
    return {'generated_at': now, 'overall': overall, 'components': components, 'states': list(STATES), 'gaps': GAPS}
