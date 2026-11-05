"""Pure AI feature-route resolution contract (first slice of #290).

Decides which provider connection and model a billable AI feature call uses,
with precedence item override > feature route > default connection, validates
provider capabilities before any transmission, and freezes the resolved route
into a digest so later settings edits cannot silently redirect queued work.
It performs no I/O, holds no credentials, never falls back to another provider
and never authorizes a response action.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

CONTRACT_VERSION = 1

# Inventory of billable/provider-touching call sites. ``structured`` means the
# feature requires structured (schema-validated) output.
FEATURES: dict[str, dict[str, Any]] = {
    'triage_first': {'structured': True, 'billable': True},
    'triage_followup': {'structured': True, 'billable': True},
    'update_scoring': {'structured': True, 'billable': True},
    'incident_plan': {'structured': True, 'billable': True},
    'startup_plan': {'structured': True, 'billable': True},
    'release_configuration': {'structured': True, 'billable': True},
    'connection_test': {'structured': False, 'billable': True},
    'model_discovery': {'structured': False, 'billable': False},
}
SOURCES = ('item', 'feature', 'default')
MAX_ID = 128


def _ident(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:MAX_ID] if value else None


def _blocked(code: str, reason: str, feature: str, source: str | None = None) -> dict[str, Any]:
    return {'ok': False, 'code': code, 'reason': reason, 'feature': feature,
            'source': source, 'route': None}


def resolve_route(feature: str, config: Any, item_override: Any = None) -> dict[str, Any]:
    """Resolve the effective route, or a blocked result with an actionable reason.

    ``config`` = {'revision': int, 'default': {connection, model},
    'features': {name: {connection, model, enabled}},
    'connections': {id: {provider, enabled, models: {model: {structured}}}}}.
    A partially specified selection inherits the missing part from the next
    level only for the model-less case; a disabled or unknown choice never
    falls through to a different provider.
    """
    if feature not in FEATURES:
        return _blocked('unknown_feature', 'Feature is not an AI-routed feature.', str(feature)[:MAX_ID])
    if not isinstance(config, dict):
        return _blocked('no_config', 'AI routing is not configured.', feature)
    selection, source = None, None
    feature_cfg = (config.get('features') or {}).get(feature)
    if isinstance(feature_cfg, dict) and feature_cfg.get('enabled') is False:
        return _blocked('feature_disabled', 'This AI feature is disabled.', feature, 'feature')
    if isinstance(item_override, dict) and item_override:
        selection, source = item_override, 'item'
    elif isinstance(feature_cfg, dict) and _ident(feature_cfg.get('connection')):
        selection, source = feature_cfg, 'feature'
    elif isinstance(config.get('default'), dict):
        selection, source = config['default'], 'default'
    connection_id = _ident((selection or {}).get('connection'))
    if not connection_id:
        return _blocked('no_route', 'No provider connection is selected and no default exists.', feature, source)
    connection = (config.get('connections') or {}).get(connection_id)
    if not isinstance(connection, dict):
        return _blocked('unknown_connection', 'The selected provider connection does not exist.', feature, source)
    if connection.get('enabled') is not True:
        return _blocked('connection_disabled', 'The selected provider connection is disabled.', feature, source)
    model = _ident(selection.get('model'))
    if not model and source != 'default':
        model = _ident((config.get('default') or {}).get('model')) if \
            _ident((config.get('default') or {}).get('connection')) == connection_id else None
    if not model:
        return _blocked('no_model', 'No model is selected for this route.', feature, source)
    caps = (connection.get('models') or {}).get(model)
    if not isinstance(caps, dict):
        return _blocked('unsupported_model', 'The model is not offered by the selected connection.', feature, source)
    if FEATURES[feature]['structured'] and caps.get('structured') is not True:
        return _blocked('missing_capability',
                        'The selected model does not support the structured output this feature requires.',
                        feature, source)
    route = {'feature': feature, 'source': source, 'connection': connection_id,
             'provider': _ident(connection.get('provider')), 'model': model,
             'revision': config.get('revision') if isinstance(config.get('revision'), int) else 0}
    if not route['provider']:
        return _blocked('unknown_provider', 'The selected connection has no provider identity.', feature, source)
    route['digest'] = route_digest(route)
    return {'ok': True, 'code': 'ok', 'reason': '', 'feature': feature, 'source': source, 'route': route}


def route_digest(route: dict[str, Any]) -> str:
    """Stable digest binding feature, provider, connection, model and revision.

    Cache/reuse identities must include it: results are never equivalent across
    providers or models.
    """
    body = {k: route.get(k) for k in ('feature', 'provider', 'connection', 'model', 'revision')}
    body['v'] = CONTRACT_VERSION
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def revalidate(frozen: Any, config: Any, item_override: Any = None) -> dict[str, Any]:
    """Check a queued item's frozen route before an outbound stage.

    Work never silently follows a changed route: if the route now resolves to
    something different (or is blocked) the item stays on its frozen route only
    when that route is still valid; otherwise it is blocked pending an explicit
    audited reroute. A changed revision alone is reported but does not redirect.
    """
    if not isinstance(frozen, dict) or not frozen.get('digest') or frozen.get('digest') != route_digest(frozen):
        return {'ok': False, 'code': 'frozen_route_invalid', 'reason': 'Queued route is missing or altered.',
                'drift': None}
    current = resolve_route(frozen.get('feature'), config, item_override)
    # Validate the frozen route itself against current policy, not the new selection.
    pinned = dict(config) if isinstance(config, dict) else {}
    pinned['features'] = {frozen['feature']: {'connection': frozen['connection'], 'model': frozen['model']}}
    pinned['default'] = {}
    still = resolve_route(frozen['feature'], pinned, {'connection': frozen['connection'], 'model': frozen['model']})
    drift = None
    if current['ok'] and current['route']['digest'] != frozen['digest']:
        drift = 'route_changed'
    elif not current['ok']:
        drift = current['code']
    if not current['ok'] and current['code'] == 'feature_disabled':
        return {'ok': False, 'code': 'feature_disabled', 'reason': current['reason'], 'drift': drift}
    if not still['ok']:
        return {'ok': False, 'code': still['code'], 'reason': still['reason'], 'drift': drift}
    return {'ok': True, 'code': 'ok', 'reason': '', 'drift': drift}
