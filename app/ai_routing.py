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


_MALFORMED = object()


def _mapping(value: Any) -> Any:
    """Return a dict for a nested config section, {} when absent, or _MALFORMED.

    Malformed nonempty sections fail closed instead of raising."""
    if value is None or (not isinstance(value, dict) and not value):
        return {}
    return value if isinstance(value, dict) else _MALFORMED


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
    features = _mapping(config.get('features'))
    connections = _mapping(config.get('connections'))
    default = _mapping(config.get('default'))
    if _MALFORMED in (features, connections, default):
        return _blocked('invalid_config', 'AI routing configuration is malformed.', feature)
    feature_cfg = features.get(feature)
    if feature_cfg is not None and not isinstance(feature_cfg, dict):
        return _blocked('invalid_config', 'AI routing configuration for this feature is malformed.',
                        feature, 'feature')
    if isinstance(feature_cfg, dict) and feature_cfg.get('enabled') is False:
        return _blocked('feature_disabled', 'This AI feature is disabled.', feature, 'feature')
    if item_override is not None and not isinstance(item_override, dict):
        return _blocked('invalid_config', 'The item route override is malformed.', feature, 'item')
    if item_override:
        selection, source = item_override, 'item'
    elif isinstance(feature_cfg, dict) and _ident(feature_cfg.get('connection')):
        selection, source = feature_cfg, 'feature'
    elif isinstance(feature_cfg, dict) and feature_cfg.get('model') is not None:
        # An explicit model without a connection is an incomplete selection:
        # never silently substitute the default model for the requested one.
        return _blocked('incomplete_selection',
                        'The feature route selects a model but no provider connection.', feature, 'feature')
    elif default:
        selection, source = default, 'default'
    connection_id = _ident((selection or {}).get('connection'))
    if not connection_id:
        return _blocked('no_route', 'No provider connection is selected and no default exists.', feature, source)
    connection = connections.get(connection_id)
    if not isinstance(connection, dict):
        return _blocked('unknown_connection', 'The selected provider connection does not exist.', feature, source)
    if connection.get('enabled') is not True:
        return _blocked('connection_disabled', 'The selected provider connection is disabled.', feature, source)
    if selection.get('model') is not None and not isinstance(selection.get('model'), str):
        return _blocked('invalid_config', 'The selected model identifier is malformed.', feature, source)
    model = _ident(selection.get('model'))
    if not model and source != 'default':
        model = _ident(default.get('model')) if _ident(default.get('connection')) == connection_id else None
    if not model:
        return _blocked('no_model', 'No model is selected for this route.', feature, source)
    models = _mapping(connection.get('models'))
    if models is _MALFORMED:
        return _blocked('invalid_config', 'The selected connection model list is malformed.', feature, source)
    caps = models.get(model)
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
    feature = frozen.get('feature')
    if not isinstance(feature, str) or not _ident(frozen.get('connection')) or not _ident(frozen.get('model')) \
            or not _ident(frozen.get('provider')):
        return {'ok': False, 'code': 'frozen_route_invalid', 'reason': 'Queued route is missing or altered.',
                'drift': None}
    current = resolve_route(feature, config, item_override)
    # Validate the frozen route itself against current policy, not the new selection.
    pinned = dict(config) if isinstance(config, dict) else {}
    pinned['features'] = {feature: {'connection': frozen['connection'], 'model': frozen['model']}}
    pinned['default'] = {}
    still = resolve_route(feature, pinned, {'connection': frozen['connection'], 'model': frozen['model']})
    drift = None
    if current['ok'] and current['route']['digest'] != frozen['digest']:
        drift = 'route_changed'
    elif not current['ok']:
        drift = current['code']
    if not current['ok'] and current['code'] in ('feature_disabled', 'invalid_config'):
        # A disabled feature or malformed current configuration fails closed.
        return {'ok': False, 'code': current['code'], 'reason': current['reason'], 'drift': drift}
    if not still['ok']:
        return {'ok': False, 'code': still['code'], 'reason': still['reason'], 'drift': drift}
    if still['route']['provider'] != frozen['provider']:
        # Same connection/model tuple but a different provider behind it: block
        # pending an explicit audited reroute rather than sending to the new provider.
        return {'ok': False, 'code': 'provider_changed',
                'reason': 'The frozen connection now points at a different provider.', 'drift': drift or 'route_changed'}
    return {'ok': True, 'code': 'ok', 'reason': '', 'drift': drift}
