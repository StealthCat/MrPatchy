"""Read-only inventory of the legacy OpenAI settings used by running code."""

import re


HOST_FEATURES = (
    'triage_first',
    'triage_followup',
    'update_scoring',
    'incident_plan',
    'startup_plan',
    'release_configuration',
)


def inventory(config, credential_saved):
    connection_id = 'legacy-openai'
    model = config.get('ai_model')
    if not isinstance(model, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,99}', model):
        model = None

    features = []
    for feature in (*HOST_FEATURES, 'connection_test', 'model_discovery'):
        host_feature = feature in HOST_FEATURES
        requires_model = feature != 'model_discovery'
        enabled = not host_feature or bool(config['ai_enabled'])
        if feature == 'update_scoring':
            enabled = enabled and bool(config['ai_updates_enabled'])
        features.append({
            'id': feature,
            'connection': connection_id,
            'scope': 'host' if host_feature else 'connection',
            'model': model if requires_model else None,
            'billable': requires_model,
            'enabled_by_settings': enabled,
            'configuration_complete': credential_saved and (not requires_model or model is not None),
        })
    return {
        'connections': [{'id': connection_id, 'provider': 'openai',
                         'credential_saved': credential_saved, 'default_model': model}],
        'features': features,
    }
