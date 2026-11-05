from app import ai_routing as r


def cfg(**kw):
    base = {
        'revision': 3,
        'default': {'connection': 'a', 'model': 'm1'},
        'features': {},
        'connections': {
            'a': {'provider': 'openai', 'enabled': True, 'models': {'m1': {'structured': True}, 'plain': {}}},
            'b': {'provider': 'anthropic', 'enabled': True, 'models': {'c1': {'structured': True}}},
        },
    }
    base.update(kw)
    return base


def test_precedence_item_over_feature_over_default():
    c = cfg(features={'update_scoring': {'connection': 'b', 'model': 'c1'}})
    assert r.resolve_route('triage_first', c)['route']['source'] == 'default'
    res = r.resolve_route('update_scoring', c)
    assert (res['route']['source'], res['route']['provider']) == ('feature', 'anthropic')
    res = r.resolve_route('update_scoring', c, {'connection': 'a', 'model': 'm1'})
    assert (res['route']['source'], res['route']['provider']) == ('item', 'openai')


def test_blocked_routes_explain_and_never_fall_back():
    c = cfg(features={'update_scoring': {'connection': 'zz', 'model': 'x'}})
    res = r.resolve_route('update_scoring', c)
    assert not res['ok'] and res['code'] == 'unknown_connection' and res['route'] is None
    c['connections']['b']['enabled'] = False
    c['features']['update_scoring'] = {'connection': 'b', 'model': 'c1'}
    assert r.resolve_route('update_scoring', c)['code'] == 'connection_disabled'
    c['features']['update_scoring'] = {'connection': 'a', 'model': 'plain'}
    assert r.resolve_route('update_scoring', c)['code'] == 'missing_capability'
    assert r.resolve_route('connection_test', c, {'connection': 'a', 'model': 'plain'})['ok']
    c['features']['update_scoring'] = {'connection': 'a', 'model': 'nope'}
    assert r.resolve_route('update_scoring', c)['code'] == 'unsupported_model'
    assert r.resolve_route('bogus', c)['code'] == 'unknown_feature'
    assert r.resolve_route('triage_first', None)['code'] == 'no_config'
    assert r.resolve_route('triage_first', cfg(default={}))['code'] == 'no_route'


def test_disabled_feature_blocks_even_with_item_override():
    c = cfg(features={'incident_plan': {'enabled': False}})
    assert r.resolve_route('incident_plan', c, {'connection': 'a', 'model': 'm1'})['code'] == 'feature_disabled'


def test_triage_stages_route_independently():
    c = cfg(features={'triage_followup': {'connection': 'b', 'model': 'c1'}})
    assert r.resolve_route('triage_first', c)['route']['provider'] == 'openai'
    assert r.resolve_route('triage_followup', c)['route']['provider'] == 'anthropic'


def test_feature_model_inherits_default_only_on_same_connection():
    c = cfg(features={'update_scoring': {'connection': 'a'}})
    assert r.resolve_route('update_scoring', c)['route']['model'] == 'm1'
    c['features']['update_scoring'] = {'connection': 'b'}
    assert r.resolve_route('update_scoring', c)['code'] == 'no_model'


def test_digest_differs_across_provider_model_and_revision():
    a = r.resolve_route('update_scoring', cfg())['route']
    b = r.resolve_route('update_scoring', cfg(revision=4))['route']
    c = r.resolve_route('update_scoring', cfg(default={'connection': 'b', 'model': 'c1'}))['route']
    assert len({a['digest'], b['digest'], c['digest']}) == 3


def test_revalidate_keeps_frozen_route_after_settings_edit():
    frozen = r.resolve_route('update_scoring', cfg())['route']
    edited = cfg(revision=4, features={'update_scoring': {'connection': 'b', 'model': 'c1'}})
    out = r.revalidate(frozen, edited)
    assert out['ok'] and out['drift'] == 'route_changed'


def test_revalidate_blocks_when_frozen_route_no_longer_valid_or_tampered():
    frozen = r.resolve_route('update_scoring', cfg())['route']
    gone = cfg()
    gone['connections']['a']['enabled'] = False
    out = r.revalidate(frozen, gone)
    assert not out['ok'] and out['code'] == 'connection_disabled'
    assert r.revalidate(dict(frozen, model='other'), cfg())['code'] == 'frozen_route_invalid'
    assert r.revalidate(None, cfg())['code'] == 'frozen_route_invalid'


def test_revalidate_respects_feature_disable():
    frozen = r.resolve_route('update_scoring', cfg())['route']
    out = r.revalidate(frozen, cfg(features={'update_scoring': {'enabled': False}}))
    assert not out['ok'] and out['code'] == 'feature_disabled'
