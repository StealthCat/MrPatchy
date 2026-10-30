import json
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import inspect
from app import ai, ai_runs, ai_pricing, db, releases
from app.identity import User
from app.security import seal


def response_body(**changes):
    return {'model': 'gpt-6-luna', 'service_tier': 'default', 'status': 'completed',
            'usage': {'input_tokens': 1000, 'output_tokens': 200, 'total_tokens': 1200,
                      'input_tokens_details': {'cached_tokens': 400, 'cache_write_tokens': 100},
                      'output_tokens_details': {'reasoning_tokens': 100}},
            'output': [{'content': [{'type': 'output_text', 'text': json.dumps({
                'risk': 'unknown', 'explanation': 'Fixture', 'recommended_checks': '', 'requested_checks': []})}]}], **changes}


def post_response(monkeypatch, body, status=200):
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: httpx.Response(status, json=body, request=httpx.Request('POST', ai.URL)))


def detail(admin, identifier):
    response = admin.get('/api/ai/runs/' + identifier)
    assert response.status_code == 200
    return response.json()


def test_cached_writes_and_reasoning_are_not_double_charged():
    estimate = ai_pricing.estimate(response_body(), {})
    # 500 ordinary, 400 cached, 100 cache writes; all 200 output billed ONCE.
    assert Decimal(estimate['pricing']['estimated_usd']) == Decimal('0.0001665')
    assert estimate['usage']['reasoning_tokens'] == 100
    assert estimate['pricing']['per_million']['cache_write'] == '0.125'
    assert estimate['pricing']['version'] == ai_pricing.VERSION


@pytest.mark.parametrize('tier,factor', [('default', 1), ('flex', 0.5), ('priority', 2), ('fast', 2)])
def test_observed_processing_tier_controls_rate(tier, factor):
    result = ai_pricing.estimate(response_body(service_tier=tier), {'service_tier': 'default'})
    assert Decimal(result['pricing']['estimated_usd']) == Decimal('0.0001665') * Decimal(str(factor))


def test_cache_lifetime_and_ultrafast_rates():
    result = ai_pricing.estimate(response_body(), {'prompt_cache_options': {'ttl': '12h'}})
    assert Decimal(result['pricing']['estimated_usd']) == Decimal('0.000179')
    result = ai_pricing.estimate(response_body(model='gpt-6.1-sol', service_tier='ultrafast'), {})
    assert result['pricing']['per_million']['input'] == '12'
    assert result['pricing']['per_million']['output'] == '60'


@pytest.mark.parametrize('changes', [
    {'usage': None}, {'usage': []}, {'model': 'ft:gpt-6-luna:private'}, {'model': 'gpt-6-luna-2099-01-01'},
    {'model': 'gpt-6-luna-private'}, {'model': None}, {'model': '<script>secret</script>'},
    {'service_tier': None}, {'service_tier': 'scale'}, {'service_tier': 'unrecognised'},
    {'service_tier': 'ultrafast'},
])
def test_missing_usage_unknown_model_or_tier_never_report_free(changes):
    result = ai_pricing.estimate(response_body(**changes), {})
    assert result['status'] == 'unavailable' and result['pricing'] == {}
    assert 'secret' not in json.dumps(result)


@pytest.mark.parametrize('path,value', [
    (('input_tokens',), -1), (('input_tokens',), True), (('output_tokens',), 2.5),
    (('total_tokens',), 1199), (('input_tokens',), 10**30),
    (('input_tokens_details', 'cached_tokens'), 1001),
    (('input_tokens_details', 'cached_tokens'), 'secret'),
    (('input_tokens_details', 'cache_write_tokens'), -1),
    (('output_tokens_details', 'reasoning_tokens'), 201),
    (('output_tokens_details', 'reasoning_tokens'), False),
])
def test_invalid_usage_is_ignored_not_echoed(path, value):
    body = response_body(); target = body['usage']
    for key in path[:-1]: target = target[key]
    target[path[-1]] = value
    result = ai_pricing.estimate(body, {})
    assert result['status'] == 'unavailable' and result['usage'] == {}
    assert 'secret' not in json.dumps(result)


def test_known_snapshot_old_usage_and_missing_cache_counts():
    body = response_body(model='gpt-4.1-mini-2025-04-14')
    del body['usage']['input_tokens_details']['cache_write_tokens']
    result = ai_pricing.estimate(body, {})
    assert Decimal(result['pricing']['estimated_usd']) == Decimal('0.0006')
    body['model'] = 'gpt-6-luna'
    assert ai_pricing.estimate(body, {})['status'] == 'unavailable'
    body = response_body(); del body['usage']['input_tokens_details']['cached_tokens']
    assert ai_pricing.estimate(body, {})['status'] == 'unavailable'


def test_long_context_and_tool_prices_are_not_guessed():
    body = response_body()
    body['usage'].update(input_tokens=300000, total_tokens=300200)
    assert ai_pricing.estimate(body, {})['status'] == 'unavailable'
    assert ai_pricing.estimate(response_body(), {'tools': [{'type': 'web_search'}]})['status'] == 'unavailable'


def test_multicall_run_cost_snapshot_is_immutable_and_redacted(admin, monkeypatch):
    body = response_body(); body['usage']['private'] = 'secret-key-and-prompt'
    post_response(monkeypatch, body)
    with ai_runs.track('triage', 'gpt-6-luna') as identifier:
        for _ in range(2): ai.investigate({'private': 'host-evidence'}, 'gpt-6-luna', 'secret-key')
    result = detail(admin, identifier)
    assert result['calls'] == 2 and result['cost']['priced_calls'] == 2
    assert Decimal(result['cost']['estimated_usd']) == Decimal('0.000333')
    assert result['cost']['tokens']['output_tokens'] == 400
    assert len(result['api_calls']) == 2
    assert all(x not in json.dumps(result) for x in ('secret-key', 'host-evidence', 'private'))
    monkeypatch.setitem(ai_pricing.RATES, 'gpt-6-luna', ('100', '10', '500', '125'))
    assert detail(admin, identifier)['cost'] == result['cost']
    assert admin.get('/api/ai/runs').json()['items'][0]['cost'] == result['cost']


@pytest.mark.parametrize('changes,status', [
    ({'status': 'incomplete', 'incomplete_details': {'reason': 'max_output_tokens'}}, 200),
    ({'output': [{'content': [{'type': 'refusal', 'refusal': 'secret'}]}]}, 200),
    ({'output': [{'content': [{'type': 'output_text', 'text': 'malformed'}]}]}, 200),
    ({'output': [{'content': [{'type': 'output_text', 'text': '{"risk":"bad"}'}]}]}, 200),
    ({'error': {'code': 'server_error', 'message': 'secret'}}, 500),
])
def test_failed_results_still_retain_billable_usage(admin, monkeypatch, changes, status):
    post_response(monkeypatch, response_body(**changes), status)
    with pytest.raises(ai.AIError), ai_runs.track('connection_test', 'gpt-6-luna') as identifier:
        ai.investigate({}, 'gpt-6-luna', 'secret-key')
    result = detail(admin, identifier)
    assert result['state'] == 'error' and result['cost']['status'] == 'estimated'
    assert Decimal(result['cost']['estimated_usd']) == Decimal('0.0001665')


def test_timeout_after_priced_followup_is_partial_and_retains_receipt(admin, monkeypatch):
    post_response(monkeypatch, response_body())
    with pytest.raises(ai.AIError), ai_runs.track('triage', 'gpt-6-luna') as identifier:
        ai.investigate({}, 'gpt-6-luna', 'secret-key')
        def timeout(*a, **k): raise httpx.ReadTimeout('secret-key')
        monkeypatch.setattr(ai.transport, 'post', timeout)
        ai.investigate({}, 'gpt-6-luna', 'secret-key')
    result = detail(admin, identifier)
    assert result['cost']['status'] == 'partial'
    assert result['cost']['priced_calls'] == 1 and result['cost']['total_calls'] == 2
    assert result['api_calls'][1]['pricing'] == {}


def test_http404_and_legacy_runs_are_unavailable_no_calls_are_zero(admin, monkeypatch):
    post_response(monkeypatch, {'error': {'code': 'model_not_found'}}, 404)
    with pytest.raises(ai.AIError), ai_runs.track('connection_test', 'bad-model') as failed:
        ai.investigate({}, 'bad-model', 'secret-key')
    assert detail(admin, failed)['cost']['estimated_usd'] is None
    with db.Session() as s:
        s.add(ai_runs.AIRun(id='legacy', purpose='triage', calls=2, state='complete'))
        s.commit()
    assert detail(admin, 'legacy')['cost']['estimated_usd'] is None
    with ai_runs.track('triage', 'bad-model') as empty: pass
    assert detail(admin, empty)['cost']['status'] == 'no_calls'
    assert detail(admin, empty)['cost']['estimated_usd'] == '0'


def test_release_review_gets_costed_run_and_remains_private(admin, monkeypatch):
    with db.Session() as s:
        s.merge(db.Setting(key='config', value={'ai_enabled': True, 'ai_model': 'gpt-6-luna'}))
        s.merge(db.Setting(key='openai_key', value={'encrypted': seal('secret-key')})); s.commit()
        body = response_body(output=[{'content': [{'type': 'output_text', 'text': json.dumps({'content': 'safe', 'reason': 'test', 'blockers': []})}]}])
        post_response(monkeypatch, body)
        assert releases.ai_review(s, 'release', '/private/path', 'host-evidence', 'safe', '')['content'] == 'safe'
    result = admin.get('/api/ai/runs?purpose=release_configuration').json()['items']
    assert len(result) == 1 and result[0]['cost']['status'] == 'estimated'
    assert 'host-evidence' not in json.dumps(result) and '/private/path' not in json.dumps(result)


def test_new_table_upgrade_keeps_old_runs_and_api_is_admin_only(admin):
    with db.Session() as s:
        s.add(ai_runs.AIRun(id='legacy', purpose='triage', calls=1, state='complete')); s.commit()
    ai_runs.AICall.__table__.drop(db.engine)
    db.init(); db.init()
    assert 'ai_calls' in inspect(db.engine).get_table_names()
    assert detail(admin, 'legacy')['cost']['status'] == 'unavailable'
    with db.Session() as s: s.get(User, 'admin').role = 'viewer'; s.commit()
    assert admin.get('/api/ai/runs').status_code == 403
    assert admin.get('/api/ai/runs/legacy').status_code == 403
