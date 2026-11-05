from app import ai, main
from app.db import Session, Setting
from app.identity import User
from app.security import password_hash


PATH = '/api/settings/ai-connections'


def test_inventory_requires_administrator(client):
    assert client.get(PATH).status_code == 401
    with Session() as session:
        session.add(User(username='viewer', password=password_hash('viewer-password'), role='viewer'))
        session.commit()
    assert client.post('/api/login', json={'username': 'viewer', 'password': 'viewer-password'}).status_code == 200
    assert client.get(PATH).status_code == 403


def test_missing_saved_configuration(admin):
    response = admin.get(PATH)
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    data = response.json()
    assert data['connections'] == [{'id': 'legacy-openai', 'provider': 'openai',
                                    'credential_saved': False, 'default_model': None}]
    assert all(not feature['configuration_complete'] for feature in data['features'])
    assert all(not feature['enabled_by_settings'] for feature in data['features'] if feature['scope'] == 'host')


def test_inventory_reflects_saved_selection_without_contacting_provider(admin, monkeypatch):
    with Session() as session:
        session.merge(Setting(key='config', value={'ai_enabled': True, 'ai_updates_enabled': False,
                                                   'ai_model': 'ft:private:model'}))
        session.merge(Setting(key='openai_key', value={'encrypted': 'credential-canary'}))
        session.commit()

    def forbidden(*args, **kwargs):
        raise AssertionError('A settings inventory read must not decrypt credentials or contact a provider')

    monkeypatch.setattr(main, 'unseal', forbidden)
    monkeypatch.setattr(ai, 'request', forbidden)
    monkeypatch.setattr(ai, 'list_models', forbidden)
    response = admin.get(PATH)
    assert response.status_code == 200
    assert 'credential-canary' not in response.text
    data = response.json()
    assert data['connections'][0]['credential_saved'] is True
    features = {row['id']: row for row in data['features']}
    assert set(features) == {'triage_first', 'triage_followup', 'update_scoring', 'incident_plan',
                             'startup_plan', 'release_configuration', 'connection_test', 'model_discovery'}
    assert all(row['connection'] == 'legacy-openai' for row in features.values())
    assert all(row['configuration_complete'] for row in features.values())
    assert not features['update_scoring']['enabled_by_settings']
    assert features['triage_first']['enabled_by_settings']
    assert features['connection_test']['billable']
    assert features['model_discovery']['model'] is None
    assert not features['model_discovery']['billable']
    assert all(row['model'] == 'ft:private:model' for key, row in features.items() if key != 'model_discovery')
