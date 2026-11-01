from app.db import Audit, Session, Setting, config

DEADLINES={'critical':24,'high':72,'normal':168,'low':720}


def test_legacy_put_settings_keeps_omitted_fields(admin):
    with Session() as s:
        s.merge(Setting(key='config', value={'history_days': 365, 'ai_hourly_limit': 5}))
        s.commit()
    r=admin.put('/api/settings', json={'repo_minutes': 90, 'deadlines': DEADLINES})
    assert r.status_code == 200
    with Session() as s:
        raw=s.get(Setting, 'config').value
        assert raw['history_days'] == 365 and raw['ai_hourly_limit'] == 5
        assert 'ai_control_mode' not in raw and raw['repo_minutes'] == 90
        assert config(s)['ai_control_mode'] == 'legacy'
        detail=s.query(Audit).filter_by(action='update settings').one().detail
        assert 'repo_minutes' in detail and 'history_days' not in detail
    assert admin.get('/api/settings').json()['ai_control_migration']['required'] is True


def test_legacy_put_settings_applies_sent_fields(admin):
    r=admin.put('/api/settings', json={'repo_minutes': 60, 'deadlines': DEADLINES, 'history_days': 10, 'ai_control_mode': 'daily_cap', 'ai_daily_cap_usd': 5, 'ai_budget_timezone': 'America/New_York'})
    assert r.status_code == 200
    with Session() as s:
        cfg=config(s)
        assert cfg['history_days'] == 10 and cfg['ai_control_mode'] == 'daily_cap'
        detail=s.query(Audit).filter_by(action='update settings').one().detail
        assert 'AI admission changed' in detail and 'daily AI cap changed from $10.0 to $5.0' in detail
        assert 'daily AI reset timezone changed from UTC to America/New_York' in detail
        assert cfg['ai_budget_timezone']=='America/New_York'


def _seed_model(enabled):
    from app.security import seal
    with Session() as s:
        s.merge(Setting(key='config', value={'ai_enabled': enabled, 'ai_model': 'saved-model', 'history_days': 365}))
        s.merge(Setting(key='openai_key', value={'encrypted': seal('sk-fixture-key')}))
        s.commit()


def test_patch_only_update_keeps_saved_model_when_ai_disabled(admin):
    _seed_model(False)
    assert admin.put('/api/settings', json={'repo_minutes': 90, 'deadlines': DEADLINES}).status_code == 200
    with Session() as s:
        assert s.get(Setting, 'config').value['ai_model'] == 'saved-model'


def test_patch_only_update_succeeds_when_ai_enabled_with_saved_model(admin):
    _seed_model(True)
    r=admin.put('/api/settings', json={'repo_minutes': 90, 'deadlines': DEADLINES})
    assert r.status_code == 200, r.text
    with Session() as s:
        assert s.get(Setting, 'config').value['ai_model'] == 'saved-model'


def test_supplied_model_is_trimmed_and_can_be_cleared(admin):
    _seed_model(False)
    assert admin.put('/api/settings', json={'repo_minutes': 60, 'deadlines': DEADLINES, 'ai_model': '  new-model '}).status_code == 200
    with Session() as s:
        assert s.get(Setting, 'config').value['ai_model'] == 'new-model'
    assert admin.put('/api/settings', json={'repo_minutes': 60, 'deadlines': DEADLINES, 'ai_model': ''}).status_code == 200
    with Session() as s:
        assert s.get(Setting, 'config').value['ai_model'] == ''


def test_legacy_partial_save_preserves_enabled_ai_model_and_key(admin):
    from app.security import seal
    encrypted=seal('fixture-api-key')
    with Session() as s:
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'saved-model','history_days':365,'ai_control_mode':'rate','ai_hourly_limit':5}))
        s.merge(Setting(key='openai_key',value={'encrypted':encrypted}))
        s.commit()
    result=admin.put('/api/settings',json={'repo_minutes':90,'deadlines':DEADLINES})
    assert result.status_code==200
    with Session() as s:
        cfg=config(s)
        assert cfg['ai_enabled'] is True and cfg['ai_model']=='saved-model'
        assert cfg['history_days']==365 and cfg['ai_control_mode']=='rate' and cfg['ai_hourly_limit']==5
        assert s.get(Setting,'openai_key').value['encrypted']==encrypted
        detail=s.query(Audit).filter_by(action='update settings').one().detail
        assert 'repo_minutes' in detail and 'ai_model' not in detail and 'fixture-api-key' not in detail
