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
    r=admin.put('/api/settings', json={'repo_minutes': 60, 'deadlines': DEADLINES, 'history_days': 10, 'ai_control_mode': 'daily_cap'})
    assert r.status_code == 200
    with Session() as s:
        cfg=config(s)
        assert cfg['history_days'] == 10 and cfg['ai_control_mode'] == 'daily_cap'
        assert 'AI admission changed' in s.query(Audit).filter_by(action='update settings').one().detail
