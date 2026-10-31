import json
import time

import httpx
import pytest
from sqlalchemy import select

from app import ai, ai_admission, ai_provider_backoff, ai_runs, update_scores
from app.db import Host, Package, Session, Setting
from app.security import seal


def seed():
    with Session() as session:
        session.add(Host(id='score-host', name='Score host', address='192.0.2.1',
            fingerprint='', state='online', inventory={'os':'ID=debian\nVERSION_ID=12'}))
        session.add(Package(id='score-host:fixture', host_id='score-host', name='fixture',
            installed='1', candidate='2', available_since=time.time()-3600))
        session.merge(Setting(key='config', value={'ai_enabled':True,
            'ai_updates_enabled':True, 'ai_model':'fixture-model',
            'ai_control_mode':'rate', 'ai_rate_per_hour':20}))
        session.merge(Setting(key='openai_key', value={'encrypted':seal('fixture-key')}))
        session.commit()


def success(*args, **kwargs):
    items=json.loads(kwargs['json']['input'])
    result={'assessments':[{'id':item['id'], 'score':50, 'confidence':'low',
        'explanation':'Bounded fixture assessment.', 'limitations':'No advisory evidence.'}
        for item in items]}
    return httpx.Response(200, json={'status':'completed', 'output':[{'content':[
        {'type':'output_text', 'text':json.dumps(result)}]}]},
        request=httpx.Request('POST', ai.URL))


def test_rate_refusal_is_durably_deferred_and_resumes_at_exact_eligibility(admin, monkeypatch):
    seed();floor=time.time()+120
    with Session() as session:
        session.add(ai_admission.Admission(id='global', next_at=floor, admitted=1,
            updated=time.time(), model='fixture-model'))
        session.commit()
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: pytest.fail('rate-deferred scoring reached transport'))
    update_scores.run_one()
    with Session() as session:
        row=session.scalar(select(update_scores.UpdateScore))
        assert row.state=='deferred' and row.next_at==pytest.approx(floor, abs=1)
        assert row.score is None and 'queued' in row.explanation.lower()
        first=session.get(ai_runs.AIRun, row.run_id)
        assert first.state=='deferred' and first.calls==0
        session.get(ai_admission.Admission, 'global').next_at=0
        session.commit()
    package=admin.get('/api/hosts/score-host/packages').json()[0]['assessment']
    assert package['state']=='deferred' and package['next_at']==pytest.approx(floor,abs=1)
    ai_runs.heartbeat();status=admin.get('/api/investigation-status').json()
    assert status['scoring_deferred']==1 and status['scoring_next_at']==pytest.approx(floor,abs=1)
    with Session() as session:
        row=session.scalar(select(update_scores.UpdateScore))
        row.next_at=time.time()-1
        session.commit()
    status=admin.get('/api/investigation-status').json()
    assert status['scoring_deferred']==1 and status['reason']=='ready'
    with Session() as session:
        session.scalar(select(update_scores.UpdateScore)).next_at=floor
        session.commit()
    monkeypatch.setattr(update_scores.time, 'time', lambda:floor+1)
    monkeypatch.setattr(ai.transport, 'post', success)
    update_scores.run_one()
    with Session() as session:
        row=session.scalar(select(update_scores.UpdateScore))
        assert row.state=='complete' and row.score==50 and row.next_at==0


def test_transient_sent_failure_uses_shared_floor_without_one_hour_delay(admin, monkeypatch):
    seed();calls=[]
    def provider(*args, **kwargs):
        calls.append(1)
        if len(calls)==1:
            return httpx.Response(503, json={'error':{'code':'server_error'}},
                headers={'retry-after':'90'}, request=httpx.Request('POST', ai.URL))
        return success(*args, **kwargs)
    monkeypatch.setattr(ai.transport, 'post', provider)
    update_scores.run_one()
    with Session() as session:
        row=session.scalar(select(update_scores.UpdateScore))
        shared=session.get(ai_provider_backoff.ProviderBackoff, 'global')
        assert row.state=='deferred' and row.next_at==pytest.approx(shared.blocked_until, abs=1)
        assert row.next_at < row.attempted+3600
        shared.blocked_until=0
        session.get(ai_admission.Admission, 'global').next_at=0
        eligible=row.next_at
        session.commit()
    monkeypatch.setattr(update_scores.time, 'time', lambda:eligible+1)
    update_scores.run_one()
    with Session() as session:
        row=session.scalar(select(update_scores.UpdateScore))
        assert row.state=='complete' and row.score==50 and row.next_at==0
    assert len(calls)==2


def test_changed_evidence_supersedes_deferred_identity(admin, monkeypatch):
    seed();floor=time.time()+120
    with Session() as session:
        session.add(ai_admission.Admission(id='global', next_at=floor, admitted=1,
            updated=time.time(), model='fixture-model'))
        session.commit()
    monkeypatch.setattr(ai.transport, 'post', lambda *a, **k: pytest.fail('rate-deferred scoring reached transport'))
    update_scores.run_one()
    with Session() as session:
        old=session.scalar(select(update_scores.UpdateScore))
        old_id=old.id
        host=session.get(Host, 'score-host')
        host.inventory={'os':'ID=debian\nVERSION_ID=13'}
        session.get(ai_admission.Admission, 'global').next_at=0
        session.commit()
    monkeypatch.setattr(update_scores.time, 'time', lambda:floor+1)
    monkeypatch.setattr(ai.transport, 'post', success)
    update_scores.run_one()
    with Session() as session:
        rows=list(session.scalars(select(update_scores.UpdateScore).order_by(update_scores.UpdateScore.id)))
        stale=next(row for row in rows if row.id==old_id)
        current=next(row for row in rows if row.id!=old_id)
        assert stale.state=='superseded' and stale.next_at==0
        assert current.state=='complete' and current.score==50
        stale.state='deferred';stale.next_at=floor+600
        session.commit()
    update_scores.run_one()
    with Session() as session:
        stale=session.get(update_scores.UpdateScore, old_id)
        assert stale.state=='superseded' and stale.next_at==0
    ai_runs.heartbeat();status=admin.get('/api/investigation-status').json()
    assert status['scoring_deferred']==0 and status['scoring_next_at'] is None
