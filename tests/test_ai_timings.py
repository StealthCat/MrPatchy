import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy import event, select
import httpx
import pytest
from app import ai,ai_runs,worker
from app.db import Session,Host,Behavior,Setting,engine
from app.security import seal


def stages(admin,identifier):
    detail=admin.get('/api/ai/runs/'+identifier).json()
    timings=[e for e in detail['events'] if e['stage'].startswith('timing_')]
    assert all(re.fullmatch(r'[a-z ]+: [0-9]+\.[0-9]{3} ms; outcome=(complete|error)',e['message']) for e in timings)
    return detail,[e['stage'].removeprefix('timing_') for e in timings]


@pytest.mark.parametrize('followup',[False,True])
def test_full_pipeline_preserves_capability_and_records_stage_timings(admin,monkeypatch,followup):
    with Session() as s:
        s.add(Host(id='timing-host',name='Fixture',address='192.0.2.1',fingerprint=''))
        s.add(Behavior(id='timing-subject',host_id='timing-host',evidence={'executable':'/private/artifact','sha256':'a'*64,'identity_verified':True}))
        s.add(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture-model'}))
        s.add(Setting(key='openai_key',value={'encrypted':seal('private-key')}));s.commit()
    sent=[];ssh_calls=[]
    def provider(*a,**kw):
        sent.append(kw)
        result={'risk':'low','explanation':'Bounded assessment','recommended_checks':'None','requested_checks':['executable'] if followup and len(sent)==1 else []}
        return httpx.Response(200,json={'status':'completed','output':[{'content':[{'type':'output_text','text':json.dumps(result)}]}]},request=httpx.Request('POST',ai.URL))
    monkeypatch.setattr(ai.transport,'post',provider)
    monkeypatch.setattr(worker.ssh,'call',lambda *a,**k:ssh_calls.append((a,k)) or {'identity_verified':True,'private':'followup-context'})
    worker.investigate_one()
    with Session() as s:
        run=s.scalar(select(ai_runs.AIRun).where(ai_runs.AIRun.purpose=='triage'));identifier=run.id
        row=s.get(Behavior,'timing-subject');assert row.verdict=='low' and not row.approved
    detail,values=stages(admin,identifier)
    assert detail['state']=='complete' and detail['stage']=='complete' and detail['calls']==1+followup
    assert detail['message']=='Structured result validated and processing completed.'
    for name in ('claim_lock','claim_lock_hold','admission','queue_age','run','result_persistence'):assert values.count(name)==1
    summary=admin.get('/api/ai/triage/timings').json()['stages']['claim_lock_hold']
    assert summary['samples']==1 and summary['errors']==0
    assert 0 <= summary['p50_ms']==summary['p95_ms']
    for name in ('provider','provider_admission','receipt_persistence','usage_persistence'):assert values.count(name)==1+followup
    assert values.count('ssh_evidence')==values.count('evidence_persistence')==int(followup)
    assert len(ssh_calls)==int(followup)
    assert all(p['json']['model']=='fixture-model' and p['json']['max_output_tokens']==1600 and p['json']['text']['format']['schema']==ai.SCHEMA for p in sent)
    if followup:assert json.loads(sent[1]['json']['input'])['investigation']['details']['private']=='followup-context'
    assert all(secret not in json.dumps(detail) for secret in ('private-key','/private/artifact','followup-context'))


def test_failed_provider_has_error_timing_no_retry_or_fabricated_usage(admin,monkeypatch):
    calls=[]
    def timeout(*a,**k):calls.append(1);raise httpx.ReadTimeout('private-secret')
    monkeypatch.setattr(ai.transport,'post',timeout)
    with pytest.raises(ai.AIError),ai_runs.track('connection_test','fixture') as identifier:ai.request({'model':'fixture'},'private-key')
    detail,values=stages(admin,identifier)
    assert len(calls)==detail['calls']==1 and detail['state']=='error'
    assert detail['cost']['status']=='unavailable' and detail['api_calls'][0]['status']=='unavailable'
    assert 'private' not in json.dumps(detail)
    assert any(e['stage']=='timing_provider' and 'outcome=error' in e['message'] for e in detail['events'])
    assert values.count('run')==1 and 'usage_persistence' not in values


def test_independent_thread_contexts_do_not_mix_timings(admin):
    barrier=threading.Barrier(4)
    def run(index):
        with ai_runs.track('connection_test','fixture',subject=str(index)) as identifier:
            barrier.wait(timeout=10)
            with ai_runs.measure('provider'):pass
        assert ai_runs.active.get() is None
        return identifier
    with ThreadPoolExecutor(max_workers=4) as pool:identifiers=list(pool.map(run,range(4)))
    for identifier in identifiers:
        detail,values=stages(admin,identifier)
        assert values==['provider','run'] and detail['calls']==0
    assert ai_runs.active.get() is None


def test_bad_timing_inputs_and_diagnostic_failure_cannot_change_result(admin,monkeypatch):
    with ai_runs.track('connection_test','fixture') as identifier:
        for value in (float('nan'),float('inf'),-1,'private-secret'):ai_runs.timing('provider',value)
        ai_runs.timing('private-secret',1)
        with monkeypatch.context() as patch:
            patch.setattr(ai_runs,'Session',lambda:(_ for _ in ()).throw(RuntimeError('private-secret')))
            with ai_runs.measure('provider'):result='validated'
            ai_runs.flush_timings()
    detail,values=stages(admin,identifier)
    assert result=='validated' and detail['state']=='complete' and values==['run']


def test_triage_timing_summary_uses_retained_samples_without_exposing_details(admin):
    with Session() as s:
        for identifier, purpose, state, finished in (
            ('good', 'triage', 'complete', 8),
            ('failed', 'triage', 'error', 9),
            ('no-timings', 'triage', 'complete', 10),
            ('running', 'triage', 'running', 0),
            ('test-call', 'connection_test', 'complete', 11),
        ):
            s.add(ai_runs.AIRun(id=identifier, purpose=purpose, state=state,
                                finished=finished, subject='/private/evidence'))
        for identifier, message in (
            ('good', 'provider: 0.000 ms; outcome=complete'),
            ('good', 'provider: 10.000 ms; outcome=complete'),
            ('failed', 'provider: 20.000 ms; outcome=error'),
            ('failed', 'provider: 30.000 ms; outcome=error'),
            ('failed', 'provider: 40.000 ms; outcome=complete private-key'),
            ('failed', 'queue age: 99.000 ms; outcome=complete'),
            ('failed', 'private-key' * 100),
            ('running', 'provider: 999.000 ms; outcome=complete'),
            ('test-call', 'provider: 999.000 ms; outcome=complete'),
        ):
            s.add(ai_runs.AIEvent(run_id=identifier, stage='timing_provider', message=message))
        s.commit()

    response = admin.get('/api/ai/triage/timings')
    assert response.status_code == 200
    data = response.json()
    assert data['sampled_runs'] == 3
    assert data['runs_without_samples'] == 1
    assert data['discarded_events'] == 3
    assert not data['events_truncated']
    assert data['stages']['provider'] == {
        'samples': 4, 'errors': 2, 'p50_ms': 10.0, 'p95_ms': 30.0,
    }
    for stage in ('ssh_evidence', 'file_provenance'):
        assert data['stages'][stage] == {
            'samples': 0, 'errors': 0, 'p50_ms': None, 'p95_ms': None,
        }
    assert '/private/evidence' not in response.text and 'private-key' not in response.text
    assert 'no-timings' not in response.text


def test_triage_timing_summary_bounds_runs_and_events(admin, monkeypatch):
    monkeypatch.setattr(ai_runs, 'TIMING_SUMMARY_EVENT_LIMIT', 2)
    with Session() as s:
        for identifier, finished in (('earlier', 1), ('latest', 2)):
            s.add(ai_runs.AIRun(id=identifier, purpose='triage', state='complete',
                                started=finished, finished=finished))
        for identifier, ms in (('earlier', 999), ('latest', 10), ('latest', 20), ('latest', 30)):
            s.add(ai_runs.AIEvent(run_id=identifier, stage='timing_queue_age',
                                  message=f'queue age: {ms}.000 ms; outcome=complete'))
        s.commit()

    response = admin.get('/api/ai/triage/timings', params={'limit': 1})
    assert response.status_code == 200
    data = response.json()
    assert data['sampled_runs'] == 1 and data['events_truncated']
    assert data['stages']['queue_age'] == {
        'samples': 2, 'errors': 0, 'p50_ms': 20.0, 'p95_ms': 30.0,
    }
    for limit in (0, 101):
        assert admin.get('/api/ai/triage/timings', params={'limit': limit}).status_code == 400


def test_timing_summary_samples_only_the_selected_activity(admin):
    with Session() as s:
        for identifier, purpose, finished in (
            ('triage-run', 'triage', 5),
            ('scoring-run', 'update_scoring', 6),
            ('scoring-failed', 'update_scoring', 7),
            ('scoring-running', 'update_scoring', 0),
        ):
            s.add(ai_runs.AIRun(id=identifier, purpose=purpose,
                                state='running' if not finished else ('error' if 'failed' in identifier else 'complete'),
                                started=finished, finished=finished, subject='/private/evidence'))
        for identifier, stage, message in (
            ('triage-run', 'provider', 'provider: 900.000 ms; outcome=complete'),
            ('triage-run', 'ssh_evidence', 'ssh evidence: 50.000 ms; outcome=complete'),
            ('scoring-run', 'provider', 'provider: 10.000 ms; outcome=complete'),
            ('scoring-run', 'result_persistence', 'result persistence: 2.000 ms; outcome=complete'),
            ('scoring-failed', 'provider', 'provider: 30.000 ms; outcome=error'),
            ('scoring-running', 'provider', 'provider: 999.000 ms; outcome=complete'),
        ):
            s.add(ai_runs.AIEvent(run_id=identifier, stage='timing_' + stage, message=message))
        s.commit()

    default = admin.get('/api/ai/triage/timings')
    triage = admin.get('/api/ai/triage/timings', params={'purpose': 'triage'})
    assert default.status_code == triage.status_code == 200
    assert default.json() == triage.json()
    assert triage.json()['purpose'] == 'triage' and triage.json()['sampled_runs'] == 1
    assert triage.json()['stages']['provider'] == {
        'samples': 1, 'errors': 0, 'p50_ms': 900.0, 'p95_ms': 900.0,
    }

    response = admin.get('/api/ai/triage/timings', params={'purpose': 'update_scoring'})
    assert response.status_code == 200
    data = response.json()
    assert data['purpose'] == 'update_scoring'
    assert data['sampled_runs'] == 2 and data['runs_without_samples'] == 0
    assert data['stages']['provider'] == {
        'samples': 2, 'errors': 1, 'p50_ms': 10.0, 'p95_ms': 30.0,
    }
    assert data['stages']['result_persistence']['samples'] == 1
    assert data['stages']['ssh_evidence'] == {
        'samples': 0, 'errors': 0, 'p50_ms': None, 'p95_ms': None,
    }
    assert '/private/evidence' not in response.text

    for purpose in ('', 'connection_test', 'worker', 'TRIAGE', 'update_scoring '):
        assert admin.get('/api/ai/triage/timings', params={'purpose': purpose}).status_code == 400


@pytest.mark.parametrize('purpose', ['triage', 'update_scoring'])
def test_timing_summary_keeps_selected_runs_and_events_on_one_snapshot(admin, purpose):
    with Session() as session:
        session.add_all([
            ai_runs.AIRun(id='timed', purpose=purpose, state='complete', started=1, finished=2),
            ai_runs.AIRun(id='untimed', purpose=purpose, state='complete', started=2, finished=3),
            ai_runs.AIEvent(run_id='timed', stage='timing_provider',
                            message='provider: 25.000 ms; outcome=complete'),
        ])
        session.commit()
    reads = []
    sqlite = engine.dialect.name == 'sqlite'

    def observe(_connection, _cursor, statement, _parameters, _context, _many):
        if not statement.lstrip().startswith(('SELECT', 'WITH')):
            return
        if 'FROM ai_runs' not in statement and 'FROM ai_events' not in statement:
            return
        reads.append(statement)
        if sqlite and len(reads) == 1:
            # Retention commits after the initial read starts. A second SQLite
            # read would see neither the sampled runs nor their timing events.
            with Session() as writer:
                ai_runs.prune_history(writer, 10)
                writer.commit()

    event.listen(engine, 'after_cursor_execute', observe)
    try:
        response = admin.get('/api/ai/triage/timings', params={'purpose': purpose, 'limit': 2})
    finally:
        event.remove(engine, 'after_cursor_execute', observe)
    assert response.status_code == 200
    summary = response.json()
    assert summary['sampled_runs'] == 2
    assert summary['runs_without_samples'] == 1
    assert summary['stages']['provider']['samples'] == 1
    assert len(reads) == 1
    if sqlite:
        later = admin.get('/api/ai/triage/timings', params={'purpose': purpose}).json()
        assert later['sampled_runs'] == 0


def test_timing_summary_rejects_unknown_purpose():
    with Session() as s, pytest.raises(ValueError):
        ai_runs.triage_timing_summary(s, 1, 'security_plan')
