import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy import select
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
    for name in ('admission','queue_age','run','result_persistence'):assert values.count(name)==1
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
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:identifiers=list(pool.map(run,range(4)))
        for identifier in identifiers:
            detail,values=stages(admin,identifier)
            assert values==['provider','run'] and detail['calls']==0
        assert ai_runs.active.get() is None
    finally:
        # Restore fresh schema caches for later destructive SQLite DDL fixtures.
        engine.dispose()


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
