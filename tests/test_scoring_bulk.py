"""Scoring idle fleets must use bounded SQL round trips, without changing eligibility."""
import hashlib
import time
import pytest
from sqlalchemy import event,select
from app import ai,ai_policy,ai_runs,update_scores
from app.db import Session,Host,Package,Setting,engine
from app.security import seal


def seed(count,state='complete',completed=None):
    now=time.time()
    with Session() as s:
        hosts=[Host(id='bulk-'+str(i),name='Fixture',address='192.0.2.1',fingerprint='',inventory={'os':'ID=debian\nVERSION_ID=12'}) for i in range(2)]
        s.add_all(hosts)
        s.merge(Setting(key='config',value={'ai_enabled':True,'ai_updates_enabled':True,'ai_model':'fixture','ai_control_mode':'unthrottled'}))
        s.merge(Setting(key='openai_key',value={'encrypted':seal('fixture-key')}))
        packages=[Package(id=hosts[i%2].id+':pkg'+str(i//2).zfill(4),host_id=hosts[i%2].id,name='pkg'+str(i//2).zfill(4),installed='1',candidate='2',available_since=now-10000+i) for i in range(count)]
        s.add_all(packages);s.flush()
        for i,p in enumerate(packages):
            if completed is not None and i>=completed:continue
            s.add(update_scores.UpdateScore(id=update_scores.identity(hosts[i%2],p),host_id=p.host_id,name=p.name,installed='1',candidate='2',state=state,score=50 if state=='complete' else None,attempted=now-7000,next_at=now+600 if state=='deferred' else 0))
        s.commit()
        return [p.id for p in packages]


def measure(monkeypatch):
    statements=[]
    def observe(conn,cursor,statement,parameters,context,executemany):
        if statement.lstrip().upper().startswith('SELECT'):statements.append(statement)
    monkeypatch.setattr(ai,'request',lambda *a,**k:pytest.fail('Completed/deferred fleet must not call provider'))
    event.listen(engine,'before_cursor_execute',observe)
    started=time.perf_counter()
    try:update_scores.run_one()
    finally:event.remove(engine,'before_cursor_execute',observe)
    return len(statements),time.perf_counter()-started


def capture_assessments(monkeypatch):
    sent=[]
    def assess(payload,key):
        import json
        batch=json.loads(payload['input']);sent.extend(batch)
        return {'assessments':[{'id':r['id'],'score':50,'confidence':'low','explanation':'Fixture','limitations':'No advisory verification'} for r in batch]}
    monkeypatch.setattr(ai,'request',assess)
    return sent


@pytest.mark.parametrize('count',[100,1000])
@pytest.mark.parametrize('state',['complete','deferred'])
def test_idle_fleet_selects_scale_by_chunks_not_packages(admin,monkeypatch,count,state):
    seed(count,state)
    queries,elapsed=measure(monkeypatch)
    print(f'{count} {state} candidates: {queries} SELECTs, {elapsed:.4f}s')
    assert queries<=12+4*((count+199)//200),f'{queries} SELECTs for {count} idle candidates'
    with Session() as s:
        rows=list(s.scalars(select(update_scores.UpdateScore)))
        assert len(rows)==count and all(r.state==state for r in rows)
        assert not list(s.scalars(select(ai_runs.AIRun)))


def test_complete_current_scores_still_supersede_changed_deferred_history(admin,monkeypatch):
    seed(450)
    with Session() as s:
        current=list(s.scalars(select(update_scores.UpdateScore)))
        for row in current:
            s.add(update_scores.UpdateScore(id=hashlib.sha256(('stale'+row.id).encode()).hexdigest(),host_id=row.host_id,name=row.name,installed='0',candidate='1',state='deferred',next_at=time.time()+10000))
        s.commit()
    queries,_=measure(monkeypatch)
    assert queries<30
    with Session() as s:
        rows=list(s.scalars(select(update_scores.UpdateScore)))
        assert sum(r.state=='complete' for r in rows)==450
        assert sum(r.state=='superseded' and r.next_at==0 for r in rows)==450


@pytest.mark.parametrize('count,completed',[(513,505),(1000,0)])
def test_new_candidates_after_multiple_completed_chunks_keep_oldest_order_and_batch_limit(admin,monkeypatch,count,completed):
    ids=seed(count,completed=completed);sent=capture_assessments(monkeypatch)
    update_scores.run_one()
    with Session() as s:
        expected=[update_scores.identity(s.get(Host,s.get(Package,p).host_id),s.get(Package,p)) for p in ids[completed:completed+5]]
        assert [r['id'] for r in sent]==expected
        assert all(s.get(update_scores.UpdateScore,identifier).state=='complete' for identifier in expected)
        last=s.get(Package,ids[-1])
        assert s.get(update_scores.UpdateScore,update_scores.identity(s.get(Host,last.host_id),last)) is None


def test_due_deferred_items_across_chunk_boundaries_are_not_starved(admin,monkeypatch):
    ids=seed(513,'deferred');due=[199,200,399,400,512];expected=[]
    with Session() as s:
        for i in due:
            p=s.get(Package,ids[i]);key=update_scores.identity(s.get(Host,p.host_id),p)
            expected.append(key);s.get(update_scores.UpdateScore,key).next_at=time.time()-1
        s.commit()
    sent=capture_assessments(monkeypatch);update_scores.run_one()
    assert [row['id'] for row in sent]==expected
    with Session() as s:
        assert sum(row.state=='deferred' for row in s.scalars(select(update_scores.UpdateScore)))==508


def test_equal_age_candidates_keep_id_tiebreak_order_across_chunks(admin,monkeypatch):
    seed(413,completed=405)
    with Session() as s:
        for p in s.scalars(select(Package)):p.available_since=1000
        s.commit()
        ordered=list(s.scalars(select(Package).order_by(Package.id)))
        expected=[]
        for p in ordered:
            key=update_scores.identity(s.get(Host,p.host_id),p)
            if not s.get(update_scores.UpdateScore,key):expected.append(key)
        expected=expected[:5]
    sent=capture_assessments(monkeypatch);update_scores.run_one()
    assert [row['id'] for row in sent]==expected


def test_paused_and_inactive_hosts_stay_out_of_scoring_and_stale_supersession(admin,monkeypatch):
    seed(450,'deferred')
    with Session() as s:
        s.add(Setting(key='server-ai:bulk-0',value={'paused':True}))
        s.get(Host,'bulk-1').enabled=False
        s.commit()
    measure(monkeypatch)
    with Session() as s:
        assert all(r.state=='deferred' for r in s.scalars(select(update_scores.UpdateScore)))
        assert ai_policy.status(s,'bulk-0')['paused']
