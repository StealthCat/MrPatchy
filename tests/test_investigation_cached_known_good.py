"""Investigations list marks verdicts reused from the fleet known-good cache (#897)."""
from app import ai_assessments
from app.db import Session, Behavior, Host
from app.main import investigations


def hit():
    return {'result':{'risk':'low','explanation':'Source assessment','recommended_checks':'None'},
        'fingerprint':'f'*64,'assessment_id':'source-assessment','source_subject':'source',
        'source_host_id':'other','created':1700000000.0,'model':'fixture','policy_hash':'p'*64}


def setup_rows():
    with Session() as s:
        s.add(Host(id='host',name='Fixture',address='192.0.2.1',fingerprint=''))
        s.add(Host(id='other',name='Other',address='192.0.2.2',fingerprint=''))
        reused=Behavior(id='reused',host_id='host',evidence={'executable':'/srv/a','sha256':'a'*64},
            verdict='low',analysis='Source assessment\n\nRecommended checks: None')
        fresh=Behavior(id='fresh',host_id='host',evidence={'executable':'/srv/b','sha256':'b'*64},
            verdict='low',analysis='Fresh provider result')
        s.add_all([reused,fresh]);s.flush()
        ai_assessments.record_reuse(s,reused,hit())
        ai_assessments.record(s,fresh,'fixture',{'risk':'low','explanation':'Fresh provider result'},[])
        s.commit()


def rows(client):
    return {r['id']:r for r in client.get('/api/investigations').json()}


def test_admin_sees_cached_mark_and_source_links(admin):
    setup_rows()
    listed=rows(admin)
    assert listed['fresh']['known_good_reuse'] is None
    mark=listed['reused']['known_good_reuse']
    assert mark['cached'] is True and mark['source_assessment_id']=='source-assessment'
    assert mark['source_subject']=='source' and mark['source_created']==1700000000.0
    assert isinstance(mark['assessment_id'],str) and 'source_host_id' not in mark


def test_non_admin_receives_only_the_flag(admin):
    setup_rows()
    listed={r['id']:r for r in investigations(user={'role':'viewer'})}
    assert listed['reused']['known_good_reuse']=={'cached':True}
    assert listed['fresh']['known_good_reuse'] is None


def test_mark_tracks_only_the_current_state(admin):
    setup_rows()
    # A later provider assessment of the same exact state supersedes the reuse.
    with Session() as s:
        row=s.get(Behavior,'reused')
        ai_assessments.record(s,row,'fixture',{'risk':'low','explanation':'Newer'},[])
        s.commit()
    assert rows(admin)['reused']['known_good_reuse'] is None


def test_changed_state_or_retriage_clears_the_mark(admin):
    setup_rows()
    with Session() as s:
        s.get(Behavior,'reused').analysis='Changed analysis';s.commit()
    assert rows(admin)['reused']['known_good_reuse'] is None
    with Session() as s:
        s.get(Behavior,'reused').analysis='Source assessment\n\nRecommended checks: None';s.commit()
    assert rows(admin)['reused']['known_good_reuse']['cached'] is True
    with Session() as s:
        row=s.get(Behavior,'reused')
        ai_assessments.queue(s,row,ai_assessments.revision(row),'Refresh','admin',False)
        s.commit()
    assert rows(admin)['reused']['known_good_reuse'] is None


def test_lookup_is_batched(admin):
    setup_rows()
    from sqlalchemy import event
    from app.db import engine
    statements=[]
    listener=lambda *args:statements.append(args[2])
    event.listen(engine,'before_cursor_execute',listener)
    try:
        with Session() as s:
            page=list(s.query(Behavior))
            ai_assessments.current_reuse(s,page,include_source=False)
            assessment_reads=[q for q in statements if 'ai_behavior_assessments' in q]
            assert len(assessment_reads)==1
            statements.clear()
            ai_assessments.current_reuse(s,page,include_source=True)
            assert len([q for q in statements if 'ai_behavior_assessments' in q])==2
    finally:
        event.remove(engine,'before_cursor_execute',listener)
