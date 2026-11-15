"""Investigations list filter for verdicts reused from the fleet known-good cache (#924)."""
from app import ai_assessments
from app.db import Session, Behavior, Host
from app.main import investigations


def hit(source='source-assessment'):
    return {'result':{'risk':'low','explanation':'Source assessment','recommended_checks':'None'},
        'fingerprint':'f'*64,'assessment_id':source,'source_subject':'source',
        'source_host_id':'other','created':1700000000.0,'model':'fixture','policy_hash':'p'*64}


def behavior(id,host='host',seen=0.0,verdict='low'):
    return Behavior(id=id,host_id=host,evidence={'executable':'/srv/'+id,'sha256':'a'*64},verdict=verdict,
        analysis='Source assessment\n\nRecommended checks: None',first_seen=seen,last_seen=seen)


def setup_rows(reused=5,fresh=3):
    with Session() as s:
        s.add(Host(id='host',name='Fixture',address='192.0.2.1',fingerprint=''))
        s.add(Host(id='other',name='Other',address='192.0.2.2',fingerprint=''))
        rows=[]
        for i in range(reused):
            row=behavior(f'r{i}',seen=1000.0-i*2);s.add(row);rows.append(('reuse',row))
        for i in range(fresh):
            row=behavior(f'f{i}',seen=999.0-i*2);s.add(row);rows.append(('fresh',row))
        s.add(behavior('pending',verdict='pending',seen=2000.0))
        s.flush()
        for kind,row in rows:
            if kind=='reuse':ai_assessments.record_reuse(s,row,hit())
            else:ai_assessments.record(s,row,'fixture',{'risk':'low','explanation':'Fresh'},[])
        s.commit()


def ids(client,query=''):
    response=client.get('/api/investigations'+query)
    assert response.status_code==200,response.text
    return [r['id'] for r in response.json()]


def test_filter_lists_only_cached_rows_in_list_order(admin):
    setup_rows()
    everything=ids(admin)
    assert len(everything)==9
    cached=ids(admin,'?cached=true')
    assert cached==[i for i in everything if i.startswith('r')]==['r0','r1','r2','r3','r4']
    listed={r['id']:r for r in admin.get('/api/investigations?cached=true').json()}
    assert all(r['known_good_reuse']['cached'] is True for r in listed.values())
    # The default view is unchanged.
    assert ids(admin,'?cached=false')==everything


def test_offset_and_limit_count_filtered_rows(admin):
    setup_rows()
    assert ids(admin,'?cached=true&offset=0&limit=2')==['r0','r1']
    assert ids(admin,'?cached=true&offset=2&limit=2')==['r2','r3']
    assert ids(admin,'?cached=true&offset=4&limit=2')==['r4']
    assert ids(admin,'?cached=true&offset=5&limit=2')==[]


def test_superseded_changed_or_retriaged_rows_are_excluded(admin):
    setup_rows()
    with Session() as s:
        ai_assessments.record(s,s.get(Behavior,'r0'),'fixture',{'risk':'low','explanation':'Newer'},[])
        s.get(Behavior,'r1').analysis='Changed analysis'
        row=s.get(Behavior,'r2')
        ai_assessments.queue(s,row,ai_assessments.revision(row),'Refresh','admin',False)
        s.commit()
    assert ids(admin,'?cached=true')==['r3','r4']
    assert ids(admin,'?cached=true&offset=1&limit=1')==['r4']


def test_scan_spans_chunks_without_skipping_rows(admin,monkeypatch):
    monkeypatch.setattr(ai_assessments,'REUSE_SCAN_CHUNK',2)
    setup_rows(reused=7,fresh=0)
    with Session() as s:
        # Superseded rows fall inside a chunk, so confirmation must continue into the next chunk.
        for i in (1,2,5):ai_assessments.record(s,s.get(Behavior,f'r{i}'),'fixture',{'risk':'low','explanation':'Newer'},[])
        s.commit()
    assert ids(admin,'?cached=true')==['r0','r3','r4','r6']
    assert ids(admin,'?cached=true&offset=1&limit=2')==['r3','r4']
    assert ids(admin,'?cached=true&offset=3&limit=2')==['r6']


def test_host_scope_inactive_servers_and_roles(admin):
    setup_rows(reused=2,fresh=1)
    with Session() as s:
        other=behavior('o0',host='other',seen=5000.0);s.add(other);s.flush()
        ai_assessments.record_reuse(s,other,hit());s.commit()
    assert ids(admin,'?cached=true')==['o0','r0','r1']
    assert ids(admin,'?host_id=host&cached=true')==['r0','r1']
    assert ids(admin,'?host_id=other&cached=true')==['o0']
    with Session() as s:
        import time
        s.get(Host,'other').deleted_at=time.time();s.commit()
    assert ids(admin,'?cached=true')==['r0','r1']
    viewer={r['id']:r for r in investigations(host_id='host',cached=True,user={'role':'viewer'})}
    assert list(viewer)==['r0','r1']
    assert all(r['known_good_reuse']=={'cached':True} for r in viewer.values())


def test_invalid_pagination_still_rejected(admin):
    assert admin.get('/api/investigations?cached=true&offset=-1').status_code==400
    assert admin.get('/api/investigations?cached=true&limit=0').status_code==400
