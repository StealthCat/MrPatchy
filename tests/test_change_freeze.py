import datetime as dt
import time

import pytest

from app import freezes, scheduling as sched, operations
from app.db import Session, Job, Setting


def stamp(text): return dt.datetime.fromisoformat(text).timestamp()


def store(rows):
    with Session() as s:
        s.merge(Setting(key=freezes.KEY,value={'freezes':rows}));s.commit()


def test_clean_requires_offsets_order_and_reason():
    ok={'start':'2026-12-24T18:00:00-05:00','end':'2026-12-26T06:00:00-05:00','reason':' Holiday freeze '}
    row=freezes.clean([ok],'alice')[0]
    assert row['start']==stamp('2026-12-24T23:00:00+00:00') and row['reason']=='Holiday freeze' and row['owner']=='alice'
    for bad in ({**ok,'start':'2026-12-24T18:00:00'},{**ok,'end':ok['start']},{**ok,'reason':'  '},{**ok,'extra':1},{'start':ok['start']},{**ok,'start':'nope'}):
        with pytest.raises(ValueError): freezes.clean([bad],'alice')
    with pytest.raises(ValueError): freezes.clean([ok]*51,'alice')


def test_boundaries_and_overlap_chain(admin):
    store([{'start':100,'end':200,'reason':'a','owner':'x'},{'start':150,'end':300,'reason':'b','owner':'x'}])
    with Session() as s:
        assert not freezes.blocked(s,99.9) and freezes.blocked(s,100) and freezes.blocked(s,299.9) and not freezes.blocked(s,300)
        assert freezes.clear_at(s,120)==300 and freezes.clear_at(s,300) is None


def test_freeze_blocks_urgent_bypass_and_manual_jobs(admin):
    now=time.time()
    policy={'critical':{'bypass_window':True,'after_minutes':0}}
    with Session() as s:
        assert sched.allow_window(s,'h',policy,'critical',now)
        job=Job(id='job1',host_id='h',action='patch',payload={},state='queued');s.add(job);s.commit()
        assert operations.eligible(s,job)
    store([{'start':now-60,'end':now+3600,'reason':'freeze','owner':'x'}])
    with Session() as s:
        assert not sched.allow_window(s,'h',policy,'critical',now)
        assert not operations.eligible(s,s.get(Job,'job1'))
    store([{'start':now-7200,'end':now-3600,'reason':'expired','owner':'x'}])
    with Session() as s:
        assert sched.allow_window(s,'h',policy,'critical',now) and operations.eligible(s,s.get(Job,'job1'))


def test_api_roundtrip_audit_and_validation(admin):
    now=time.time()
    start=dt.datetime.fromtimestamp(now-60,dt.timezone.utc).isoformat()
    end=dt.datetime.fromtimestamp(now+3600,dt.timezone.utc).isoformat()
    assert admin.put('/api/operations/freezes',json={'freezes':[{'start':start,'end':'2026-01-01T00:00:00'}]}).status_code==400
    result=admin.put('/api/operations/freezes',json={'freezes':[{'start':start,'end':end,'reason':'Quarter close'}]})
    assert result.status_code==200
    body=admin.get('/api/operations/freezes').json()
    assert len(body['active'])==1 and body['clear_at']==pytest.approx(now+3600,abs=2) and body['freezes'][0]['owner']
    assert 'blocks' in body['precedence']
    assert any(a['action']=='change freezes' for a in admin.get('/api/audit').json())
