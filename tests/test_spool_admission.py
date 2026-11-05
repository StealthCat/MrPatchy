"""Pure spool admission contract (issue #107 first slice)."""
import pytest
from app import spool_admission as sa

CAP=1000
BASE=dict(logical_bytes=100,physical_bytes=150,capacity_bytes=CAP,free_disk_bytes=10_000,reserve_bytes=500)


def run(size=10,priority='normal',**over):
    return sa.admit(size,priority,**{**BASE,**over})


def test_admits_when_healthy():
    assert run()=={'decision':'admit','reason':None,'pressure':'ok','counted_loss':False}


def test_pressure_uses_physical_when_larger():
    assert sa.pressure(100,750,CAP)=='warning'
    assert sa.pressure(100,900,CAP)=='critical'
    assert sa.pressure(100,100,0)=='unavailable'


def test_free_space_reserve_blocks_even_under_nominal_cap():
    r=run(size=10,overhead_bytes=10,free_disk_bytes=519)
    assert (r['decision'],r['reason'])==('refuse','free_space_reserve')
    assert run(size=10,overhead_bytes=10,free_disk_bytes=520)['decision']=='admit'


def test_physical_overhead_counts_against_capacity():
    r=run(size=10,overhead_bytes=100,physical_bytes=895,logical_bytes=0)
    assert r['reason']=='capacity'


def test_critical_pressure_only_admits_security():
    over=dict(physical_bytes=900,logical_bytes=900)
    assert run(priority='security',**over)['decision']=='admit'
    for p in ('normal','low'):
        assert run(priority=p,**over)['reason']=='critical_pressure'


def test_oversize_and_invalid_inputs_refuse():
    assert run(size=11,max_record_bytes=10)['reason']=='oversize'
    for bad in (dict(priority='urgent'),dict(size=-1),dict(size=True),dict(size=float('nan')),dict(capacity_bytes=0),dict(max_record_bytes='x')):
        assert run(**bad)['reason']=='invalid'


def test_loss_ledger_accumulates_without_mutating_and_keeps_epoch():
    first={'epoch':'e1','by_reason':{},'by_priority':{}}
    d=run(priority='low',physical_bytes=950)
    out=sa.loss_ledger(first,d,'low',3)
    assert out=={'epoch':'e1','by_reason':{'critical_pressure':3},'by_priority':{'low':3}}
    assert first['by_reason']=={}
    assert sa.loss_ledger(out,run(),'normal')==out
    assert sa.loss_ledger(None,d,'low')['epoch']=='unknown'
