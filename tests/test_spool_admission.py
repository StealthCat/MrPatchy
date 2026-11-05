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


def test_lower_priority_record_cannot_cross_into_critical_headroom():
    # Review regression: warning-level occupancy, a normal record that would
    # fill the spool must be refused so security records keep the headroom.
    over=dict(logical_bytes=890,physical_bytes=890,free_disk_bytes=5_000,reserve_bytes=500)
    r=run(size=110,priority='normal',**over)
    assert (r['decision'],r['reason'],r['pressure'])==('refuse','critical_pressure','warning')
    assert run(size=110,priority='low',**over)['reason']=='critical_pressure'
    # The same-sized security record stays eligible when capacity and reserve permit.
    assert run(size=110,priority='security',**over)['decision']=='admit'
    # And after the refused normal record, a 1-byte security record is still admitted.
    assert run(size=1,priority='security',**over)['decision']=='admit'


def test_projected_physical_pressure_includes_overhead():
    # Logical stays well below critical, but record + journal overhead pushes
    # physical use from warning to critical.
    over=dict(logical_bytes=100,physical_bytes=800,overhead_bytes=90)
    assert run(size=20,priority='normal',**over)['reason']=='critical_pressure'
    assert run(size=20,priority='security',**over)['decision']=='admit'
    # Staying below the critical threshold after the append is still admitted.
    assert run(size=5,priority='normal',logical_bytes=100,physical_bytes=800,overhead_bytes=90)['decision']=='admit'


def test_loss_counters_stay_monotonic_and_saturate_at_limit():
    start={'epoch':'e1','by_reason':{'critical_pressure':2**53-1},'by_priority':{'low':2**53-1}}
    d=run(priority='low',physical_bytes=950)
    one=sa.loss_ledger(start,d,'low')
    assert one['by_reason']['critical_pressure']==sa.COUNTER_MAX
    assert one['by_priority']['low']==sa.COUNTER_MAX
    assert one['saturated'] is True
    two=sa.loss_ledger(one,d,'low')
    three=sa.loss_ledger(two,d,'low',5)
    for led in (two,three):
        assert led['by_reason']['critical_pressure']==sa.COUNTER_MAX
        assert led['by_priority']['low']==sa.COUNTER_MAX
        assert led['saturated'] is True and led['epoch']=='e1'
    # A counter already beyond the bound is clamped, never reset to the increment.
    beyond={'epoch':'e1','by_reason':{'critical_pressure':2**53+1},'by_priority':{'low':2**60}}
    out=sa.loss_ledger(beyond,d,'low')
    assert out['by_reason']['critical_pressure']==sa.COUNTER_MAX
    assert out['by_priority']['low']==sa.COUNTER_MAX
    # Admitted decisions keep the saturation marker unchanged.
    assert sa.loss_ledger(three,run(),'normal')==three


def test_loss_counters_below_limit_still_accumulate_exactly():
    led={'epoch':'e2','by_reason':{'capacity':2**52},'by_priority':{'normal':2**52}}
    d=run(size=10,logical_bytes=995)
    assert d['reason']=='capacity'
    out=sa.loss_ledger(led,d,'normal',7)
    assert out['by_reason']['capacity']==2**52+7
    assert out['by_priority']['normal']==2**52+7
    assert 'saturated' not in out
