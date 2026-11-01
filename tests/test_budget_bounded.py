from decimal import Decimal

from app import ai_budget
from app.db import Session, config
from test_ai_budget import configure


def test_distinct_receipts_return_bounded_totals(admin, monkeypatch):
    import time
    configure(cap=Decimal('100'))
    now=time.time()
    with Session() as session:
        session.add_all(ai_budget.BudgetEntry(id=str(i), created=now, updated=now,
            reset_at=now+3600, timezone='UTC', model='fixture', status='settled',
            reservation_usd=Decimal('1'), actual_usd=Decimal(i+1)/Decimal('1000000000'),
            pricing_version='fixture', pricing_source='fixture') for i in range(1000))
        session.commit()
    rows=[]
    with Session() as session:
        execute=session.execute
        def observed(statement, *args, **kwargs):
            result=execute(statement, *args, **kwargs)
            if 'ai_budget_entries' in str(statement):
                values=result.all(); rows.extend(values); return values
            return result
        monkeypatch.setattr(session, 'execute', observed)
        state=ai_budget._state(session, config(session), now)
    assert state[5]==Decimal('0.000500500')
    assert len(rows)<=5, f'Aggregation returned {len(rows)} ledger groups'


def test_mixed_and_unknown_totals_match_retained_numeric_values(admin):
    import time
    from sqlalchemy import event, select
    configure(cap=Decimal('1000000'))
    now=time.time()
    statuses=['reserved', 'sent', 'settled', 'uncertain', 'released']
    with Session() as session:
        session.add_all(ai_budget.BudgetEntry(id=str(i), created=now, updated=now,
            reset_at=now+3600, timezone='UTC', model='fixture',
            status=statuses[i%7] if i%7<5 else 'unknown-'+str(i),
            reservation_usd=Decimal('0.123456'),
            actual_usd=(None if i%3==0 else Decimal('1000000.123456789')+Decimal(i)/10**9),
            pricing_version='fixture', pricing_source='fixture') for i in range(700))
        session.commit()
        # Independent reference uses the old Numeric reader, including SQLite's
        # storage precision; summation must not introduce further float error.
        expected={k:Decimal(0) for k in statuses}; counted=Decimal(0)
        for row in session.scalars(select(ai_budget.BudgetEntry)):
            if row.status=='released':continue
            value=row.actual_usd if row.status=='settled' and row.actual_usd is not None else row.reservation_usd
            counted+=value
            if row.status in expected:expected[row.status]+=value
    loaded=[]
    def observe(*args):loaded.append(1)
    event.listen(ai_budget.BudgetEntry, 'load', observe)
    try:
        with Session() as session:
            state=ai_budget._state(session, config(session), now)
    finally:event.remove(ai_budget.BudgetEntry, 'load', observe)
    assert not loaded
    assert state[5]==counted
    assert state[4]=={k:expected[k] for k in ('reserved','sent','settled','uncertain')}


def test_large_ledger_parallel_cap_admission_is_still_atomic(admin, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    import time
    from app import ai
    from test_ai_budget import payload
    configure(cap=Decimal('1'))
    now=time.time()
    with Session() as session:
        session.add_all(ai_budget.BudgetEntry(id=str(i), created=now, updated=now,
            reset_at=now+3600, timezone='UTC', model='fixture', status='settled',
            reservation_usd=Decimal('0.01'), actual_usd=Decimal('0.00099'),
            pricing_version='fixture', pricing_source='fixture') for i in range(1000))
        session.commit()
    quote={'ok':True,'amount_usd':Decimal('0.01'),'model':'fixture',
        'pricing_version':'fixture','pricing_source':'fixture'}
    monkeypatch.setattr(ai_budget.ai_pricing, 'reservation', lambda _:quote)
    barrier=threading.Barrier(8)
    def attempt(_):
        barrier.wait(timeout=10)
        try:return ai_budget.reserve(payload())
        except ai.AIError:return None
    with ThreadPoolExecutor(max_workers=8) as pool: results=list(pool.map(attempt, range(8)))
    assert sum(x is not None for x in results)==1
    with Session() as session:
        state=ai_budget.status(session, now)
    assert state['counted_usd']=='1'
    assert state['remaining_usd']=='0'
