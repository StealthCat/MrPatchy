"""Durable shared daily AI spend reservations, independent of diagnostic pruning."""
from datetime import datetime, time as day_time, timedelta, timezone
from decimal import Decimal, InvalidOperation
import time
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import String, Text, Double, Numeric, and_, case, func, or_, select
from sqlalchemy.orm import Mapped, mapped_column

from .coordination import Lock
from .db import Base, Session, config
from . import ai_pricing


class BudgetEntry(Base):
    __tablename__='ai_budget_entries'
    id: Mapped[str]=mapped_column(String(36),primary_key=True)
    run_id: Mapped[str]=mapped_column(String(36),default='',index=True)
    call_id: Mapped[str]=mapped_column(String(36),default='')
    created: Mapped[float]=mapped_column(Double,default=time.time,index=True)
    updated: Mapped[float]=mapped_column(Double,default=time.time)
    reset_at: Mapped[float]=mapped_column(Double,index=True)
    timezone: Mapped[str]=mapped_column(String(64))
    model: Mapped[str]=mapped_column(String(100))
    status: Mapped[str]=mapped_column(String(20),default='reserved')
    reservation_usd: Mapped[Decimal]=mapped_column(Numeric(18,6))
    actual_usd: Mapped[Decimal|None]=mapped_column(Numeric(18,9),nullable=True)
    pricing_version: Mapped[str]=mapped_column(String(30))
    pricing_source: Mapped[str]=mapped_column(String(200))
    reason: Mapped[str]=mapped_column(Text,default='Reserved before provider transmission.')


def valid_timezone(value):
    if not isinstance(value,str) or not 1<=len(value)<=64:return False
    try:ZoneInfo(value);return True
    except (ZoneInfoNotFoundError,ValueError):return False


def _window(now, name):
    zone=ZoneInfo(name)
    local=datetime.fromtimestamp(now,timezone.utc).astimezone(zone)
    start=datetime.combine(local.date(),day_time.min,tzinfo=zone).timestamp()
    reset=datetime.combine(local.date()+timedelta(days=1),day_time.min,tzinfo=zone).timestamp()
    return start,reset


def _money(value):
    value=Decimal(value or 0)
    rendered=format(value,'f')
    if '.' in rendered:rendered=rendered.rstrip('0').rstrip('.')
    return rendered if rendered and rendered!='-0' else '0'


def _aggregate(session,value):
    """Return an exact SQL aggregate without materializing ledger entries."""
    return (func.mrpatchy_money_sum(value,type_=String) if session.get_bind().dialect.name=='sqlite'
        else func.sum(value,type_=Numeric(38,9)))


def _window_start(reset_at,name):
    try:
        zone=ZoneInfo(name)
        reset_date=datetime.fromtimestamp(reset_at,timezone.utc).astimezone(zone).date()
        return datetime.combine(reset_date-timedelta(days=1),day_time.min,tzinfo=zone).timestamp()
    except (ZoneInfoNotFoundError,ValueError,OverflowError,OSError):
        # Keep a malformed retained group visible without inventing its local boundary.
        return None


def _state(session,cfg,now):
    mode=cfg['ai_control_mode'];enabled=mode in ai_pricing.CAP_MODES
    name=cfg['ai_budget_timezone'];start,reset=_window(now,name)
    groups={key:Decimal(0) for key in ('reserved','sent','settled','uncertain')};counted=Decimal(0)
    if enabled:
        # At most five result rows, regardless of receipt amounts or unknown statuses.
        # SQLite's exact aggregate preserves the previous nine-place Numeric reader;
        # MySQL performs the sum in native DECIMAL without a float intermediate.
        amount=case((and_(BudgetEntry.status=='settled',BudgetEntry.actual_usd.is_not(None)),BudgetEntry.actual_usd),else_=BudgetEntry.reservation_usd)
        bucket=case((BudgetEntry.status.in_(tuple(groups)),BudgetEntry.status),else_='other')
        total=_aggregate(session,amount)
        # A row also counts while the window it was admitted under (its own reset_at) is still
        # open, so changing the reset timezone cannot hand back spend from that window.
        query=select(bucket,total).where(or_(and_(BudgetEntry.created>=start,BudgetEntry.created<reset),
            and_(BudgetEntry.reset_at>now,BudgetEntry.created<=now)),BudgetEntry.status!='released').group_by(bucket)
        for key,value in session.execute(query):
            total=Decimal(value or 0);counted+=total
            if key in groups:groups[key]+=total
    # Settled rows count actual cost; every other unreleased row, including an unrecognized
    # status, counts its safe ceiling so unknown durable state never becomes zero spend.
    cap=Decimal(str(cfg['ai_daily_cap_usd']))
    return enabled,name,start,reset,groups,counted,cap


def waiting(session,now,payload=None,*,settings=None):
    """Read-only preflight; final atomic reserve still owns spending authority."""
    if settings is None:settings=config(session)
    enabled,_name,_start,reset,_groups,counted,cap=_state(session,settings,now)
    if not enabled:return 0
    if counted>=cap:return reset
    if payload is not None:
        quote=ai_pricing.reservation(payload)
        if not quote['ok'] or counted+quote['amount_usd']>cap:return reset
    return 0


def reserve(payload):
    """Atomically retain a conservative per-call amount before rate admission."""
    from .ai import AIError
    quote=ai_pricing.reservation(payload)
    with Lock('ai-shared-budget'):
        with Session() as session:
            cfg=config(session)
            if cfg['ai_control_mode'] not in ai_pricing.CAP_MODES:return None
            if not quote['ok']:
                raise AIError(quote['reason']+' Capped AI admission was blocked; no provider request was sent.')
            now=time.time();enabled,name,start,reset,groups,counted,cap=_state(session,cfg,now)
            amount=quote['amount_usd']
            if counted+amount>cap:
                raise AIError('The configured daily AI spend cap has no remaining safe reservation. No provider request was sent.',
                    policy_wait=True,retry_after=max(0,reset-now))
            from . import ai_runs
            row=BudgetEntry(id=str(uuid.uuid4()),run_id=ai_runs.active.get() or '',created=now,updated=now,
                reset_at=reset,timezone=name,model=quote['model'],reservation_usd=amount,
                pricing_version=quote['pricing_version'],pricing_source=quote['pricing_source'])
            session.add(row);session.commit();return row.id


def mark_sent(identifier,call_id):
    if not identifier:return
    with Lock('ai-shared-budget'):
        with Session() as session:
            row=session.get(BudgetEntry,identifier)
            if not row or row.status!='reserved':raise RuntimeError('AI budget reservation changed before provider transmission')
            row.status='sent';row.call_id=call_id or '';row.updated=time.time()
            row.reason='Provider transmission began; the reserved ceiling remains counted until reconciliation.'
            session.commit()


def release_unsent(identifier,reason):
    if not identifier:return
    with Lock('ai-shared-budget'):
        with Session() as session:
            row=session.get(BudgetEntry,identifier)
            if row and row.status=='reserved':
                row.status='released';row.updated=time.time();row.reason=str(reason)[:500];session.commit()


def reconcile(identifier,values):
    if not identifier:return
    with Lock('ai-shared-budget'):
        with Session() as session:
            row=session.get(BudgetEntry,identifier)
            if not row or row.status not in ('sent','uncertain'):return
            try:actual=Decimal(str((values.get('pricing') or {}).get('estimated_usd')))
            except (InvalidOperation,TypeError,ValueError):actual=None
            if values.get('status')=='estimated' and actual is not None and 0<=actual<=Decimal('1000000'):
                row.status='settled';row.actual_usd=actual
                row.reason='Reconciled to provider-reported usage using the retained public price snapshot; not an invoice.'
            else:
                row.status='uncertain';row.reason=str(values.get('reason') or 'Provider usage or pricing was unavailable; the full reservation remains counted.')[:500]
            row.updated=time.time();session.commit()


def mark_uncertain(identifier,reason):
    if not identifier:return
    with Lock('ai-shared-budget'):
        with Session() as session:
            row=session.get(BudgetEntry,identifier)
            if row and row.status=='sent':
                row.status='uncertain';row.updated=time.time();row.reason=str(reason)[:500];session.commit()


def status(session,now=None):
    now=time.time() if now is None else now;cfg=config(session)
    enabled,name,start,reset,groups,counted,cap=_state(session,cfg,now)
    # A transmitted call without a receipt is already uncertain, including after
    # another controller/worker observes it following a restart.
    uncertain=groups['sent']+groups['uncertain'];reserved=groups['reserved'];settled=groups['settled']
    return {'mode':cfg['ai_control_mode'],'enabled':enabled,'timezone':name,'cap_usd':_money(cap),
        'counted_usd':_money(counted),'settled_usd':_money(settled),'reserved_usd':_money(reserved),
        'uncertain_usd':_money(uncertain),'remaining_usd':_money(max(Decimal(0),cap-counted)),
        'next_reset':reset if enabled else None,'pricing_version':ai_pricing.VERSION,'pricing_source':ai_pricing.SOURCE,
        'pricing_catalog':ai_pricing.catalog_status(now)}


def history(session,days=30,now=None):
    """Return bounded aggregate spend windows from the retained accounting ledger."""
    if isinstance(days,bool) or not isinstance(days,int) or not 1<=days<=90:
        raise ValueError('AI spend history must cover 1 to 90 days')
    now=time.time() if now is None else now
    cutoff=now-days*86400
    # Four persisted reset/timezone combinations per requested day keeps configuration
    # churn bounded while still surfacing it. The explicit flag prevents silent omission.
    max_windows=min(360,days*4)
    amount=case((and_(BudgetEntry.status=='settled',BudgetEntry.actual_usd.is_not(None)),BudgetEntry.actual_usd),
        else_=BudgetEntry.reservation_usd)
    zero=Decimal(0)
    def bucket(*statuses):
        return _aggregate(session,case((BudgetEntry.status.in_(statuses),amount),else_=zero))
    recognized=('reserved','sent','settled','uncertain')
    other=_aggregate(session,case((~BudgetEntry.status.in_(recognized),amount),else_=zero))
    query=(select(BudgetEntry.timezone,BudgetEntry.reset_at,func.count(BudgetEntry.id).label('call_count'),
        bucket('settled').label('settled_usd'),bucket('reserved').label('reserved_usd'),
        bucket('sent').label('sent_usd'),bucket('uncertain').label('uncertain_usd'),
        other.label('other_usd'),_aggregate(session,amount).label('counted_usd'))
        .where(BudgetEntry.reset_at>cutoff,BudgetEntry.created<=now,BudgetEntry.status!='released')
        .group_by(BudgetEntry.timezone,BudgetEntry.reset_at)
        .order_by(BudgetEntry.reset_at.desc(),BudgetEntry.timezone.asc()).limit(max_windows+1))
    rows=session.execute(query).mappings().all()
    truncated=len(rows)>max_windows
    windows=[]
    for row in rows[:max_windows]:
        windows.append({'timezone':row['timezone'],'window_start':_window_start(row['reset_at'],row['timezone']),
            'reset_at':row['reset_at'],'call_count':row['call_count'],'settled_usd':_money(row['settled_usd']),
            'reserved_usd':_money(row['reserved_usd']),'sent_usd':_money(row['sent_usd']),
            'uncertain_usd':_money(row['uncertain_usd']),'other_usd':_money(row['other_usd']),
            'counted_usd':_money(row['counted_usd'])})
    return {'days':days,'generated_at':now,'cutoff':cutoff,'max_windows':max_windows,
        'truncated':truncated,'windows':windows}
