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


def _state(session,cfg,now):
    mode=cfg['ai_control_mode'];enabled=mode in ai_pricing.CAP_MODES
    name=cfg['ai_budget_timezone'];start,reset=_window(now,name)
    groups={key:Decimal(0) for key in ('reserved','sent','settled','uncertain')};counted=Decimal(0)
    if enabled:
        # Group by status and per-row amount in SQL so the ledger is never loaded row by row;
        # exact Decimal(amount)*count keeps the sums exact on SQLite and MySQL.
        amount=case((and_(BudgetEntry.status=='settled',BudgetEntry.actual_usd.is_not(None)),BudgetEntry.actual_usd),else_=BudgetEntry.reservation_usd)
        # A row also counts while the window it was admitted under (its own reset_at) is still
        # open, so changing the reset timezone cannot hand back spend from that window.
        query=select(BudgetEntry.status,amount,func.count()).where(or_(and_(BudgetEntry.created>=start,BudgetEntry.created<reset),
            and_(BudgetEntry.reset_at>now,BudgetEntry.created<=now)),BudgetEntry.status!='released').group_by(BudgetEntry.status,amount)
        for key,value,count in session.execute(query):
            total=Decimal(value or 0)*count;counted+=total
            if key in groups:groups[key]+=total
    # Settled rows count actual cost; every other unreleased row, including an unrecognized
    # status, counts its safe ceiling so unknown durable state never becomes zero spend.
    cap=Decimal(str(cfg['ai_daily_cap_usd']))
    return enabled,name,start,reset,groups,counted,cap


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
        'next_reset':reset if enabled else None,'pricing_version':ai_pricing.VERSION,'pricing_source':ai_pricing.SOURCE}
