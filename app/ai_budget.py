"""Durable shared daily AI spend reservations, independent of diagnostic pruning."""
from datetime import datetime, time as day_time, timedelta, timezone
from decimal import Decimal, InvalidOperation
import hashlib
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


def _state(session,cfg,now,*,include_reconciliation=False):
    mode=cfg['ai_control_mode'];enabled=mode in ai_pricing.CAP_MODES
    name=cfg['ai_budget_timezone'];start,reset=_window(now,name)
    groups={key:Decimal(0) for key in ('reserved','sent','settled','uncertain')};counted=Decimal(0)
    unreconciled_count=0
    oldest_reservation=None
    if enabled:
        # At most five result rows, regardless of receipt amounts or unknown statuses.
        # SQLite's exact aggregate preserves the previous nine-place Numeric reader;
        # MySQL performs the sum in native DECIMAL without a float intermediate.
        amount=case((and_(BudgetEntry.status=='settled',BudgetEntry.actual_usd.is_not(None)),BudgetEntry.actual_usd),else_=BudgetEntry.reservation_usd)
        bucket=case((BudgetEntry.status.in_(tuple(groups)),BudgetEntry.status),else_='other')
        total=_aggregate(session,amount)
        # A row also counts while the window it was admitted under (its own reset_at) is still
        # open, so changing the reset timezone cannot hand back spend from that window.
        metrics=(func.count(),func.min(BudgetEntry.created)) if include_reconciliation else ()
        query=select(bucket,total,*metrics).where(or_(and_(BudgetEntry.created>=start,BudgetEntry.created<reset),
            and_(BudgetEntry.reset_at>now,BudgetEntry.created<=now)),BudgetEntry.status!='released').group_by(bucket)
        for key,value,*summary in session.execute(query):
            total=Decimal(value or 0);counted+=total
            if key in groups:groups[key]+=total
            if summary and key in ('sent','uncertain'):
                call_count,oldest=summary
                unreconciled_count+=call_count
                if oldest is not None and (oldest_reservation is None or oldest<oldest_reservation):
                    oldest_reservation=oldest
    # Settled rows count actual cost; every other unreleased row, including an unrecognized
    # status, counts its safe ceiling so unknown durable state never becomes zero spend.
    cap=Decimal(str(cfg['ai_daily_cap_usd']))
    return enabled,name,start,reset,groups,counted,cap,(unreconciled_count,oldest_reservation)


def waiting(session,now,payload=None,*,settings=None):
    """Read-only preflight; final atomic reserve still owns spending authority."""
    if settings is None:settings=config(session)
    enabled,_name,_start,reset,_groups,counted,cap,_reconciliation=_state(session,settings,now)
    if not enabled:return 0
    if counted>=cap:return reset
    if payload is not None:
        quote=ai_pricing.reservation(payload)
        if not quote['ok'] or counted+quote['amount_usd']>cap:return reset
    return 0


def reserve(payload):
    """Atomically retain a conservative per-call amount before rate admission."""
    from .ai import AIError
    with Session() as session:
        if config(session)['ai_control_mode'] not in ai_pricing.CAP_MODES:
            return None

    with Lock('ai-shared-budget'):
        # Read again after waiting: the preflight does not authorize a capped reservation.
        with Session() as session:
            cfg=config(session)
            if cfg['ai_control_mode'] not in ai_pricing.CAP_MODES:return None
            quote=ai_pricing.reservation(payload)
            if not quote['ok']:
                raise AIError(quote['reason']+' Capped AI admission was blocked; no provider request was sent.')
            now=time.time();enabled,name,start,reset,groups,counted,cap,_reconciliation=_state(session,cfg,now)
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


def release_unsent(identifier,reason,*,pool_timeout_call_id=None):
    """Release before transmission, or after a matching pool acquisition failure."""
    if not identifier:return
    with Lock('ai-shared-budget'):
        with Session() as session:
            row=session.get(BudgetEntry,identifier)
            if not row:return
            if pool_timeout_call_id is None:
                unsent=row.status=='reserved'
            else:
                unsent=row.status=='sent' and row.call_id==pool_timeout_call_id
            if unsent:
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
    enabled,name,start,reset,groups,counted,cap,reconciliation=_state(session,cfg,now,include_reconciliation=True)
    unreconciled_count,oldest=reconciliation
    # A timezone change can leave a previously admitted window open beyond the
    # configured reset.  In that case the configured boundary is useful for a
    # recheck, but it cannot promise that recorded headroom will be available.
    amount=case((and_(BudgetEntry.status=='settled',BudgetEntry.actual_usd.is_not(None)),BudgetEntry.actual_usd),
        else_=BudgetEntry.reservation_usd)
    overlapping=(enabled and session.scalar(select(BudgetEntry.id).where(
        BudgetEntry.reset_at>reset,BudgetEntry.created<=now,BudgetEntry.status!='released',amount>0).limit(1)) is not None)
    # A transmitted call without a receipt is already uncertain, including after
    # another controller/worker observes it following a restart.
    uncertain=groups['sent']+groups['uncertain'];reserved=groups['reserved'];settled=groups['settled']
    return {'mode':cfg['ai_control_mode'],'enabled':enabled,'timezone':name,'cap_usd':_money(cap),
        'counted_usd':_money(counted),'settled_usd':_money(settled),'reserved_usd':_money(reserved),
        'uncertain_usd':_money(uncertain),'remaining_usd':_money(max(Decimal(0),cap-counted)),
        'unreconciled_call_count':unreconciled_count,'oldest_unreconciled_reservation_at':oldest,
        'next_reset':reset if enabled else None,'next_reset_authoritative':enabled and not overlapping,
        'pricing_version':ai_pricing.VERSION,'pricing_source':ai_pricing.SOURCE,
        'pricing_catalog':ai_pricing.catalog_status(now)}


DAILY_CAP_NOTIFICATION=dict(source='ai-budget',kind='daily-cap',subject_type='daily-cap',subject_id='shared-daily-ai-spend')
DAILY_CAP_WARNING_NOTIFICATION=dict(source='ai-budget',kind='daily-cap-warning',subject_type='daily-cap',subject_id='shared-daily-ai-spend')
# Fixed advance-warning fraction of the cap; configurable thresholds are not yet offered.
DAILY_CAP_WARNING_FRACTION=Decimal('0.8')


def _resolve_notification(session,spec,reason,now):
    from . import notifications
    from .notifications import NotificationEvent, NotificationRevision
    event=session.scalar(select(NotificationEvent).where(*(getattr(NotificationEvent,key)==value
        for key,value in spec.items())))
    if event is not None:
        current=session.get(NotificationRevision,(event.id,event.revision))
        if current is None or current.lifecycle!='resolved':
            notifications.publish(session,**spec,subject_revision='resolved',severity='info',reason=reason,
                deep_link='#settings/ai',minimum_role='admin',lifecycle='resolved',now=now)


def publish_cap_notification(session,cfg,now):
    """Publish admin attention while the current capped window has no remaining spend.

    A separate advance warning is active while counted spend is at least
    DAILY_CAP_WARNING_FRACTION of the cap but below it, and resolves once the
    cap is reached so only the exhausted notification remains active.

    The revision is bound to the budget window (timezone and reset) and cap. The
    warning records counted and remaining amounts when it is raised and is not
    republished while active for the same window and cap, so further
    reservations or reconciliation in that window do not create new revisions.
    This reads the same conservative total that admission uses but neither
    reserves, releases nor authorizes anything. It runs in the
    caller's transaction and adds no SMTP/webhook alert.
    """
    from . import notifications
    from .notifications import NotificationEvent, NotificationRevision
    capped=bool(cfg.get('ai_enabled')) and cfg['ai_control_mode'] in ai_pricing.CAP_MODES
    warning=False
    if capped:
        _enabled,name,_start,reset,_groups,counted,cap,_reconciliation=_state(session,cfg,now)
        reset_text=datetime.fromtimestamp(reset,timezone.utc).isoformat().replace('+00:00','Z')
        if counted<cap and counted>=cap*DAILY_CAP_WARNING_FRACTION:
            # Advance warning only: admission is unchanged and still decides each call.
            warning=True
            subject_revision='nearing:'+name+':'+repr(float(reset))+':'+_money(cap)
            event=session.scalar(select(NotificationEvent).where(*(getattr(NotificationEvent,key)==value
                for key,value in DAILY_CAP_WARNING_NOTIFICATION.items())))
            current=session.get(NotificationRevision,(event.id,event.revision)) if event is not None else None
            # The amounts are captured when spend first crosses the threshold for this
            # window and cap. The reason is part of the revision fingerprint, so an
            # active warning for the same window and cap is left unchanged rather than
            # republished with live amounts; Settings shows current totals.
            if current is None or current.lifecycle!='active' or current.subject_revision!=subject_revision:
                remaining=max(cap-counted,Decimal(0))
                message=('Counted AI spend reached $'+_money(counted)+' of the shared daily cap of $'+_money(cap)+
                    ' ('+name+' day), at least '+str(int(DAILY_CAP_WARNING_FRACTION*100))+'% of the cap, leaving $'+
                    _money(remaining)+' before the reset at '+reset_text+'. These amounts were recorded when the '
                    'warning was raised; Settings shows current totals. When a call\'s conservative reservation no longer fits, new paid AI work, including triage, scoring '
                    'and plans, is deferred, not discarded. Review the cap or mode in Settings if that is not intended. Counted spend '
                    'conservatively includes reserved and uncertain charges; it is a local estimate, not a provider invoice.')
                notifications.publish(session,**DAILY_CAP_WARNING_NOTIFICATION,
                    subject_revision=subject_revision,
                    severity='low',reason=message,deep_link='#settings/ai',minimum_role='admin',now=now)
    if not warning:
        _resolve_notification(session,DAILY_CAP_WARNING_NOTIFICATION,
            'Shared daily AI spend is no longer approaching the cap: the window reset, the cap or mode changed, AI was '
            'disabled, or the cap was reached and its own notification applies.',now)
    if capped:
        if counted>=cap:
            message=('The shared daily AI spend cap of $'+_money(cap)+' ('+name+' day) has no remaining safe reservation. '
                'New paid AI work, including triage, scoring and plans, is deferred, not discarded, until the reset at '+reset_text+
                ' or until an administrator changes the cap or mode. Counted spend conservatively includes reserved and '
                'uncertain charges; it is a local estimate, not a provider invoice.')
            notifications.publish(session,**DAILY_CAP_NOTIFICATION,
                subject_revision='exhausted:'+name+':'+repr(float(reset))+':'+_money(cap),
                severity='medium',reason=message,deep_link='#settings/ai',minimum_role='admin',now=now)
            return True
    event=session.scalar(select(NotificationEvent).where(*(getattr(NotificationEvent,key)==value
        for key,value in DAILY_CAP_NOTIFICATION.items())))
    if event is not None:
        current=session.get(NotificationRevision,(event.id,event.revision))
        if current is None or current.lifecycle!='resolved':
            notifications.publish(session,**DAILY_CAP_NOTIFICATION,subject_revision='resolved',
                severity='info',reason='The shared daily AI spend cap no longer blocks new paid AI work.',
                deep_link='#settings/ai',minimum_role='admin',lifecycle='resolved',now=now)
    return False


UNPRICED_MODEL_NOTIFICATION=dict(source='ai-budget',kind='unpriced-model',subject_type='pricing-model',subject_id='saved-ai-model')


def publish_unpriced_model_notification(session,cfg,now):
    """Publish admin attention while capped admission cannot price the saved model.

    The revision is bound to the catalog version and a digest of the saved model
    ID, never to counts or times, so repeated collection publishes nothing new.
    An invalid or expired catalog is left to the separate pricing-catalog alert
    and neither publishes nor resolves this event. Read-only: it never reserves,
    releases or authorizes spend and adds no SMTP/webhook alert.
    """
    from . import notifications
    from .notifications import NotificationEvent, NotificationRevision
    model=cfg.get('ai_model') or ''
    if cfg.get('ai_enabled') and model and cfg['ai_control_mode'] in ai_pricing.CAP_MODES:
        result=ai_pricing.model_status(model,now)
        if not result['ok'] and result['code']=='catalog':return False
        if not result['ok']:
            name=('model '+result['model']) if result['model'] else 'model ID'
            message=('Capped AI admission cannot price the saved '+name+': it is not in the bundled public-price catalog '+
                ai_pricing.VERSION+'. Every paid AI call, including triage, scoring and plans, is refused before sending '
                'while a daily spend cap applies. Choose a catalogued model or change the AI control mode in Settings. '
                'No provider request is sent and no spend is reserved.')
            notifications.publish(session,**UNPRICED_MODEL_NOTIFICATION,
                subject_revision='unpriced:'+ai_pricing.VERSION+':model-sha256:'+hashlib.sha256(model.encode('utf-8')).hexdigest(),
                severity='high',reason=message,deep_link='#settings/ai',minimum_role='admin',now=now)
            return True
    event=session.scalar(select(NotificationEvent).where(*(getattr(NotificationEvent,key)==value
        for key,value in UNPRICED_MODEL_NOTIFICATION.items())))
    if event is not None:
        current=session.get(NotificationRevision,(event.id,event.revision))
        if current is None or current.lifecycle!='resolved':
            notifications.publish(session,**UNPRICED_MODEL_NOTIFICATION,subject_revision='resolved',
                severity='info',reason='Capped AI admission no longer refuses calls because the saved model is unpriced.',
                deep_link='#settings/ai',minimum_role='admin',lifecycle='resolved',now=now)
    return False


def history(session,days=30,now=None,*,timezone_name=None):
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
    filters=[BudgetEntry.reset_at>cutoff,BudgetEntry.created<=now,BudgetEntry.status!='released']
    if timezone_name is not None:
        # Compare encoded bytes so MySQL's text collation cannot fold case.
        filters.append(func.hex(BudgetEntry.timezone)==timezone_name.encode('utf-8').hex().upper())
    query=(select(BudgetEntry.timezone,BudgetEntry.reset_at,func.count(BudgetEntry.id).label('call_count'),
        bucket('settled').label('settled_usd'),bucket('reserved').label('reserved_usd'),
        bucket('sent').label('sent_usd'),bucket('uncertain').label('uncertain_usd'),
        other.label('other_usd'),_aggregate(session,amount).label('counted_usd'))
        .where(*filters)
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
