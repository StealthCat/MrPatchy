"""Short, distributed triage admission and renewable, fenced per-subject leases.

No provider/SSH operation runs under the admission lock or a SQL transaction.
Leases prevent stale acceptance, not duplicate billing after a lost response.
"""
import copy
import os
import threading
import time
import uuid
from contextlib import contextmanager
from decimal import Decimal
from contextvars import ContextVar
from types import SimpleNamespace
from time import perf_counter
from sqlalchemy import String, Double, select, func, and_, or_, union_all
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base, Session, Behavior, Host, Setting, config
from .coordination import Lock
from . import ai, ai_runs, ai_retry, ai_assessments, ai_policy, host_lifecycle

LEASE_SECONDS=120
RENEW_SECONDS=15
PROCESS_BOOT=uuid.uuid4().hex
current=ContextVar('ai_triage_lease',default=None)


class Claim(Base):
    __tablename__='ai_triage_claims'
    subject: Mapped[str]=mapped_column(String(64),primary_key=True)
    host_id: Mapped[str]=mapped_column(String(36),index=True)
    token: Mapped[str]=mapped_column(String(36))
    worker_id: Mapped[str]=mapped_column(String(48))
    boot_id: Mapped[str]=mapped_column(String(32))
    run_id: Mapped[str]=mapped_column(String(36),index=True)
    revision: Mapped[str]=mapped_column(String(64))
    configuration: Mapped[str]=mapped_column(String(64))
    created: Mapped[float]=mapped_column(Double)
    renewed: Mapped[float]=mapped_column(Double)
    expires: Mapped[float]=mapped_column(Double,index=True)


def occupancy(s,host_id,now=None):
    now=time.time() if now is None else now
    count,earliest=s.execute(select(func.count(Claim.subject),func.min(Claim.expires)).where(
        Claim.host_id==host_id,Claim.expires>now)).one()
    return {'active_lease_count':count,'earliest_lease_expires_at':earliest}


class HostTurn(Base):
    """Durable cross-worker order for fair process-investigation admission."""
    __tablename__='ai_triage_host_turns'
    host_id: Mapped[str]=mapped_column(String(36),primary_key=True)
    last_turn: Mapped[int]=mapped_column(index=True)


class Lost(ai.AIError):
    def __init__(self):
        super().__init__('Investigation ownership, evidence, approval or configuration changed; no stale result was accepted. A sent request may still be billable.')


def owner_valid(s,owner,admitting=False):
    if owner is None:return True
    from .worker_registry import record_key,control_value,report_state
    row=s.get(Setting,record_key(owner[0]));value=row.value if row else {}
    if value.get('boot_id')!=owner[1] or report_state(value,time.time())[0] not in ('reporting','draining','drained'):return False
    if admitting and (value.get('state')!='reporting' or control_value(s,*owner)['action']=='drain'):return False
    return True


def reconcile(s,now):
    # Called under ai-triage. Never interrupt a different worker's live lease.
    runs=ai_runs.AIRun
    expired=select(Claim,runs).outerjoin(runs,runs.id==Claim.run_id).where(Claim.expires<=now)
    for claim,run in s.execute(expired):
        _interrupt_run(s,run);s.delete(claim)
    s.flush()
    live=select(Claim.run_id)
    for run in s.scalars(select(runs).where(runs.purpose=='triage',runs.state=='running',runs.id.not_in(live))):
        _interrupt_run(s,run)


def interrupt(s,run_id):
    _interrupt_run(s,s.get(ai_runs.AIRun,run_id))


def _interrupt_run(s,run):
    if run and run.state=='running':
        run.state='interrupted';run.finished=time.time();run.stage='interrupted'
        run.message='Investigation lease was lost or expired. No stale result can be accepted; existing retry limits apply and sent calls may still be billable.'
        s.add(ai_runs.AIEvent(run_id=run.id,stage=run.stage,message=run.message))


def abandon_owner(owner):
    """Fence assigned work immediately when the scheduler loses its identity."""
    with Lock('ai-triage'),Session() as s:
        for claim in s.scalars(select(Claim).where(Claim.worker_id==owner[0],Claim.boot_id==owner[1])):
            claim.expires=0;interrupt(s,claim.run_id)
        s.commit()


def record_turn(s,host_id):
    """Assign the next durable turn while the distributed admission lock is held."""
    turn=(s.scalar(select(func.max(HostTurn.last_turn))) or 0)+1
    row=s.get(HostTurn,host_id)
    if row:row.last_turn=turn
    else:s.add(HostTurn(host_id=host_id,last_turn=turn))


FREE_HIT_SCAN=50
# Where the previous closed-gate pass stopped without a hit, as (first_seen, id).
# Per process; admission runs under the distributed ``ai-triage`` lock, so
# passes in one process never overlap. ``None`` starts from the oldest subject.
_free_hit_cursor=None


def _elect_host(s,election_filters,live_counts,signature,now):
    # Balance live occupancy first. Ties use the durable least-recent host
    # turn; a host with no turn sorts ahead of one already served. Project each
    # eligible verdict as its own equality range so host election reads the
    # admission index instead of scanning retained completed history.
    eligible=union_all(*(select(Behavior.host_id,Behavior.first_seen).outerjoin(
        ai_retry.TriageRetry,ai_retry.TriageRetry.subject==Behavior.id).where(
        *election_filters,Behavior.verdict==verdict) for verdict in ('pending','error'))).subquery()
    return s.scalar(select(eligible.c.host_id).outerjoin(
        live_counts,live_counts.c.host_id==eligible.c.host_id).outerjoin(
        HostTurn,HostTurn.host_id==eligible.c.host_id).group_by(
        eligible.c.host_id,live_counts.c.live_count,HostTurn.last_turn).order_by(
        func.coalesce(live_counts.c.live_count,0),func.coalesce(HostTurn.last_turn,0),
        func.min(eligible.c.first_seen),eligible.c.host_id).limit(1))


def _oldest(s,host_id,signature,now):
    # Within the elected host, keep each verdict as an equality range so the
    # admission index can skip retained completed history and satisfy
    # oldest-first ordering; the oldest member of either range is the host's
    # oldest eligible pending/error candidate.
    filters=(Behavior.host_id==host_id,Behavior.approved==False,
        Behavior.id.not_in(select(Claim.subject)),ai_retry.eligible(signature,now))
    oldest=[]
    for verdict in ('pending','error'):
        candidate=select(Behavior.id,Behavior.first_seen).outerjoin(
            ai_retry.TriageRetry,ai_retry.TriageRetry.subject==Behavior.id).where(
            *filters,Behavior.verdict==verdict).order_by(Behavior.first_seen,Behavior.id).limit(1).subquery()
        oldest.append(select(candidate.c.id,candidate.c.first_seen))
    candidates=union_all(*oldest).subquery()
    return s.scalar(select(Behavior).join(candidates,candidates.c.id==Behavior.id).order_by(
        candidates.c.first_seen,candidates.c.id).limit(1))


def _free_hit(s,model,election_filters):
    """Oldest eligible subject, within a bounded rotating window, with an exact known-good hit.

    Used while a shared provider start gate is closed. The same pause, lifecycle,
    saturation, claim and retry filters as normal election apply. Each pass probes
    at most ``FREE_HIT_SCAN`` subjects. A pass without a hit records where it
    stopped, and the next pass resumes after that subject and wraps to the oldest,
    so a hit behind any number of older paid subjects is reached in a bounded
    number of passes (#1241). A hit restarts the next pass from the oldest.
    """
    global _free_hit_cursor
    from . import known_good
    key=lambda row:(row.first_seen,row.id)

    def window(*bounds,limit):
        rows=[]
        for verdict in ('pending','error'):
            rows.extend(s.scalars(select(Behavior).outerjoin(
                ai_retry.TriageRetry,ai_retry.TriageRetry.subject==Behavior.id).where(
                *election_filters,*bounds,Behavior.verdict==verdict).order_by(
                Behavior.first_seen,Behavior.id).limit(limit)))
        return sorted(rows,key=key)[:limit]

    cursor=_free_hit_cursor
    if cursor is None or cursor[0] is None:
        probe=window(limit=FREE_HIT_SCAN)
    else:
        seen,subject=cursor
        after=or_(Behavior.first_seen>seen,and_(Behavior.first_seen==seen,Behavior.id>subject))
        probe=window(after,limit=FREE_HIT_SCAN)
        if len(probe)<FREE_HIT_SCAN:
            # The queue end was reached: wrap to the oldest subjects not probed yet.
            probe+=window(or_(Behavior.first_seen.is_(None),~after),limit=FREE_HIT_SCAN-len(probe))
    for row in probe:
        if known_good.exact_hit_available(s,row,model):
            _free_hit_cursor=None
            return row
    _free_hit_cursor=key(probe[-1]) if probe else None
    return None


def _needs_admission_lock(s, now):
    """One read probes for possible work or recovery without selecting evidence."""
    pending = select(Behavior.id).where(Behavior.approved == False, Behavior.verdict.in_(('pending', 'error')))
    expired = select(Claim.subject).where(Claim.expires <= now)
    runs = ai_runs.AIRun
    has_claim = select(Claim.subject).where(Claim.run_id == runs.id).exists()
    orphaned = select(runs.id).where(runs.purpose == 'triage', runs.state == 'running', ~has_claim)
    return s.scalar(select(or_(pending.exists(), expired.exists(), orphaned.exists())))


def acquire(owner=None):
    # Close the preflight snapshot before taking the distributed lock. A positive
    # answer only enters the normal election and recovery path in a fresh session.
    with Session() as s:
        if not _needs_admission_lock(s, time.time()):
            return None
    lock=Lock('ai-triage')
    lock_started=perf_counter()
    if not lock.acquire():return None
    claim_lock_wait=perf_counter()-lock_started
    try:
        with Session() as s:
            now=time.time();reconcile(s,now);s.commit()
            cfg=config(s);secret=s.get(Setting,'openai_key')
            if not cfg['ai_enabled'] or not cfg['ai_model'] or not secret or not owner_valid(s,owner,True):return None
            if cfg['ai_control_mode']=='legacy':
                recent=s.scalar(select(func.count()).select_from(Behavior).where(Behavior.attempted>now-3600))
                count=s.scalar(select(func.count()).select_from(ai_runs.AIRun).where(ai_runs.AIRun.purpose=='triage',ai_runs.AIRun.started>now-3600))
                if max(recent,count)>=cfg['ai_hourly_limit']:return None
            from . import ai_admission,ai_budget,ai_pricing,known_good
            # A local exact cache hit needs no provider admission. Keep paid
            # work queued while any shared provider start gate is closed.
            free_only=bool(ai_admission.shared_start_waiting(s,now,settings=cfg)
                or ai_budget.waiting(s,now,settings=cfg))
            if free_only and s.scalar(select(known_good.Entry.fingerprint).where(
                    known_good.Entry.active.is_(True),known_good.Entry.model==cfg['ai_model'].strip()).limit(1)) is None:
                return None
            signature=ai_retry.configuration_signature(cfg['ai_model'],secret.value)
            # Active claims are globally bounded by worker capacity. Resolve
            # each occupied host's revisioned policy under this admission lock
            # so a settings change and the next claim cannot cross.
            live_counts=(select(Claim.host_id,func.count().label('live_count')).where(
                Claim.expires>now).group_by(Claim.host_id).subquery())
            occupancy=s.execute(select(live_counts.c.host_id,live_counts.c.live_count,Setting.key,Setting.value)
                .select_from(live_counts).outerjoin(Setting,Setting.key==ai_policy.PREFIX+live_counts.c.host_id)).all()
            saturated_hosts=[host_id for host_id,count,key,policy in occupancy
                if count>=ai_policy.investigation_limit_value(policy if key is not None else {})]
            election_filters=(Behavior.approved==False,Behavior.host_id.not_in(ai_policy.paused_ids()),
                Behavior.host_id.not_in(host_lifecycle.inactive_ids()),Behavior.host_id.not_in(saturated_hosts),
                Behavior.id.not_in(select(Claim.subject)),ai_retry.eligible(signature,now))
            if free_only:
                row=_free_hit(s,cfg['ai_model'],election_filters)
                if not row:return None
                host_id=row.host_id
            else:
                host_id=_elect_host(s,election_filters,live_counts,signature,now)
                if not host_id:return None
                row=_oldest(s,host_id,signature,now)
                if not row:return None
            # Approval writes use this host queue gate. Re-read after acquiring
            # it, including on MySQL repeatable-read connections.
            subject=row.id;host_id=row.host_id
            try:
                with host_lifecycle.activity([host_id],'queue'):
                    s.rollback();row=s.get(Behavior,subject)
                    if not row or row.approved or row.verdict not in ('pending','error'):return None
                    # Legacy/test behavior rows may predate a retained Host row;
                    # only a present host can carry a lifecycle transition.
                    host=s.get(Host,host_id)
                    if host is not None and not host_lifecycle.active(host):return None
                    if free_only:
                        # Re-check under the host queue gate. A subsequent cache
                        # miss still goes through paid admission at the provider boundary.
                        if not known_good.exact_hit_available(s,row,cfg['ai_model']):return None
                    elif cfg['ai_control_mode'] in ai_pricing.CAP_MODES:
                        try:payload=ai.investigation_payload(row.evidence,cfg['ai_model'])
                        except ai.AIError as error:
                            # This subject's own evidence cannot be shared (for
                            # example over the 64 KB limit). Record the outcome an
                            # uncapped attempt records instead of leaving it at the
                            # head of the queue, where it would stall every host.
                            # Nothing is reserved or sent.
                            ai_retry.begin(s,row,signature,now)
                            retry=ai_retry.failed(s,row,error,now)
                            row.verdict='error';row.attempted=now
                            row.analysis='Investigation failed. '+retry.reason+' '+ai_runs.safe_error(error)
                            s.commit();return None
                        # A subject whose own conservative reservation exceeds the
                        # whole cap can never be admitted, even after a reset.
                        # Block it with an explained reason instead of leaving it at
                        # the head of the queue, where it would stall every host
                        # (#1003). Nothing is reserved or sent; ordinary exhaustion
                        # below still defers the whole fleet until the reset.
                        # An exact known-good hit spends nothing, so neither refusal
                        # holds it back (#1030).
                        quote=ai_pricing.reservation(payload)
                        cap=Decimal(str(cfg['ai_daily_cap_usd']))
                        over=quote['ok'] and quote['amount_usd']>cap
                        if ((over or ai_budget.waiting(s,now,payload)) and
                            not known_good.exact_hit_available(s,row,cfg['ai_model'])):
                            if over:ai_retry.over_cap(s,row,signature,quote['amount_usd'],cap);s.commit()
                            return None
                    row.attempted=now;ai_retry.begin(s,row,signature,now)
                    run=ai_runs.AIRun(id=str(uuid.uuid4()),purpose='triage',model=cfg['ai_model'],host_id=host_id,subject=subject)
                    s.add(run);s.add(ai_runs.AIRunHost(run_id=run.id,host_id=host_id))
                    claim=Claim(subject=subject,host_id=host_id,token=str(uuid.uuid4()),worker_id=owner[0] if owner else 'process-'+str(os.getpid()),
                        boot_id=owner[1] if owner else PROCESS_BOOT,run_id=run.id,revision=ai_assessments.lease_revision(row),
                        configuration=signature,created=now,renewed=now,expires=now+LEASE_SECONDS)
                    s.add(claim);record_turn(s,host_id);s.commit()
                    work=SimpleNamespace(**{key:copy.deepcopy(getattr(row,key)) for key in ('id','host_id','evidence','verdict','analysis','approved','attempted','first_seen')})
                    return Lease(claim,work,copy.deepcopy(cfg),copy.deepcopy(secret.value),owner,claim_lock_wait)
            except host_lifecycle.Inactive:return None
    finally:lock.release()


class Lease:
    def __init__(self,claim,work,cfg,secret,owner,claim_lock_wait):
        self.subject=claim.subject;self.token=claim.token;self.run_id=claim.run_id;self.host_id=claim.host_id
        self.work=work;self.cfg=cfg;self.secret=SimpleNamespace(value=secret);self.owner=owner
        self.claim_lock_wait=claim_lock_wait
        self.stopped=threading.Event();self.lost=threading.Event()

    def validate(self,s):
        if self.lost.is_set():raise Lost()
        claim=s.get(Claim,self.subject)
        if not claim or claim.token!=self.token or claim.expires<=time.time():
            self.lost.set();raise Lost()
        row=s.get(Behavior,self.subject)
        host=s.execute(select(Host.enabled,Host.deleted_at).where(Host.id==self.host_id)).one_or_none()
        # Recheck expiry and the heartbeat fence after database I/O.
        if (self.lost.is_set() or claim.expires<=time.time() or
            not row or row.host_id!=self.host_id or ai_assessments.lease_revision(row)!=claim.revision or
            ai_retry.configuration(s)!=claim.configuration or not owner_valid(s,self.owner) or
            (host is not None and not host_lifecycle.active(host))):
            self.lost.set();raise Lost()
        return claim,row

    def check(self):
        with Session() as s:self.validate(s)

    @contextmanager
    def mutation(self):
        with Lock('ai-triage'),host_lifecycle.activity([self.host_id],'queue'),Session() as s:
            claim,row=self.validate(s)
            yield s,row
            # Native JSON may normalize numeric representation on write. Bind
            # the actual stored row, not a stale ORM copy, without relaxing any
            # equality check or tolerating changed evidence on the next read.
            s.flush();s.refresh(row)
            claim.revision=ai_assessments.lease_revision(row);s.commit()

    def renew(self):
        lock=Lock('ai-triage')
        if not lock.acquire(False):return
        try:
            with Session() as s:
                claim,_=self.validate(s);claim.renewed=time.time();claim.expires=claim.renewed+LEASE_SECONDS;s.commit()
        finally:lock.release()

    def heartbeat(self):
        while not self.stopped.wait(RENEW_SECONDS):
            try:self.renew()
            except Exception:self.lost.set();return

    def __enter__(self):
        self.context=current.set(self)
        self.thread=threading.Thread(target=self.heartbeat,name='triage-lease',daemon=True);self.thread.start()
        return self

    def __exit__(self,*args):
        self.stopped.set();self.thread.join();current.reset(self.context)
        with Lock('ai-triage'),Session() as s:
            claim=s.get(Claim,self.subject)
            if claim and claim.token==self.token:
                if self.lost.is_set():interrupt(s,self.run_id)
                s.delete(claim);s.commit()


def check_current():
    lease=current.get()
    if lease:lease.check()
