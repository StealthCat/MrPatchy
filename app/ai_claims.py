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
from contextvars import ContextVar
from types import SimpleNamespace
from sqlalchemy import String, Double, select, func
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
    for claim in s.scalars(select(Claim).where(Claim.expires<=now)):
        interrupt(s,claim.run_id);s.delete(claim)
    s.flush()
    live=select(Claim.run_id)
    for run in s.scalars(select(ai_runs.AIRun).where(ai_runs.AIRun.purpose=='triage',ai_runs.AIRun.state=='running',ai_runs.AIRun.id.not_in(live))):
        interrupt(s,run.id)


def interrupt(s,run_id):
    run=s.get(ai_runs.AIRun,run_id)
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


def acquire(owner=None):
    lock=Lock('ai-triage')
    lock.acquire()
    try:
        with Session() as s:
            now=time.time();reconcile(s,now);s.commit()
            cfg=config(s);secret=s.get(Setting,'openai_key')
            if not cfg['ai_enabled'] or not cfg['ai_model'] or not secret or not owner_valid(s,owner,True):return None
            recent=s.scalar(select(func.count()).select_from(Behavior).where(Behavior.attempted>now-3600))
            count=s.scalar(select(func.count()).select_from(ai_runs.AIRun).where(ai_runs.AIRun.purpose=='triage',ai_runs.AIRun.started>now-3600))
            if max(recent,count)>=cfg['ai_hourly_limit']:return None
            signature=ai_retry.configuration(s)
            # One process investigation per host preserves lifecycle/provider
            # serialization and prevents a noisy host occupying every slot.
            row=s.scalar(select(Behavior).outerjoin(ai_retry.TriageRetry,ai_retry.TriageRetry.subject==Behavior.id).where(
                Behavior.approved==False,Behavior.host_id.not_in(ai_policy.paused_ids()),
                Behavior.host_id.not_in(host_lifecycle.inactive_ids()),Behavior.host_id.not_in(select(Claim.host_id)),
                Behavior.verdict.in_(('pending','error')),ai_retry.eligible(signature,now)).order_by(Behavior.first_seen,Behavior.id).limit(1))
            if not row:return None
            # Approval writes use this host queue gate. Re-read after acquiring
            # it, including on MySQL repeatable-read connections.
            subject=row.id;host_id=row.host_id
            with host_lifecycle.activity([host_id],'queue'):
                s.rollback();row=s.get(Behavior,subject)
                if not row or row.approved or row.verdict not in ('pending','error'):return None
                row.attempted=now;ai_retry.begin(s,row,signature,now)
                run=ai_runs.AIRun(id=str(uuid.uuid4()),purpose='triage',model=cfg['ai_model'],host_id=host_id,subject=subject)
                s.add(run);s.add(ai_runs.AIRunHost(run_id=run.id,host_id=host_id))
                claim=Claim(subject=subject,host_id=host_id,token=str(uuid.uuid4()),worker_id=owner[0] if owner else 'process-'+str(os.getpid()),
                    boot_id=owner[1] if owner else PROCESS_BOOT,run_id=run.id,revision=ai_assessments.revision(row),
                    configuration=signature,created=now,renewed=now,expires=now+LEASE_SECONDS)
                s.add(claim);s.commit()
                work=SimpleNamespace(**{key:copy.deepcopy(getattr(row,key)) for key in ('id','host_id','evidence','verdict','analysis','approved','attempted','first_seen')})
                return Lease(claim,work,copy.deepcopy(cfg),copy.deepcopy(secret.value),owner)
    finally:lock.release()


class Lease:
    def __init__(self,claim,work,cfg,secret,owner):
        self.subject=claim.subject;self.token=claim.token;self.run_id=claim.run_id;self.host_id=claim.host_id
        self.work=work;self.cfg=cfg;self.secret=SimpleNamespace(value=secret);self.owner=owner
        self.stopped=threading.Event();self.lost=threading.Event()

    def validate(self,s):
        claim=s.get(Claim,self.subject);row=s.get(Behavior,self.subject)
        host=s.get(Host,self.host_id)
        if (self.lost.is_set() or not claim or claim.token!=self.token or claim.expires<=time.time() or
            not row or row.host_id!=self.host_id or ai_assessments.revision(row)!=claim.revision or
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
            claim.revision=ai_assessments.revision(row);s.commit()

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
