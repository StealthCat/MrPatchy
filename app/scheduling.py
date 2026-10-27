"""Opt-in recurring and urgency-driven patching, using the existing job executor."""
import datetime as dt
import hashlib
import json
import math
import time
import uuid
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, Field, model_validator
from sqlalchemy import String, JSON, Double, Integer, select, update, func
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base, Session, Host, Package, Job, config, audit
from .coordination import Lock
from . import operations

UTC = dt.timezone.utc
PRIORITIES = ('critical', 'high', 'normal', 'low')
ACTIVE = ('waiting', 'refreshing', 'queued', 'running')


class Urgency(BaseModel):
    enabled: bool = False
    after_minutes: int = Field(default=60, ge=0, le=43200)
    bypass_window: bool = False


class Recovery(BaseModel):
    reboot: bool = False
    rollback: bool = False


class ScheduleInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    enabled: bool = False
    all_hosts: bool = True
    host_ids: list[str] = Field(default_factory=list, max_length=1000)
    timezone: str = Field(default='UTC', max_length=100)
    frequency: Literal['daily', 'weekly', 'monthly'] = 'weekly'
    days: list[int] = Field(default_factory=lambda: [6], min_length=1, max_length=7)
    month_day: int = Field(default=1, ge=1, le=31)
    minute: int = Field(default=120, ge=0, le=1439)
    window_minutes: int = Field(default=120, ge=15, le=1440)
    priorities: list[Literal['critical', 'high', 'normal', 'low']] = Field(default_factory=lambda: list(PRIORITIES), min_length=1, max_length=4)
    critical: Urgency = Field(default_factory=lambda: Urgency(after_minutes=0))
    high: Urgency = Field(default_factory=Urgency)
    recovery: Recovery = Field(default_factory=Recovery)
    approved: bool = False
    revision: int | None = Field(default=None, ge=1)

    @model_validator(mode='after')
    def validate_policy(self):
        try: ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError): raise ValueError('Use an IANA timezone such as America/New_York or UTC')
        if any(type(day) is not int or not 0 <= day <= 6 for day in self.days) or len(set(self.days)) != len(self.days):
            raise ValueError('Weekdays must be distinct numbers 0–6 (Monday first)')
        if len(set(self.priorities)) != len(self.priorities) or len(set(self.host_ids)) != len(self.host_ids):
            raise ValueError('Duplicate priorities or servers')
        if not self.all_hosts and not self.host_ids: raise ValueError('Select at least one server')
        if self.enabled and not self.approved: raise ValueError('Approve unattended patching before enabling a schedule')
        return self


class PatchSchedule(Base):
    __tablename__ = 'patch_schedules'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    policy: Mapped[dict] = mapped_column(JSON)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    updated: Mapped[float] = mapped_column(Double, default=time.time)


class PatchRun(Base):
    __tablename__ = 'patch_schedule_runs'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    schedule_id: Mapped[str] = mapped_column(String(36), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    host_id: Mapped[str] = mapped_column(String(36), index=True)
    trigger: Mapped[str] = mapped_column(String(12))
    due: Mapped[float] = mapped_column(Double, index=True)
    expires: Mapped[float] = mapped_column(Double)
    state: Mapped[str] = mapped_column(String(30), default='waiting')
    detail: Mapped[str] = mapped_column(String(1000), default='')
    refresh_id: Mapped[str] = mapped_column(String(36), default='')
    job_id: Mapped[str] = mapped_column(String(36), default='')


def occurrences(policy, start, end):
    """Wall-clock recurrences; skip nonexistent DST times, choose the first fold once."""
    zone = ZoneInfo(policy['timezone'])
    day = dt.datetime.fromtimestamp(start, zone).date()
    last = dt.datetime.fromtimestamp(end, zone).date()
    while day <= last:
        matches = (policy['frequency'] == 'daily' or
                   policy['frequency'] == 'weekly' and day.weekday() in policy['days'] or
                   policy['frequency'] == 'monthly' and day.day == policy['month_day'])
        if matches:
            wall = dt.datetime.combine(day, dt.time(policy['minute']//60, policy['minute']%60))
            local = wall.replace(tzinfo=zone, fold=0)
            stamp = local.timestamp()
            if start <= stamp < end and dt.datetime.fromtimestamp(stamp, zone).replace(tzinfo=None) == wall:
                yield stamp
        day += dt.timedelta(days=1)


def hosts_for(s, policy):
    query = select(Host).order_by(Host.name, Host.id)
    if not policy['all_hosts']: query = query.where(Host.id.in_(policy['host_ids']))
    return list(s.scalars(query))


def serialize(row):
    return {'id': row.id, 'revision': row.revision, 'updated': row.updated, **row.policy}


def save(s, body, schedule_id, username):
    row = s.get(PatchSchedule, schedule_id) if schedule_id else None
    if schedule_id and not row: raise ValueError('Schedule no longer exists')
    if row and body.revision != row.revision: raise ValueError('Schedule changed; reload before saving')
    if not row and s.scalar(select(func.count()).select_from(PatchSchedule)) >= 100: raise ValueError('Limit of 100 schedules reached')
    if not body.all_hosts and len(list(s.scalars(select(Host.id).where(Host.id.in_(body.host_ids))))) != len(body.host_ids):
        raise ValueError('Selected server no longer exists')
    policy = body.model_dump(exclude={'approved', 'revision'})
    if policy['all_hosts']: policy['host_ids'] = []
    if row:
        cancel_pending(s, row.id, 'Schedule edited or paused')
        row.policy = policy; row.revision += 1; row.updated = time.time()
    else:
        row = PatchSchedule(id=str(uuid.uuid4()), policy=policy, revision=1, updated=time.time()); s.add(row)
    audit(s, 'approve patch schedule' if body.enabled else 'save paused patch schedule', username+' '+row.id+' '+json.dumps(policy))
    s.commit()
    return serialize(row)


def cancel_pending(s, schedule_id, reason):
    for run in s.scalars(select(PatchRun).where(PatchRun.schedule_id == schedule_id, PatchRun.state.in_(ACTIVE))):
        for job_id in (run.job_id, run.refresh_id):
            if job_id:
                s.execute(update(Job).where(Job.id == job_id, Job.state == 'queued').values(state='cancelled', output=reason))
        job = s.get(Job, run.job_id, populate_existing=True) if run.job_id else None
        if not job or job.state != 'running': run.state = 'cancelled'; run.detail = reason


def candidates(s, host_id, policy, trigger, now):
    priorities = policy['priorities'] if trigger == 'regular' else [trigger]
    rows = s.scalars(select(Package).where(Package.host_id == host_id, Package.candidate != '',
                                         Package.held == False, Package.priority.in_(priorities)).order_by(Package.name))
    return [p for p in rows if p.dpkg_state.endswith(' installed') and (trigger == 'regular' or
            p.available_since > 0 and now >= p.available_since + policy[trigger]['after_minutes']*60)]


def allow_window(s, host_id, policy, trigger, now):
    if trigger != 'regular' and policy[trigger]['bypass_window']: return True
    from .db import Setting
    row = s.get(Setting, 'window:'+host_id)
    return operations.in_window(row.value['windows'] if row else [], now)


def add_run(s, schedule, host, trigger, due, key):
    identity = hashlib.sha256(f'{schedule.id}:{schedule.revision}:{host.id}:{trigger}:{key}'.encode()).hexdigest()
    if not s.get(PatchRun, identity):
        s.add(PatchRun(id=identity, schedule_id=schedule.id, revision=schedule.revision, host_id=host.id,
                       trigger=trigger, due=due, expires=due+schedule.policy['window_minutes']*60))
        s.flush()


def job_guard(s, job, now=None):
    """Revalidate schedule authorization and start deadline immediately before claim."""
    ref = job.payload.get('_schedule')
    if not ref: return None
    now = time.time() if now is None else now
    run = s.get(PatchRun, ref['run_id'])
    schedule = s.get(PatchSchedule, run.schedule_id) if run else None
    if (not run or not schedule or not schedule.policy['enabled'] or schedule.revision != run.revision or
            run.host_id != job.host_id or now >= run.expires):
        job.state = 'cancelled'; job.output = 'Scheduled authorization changed or start window expired'; s.commit(); return False
    host = s.get(Host, job.host_id)
    if not host or host.state != 'online' or now-host.last_seen > 120 or host.integrity:
        return False
    return allow_window(s, job.host_id, schedule.policy, run.trigger, now)


def advance(s, run, now):
    # Once queued, the executor owns the package transaction. Do not retry uncertain work.
    if run.job_id:
        if now >= run.expires:
            cancelled = s.execute(update(Job).where(Job.id == run.job_id, Job.state == 'queued').values(state='cancelled', output='Scheduled start window expired')).rowcount
            if cancelled:
                run.state = 'skipped'; run.detail = 'Scheduled start window expired before execution'; return
        job = s.get(Job, run.job_id, populate_existing=True)
        run.state = job.state if job else 'failed'
        run.detail = (job.output or 'Patch job '+job.state)[:1000] if job else 'Patch job missing'
        return
    schedule = s.get(PatchSchedule, run.schedule_id)
    if not schedule or not schedule.policy['enabled'] or schedule.revision != run.revision:
        run.state = 'cancelled'; run.detail = 'Schedule changed'; return
    policy = schedule.policy
    if now >= run.expires:
        if run.refresh_id:
            s.execute(update(Job).where(Job.id == run.refresh_id, Job.state == 'queued').values(state='cancelled', output='Patch start window expired'))
        run.state = 'skipped'; run.detail = 'Start window expired: '+run.detail; return
    host = s.get(Host, run.host_id)
    if not host:
        run.state = 'skipped'; run.detail = 'Server removed'; return
    if operations.host_quarantined(s,host.id):
        run.detail='Waiting for operation or file response reconciliation';return
    if host.state != 'online' or now-host.last_seen > 120 or host.integrity or not host.fingerprint or not host.inventory:
        run.detail = 'Waiting for an enrolled, online server with fresh telemetry and no integrity findings'; return
    if operations.recovery_policy(s, host.id) != policy['recovery']:
        run.state = 'blocked'; run.detail = 'Recovery policy differs from the approved schedule; review and save the schedule'; return
    if not allow_window(s, host.id, policy, run.trigger, now):
        run.detail = 'Waiting for the server maintenance window'; return
    busy = s.scalar(select(Job.id).where(Job.host_id == host.id,
                    Job.state.in_(('queued', 'running', 'recovery_required')),
                    Job.action != 'refresh').limit(1))
    if busy: run.detail = 'Waiting for existing work or recovery reconciliation'; return
    if not run.refresh_id:
        existing = s.scalar(select(Job.id).where(Job.host_id == host.id, Job.action == 'refresh', Job.state.in_(('queued', 'running'))).limit(1))
        if existing: run.detail = 'Waiting for the existing repository check'; return
        job = Job(id=str(uuid.uuid4()), host_id=host.id, action='refresh', payload={'_schedule': {'run_id':run.id}})
        s.add(job); run.refresh_id = job.id; run.state = 'refreshing'; run.detail = 'Refreshing signed repository metadata'; return
    refresh = s.get(Job, run.refresh_id)
    if not refresh or refresh.state in ('failed', 'blocked', 'cancelled', 'interrupted', 'recovery_required'):
        run.state = 'failed'; run.detail = 'Repository refresh did not complete; inspect Activity'; return
    if refresh.state != 'complete': return
    specs = [p.name+'='+p.candidate for p in candidates(s, host.id, policy, run.trigger, now)]
    if not specs:
        run.state = 'no_updates'; run.detail = 'No eligible updates (held and broken packages excluded)'; return
    if len(specs) > 500:
        run.state = 'blocked'; run.detail = 'More than 500 updates; split into reviewed manual batches'; return
    from .worker import validate_patch
    try: validate_patch(s, host, specs)
    except ValueError as error:
        run.state = 'failed'; run.detail = str(error)[:1000]; return
    job = Job(id=str(uuid.uuid4()), host_id=host.id, action='patch', payload={
        'packages':specs, '_actor':'schedule:'+schedule.id, '_recovery_policy':policy['recovery'], '_schedule':{'run_id':run.id}, '_schedule_policy':policy, '_depends_on':[]})
    s.add(job); run.job_id = job.id; run.state = 'queued'; run.detail = f'{len(specs)} exact-version updates queued'
    audit(s, 'queue scheduled patch', run.id+' '+host.id+' '+run.trigger)


def tick(now=None):
    now = time.time() if now is None else now
    lock = Lock('patch-schedules')
    if not lock.acquire(False): return
    try:
        with Session() as s:
            for schedule in s.scalars(select(PatchSchedule)):
                policy = schedule.policy
                if not policy['enabled']: continue
                for host in hosts_for(s, policy):
                    for due in occurrences(policy, max(schedule.updated, now-policy['window_minutes']*60), now+0.001):
                        add_run(s, schedule, host, 'regular', due, str(int(due)))
                    for priority in ('critical', 'high'):
                        if not policy[priority]['enabled']: continue
                        packages = candidates(s, host.id, policy, priority, now)
                        if packages:
                            key = json.dumps([(p.name, p.candidate, p.available_since) for p in packages])
                            add_run(s, schedule, host, priority, now, key)
            runs = list(s.scalars(select(PatchRun).where(PatchRun.state.in_(ACTIVE))))
            for run in sorted(runs, key=lambda r: ({'critical':0,'high':1,'regular':2}[r.trigger],r.due,r.id)):
                advance(s, run, now)
                s.flush()
            s.commit()
    finally: lock.release()


def calendar(s, start, end, host_id=''):
    if not math.isfinite(start) or not math.isfinite(end) or not 0 <= start < end <= 4102444800 or end-start > 62*86400:
        raise ValueError('Calendar range must be within 1970–2100 and at most 62 days')
    schedules = list(s.scalars(select(PatchSchedule)))
    names = {r.id:r.policy['name'] for r in schedules}
    events = {}
    for row in schedules:
        if not row.policy['enabled']: continue
        if host_id and not (row.policy['all_hosts'] or host_id in row.policy['host_ids']): continue
        target_count = 1 if host_id else len(hosts_for(s,row.policy))
        for due in occurrences(row.policy, max(start-86400, row.updated), end):
            key = row.id+':'+str(int(due))
            events[key] = {'id':key,'schedule_id':row.id,'title':row.policy['name'],'start':due,
                           'end':due+row.policy['window_minutes']*60,'trigger':'regular','states':{},
                           'servers':target_count, 'timezone':row.policy['timezone']}
    runs = select(PatchRun).where(PatchRun.due >= start-86400, PatchRun.due < end)
    if host_id: runs = runs.where(PatchRun.host_id == host_id)
    for run in s.scalars(runs.order_by(PatchRun.due).limit(10000)):
        key = run.schedule_id+':'+str(int(run.due)) if run.trigger == 'regular' else run.id
        event = events.setdefault(key, {'id':key,'schedule_id':run.schedule_id,'title':names.get(run.schedule_id,'Deleted schedule'),
                  'start':run.due,'end':run.expires,'trigger':run.trigger,'states':{},'servers':0,'timezone':''})
        job = s.get(Job,run.job_id) if run.job_id else None
        state = job.state if job and run.state in ACTIVE else run.state
        event['states'][state] = event['states'].get(state,0)+1
        if run.trigger != 'regular': event['host_id'] = run.host_id
    for event in events.values():
        event['servers'] = max(event['servers'],sum(event['states'].values()))
    return sorted((event for event in events.values() if event['end'] > start),key=lambda item:item['start'])


def validate_selection(s, host, job):
    run = s.get(PatchRun, job.payload['_schedule']['run_id'])
    # The approved policy is copied into the job so edits do not alter claimed work.
    policy = job.payload['_schedule_policy']
    eligible = {p.name+'='+p.candidate for p in candidates(s,host.id,policy,run.trigger,time.time())}
    if not set(job.payload['packages']) <= eligible:
        raise ValueError('Scheduled package priority or eligibility changed; review Activity')
    if host.state != 'online' or time.time()-host.last_seen > 120 or host.integrity:
        raise ValueError('Scheduled patch requires fresh healthy target telemetry')
    if time.time() >= run.expires:
        raise ValueError('Scheduled start window expired before package installation')
    if not allow_window(s, host.id, policy, run.trigger, time.time()):
        raise ValueError('Server maintenance window closed before package installation')
