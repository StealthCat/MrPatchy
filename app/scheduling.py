"""Opt-in recurring and urgency-driven patching, using the existing job executor."""
from . import host_lifecycle
import datetime as dt
import hashlib
import json
import math
import time
import uuid
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, Field, model_validator
from sqlalchemy import String, JSON, Double, Integer, select, update, func, case
from sqlalchemy.orm import Mapped, mapped_column, load_only
from .db import Base, Session, Host, Package, Job, audit
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
    query = select(Host).where(Host.enabled==True,Host.deleted_at==0).order_by(Host.name, Host.id)
    if not policy['all_hosts']: query = query.where(Host.id.in_(policy['host_ids']))
    return list(s.scalars(query))


def host_count(s, policy):
    """Number of hosts hosts_for() would return, without loading host rows or their JSON blobs."""
    query = select(func.count()).select_from(Host).where(Host.enabled==True,Host.deleted_at==0)
    if not policy['all_hosts']: query = query.where(Host.id.in_(policy['host_ids']))
    return s.scalar(query) or 0


def tick_hosts(s, policy):
    # Load every column advance()/host_lifecycle read, so no attribute becomes a per-host lazy-load SELECT;
    # the telemetry/baseline JSON blobs stay deferred.
    query = select(Host).options(load_only(Host.id, Host.state, Host.last_seen, Host.integrity, Host.enabled,
                                           Host.deleted_at, Host.fingerprint, Host.inventory, Host.lifecycle_revision)).where(
        Host.enabled==True, Host.deleted_at==0).order_by(Host.name, Host.id)
    if not policy['all_hosts']: query = query.where(Host.id.in_(policy['host_ids']))
    return list(s.scalars(query))


def candidate_packages(s, host_ids, policy):
    """Outstanding candidates for many hosts in one query, grouped by host id (same filters as candidates())."""
    wanted = [p for p in ('critical', 'high') if policy[p]['enabled']]
    grouped = {host_id: [] for host_id in host_ids}
    if not wanted or not host_ids: return grouped
    priorities = set(wanted)
    for start in range(0, len(host_ids), 500):
        rows = s.scalars(select(Package).where(Package.host_id.in_(host_ids[start:start+500]), Package.candidate != '',
                                               Package.held == False, Package.priority.in_(priorities)).order_by(Package.name))
        for row in rows: grouped[row.host_id].append(row)
    return grouped


def serialize(row):
    return {'id': row.id, 'revision': row.revision, 'updated': row.updated, **row.policy}


def save(s, body, schedule_id, username):
    row = s.get(PatchSchedule, schedule_id) if schedule_id else None
    if schedule_id and not row: raise ValueError('Schedule no longer exists')
    if row and body.revision != row.revision: raise ValueError('Schedule changed; reload before saving')
    if not row and s.scalar(select(func.count()).select_from(PatchSchedule)) >= 100: raise ValueError('Limit of 100 schedules reached')
    if not body.all_hosts and len(list(s.scalars(select(Host.id).where(Host.id.in_(body.host_ids),Host.deleted_at==0)))) != len(body.host_ids):
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


def candidates(s, host_id, policy, trigger, now, preloaded=None):
    priorities = policy['priorities'] if trigger == 'regular' else [trigger]
    if preloaded is not None: rows = [p for p in preloaded if p.priority in priorities]
    else:
        rows = s.scalars(select(Package).where(Package.host_id == host_id, Package.candidate != '',
                                             Package.held == False, Package.priority.in_(priorities)).order_by(Package.name))
    return [p for p in rows if p.dpkg_state.endswith(' installed') and (trigger == 'regular' or
            p.available_since > 0 and now >= p.available_since + policy[trigger]['after_minutes']*60)]


def window_settings(s, host_ids):
    """Maintenance windows for many hosts using one Setting query per 500 hosts, keyed by host id."""
    from .db import Setting
    host_ids = list(host_ids); found = {}
    for start in range(0, len(host_ids), 500):
        keys = ['window:'+h for h in host_ids[start:start+500]]
        for row in s.scalars(select(Setting).where(Setting.key.in_(keys))): found[row.key[7:]] = row.value['windows']
    return {h: found.get(h, []) for h in host_ids}


def allow_window(s, host_id, policy, trigger, now, windows=None):
    if trigger != 'regular' and policy[trigger]['bypass_window']: return True
    if windows is not None and host_id in windows: return operations.in_window(windows[host_id], now)
    from .db import Setting
    row = s.get(Setting, 'window:'+host_id)
    return operations.in_window(row.value['windows'] if row else [], now)


def run_identity(schedule, host_id, trigger, key, attempt=0):
    base = f'{schedule.id}:{schedule.revision}:{host_id}:{trigger}:{key}'
    return hashlib.sha256((base+f':attempt{attempt}' if attempt else base).encode()).hexdigest()


class TickCache:
    """Per-tick lookups for the hosts of one schedule, so advance() issues no per-host existence queries."""
    def __init__(self, s, host_ids, runs, shared=None):
        host_ids = list(host_ids)
        self.windows = window_settings(s, host_ids)
        self.recovery = operations.recovery_policies(s, host_ids)
        self.quarantined = operations.quarantined_hosts(s, host_ids)
        if shared is not None:
            # Tick-global sets: work queued for a host by one schedule is visible to every other schedule's runs.
            self.busy, self.refreshing = shared.busy, shared.refreshing
        else: self._load_active_jobs(s, host_ids)
        # Load the runs' refresh jobs together; s.get() then finds them in the identity map.
        ids = [r.refresh_id for r in runs if r.refresh_id and not r.job_id]
        for start in range(0, len(ids), 500): list(s.scalars(select(Job).where(Job.id.in_(ids[start:start+500]))))

    def _load_active_jobs(self, s, host_ids):
        self.busy = set(); self.refreshing = set()
        for start in range(0, len(host_ids), 500):
            chunk = host_ids[start:start+500]
            self.busy.update(s.scalars(select(Job.host_id).where(Job.host_id.in_(chunk),
                             Job.state.in_(('queued', 'running', 'recovery_required')), Job.action != 'refresh').distinct()))
            self.refreshing.update(s.scalars(select(Job.host_id).where(Job.host_id.in_(chunk), Job.action == 'refresh',
                                   Job.state.in_(('queued', 'running'))).distinct()))


def add_run(s, schedule, host, trigger, due, key, reissue=False, known=None):
    attempt = 0
    identity = run_identity(schedule, host.id, trigger, key)
    existing = known[identity] if known is not None and identity in known else s.get(PatchRun, identity)
    # An urgent run that expired without ever queuing a patch job never executed; once gates allow, issue a fresh attempt.
    while reissue and existing and existing.state == 'skipped' and not existing.job_id:
        attempt += 1
        identity = run_identity(schedule, host.id, trigger, key, attempt)
        existing = s.get(PatchRun, identity)
    if not existing:
        run = PatchRun(id=identity, schedule_id=schedule.id, revision=schedule.revision, host_id=host.id,
                       trigger=trigger, due=due, expires=due+schedule.policy['window_minutes']*60)
        s.add(run)
        if known is not None: known[identity] = run
        s.flush()


def job_guard(s, job, now=None):
    """Revalidate schedule authorization and start deadline immediately before claim."""
    ref = job.payload.get('_schedule')
    if not ref: return None
    now = time.time() if now is None else now
    run = s.get(PatchRun, ref['run_id'])
    schedule = s.get(PatchSchedule, run.schedule_id) if run else None
    if (run and schedule and schedule.policy['enabled'] and schedule.revision == run.revision and
            run.host_id == job.host_id and now >= run.expires):
        # An expired window is a missed run (alerting), not an authorization change.
        job.state = 'cancelled'; job.output = 'Scheduled start window expired'
        run.state = 'skipped'; run.detail = 'Scheduled start window expired before execution'; s.commit(); return False
    if (not run or not schedule or not schedule.policy['enabled'] or schedule.revision != run.revision or
            run.host_id != job.host_id or now >= run.expires):
        job.state = 'cancelled'; job.output = 'Scheduled authorization changed or start window expired'; s.commit(); return False
    host = s.get(Host, job.host_id)
    if not host_lifecycle.active(host) or host.state != 'online' or now-host.last_seen > 120 or host.integrity:
        return False
    return allow_window(s, job.host_id, schedule.policy, run.trigger, now)


def advance(s, run, now, cache=None):
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
    if not host_lifecycle.active(host):
        run.state = 'cancelled'; run.detail = 'Server management disabled or deleted'; return
    if (host.id in cache.quarantined) if cache else operations.host_quarantined(s,host.id):
        run.detail='Waiting for operation or file response reconciliation';return
    if host.state != 'online' or now-host.last_seen > 120 or host.integrity or not host.fingerprint or not host.inventory:
        run.detail = 'Waiting for an enrolled, online server with fresh telemetry and no integrity findings'; return
    if (cache.recovery[host.id] if cache else operations.recovery_policy(s, host.id)) != policy['recovery']:
        run.state = 'blocked'; run.detail = 'Recovery policy differs from the approved schedule; review and save the schedule'; return
    if not allow_window(s, host.id, policy, run.trigger, now, cache.windows if cache else None):
        run.detail = 'Waiting for the server maintenance window'; return
    busy = (host.id in cache.busy) if cache else s.scalar(select(Job.id).where(Job.host_id == host.id,
                    Job.state.in_(('queued', 'running', 'recovery_required')),
                    Job.action != 'refresh').limit(1))
    if busy: run.detail = 'Waiting for existing work or recovery reconciliation'; return
    if not run.refresh_id:
        existing = (host.id in cache.refreshing) if cache else s.scalar(select(Job.id).where(Job.host_id == host.id, Job.action == 'refresh', Job.state.in_(('queued', 'running'))).limit(1))
        if existing: run.detail = 'Waiting for the existing repository check'; return
        job = Job(id=str(uuid.uuid4()), host_id=host.id, action='refresh', payload={'_schedule': {'run_id':run.id},'_host_revision':host.lifecycle_revision})
        s.add(job); run.refresh_id = job.id; run.state = 'refreshing'
        run.detail = 'Refreshing signed repository metadata'
        if cache: cache.refreshing.add(host.id)
        return
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
        'packages':specs, '_host_revision':host.lifecycle_revision, '_actor':'schedule:'+schedule.id, '_recovery_policy':policy['recovery'], '_schedule':{'run_id':run.id}, '_schedule_policy':policy, '_depends_on':[]})
    s.add(job); run.job_id = job.id; run.state = 'queued'
    run.detail = f'{len(specs)} exact-version updates queued'
    if cache: cache.busy.add(host.id)
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
                targets = tick_hosts(s, policy)
                ids = [h.id for h in targets]
                pending = candidate_packages(s, ids, policy)
                windows = window_settings(s, ids)
                plans = []
                for host in targets:
                    for due in occurrences(policy, max(schedule.updated, now-policy['window_minutes']*60), now+0.001):
                        plans.append((host, 'regular', due, str(int(due)), False))
                    for priority in ('critical', 'high'):
                        if not policy[priority]['enabled']: continue
                        packages = candidates(s, host.id, policy, priority, now, pending[host.id])
                        if packages:
                            key = json.dumps([(p.name, p.candidate, p.available_since) for p in packages])
                            ready = (host.state == 'online' and now-host.last_seen <= 120 and not host.integrity and
                                     allow_window(s, host.id, policy, priority, now, windows))
                            plans.append((host, priority, now, key, ready))
                # Look up every planned run together; add_run() then needs no per-run SELECT.
                wanted = [run_identity(schedule, h.id, trigger, key) for h, trigger, _, key, _ in plans]
                known = {}
                for start in range(0, len(wanted), 500):
                    known.update({r.id: r for r in s.scalars(select(PatchRun).where(PatchRun.id.in_(wanted[start:start+500])))})
                for host, trigger, due, key, reissue in plans: add_run(s, schedule, host, trigger, due, key, reissue=reissue, known=known)
            runs = list(s.scalars(select(PatchRun).where(PatchRun.state.in_(ACTIVE))))
            caches = {}; shared = None
            for schedule in s.scalars(select(PatchSchedule)):
                waiting = [r for r in runs if r.schedule_id == schedule.id and not r.job_id]
                if schedule.policy['enabled'] and waiting:
                    if shared is None:
                        shared = TickCache(s, {r.host_id for r in runs if not r.job_id}, [])
                    caches[schedule.id] = TickCache(s, {r.host_id for r in waiting}, waiting, shared)
            for run in sorted(runs, key=lambda r: ({'critical':0,'high':1,'regular':2}[r.trigger],r.due,r.id)):
                advance(s, run, now, caches.get(run.schedule_id))
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
        target_count = 1 if host_id else host_count(s,row.policy)
        for due in occurrences(row.policy, max(start-86400, row.updated), end):
            key = row.id+':'+str(int(due))
            events[key] = {'id':key,'schedule_id':row.id,'title':row.policy['name'],'start':due,
                           'end':due+row.policy['window_minutes']*60,'trigger':'regular','states':{},
                           'servers':target_count, 'timezone':row.policy['timezone']}
    # Aggregate in SQL: one row per (run slot, effective state) instead of one row and one Job lookup per run,
    # and no row cap that would silently drop the newest runs (#434). Job state only matters for ACTIVE runs.
    single = PatchRun.trigger != 'regular'
    state = case((PatchRun.state.in_(ACTIVE) & Job.state.is_not(None), Job.state), else_=PatchRun.state)
    run_id = case((single, PatchRun.id), else_='')
    run_host = case((single, PatchRun.host_id), else_='')
    runs = (select(PatchRun.schedule_id, PatchRun.trigger, PatchRun.due, func.max(PatchRun.expires), run_id, run_host,
                   state, func.count())
            .outerjoin(Job, Job.id == PatchRun.job_id)
            .where(PatchRun.due >= start-86400, PatchRun.due < end))
    if host_id: runs = runs.where(PatchRun.host_id == host_id)
    runs = runs.group_by(PatchRun.schedule_id, PatchRun.trigger, PatchRun.due, run_id, run_host, state)
    for schedule_id, trigger, due, expires, rid, rhost, run_state, count in s.execute(runs.order_by(PatchRun.due)):
        key = schedule_id+':'+str(int(due)) if trigger == 'regular' else rid
        event = events.setdefault(key, {'id':key,'schedule_id':schedule_id,'title':names.get(schedule_id,'Deleted schedule'),
                  'start':due,'end':expires,'trigger':trigger,'states':{},'servers':0,'timezone':''})
        event['states'][run_state] = event['states'].get(run_state,0)+count
        if trigger != 'regular': event['host_id'] = rhost
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
