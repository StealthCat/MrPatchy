"""Conservative earliest-start estimates, never fabricated completion deadlines."""
import datetime as dt
import hashlib
import json
import time
from sqlalchemy import select
from .db import Job, Setting, Package, config
from . import operations, scheduling,host_lifecycle


def next_window(windows,start,end):
    if not windows:return start if start<end else None
    day=dt.datetime.fromtimestamp(start,dt.timezone.utc).replace(hour=0,minute=0,second=0,microsecond=0)
    # Windows recur weekly. A later window cannot improve on the first week.
    for offset in range(8):
        date=day+dt.timedelta(days=offset)
        choices=[]
        for window in windows:
            if date.weekday() not in window['days']:continue
            begin=date.timestamp()+window['start']*60;finish=min(end,date.timestamp()+window['end']*60)
            if max(start,begin)<finish:choices.append(max(start,begin))
        if choices:return min(choices)
    return None

class Planner:
    def __init__(self,s,host,now=None):
        self.s=s;self.host=host;self.now=time.time() if now is None else now
        self.jobs=list(s.scalars(select(Job).where(Job.host_id==host.id,Job.state.in_(('queued','running','recovery_required'))).order_by(Job.created)))
        window=s.get(Setting,'window:'+host.id);self.windows=window.value['windows'] if window else []
        self.policy=operations.recovery_policy(s,host.id)
        self.schedules=[r for r in s.scalars(select(scheduling.PatchSchedule)) if r.policy['enabled'] and (r.policy['all_hosts'] or host.id in r.policy['host_ids'])]
        self.runs={r.id:r for r in s.scalars(select(scheduling.PatchRun).where(scheduling.PatchRun.host_id==host.id))}
        self.packages=list(s.scalars(select(Package).where(Package.host_id==host.id,Package.candidate!='').order_by(Package.name)))
        self.cache={}
        # One read-only snapshot per planner, shared by all package forecasts.
        self.hold_reason=self._hold_reason()
    def result(self,state,reason,at=None,**extra):return {'state':state,'at':at,'reason':reason,'estimated':True,**extra}
    def for_package(self,p):
        if not p.candidate:return None
        if not host_lifecycle.active(self.host):return self.result('blocked','Server management is disabled or deleted.')
        now=self.now
        if p.held:return self.result('blocked','Held or version-locked by target policy.')
        if not p.dpkg_state.endswith(' installed'):return self.result('blocked','Repair the package state before installation.')
        spec=p.name+'='+p.candidate
        matching=[j for j in self.jobs if j.action=='patch' and spec in j.payload.get('packages',[])]
        if matching:
            job=matching[0]
            if job.state=='running':return self.result('installing','Installation is running; completion time is unknown.',job_id=job.id)
            if job.state=='recovery_required':return self.result('blocked','Review the interrupted operation in Activity.',job_id=job.id)
            blocked=self._busy(job)
            if blocked:return self.result('waiting',blocked,job_id=job.id)
            if self.host.state=='offline':return self.result('waiting','Target is offline; no reliable start estimate.',job_id=job.id)
            if self.host.repo_error or not self.host.last_repo or now-self.host.last_repo>config(self.s)['repo_minutes']*120:return self.result('blocked','Repository metadata needs a successful refresh before execution.',job_id=job.id)
            windows=self.windows;end=now+8*86400
            if job.payload.get('_schedule'):
                run=self.runs.get(job.payload['_schedule']['run_id'])
                schedule=next((r for r in self.schedules if run and r.id==run.schedule_id and r.revision==run.revision),None)
                if not schedule or now>=run.expires:return self.result('blocked','Scheduled approval expired or changed; awaiting reconciliation.',job_id=job.id)
                end=run.expires
                if run.trigger!='regular' and schedule.policy[run.trigger]['bypass_window']:windows=[]
            at=next_window(windows,now,end)
            return self.result('queued' if at is not None else 'blocked','Earliest worker start, subject to repository revalidation.' if at is not None else 'No remaining permitted start window.',at,job_id=job.id)
        if self.hold_reason:return self.result('waiting',self.hold_reason)
        if not self.schedules:return self.result('unscheduled','No enabled schedule covers this server. Select updates to install on demand.')
        if self.host.state!='online' or now-self.host.last_seen>120 or self.host.integrity:return self.result('blocked','Automatic patching awaits a healthy online server with fresh telemetry.')
        if self._busy():return self.result('waiting',self._busy())
        choices=[];mismatch=False
        for row in self.schedules:
            policy=row.policy
            if policy['recovery']!=self.policy:mismatch=True;continue
            if p.priority in policy['priorities']:
                cachekey=(row.id,'regular')
                if cachekey not in self.cache:
                    self.cache[cachekey]=None
                    for due in scheduling.occurrences(policy,max(row.updated,now-policy['window_minutes']*60),now+62*86400):
                        prior=next((r for r in self.runs.values() if r.schedule_id==row.id and r.revision==row.revision and r.trigger=='regular' and r.due==due),None)
                        if prior and prior.state not in scheduling.ACTIVE:continue
                        at=next_window(self.windows,max(now,due),due+policy['window_minutes']*60)
                        if at is not None:self.cache[cachekey]=at;break
                if self.cache[cachekey] is not None:choices.append((self.cache[cachekey],policy['name'],'regular'))
            if p.priority in ('high','critical') and policy[p.priority]['enabled'] and p.available_since:
                due=max(now,row.updated,p.available_since+policy[p.priority]['after_minutes']*60)
                eligible=[q for q in self.packages if q.priority==p.priority and not q.held and q.dpkg_state.endswith(' installed') and q.available_since and due>=q.available_since+policy[p.priority]['after_minutes']*60]
                key=json.dumps([(q.name,q.candidate,q.available_since) for q in eligible])
                identifier=hashlib.sha256(f'{row.id}:{row.revision}:{self.host.id}:{p.priority}:{key}'.encode()).hexdigest()
                prior=self.runs.get(identifier)
                if prior and prior.state not in scheduling.ACTIVE:continue
                start=prior.due if prior else due;end=prior.expires if prior else due+policy['window_minutes']*60
                windows=[] if policy[p.priority]['bypass_window'] else self.windows
                at=next_window(windows,max(now,start),end)
                if at is not None:choices.append((at,policy['name'],p.priority))
        if choices:
            at,name,trigger=min(choices)
            return self.result('scheduled','Estimated start window; repository refresh, worker availability and safety checks must pass.',at,schedule=name,trigger=trigger)
        return self.result('blocked' if mismatch else 'unscheduled','Recovery policy differs from the schedule approval.' if mismatch else 'No eligible start in the next 62 days, or this urgency batch already ran. Review schedules or install on demand.')
    def _hold_reason(self):
        # The executor's predicate decides whether work is held. These additional
        # local queries explain the review categories; they grant no exemptions.
        if not operations.host_quarantined(self.s,self.host.id):return ''
        from .quarantine import Quarantine
        from .process_response import ProcessResponse
        from .repair_publication import Publication
        from .service_monitor import Watch
        reviews=[]
        for model,label in ((Quarantine,'file response'),(ProcessResponse,'process response'),
                            (Publication,'replacement publication'),(Watch,'service monitoring')):
            if self.s.scalar(select(model.id).where(model.host_id==self.host.id,model.hold==True).limit(1)) is not None:
                reviews.append(label)
        if reviews:return 'Waiting for review of '+', '.join(reviews)+' holds; start time is unknown.'
        return 'Waiting for other server work or recovery; its finish time is unknown.'

    def _busy(self,job=None):
        if self.hold_reason:return self.hold_reason
        for other in self.jobs:
            if job and other.id==job.id:continue
            if other.state in ('running','recovery_required') or (other.state=='queued' and other.action!='refresh' and (job is None or other.created<job.created)):
                return 'Waiting for other server work or recovery; its finish time is unknown.'
        if job:
            for identifier in job.payload.get('_depends_on',[]):
                previous=self.s.get(Job,identifier)
                if not previous or previous.state!='complete':return 'Waiting for a successful canary/dependency; its finish time is unknown.'
            if job.payload.get('_recovery_policy',{'reboot':False,'rollback':False})!=self.policy:return 'Recovery policy changed; review and submit the patch again.'
        return ''
