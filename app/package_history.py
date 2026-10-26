"""Observed package changes, distinct from requested/failed package operations."""
import math
import time
from contextvars import ContextVar
from sqlalchemy import String, JSON, Double, Integer, select
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base

operation = ContextVar('package_operation', default=None)
class PackageEvent(Base):
    __tablename__='package_events'
    id: Mapped[int]=mapped_column(Integer,primary_key=True,autoincrement=True)
    host_id: Mapped[str]=mapped_column(String(36),index=True)
    name: Mapped[str]=mapped_column(String(240),index=True)
    action: Mapped[str]=mapped_column(String(24))
    before: Mapped[list]=mapped_column(JSON,default=list)
    after: Mapped[list]=mapped_column(JSON,default=list)
    state_before: Mapped[str]=mapped_column(String(80),default='')
    state_after: Mapped[str]=mapped_column(String(80),default='')
    observed: Mapped[float]=mapped_column(Double,index=True)
    recorded: Mapped[float]=mapped_column(Double,default=time.time)
    source: Mapped[str]=mapped_column(String(30))
    job_id: Mapped[str]=mapped_column(String(36),default='',index=True)
    actor: Mapped[str]=mapped_column(String(120),default='')


def versions(inv, name, fallback):
    if inv.get('package_manager')=='rpm':
        values=sorted({p['evr'] for p in inv.get('rpm_packages',[]) if p['name']+':'+p['arch']==name})
        if values:return values
    return [fallback] if fallback else []


def record(s, host, inventory, old, items):
    now=time.time(); observed=inventory.get('collected',now)
    if not isinstance(observed,(int,float)) or not math.isfinite(observed) or observed<=0 or observed>now+120:observed=now
    context=operation.get() or {}
    def add(name, action, before, after, state_before='', state_after='', baseline=False):
        s.add(PackageEvent(host_id=host.id,name=name,action=action,before=before,after=after,state_before=state_before,
            state_after=state_after,observed=observed,source='baseline' if baseline else 'job_observation' if context else 'inventory',
            job_id=context.get('job_id','') if not baseline else '',actor=context.get('actor','') if not baseline else ''))
    has_history=s.scalar(select(PackageEvent.id).where(PackageEvent.host_id==host.id).limit(1)) is not None
    if not has_history:
        backfill(s,host)
        has_history=s.scalar(select(PackageEvent.id).where(PackageEvent.host_id==host.id).limit(1)) is not None
    if not has_history:
        for name,p in old.items():add(name,'baseline',[],versions(host.inventory,name,p.installed),state_after=p.dpkg_state,baseline=True)
    current={p['name']:p for p in items}
    for name,p in current.items():
        after=versions(inventory,name,p['installed']); previous=old.get(name)
        if not previous:
            baseline=not old and not has_history
            add(name,'baseline' if baseline else 'installed',[],after,state_after=p['dpkg_state'],baseline=baseline)
        else:
            before=versions(host.inventory,name,previous.installed)
            if before!=after:add(name,'version_changed',before,after,previous.dpkg_state,p['dpkg_state'])
            elif previous.dpkg_state!=p['dpkg_state']:add(name,'state_changed',before,after,previous.dpkg_state,p['dpkg_state'])
    for name,p in old.items():
        if name not in current:add(name,'removed',versions(host.inventory,name,p.installed),[],p.dpkg_state,'')


def backfill(s,host):
    """Recover changes from retained snapshots once, without inventing old actors/jobs."""
    from .db import InventoryRevision
    from .apt import installed
    previous=None;offset=0
    while True:
        revisions=list(s.scalars(select(InventoryRevision).where(InventoryRevision.host_id==host.id).order_by(InventoryRevision.created,InventoryRevision.id).offset(offset).limit(20)))
        if not revisions:break
        for revision in revisions:
            inv=revision.inventory
            if inv.get('package_manager')=='rpm':
                current={}
                for item in inv.get('rpm_packages',[]):
                    name=item['name']+':'+item['arch']
                    values,_=current.setdefault(name,([], 'install ok installed'))
                    if item['evr'] not in values:values.append(item['evr'])
                current={name:(sorted(values),state) for name,(values,state) in current.items()}
            else:current={p['name']:([p['installed']],p['dpkg_state']) for p in installed(inv.get('status',''))}
            observed=inv.get('collected',revision.created)
            if not isinstance(observed,(int,float)) or not math.isfinite(observed) or observed<=0 or observed>revision.created+120:observed=revision.created
            for name in sorted(set(current)|set(previous or {})):
                before,state_before=(previous or {}).get(name,([],''));after,state_after=current.get(name,([],''))
                action='baseline' if previous is None else 'installed' if name not in previous else 'removed' if name not in current else 'version_changed' if before!=after else 'state_changed' if state_before!=state_after else None
                if action:s.add(PackageEvent(host_id=host.id,name=name,action=action,before=before,after=after,state_before=state_before,state_after=state_after,observed=observed,recorded=revision.created,source='retained_inventory'))
            previous=current
        offset+=len(revisions)
    s.flush()
