"""Saved server-side fleet queries over existing host and package fields.

A saved query is a versioned, bounded filter definition. Results are evaluated at read time
with the caller's authorization, carry the evaluation time and filter version, and drill down
to the exact hosts and packages that matched. Hosts without a fresh observation are flagged so
a missing observation is never presented as compliant.
"""
import time
import uuid
from pydantic import BaseModel, Field
from sqlalchemy import String, JSON, Double, Integer, select, func, or_, and_
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base, Host, Package, config

PAGE_MAX=100
PACKAGES_PER_HOST=20

class SavedFleetQuery(Base):
    __tablename__='saved_fleet_queries'
    id:Mapped[str]=mapped_column(String(36),primary_key=True)
    name:Mapped[str]=mapped_column(String(120),unique=True)
    definition:Mapped[dict]=mapped_column(JSON)
    version:Mapped[int]=mapped_column(Integer,default=1)
    created_by:Mapped[str]=mapped_column(String(80),default='')
    created:Mapped[float]=mapped_column(Double,default=time.time)
    updated:Mapped[float]=mapped_column(Double,default=time.time)

class FleetFilter(BaseModel):
    """Every field narrows the result (logical AND); an empty filter matches all active servers."""
    os:str=Field(default='',max_length=120)
    package:str=Field(default='',max_length=200)
    state:str=Field(default='',max_length=40)
    enabled:bool|None=None
    updates_only:bool=False
    overdue_only:bool=False

class SavedQueryInput(BaseModel):
    name:str=Field(min_length=1,max_length=120)
    filter:FleetFilter
    expected_version:int|None=Field(default=None,ge=1)

def public(row):
    return {'id':row.id,'name':row.name,'filter':row.definition,'version':row.version,'created_by':row.created_by,'created':row.created,'updated':row.updated}

def package_conditions(f,cfg,now):
    conditions=[]
    if f.package:conditions.append(Package.name.contains(f.package,autoescape=True))
    if f.updates_only or f.overdue_only:conditions.append(Package.candidate!='')
    if f.overdue_only:
        conditions.append(or_(*(and_(Package.priority==priority,Package.available_since<now-hours*3600) for priority,hours in cfg['deadlines'].items())))
    return conditions

def evaluate(s,f,offset=0,limit=50,now=None):
    """Return one bounded page of matching active servers and their matching packages."""
    now=time.time() if now is None else now
    cfg=config(s)
    fresh_after=now-max(2*cfg['repo_minutes'],1)*60
    host_filter=[Host.deleted_at==0]
    if f.os:host_filter.append(Host.inventory['os'].as_string().contains(f.os,autoescape=True))
    if f.state:host_filter.append(Host.state==f.state)
    if f.enabled is not None:host_filter.append(Host.enabled==f.enabled)
    pkg=package_conditions(f,cfg,now)
    if pkg:host_filter.append(Host.id.in_(select(Package.host_id).where(*pkg)))
    matched=s.scalar(select(func.count()).select_from(Host).where(*host_filter)) or 0
    stale=s.scalar(select(func.count()).select_from(Host).where(*host_filter,Host.last_seen<fresh_after)) or 0
    rows=s.execute(select(Host.id,Host.name,Host.state,Host.enabled,Host.last_seen).where(*host_filter).order_by(Host.name,Host.id).offset(offset).limit(limit)).all()
    ids=[r.id for r in rows]; evidence={i:[] for i in ids}; counts={i:0 for i in ids}
    if pkg and ids:
        for host_id,total in s.execute(select(Package.host_id,func.count()).where(Package.host_id.in_(ids),*pkg).group_by(Package.host_id)):counts[host_id]=total
        for p in s.scalars(select(Package).where(Package.host_id.in_(ids),*pkg).order_by(Package.host_id,Package.name)):
            if len(evidence[p.host_id])<PACKAGES_PER_HOST:
                due=p.available_since+cfg['deadlines'][p.priority]*3600 if p.candidate else None
                evidence[p.host_id].append({'name':p.name,'installed':p.installed,'candidate':p.candidate,'priority':p.priority,'available_since':p.available_since,'due':due,'overdue':bool(due and now>due)})
    return {'as_of':now,'offset':offset,'limit':limit,'matched_hosts':matched,'stale_hosts':stale,'fresh_after':fresh_after,
            'hosts':[{'id':r.id,'name':r.name,'state':r.state,'enabled':r.enabled,'last_seen':r.last_seen,'fresh':r.last_seen>=fresh_after,
                      'matching_package_count':counts[r.id],'matching_packages':evidence[r.id]} for r in rows]}

def new_id():return str(uuid.uuid4())
