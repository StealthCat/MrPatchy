"""Retained process assessments and explicit refresh intent, not a safe cache.

Writes use the existing distributed ai-triage lock. Rows never imply approval or
cross-host eligibility; diagnostic pruning intentionally does not delete them.
"""
import copy
import hashlib
import json
import time
import uuid
from sqlalchemy import String, Text, Double, JSON, select
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base, audit

COMPLETE=('low','medium','high','unknown')


class Assessment(Base):
    __tablename__='ai_behavior_assessments'
    id: Mapped[str]=mapped_column(String(36),primary_key=True)
    subject: Mapped[str]=mapped_column(String(64),index=True)
    host_id: Mapped[str]=mapped_column(String(36),index=True)
    created: Mapped[float]=mapped_column(Double,default=time.time)
    source: Mapped[str]=mapped_column(String(30))
    model: Mapped[str]=mapped_column(String(100),default='')
    run_id: Mapped[str]=mapped_column(String(36),default='')
    policy_hash: Mapped[str]=mapped_column(String(64),default='')
    state_hash: Mapped[str]=mapped_column(String(64),index=True)
    result: Mapped[dict]=mapped_column(JSON)
    snapshot: Mapped[dict]=mapped_column(JSON)
    inputs: Mapped[list]=mapped_column(JSON,default=list)
    refresh: Mapped[dict]=mapped_column(JSON,default=dict)


class Refresh(Base):
    __tablename__='ai_behavior_refreshes'
    subject: Mapped[str]=mapped_column(String(64),primary_key=True)
    id: Mapped[str]=mapped_column(String(36))
    created: Mapped[float]=mapped_column(Double,default=time.time)
    actor: Mapped[str]=mapped_column(String(64))
    reason: Mapped[str]=mapped_column(Text)
    previous: Mapped[str]=mapped_column(String(36))
    withdrew_approval: Mapped[bool]=mapped_column(default=False)


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def state_hash(row):
    return digest([row.id,row.host_id,row.evidence,row.verdict,row.analysis])


def revision(row):
    return digest([state_hash(row),row.approved,row.attempted])


def refresh_info(row):
    return {} if not row else {'id':row.id,'created':row.created,'actor':row.actor,'reason':row.reason,
        'previous':row.previous,'withdrew_approval':row.withdrew_approval,'bypass_cache':True}


def queue(s,row,expected,reason,actor,withdraw_approval):
    from . import ai_retry
    if revision(row)!=expected:raise ValueError('Assessment or approval changed; reopen Re-triage before submitting')
    if row.verdict not in COMPLETE:raise ValueError('Re-triage requires a completed assessment; use Retry for failed or pending work')
    if s.get(Refresh,row.id):raise ValueError('A re-triage request already exists')
    if row.approved and not withdraw_approval:raise ValueError('Explicitly confirm withdrawal of the current approval before re-triage')
    ai_retry.manual(s,row)
    saved=s.scalar(select(Assessment).where(Assessment.subject==row.id,Assessment.state_hash==state_hash(row)).order_by(Assessment.created.desc(),Assessment.id.desc()).limit(1))
    if not saved:
        # Preserve only what actually exists; do not invent an old model, run,
        # input binding or assessment timestamp from the current saved settings.
        saved=Assessment(id=str(uuid.uuid4()),subject=row.id,host_id=row.host_id,source='legacy',
            state_hash=state_hash(row),result={'risk':row.verdict,'saved_analysis':row.analysis},snapshot=copy.deepcopy(row.evidence))
        s.add(saved)
    request=Refresh(subject=row.id,id=str(uuid.uuid4()),actor=actor,reason=reason,previous=saved.id,withdrew_approval=row.approved)
    s.add(request)
    if row.approved:audit(s,'withdraw behavior approval for re-triage',actor+' '+row.id+' '+reason)
    row.approved=False;row.attempted=0;row.verdict='pending'
    row.analysis='Administrator requested fresh triage. Previous result is retained in Assessment history; AI policy and admission limits still apply.'
    audit(s,'request AI re-triage',actor+' '+row.id+' '+request.id+' '+reason)
    return request


def record(s,row,model,result,inputs):
    from . import ai_runs
    request=s.get(Refresh,row.id)
    saved=Assessment(id=str(uuid.uuid4()),subject=row.id,host_id=row.host_id,source='ai',model=model.strip(),
        run_id=ai_runs.active.get() or '',policy_hash=digest([item['policy'] for item in inputs]),
        state_hash=state_hash(row),result=copy.deepcopy(result),snapshot=copy.deepcopy(row.evidence),
        inputs=copy.deepcopy(inputs),refresh=refresh_info(request))
    s.add(saved)
    if request:s.delete(request)
    return saved


def record_reuse(s, row, hit):
    """Retain an exact cache hit without misrepresenting it as a provider call."""
    if s.get(Refresh, row.id):
        raise ValueError('Explicit Re-triage cannot reuse a known-good candidate')
    result=copy.deepcopy(hit['result'])
    result['known_good_reuse']={'fingerprint':hit['fingerprint'],
        'source_assessment_id':hit['assessment_id'],
        'source_subject':hit['source_subject'],
        'source_host_id':hit['source_host_id'],'source_created':hit['created']}
    saved=Assessment(id=str(uuid.uuid4()),subject=row.id,host_id=row.host_id,
        source='known_good',model=hit['model'],run_id='',policy_hash=hit['policy_hash'],
        state_hash=state_hash(row),result=result,snapshot=copy.deepcopy(row.evidence),
        inputs=[],refresh={})
    s.add(saved)
    return saved
