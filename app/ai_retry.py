"""Durable process-triage retry scheduling. Not shared pacing or cost admission.

The existing distributed ai-triage lock owns all mutations. No network calls or
sleeps occur here. Legacy/interrupted attempts retain a one-hour recovery delay.
"""
import hashlib
import json
import random
import time
from sqlalchemy import String, Double, Integer, Text, and_, or_
from sqlalchemy.orm import Mapped, mapped_column
from .db import Base, Behavior, Setting, config

MAX_ATTEMPTS=5


class TriageRetry(Base):
    __tablename__='ai_triage_retries'
    subject: Mapped[str]=mapped_column(String(64),primary_key=True)
    configuration: Mapped[str]=mapped_column(String(64))
    attempts: Mapped[int]=mapped_column(Integer,default=0)
    state: Mapped[str]=mapped_column(String(30),default='interrupted')
    next_at: Mapped[float]=mapped_column(Double,default=0,index=True)
    provider_until: Mapped[float]=mapped_column(Double,default=0)
    reason: Mapped[str]=mapped_column(Text,default='')


def configuration(s):
    cfg=config(s);key=s.get(Setting,'openai_key')
    # The ciphertext is hashed locally, never returned. Model/key changes unblock
    # configuration failures; enable/disable toggles do not reset attempt limits.
    return hashlib.sha256(json.dumps(['triage-retry-v1',cfg['ai_model'],key.value if key else None],sort_keys=True).encode()).hexdigest()


def eligible(signature,now):
    return or_(and_(TriageRetry.subject.is_(None),Behavior.attempted<=now-3600),
               and_(TriageRetry.state.in_(('deferred','interrupted')),TriageRetry.attempts<MAX_ATTEMPTS,TriageRetry.next_at<=now),
               and_(or_(TriageRetry.state=='blocked',and_(TriageRetry.state=='interrupted',TriageRetry.attempts>=MAX_ATTEMPTS)),TriageRetry.configuration!=signature,TriageRetry.provider_until<=now))


def begin(s,row,signature,now):
    retry=s.get(TriageRetry,row.id)
    if not retry:
        retry=TriageRetry(subject=row.id,configuration=signature,attempts=0);s.add(retry)
    if retry.configuration!=signature:retry.attempts=0
    retry.configuration=signature;retry.attempts+=1
    retry.state='interrupted';retry.next_at=now+3600
    retry.reason='Interrupted attempt; waiting for the one-hour recovery interval.'
    retry.provider_until=0
    return retry


def failed(s,row,error,now):
    from .ai import AIError
    retry=s.get(TriageRetry,row.id)
    retry.state='blocked';retry.next_at=0
    retry.reason='Review the failure and correct API configuration or explicitly retry. No automatic retry is scheduled.'
    if isinstance(error,AIError) and error.policy_wait:
        retry.attempts=max(0,retry.attempts-1)
        retry.state='deferred';retry.next_at=now
        retry.reason='Waiting for AI policy resume; eligibility is rechecked before every provider call.'
    elif isinstance(error,AIError) and error.transient:
        retry.provider_until=now+error.retry_after if error.retry_after else 0
        if retry.attempts<MAX_ATTEMPTS:
            delay=random.uniform(30,min(1800,60*2**(retry.attempts-1)))
            retry.state='deferred';retry.next_at=max(now+delay,retry.provider_until)
            retry.reason='Transient failure; queued until retry eligibility. Existing hourly and AI policy limits still apply.'
        else:retry.reason='Automatic retry limit reached (5 attempts). Review the failure before explicitly retrying.'
    return retry


def clear(s,row):
    retry=s.get(TriageRetry,row.id)
    if retry:s.delete(retry)


def manual(s,row,now=None):
    now=time.time() if now is None else now
    retry=s.get(TriageRetry,row.id)
    if retry and retry.provider_until>now:raise ValueError('Provider Retry-After is still active; retry after the displayed eligibility time.')
    clear(s,row)


def summary(retry,signature,now,attempted=0):
    if not retry:
        return {'state':'legacy_wait' if attempted>now-3600 else 'ready','attempts':0,
                'next_at':attempted+3600 if attempted>now-3600 else 0,'reason':''}
    exhausted=retry.state=='interrupted' and retry.attempts>=MAX_ATTEMPTS
    changed=(retry.state=='blocked' or exhausted) and retry.configuration!=signature and retry.provider_until<=now
    if exhausted and not changed:return {'state':'blocked','attempts':retry.attempts,'next_at':0,'reason':'Interrupted automatic attempt limit reached. Review the failure before explicitly retrying.'}
    state='ready' if changed or (retry.state in ('deferred','interrupted') and retry.next_at<=now) else retry.state
    return {'state':state,'attempts':retry.attempts,'next_at':retry.next_at or retry.provider_until,
            'reason':'API configuration changed; eligible for another attempt.' if changed else retry.reason}
