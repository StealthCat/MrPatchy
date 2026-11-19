"""Durable process-triage retry scheduling. Not shared pacing or cost admission.

The existing distributed ai-triage lock owns all mutations. No network calls or
sleeps occur here. Legacy/interrupted attempts retain a one-hour recovery delay.
"""
import hashlib
import json
import math
import random
import time
from sqlalchemy import String, Double, Integer, Text, and_, or_, func, select
from sqlalchemy.orm import Mapped, mapped_column
from . import ai_provider_backoff
from .db import Base, Behavior, Setting, config

MAX_ATTEMPTS=5
RATE_WAIT_REASON='Waiting for shared AI rate eligibility; no provider request was sent.'
BUDGET_WAIT_REASON='Waiting for the daily AI spend cap to reset; no provider request was sent.'
PROVIDER_BLOCKED_REASON='Review the failure and correct API configuration or explicitly retry. No automatic retry is scheduled.'
# A local refusal is not a key, quota or model problem (#1007): say so, so an
# administrator does not rotate the key or change the model to clear it.
EVIDENCE_SIZE_BLOCKED_REASON=('This observation\'s evidence is larger than Mr Patchy shares with the AI provider, so '
    'nothing was sent. Review it manually. Changing the API key or model does not help. No automatic retry is scheduled.')
FOLLOW_UP_EVIDENCE_SIZE_BLOCKED_REASON=('The follow-up evidence collected from the server is larger than Mr Patchy shares with '
    'the AI provider, so the follow-up request was not sent. The first-stage request was sent and may be billed. '
    'Review it manually. Changing the API key or model does not help. No automatic retry is scheduled.')
# Both requests reached the provider (#1158), so neither reason may say nothing was
# sent, and neither is a key or quota problem. A model change still re-admits them.
MODEL_REFUSAL_BLOCKED_REASON=('The AI model declined to assess this observation. The request was sent and may be billed. '
    'Review it manually. Changing the API key does not help; a different model may assess it. '
    'No automatic retry is scheduled.')
TOKEN_BUDGET_BLOCKED_REASON=('The AI model used its whole response token budget before finishing the assessment. '
    'The request was sent and may be billed. Select a model that completes within Mr Patchy\'s task budget, '
    'or review it manually. Changing the API key does not help. No automatic retry is scheduled.')


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
    return configuration_signature(cfg['ai_model'],key.value if key else None)


def configuration_signature(model,key_value):
    # The ciphertext is hashed locally, never returned. Model/key changes unblock
    # configuration failures; enable/disable toggles do not reset attempt limits.
    return hashlib.sha256(json.dumps(['triage-retry-v1',model,key_value],sort_keys=True).encode()).hexdigest()


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
    retry.reason=PROVIDER_BLOCKED_REASON
    cause=getattr(error,'cause',None) if isinstance(error,AIError) else None
    if cause=='evidence_size':retry.reason=EVIDENCE_SIZE_BLOCKED_REASON
    elif cause=='follow_up_evidence_size':retry.reason=FOLLOW_UP_EVIDENCE_SIZE_BLOCKED_REASON
    elif cause=='model_refusal':retry.reason=MODEL_REFUSAL_BLOCKED_REASON
    elif cause=='token_budget':retry.reason=TOKEN_BUDGET_BLOCKED_REASON
    if isinstance(error,AIError) and error.policy_wait:
        retry.attempts=max(0,retry.attempts-1)
        retry.state='deferred';retry.next_at=now+(error.retry_after or 0)
        provider_wait=getattr(error,'provider_wait_until',0)
        provider_wait=(provider_wait if type(provider_wait) in (int,float)
            and math.isfinite(provider_wait) and provider_wait>0 else 0)
        budget_reset=getattr(error,'budget_wait_until',None)
        if provider_wait:
            retry.provider_until=provider_wait
            retry.next_at=max(now,provider_wait)
            retry.reason='Waiting for shared provider backoff; no provider request was sent.'
        elif budget_reset is not None:
            retry.next_at=max(now,budget_reset)
            retry.reason=BUDGET_WAIT_REASON
        elif error.retry_after:
            # Only rate waiters share the pacing queue. Budget and provider
            # waits each have their own time boundary.
            tail=s.scalar(select(func.max(TriageRetry.next_at)).where(TriageRetry.subject!=row.id,
                TriageRetry.state=='deferred',TriageRetry.next_at>now,TriageRetry.provider_until<=now,
                TriageRetry.reason==RATE_WAIT_REASON))
            cfg=config(s);rate=cfg['ai_rate_per_hour'] if cfg['ai_control_mode'] in ('rate','rate_and_daily') else 120
            if tail is not None:retry.next_at=max(retry.next_at,tail+3600.0/max(1,rate))
            retry.reason=RATE_WAIT_REASON
        else:
            retry.reason='Waiting for AI policy resume; eligibility is rechecked before every provider call.'
    elif isinstance(error,AIError) and error.transient:
        provider=min(error.provider_retry_after or 0,ai_provider_backoff.MAX_PROVIDER_DELAY)
        retry.provider_until=now+provider if provider else 0
        if retry.attempts<MAX_ATTEMPTS:
            delay=random.uniform(30,min(1800,60*2**(retry.attempts-1)))
            retry.state='deferred';retry.next_at=max(now+delay,retry.provider_until)
            retry.reason='Transient failure; queued until retry eligibility. Existing hourly and AI policy limits still apply.'
        else:retry.reason='Automatic retry limit reached (5 attempts). Review the failure before explicitly retrying.'
    return retry


def over_cap(s,row,signature,quote,cap):
    """Block a subject whose conservative reservation alone exceeds the daily cap.

    No attempt is counted because nothing was reserved or sent. The row keeps the
    current model/key signature, so the existing blocked count, notification and
    administrator retry apply, and a model or key change makes it eligible again.
    """
    retry=s.get(TriageRetry,row.id)
    if not retry:
        retry=TriageRetry(subject=row.id,configuration=signature,attempts=0);s.add(retry)
    if retry.configuration!=signature:retry.attempts=0
    retry.configuration=signature;retry.state='blocked';retry.next_at=0
    retry.reason=(f'The daily spend cap (${cap:.4f}) is smaller than this investigation\'s conservative '
        f'reservation (${quote:.4f}), so it can never be admitted. Nothing was reserved or sent. Raise the '
        'cap or change the model, then explicitly retry. Other investigations continue.')
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
