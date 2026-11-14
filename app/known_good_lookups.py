"""Durable fleet known-good cache lookup outcome counters (roadmap B, #802).

Process triage records one fixed outcome per exact-match cache lookup: ``hit``
or one ``known_good.MISS_TEXT`` reason. Rows hold only a UTC day, a fixed
outcome label and a count -- never evidence, identifiers, hosts or subjects --
so they survive AI-log pruning without retaining private context. Counters are
advisory diagnostics: they never grant reuse, alter lookup results or
authorize a response.
"""
from __future__ import annotations

import datetime
import time

from sqlalchemy import Integer, String, delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base
from .known_good import MISS_TEXT

HIT = 'hit'
UNCLASSIFIED = 'miss_unclassified'
MISSES = (*MISS_TEXT, UNCLASSIFIED)
OUTCOMES = (HIT, *MISSES)
RETENTION_DAYS = 400
SUMMARY_DAYS = 30


class LookupCount(Base):
    """One UTC day's count of one fixed lookup outcome; diagnostics only."""
    __tablename__ = 'ai_known_good_lookup_counts'
    day: Mapped[str] = mapped_column(String(10), primary_key=True)
    outcome: Mapped[str] = mapped_column(String(32), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0, server_default='0')


def _day(now, offset=0):
    moment = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).date()
    return (moment - datetime.timedelta(days=offset)).isoformat()


def _increment(s, day, outcome):
    statement = update(LookupCount).where(
        LookupCount.day == day, LookupCount.outcome == outcome,
    ).values(count=LookupCount.count + 1).execution_options(synchronize_session=False)
    return s.execute(statement).rowcount


def record(s, outcome, now=None):
    """Atomically count one lookup outcome in the caller's transaction.

    The update is a current read on MySQL and serialized on SQLite. A first
    insert for the day races under a savepoint; the loser increments the
    winner's committed row instead of poisoning the caller's unit of work.
    """
    if outcome not in OUTCOMES:
        raise ValueError('Unknown known-good lookup outcome')
    now = time.time() if now is None else now
    day = _day(now)
    if _increment(s, day, outcome):
        return
    try:
        with s.begin_nested():
            s.add(LookupCount(day=day, outcome=outcome, count=1))
            s.flush()
    except IntegrityError:
        if not _increment(s, day, outcome):
            raise
        return
    # A new row starts at most a few times per day: bound retention then.
    s.execute(delete(LookupCount).where(
        LookupCount.day < _day(now, RETENTION_DAYS)).execution_options(synchronize_session=False))


def summary(s, now=None):
    """Return bounded recent counts by fixed outcome; no evidence is read."""
    now = time.time() if now is None else now
    since = _day(now, SUMMARY_DAYS - 1)
    rows = dict(s.execute(select(LookupCount.outcome, func.sum(LookupCount.count)).where(
        LookupCount.day >= since).group_by(LookupCount.outcome)).all())
    misses = {code: int(rows.get(code) or 0) for code in MISSES}
    first = s.scalar(select(func.min(LookupCount.day)))
    return {'window_days': SUMMARY_DAYS, 'since_day': since, 'timezone': 'UTC',
        'counted_since_day': first, 'hits': int(rows.get(HIT) or 0),
        'misses': misses, 'total_misses': sum(misses.values()),
        'scope': 'process_triage'}
