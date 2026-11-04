"""Administrator-managed change freezes (blackout intervals).

A freeze is an absolute interval with an owner and reason. It blocks every
patch, repair and release-upgrade dispatch, including urgent/bypass triggers,
and expires on its own at its end time. Nothing here grants execution: when no
freeze is active the existing windows, holds and approvals decide as before.
"""
import datetime
import time
import math
import json
import hashlib
from .db import Setting

KEY = 'freeze:global'
MAX_FREEZES = 50


def parse_instant(text):
    """Epoch seconds for an ISO-8601 timestamp that carries an explicit UTC offset."""
    if not isinstance(text, str) or len(text) > 40: raise ValueError('timestamp must be an ISO-8601 string')
    try: value = datetime.datetime.fromisoformat(text)
    except ValueError: raise ValueError('timestamp must be ISO-8601') from None
    if value.tzinfo is None or value.utcoffset() is None: raise ValueError('timestamp requires an explicit UTC offset')
    return value.timestamp()


def clean(items, owner):
    """Validate submitted freezes and return stored rows (start/end as epoch seconds)."""
    if not isinstance(items, list) or len(items) > MAX_FREEZES: raise ValueError(f'At most {MAX_FREEZES} freezes are allowed')
    rows = []
    for item in items:
        if not isinstance(item, dict) or set(item) - {'start', 'end', 'reason'} or not {'start', 'end', 'reason'} <= set(item):
            raise ValueError('Each freeze requires start, end and reason')
        start, end = parse_instant(item['start']), parse_instant(item['end'])
        reason = item['reason']
        if end <= start: raise ValueError('A freeze must end after it starts')
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 200: raise ValueError('A freeze requires a reason of at most 200 characters')
        rows.append({'start': start, 'end': end, 'reason': reason.strip(), 'owner': owner})
    return sorted(rows, key=lambda row: (row['start'], row['end']))


def load(s):
    row = s.get(Setting, KEY)
    if not row:return []
    if not isinstance(row.value,dict):raise ValueError('Saved change freeze policy is malformed')
    rows=row.value.get('freezes')
    if not isinstance(rows,list) or len(rows)>MAX_FREEZES:raise ValueError('Saved change freeze policy is malformed')
    for item in rows:
        if not isinstance(item,dict):raise ValueError('Saved change freeze policy is malformed')
        start,end=item.get('start'),item.get('end')
        try:valid=(type(start) in (int,float) and type(end) in (int,float) and math.isfinite(start) and math.isfinite(end) and end>start)
        except OverflowError:valid=False
        if (not valid or not isinstance(item.get('reason'),str) or not item['reason'].strip() or len(item['reason'])>200
                or not isinstance(item.get('owner'),str) or len(item['owner'])>80):
            raise ValueError('Saved change freeze policy is malformed')
    return rows


def revision(s):
    row=s.get(Setting,KEY)
    return hashlib.sha256(json.dumps(row.value,sort_keys=True,separators=(',',':')).encode()).hexdigest() if row else ''


def active(s, now=None):
    """Freezes in force now, soonest first."""
    now = time.time() if now is None else now
    return [row for row in load(s) if row['start'] <= now < row['end']]


def clear_at(s, now=None):
    """First instant at or after now outside every freeze (follows overlapping/adjacent freezes), or None."""
    now = time.time() if now is None else now
    rows, moved = load(s), True
    point = now
    while moved:
        moved = False
        for row in rows:
            if row['start'] <= point < row['end']: point = row['end']; moved = True
    return None if point == now else point


def blocked(s, now=None):
    try:return bool(active(s, now))
    except (ValueError,TypeError,OverflowError):return True
