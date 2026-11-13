"""Durable, role-filtered in-app notification events and per-user state.

This module deliberately does not acknowledge operational alerts, transition
incidents, approve AI output, or execute response actions.  Producers publish a
safe summary of an already committed subject; transports and UI consume it in a
later milestone.
"""
import hashlib
import json
import re
import threading
import time

from sqlalchemy import Double, Integer, String, Text, and_, delete, func, select, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, Session, audit


ROLES = {'viewer': 0, 'operator': 1, 'admin': 2}
SEVERITIES = {'info', 'low', 'medium', 'high', 'critical'}
LIFECYCLES = {'active', 'resolved'}
IDENTIFIER = re.compile(r'^[a-z0-9][a-z0-9_.-]*$')


class StreamConnections:
    """Small process-local guard for long-lived notification streams.

    Streams carry only invalidation cursors and keep no event queue.  The shared
    database remains authoritative, so a client refused here can use the polling
    fallback and reconnect without losing notification history.
    """

    def __init__(self, limit):
        if type(limit) is not int or not 1 <= limit <= 256:
            raise ValueError('Notification stream limit must be between 1 and 256')
        self.limit = limit
        self.active = 0
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            if self.active >= self.limit:
                return False
            self.active += 1
            return True

    def release(self):
        with self.lock:
            if self.active:
                self.active -= 1


class NotificationEvent(Base):
    """Stable identity and current revision for one exact attention subject."""

    __tablename__ = 'notification_events'
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(40), index=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    subject_type: Mapped[str] = mapped_column(String(40))
    subject_id: Mapped[str] = mapped_column(String(200))
    host_id: Mapped[str] = mapped_column(String(36), default='', index=True)
    minimum_role: Mapped[str] = mapped_column(String(20), default='viewer')
    revision: Mapped[int] = mapped_column(Integer, default=1)
    fingerprint: Mapped[str] = mapped_column(String(64))
    created: Mapped[float] = mapped_column(Double, default=time.time)
    updated: Mapped[float] = mapped_column(Double, default=time.time, index=True)


class NotificationRevision(Base):
    """Retained, safe public payload for one event revision."""

    __tablename__ = 'notification_revisions'
    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject_revision: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    reason: Mapped[str] = mapped_column(Text)
    deep_link: Mapped[str] = mapped_column(String(512), default='')
    lifecycle: Mapped[str] = mapped_column(String(20), default='active')
    created: Mapped[float] = mapped_column(Double, default=time.time)


class NotificationArrival(Base):
    """Append-only arrival record for every created notification revision.

    ``publish()`` inserts the row unsequenced inside the producer transaction.
    ``sequence_arrivals()`` later assigns ``seq`` only to rows that have already
    committed, one serialized sequencing transaction at a time, so every reader
    snapshot sees a gap-free committed prefix.  A slow or rolled-back producer
    can therefore never be skipped or replayed by a cursor, and the sequence is
    independent of producer timestamps and bounded list ordering.
    """
    __tablename__ = 'notification_arrivals'
    __table_args__ = {'sqlite_autoincrement': True}
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    seq: Mapped[int | None] = mapped_column(Integer, nullable=True, unique=True)
    event_id: Mapped[str] = mapped_column(String(64), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    created: Mapped[float] = mapped_column(Double, default=time.time)


class NotificationArrivalHead(Base):
    """Single-row lock and high-water mark serializing arrival sequencing."""
    __tablename__ = 'notification_arrival_head'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    head: Mapped[int] = mapped_column(Integer, default=0)


class NotificationUserState(Base):
    """Per-user state; revisions keep changed/reopened events discoverable."""

    __tablename__ = 'notification_user_state'
    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), primary_key=True)
    read_revision: Mapped[int] = mapped_column(Integer, default=0)
    dismissed_revision: Mapped[int] = mapped_column(Integer, default=0)
    updated: Mapped[float] = mapped_column(Double, default=time.time)


def _text(name, value, limit, *, identifier=False, empty=False):
    if not isinstance(value, str) or (not value and not empty) or len(value) > limit:
        raise ValueError(f'Invalid notification {name}')
    if any(ord(char) < 32 and char not in ('\n', '\t') for char in value):
        raise ValueError(f'Invalid notification {name}')
    if identifier and value and not IDENTIFIER.fullmatch(value):
        raise ValueError(f'Invalid notification {name}')
    return value


def _link(value):
    value = _text('deep link', value, 512, empty=True)
    if value and ('\\' in value or not (
            (value.startswith('/') and not value.startswith('//')) or value.startswith('#'))):
        raise ValueError('Notification deep links must be same-origin paths or fragments')
    return value


def _event_id(source, kind, subject_type, subject_id, host_id):
    identity = '\0'.join(('notification-v1', source, kind, subject_type, subject_id, host_id))
    return hashlib.sha256(identity.encode()).hexdigest()


def publish(session, *, source, kind, subject_type, subject_id,
            subject_revision, severity, reason, deep_link='', host_id='',
            minimum_role='viewer', lifecycle='active', now=None):
    """Publish one safe committed-subject observation.

    Returns ``(event, created_revision)``. Repeating an exact observation is a
    no-op. Any material payload/lifecycle change appends a retained revision, so
    users who read or dismissed an earlier revision see the change as unread.
    The caller owns the surrounding transaction.
    """
    source = _text('source', source, 40, identifier=True)
    kind = _text('kind', kind, 40, identifier=True)
    subject_type = _text('subject type', subject_type, 40, identifier=True)
    subject_id = _text('subject id', subject_id, 200)
    subject_revision = _text('subject revision', subject_revision, 128)
    host_id = _text('host id', host_id, 36, empty=True)
    reason = _text('reason', reason, 2000)
    deep_link = _link(deep_link)
    if severity not in SEVERITIES:
        raise ValueError('Invalid notification severity')
    if minimum_role not in ROLES:
        raise ValueError('Invalid notification minimum role')
    if lifecycle not in LIFECYCLES:
        raise ValueError('Invalid notification lifecycle')
    payload = {
        'subject_revision': subject_revision,
        'severity': severity,
        'reason': reason,
        'deep_link': deep_link,
        'host_id': host_id,
        'minimum_role': minimum_role,
        'lifecycle': lifecycle,
    }
    fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    event_id = _event_id(source, kind, subject_type, subject_id, host_id)
    event = session.get(NotificationEvent, event_id)
    if event and event.fingerprint == fingerprint:
        return event, False
    timestamp = time.time() if now is None else now
    if event:
        event.revision += 1
        event.host_id = host_id
        event.minimum_role = minimum_role
        event.fingerprint = fingerprint
        event.updated = timestamp
    else:
        event = NotificationEvent(
            id=event_id, source=source, kind=kind, subject_type=subject_type,
            subject_id=subject_id, host_id=host_id,
            minimum_role=minimum_role, revision=1,
            fingerprint=fingerprint, created=timestamp, updated=timestamp)
        session.add(event)
    session.add(NotificationRevision(
        event_id=event_id, revision=event.revision,
        subject_revision=subject_revision, severity=severity, reason=reason,
        deep_link=deep_link, lifecycle=lifecycle, created=timestamp))
    # Unsequenced until committed; readers order by the sequence assigned later.
    session.add(NotificationArrival(
        event_id=event_id, revision=event.revision, created=time.time()))
    return event, True


def _user(session, username):
    from .identity import User
    user = session.get(User, username)
    return user if user and user.enabled and user.role in ROLES else None


def _allowed_roles(role):
    return [candidate for candidate, rank in ROLES.items() if rank <= ROLES[role]]


def _query(session, username, *, unread_only=False, include_dismissed=False,
           severity='', source='', host_id=''):
    user = _user(session, username)
    if not user:
        return None
    current = and_(
        NotificationRevision.event_id == NotificationEvent.id,
        NotificationRevision.revision == NotificationEvent.revision)
    own_state = and_(
        NotificationUserState.event_id == NotificationEvent.id,
        NotificationUserState.username == username)
    query = (select(NotificationEvent, NotificationRevision, NotificationUserState)
             .join(NotificationRevision, current)
             .outerjoin(NotificationUserState, own_state)
             .where(NotificationEvent.minimum_role.in_(_allowed_roles(user.role))))
    read_revision = func.coalesce(NotificationUserState.read_revision, 0)
    dismissed_revision = func.coalesce(NotificationUserState.dismissed_revision, 0)
    if unread_only:
        query = query.where(read_revision < NotificationEvent.revision)
    if not include_dismissed:
        query = query.where(dismissed_revision < NotificationEvent.revision)
    if severity:
        query = query.where(NotificationRevision.severity == severity)
    if source:
        query = query.where(NotificationEvent.source == source)
    if host_id:
        query = query.where(NotificationEvent.host_id == host_id)
    return query


def list_for_user(session, username, *, unread_only=False,
                  include_dismissed=False, severity='', source='', host_id='',
                  limit=50, offset=0):
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('Notification limit must be between 1 and 100')
    if type(offset) is not int or offset < 0:
        raise ValueError('Notification offset must be non-negative')
    severity, source, host_id = validate_filters(severity, source, host_id)
    query = _query(session, username, unread_only=unread_only,
                   include_dismissed=include_dismissed, severity=severity,
                   source=source, host_id=host_id)
    if query is None:
        return []
    rows = session.execute(query.order_by(
        NotificationEvent.updated.desc(), NotificationEvent.id).limit(limit).offset(offset))
    return [_item(event, revision, state) for event, revision, state in rows]


def _item(event, revision, state):
    return {
        'id': event.id,
        'revision': event.revision,
        'source': event.source,
        'kind': event.kind,
        'subject_type': event.subject_type,
        'subject_id': event.subject_id,
        'host_id': event.host_id,
        'severity': revision.severity,
        'reason': revision.reason,
        'deep_link': revision.deep_link,
        'lifecycle': revision.lifecycle,
        'created': revision.created,
        'read': bool(state and state.read_revision >= event.revision),
        'dismissed': bool(state and state.dismissed_revision >= event.revision),
    }


def unread_count(session, username):
    return count_for_user(session, username, unread_only=True, include_dismissed=False)


def stream_cursor(session, username):
    """Return a safe digest of all durable notification state visible to a user.

    The digest changes for a new/revised visible event, a current-role change, or
    this user's read/dismiss progress.  It contains no event text or identifiers.
    Aggregate inputs make equal timestamps safe and avoid loading event rows.
    """
    user = _user(session, username)
    if not user:
        return None
    roles = _allowed_roles(user.role)
    event_values = session.execute(select(
        func.count(NotificationEvent.id),
        func.coalesce(func.max(NotificationEvent.updated), 0),
        func.coalesce(func.sum(NotificationEvent.revision), 0),
    ).where(NotificationEvent.minimum_role.in_(roles))).one()
    state_values = session.execute(select(
        func.count(NotificationUserState.event_id),
        func.coalesce(func.max(NotificationUserState.updated), 0),
        func.coalesce(func.sum(NotificationUserState.read_revision), 0),
        func.coalesce(func.sum(NotificationUserState.dismissed_revision), 0),
    ).join(NotificationEvent, NotificationEvent.id == NotificationUserState.event_id)
      .where(NotificationUserState.username == username,
             NotificationEvent.minimum_role.in_(roles))).one()
    values = [user.role, *(str(value) for value in event_values),
              *(str(value) for value in state_values)]
    return hashlib.sha256(json.dumps(values, separators=(',', ':')).encode()).hexdigest()


def validate_filters(severity='', source='', host_id=''):
    if severity and severity not in SEVERITIES:
        raise ValueError('Invalid notification severity filter')
    source = _text('source filter', source, 40, identifier=True, empty=True)
    host_id = _text('host filter', host_id, 36, empty=True)
    return severity, source, host_id


def count_for_user(session, username, *, unread_only=False, include_dismissed=False,
                   severity='', source='', host_id=''):
    """Count only the current revisions visible to the user's current role."""
    severity, source, host_id = validate_filters(severity, source, host_id)
    query = _query(session, username, unread_only=unread_only,
                   include_dismissed=include_dismissed, severity=severity,
                   source=source, host_id=host_id)
    if query is None:
        return 0
    return session.scalar(select(func.count()).select_from(query.subquery()))


def _state(session, username, event_id, revision):
    user = _user(session, username)
    event = session.get(NotificationEvent, event_id)
    if not user or not event or event.minimum_role not in _allowed_roles(user.role):
        raise PermissionError('Notification unavailable')
    if type(revision) is not int or not 1 <= revision <= event.revision:
        raise ValueError('Invalid notification revision')
    state = session.get(NotificationUserState, (event_id, username))
    if not state:
        state = NotificationUserState(
            event_id=event_id, username=username, read_revision=0,
            dismissed_revision=0, updated=time.time())
        session.add(state)
    return event, state


def mark_read(session, username, event_id, revision, *, now=None):
    event, state = _state(session, username, event_id, revision)
    state.read_revision = max(state.read_revision, revision)
    state.updated = time.time() if now is None else now
    audit(session, 'read notification', f'{username} {event_id} revision {revision}')
    return state


READ_BATCH_LIMIT = 100
_EVENT_ID = re.compile(r'^[0-9a-f]{64}$')


def mark_read_batch(session, username, items, *, now=None):
    """Mark exactly the displayed revisions read for one user.

    ``items`` are ``(event_id, revision)`` pairs the client rendered.  Each pair
    follows ``mark_read`` semantics, so a revision published after the client
    loaded its page stays unread.  Events that no longer exist or are hidden
    from the user's current role are skipped without writing or disclosing
    which.  Malformed input rejects the whole batch before any write.  Read
    state never acknowledges, resolves, approves or remediates anything.
    """
    if not isinstance(items, (list, tuple)) or not 1 <= len(items) <= READ_BATCH_LIMIT:
        raise ValueError(f'Provide between 1 and {READ_BATCH_LIMIT} notifications')
    pairs = []
    for item in items:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise ValueError('Invalid notification batch item')
        event_id, revision = item
        if not isinstance(event_id, str) or not _EVENT_ID.match(event_id):
            raise ValueError('Invalid notification id')
        if type(revision) is not int or revision < 1:
            raise ValueError('Invalid notification revision')
        pairs.append((event_id, revision))
    if len({event_id for event_id, _ in pairs}) != len(pairs):
        raise ValueError('Duplicate notification id')
    user = _user(session, username)
    if not user:
        raise PermissionError('Notification unavailable')
    roles = set(_allowed_roles(user.role))
    events = {event.id: event for event in session.scalars(
        select(NotificationEvent).where(
            NotificationEvent.id.in_([event_id for event_id, _ in pairs])))}
    visible = []
    for event_id, revision in pairs:
        event = events.get(event_id)
        if not event or event.minimum_role not in roles:
            continue
        if revision > event.revision:
            raise ValueError('Invalid notification revision')
        visible.append((event_id, revision))
    states = {state.event_id: state for state in session.scalars(
        select(NotificationUserState).where(
            NotificationUserState.username == username,
            NotificationUserState.event_id.in_([event_id for event_id, _ in visible])))
    } if visible else {}
    stamp = time.time() if now is None else now
    marked = 0
    for event_id, revision in visible:
        state = states.get(event_id)
        if not state:
            state = NotificationUserState(
                event_id=event_id, username=username, read_revision=0,
                dismissed_revision=0, updated=stamp)
            session.add(state)
        if state.read_revision < revision:
            state.read_revision = revision
            state.updated = stamp
            marked += 1
    if marked:
        audit(session, 'read notifications',
              f'{username} marked {marked} shown notification revision(s) read')
    return {'marked': marked, 'already_read': len(visible) - marked,
            'unavailable': len(pairs) - len(visible)}


def dismiss(session, username, event_id, revision, *, now=None):
    event, state = _state(session, username, event_id, revision)
    state.dismissed_revision = max(state.dismissed_revision, revision)
    state.read_revision = max(state.read_revision, revision)
    state.updated = time.time() if now is None else now
    audit(session, 'dismiss notification', f'{username} {event_id} revision {revision}')
    return state


ARRIVAL_SEQUENCE_BATCH = 500


ARRIVAL_HEAD_SEED_ATTEMPTS = 20
# MySQL reports deadlocks (1213) and lock-wait timeouts (1205) as OperationalError.
_RETRYABLE_LOCK_ERRORS = {1205, 1213}


def _seed_arrival_head(session):
    """Insert the head row at the highest sequence already assigned."""
    start = session.scalar(select(func.max(NotificationArrival.seq))) or 0
    session.add(NotificationArrivalHead(id=1, head=start))
    session.commit()


def _ensure_arrival_head(factory):
    """Create the single sequencing head row once, safely across controllers.

    The existence check is a plain non-locking read, and the seed runs in its
    own transaction before any locking statement.  A locking ``UPDATE`` that
    misses the row would take a gap lock, and two such transactions then
    deadlock on their inserts (MySQL 1213).  Here concurrent first users only
    race on the primary-key insert: the loser gets a duplicate-key error, or a
    retryable lock error, and re-reads the committed row.
    """
    for _ in range(ARRIVAL_HEAD_SEED_ATTEMPTS):
        with factory() as session:
            if session.get(NotificationArrivalHead, 1) is not None:
                return
            try:
                _seed_arrival_head(session)
                return
            except IntegrityError:
                session.rollback()
            except OperationalError as error:
                session.rollback()
                code = error.orig.args[0] if getattr(error.orig, 'args', None) else None
                if code not in _RETRYABLE_LOCK_ERRORS:
                    raise
    raise RuntimeError('Notification arrival head could not be initialized')


def sequence_arrivals(factory=Session):
    """Assign arrival sequence numbers to committed, unsequenced arrivals.

    Each pass runs in its own short transaction whose first statement writes the
    single head row, so concurrent sequencers (and SQLite writers) serialize
    before reading.  On MySQL the pass's snapshot therefore starts after the
    previous pass committed, and only rows already committed by producers are
    visible to it.  Numbers are dense and strictly above every earlier pass, and
    a pass commits atomically, so readers only ever see a complete prefix.
    Callers must not hold uncommitted writes in another session on SQLite.
    Returns the committed head.
    """
    _ensure_arrival_head(factory)
    while True:
        with factory() as session:
            session.execute(
                update(NotificationArrivalHead).where(NotificationArrivalHead.id == 1)
                .values(head=NotificationArrivalHead.head)
                .execution_options(synchronize_session=False))
            head = session.scalar(select(NotificationArrivalHead.head)
                                  .where(NotificationArrivalHead.id == 1))
            if head is None:
                raise RuntimeError('Notification arrival head is inconsistent')
            pending = session.scalars(
                select(NotificationArrival.id).where(NotificationArrival.seq.is_(None))
                .order_by(NotificationArrival.id).limit(ARRIVAL_SEQUENCE_BATCH)).all()
            if not pending:
                session.rollback()
                return head
            session.execute(update(NotificationArrival), [
                {'id': row_id, 'seq': head + index}
                for index, row_id in enumerate(pending, start=1)])
            head += len(pending)
            session.execute(update(NotificationArrivalHead)
                            .where(NotificationArrivalHead.id == 1).values(head=head)
                            .execution_options(synchronize_session=False))
            session.commit()
            if len(pending) < ARRIVAL_SEQUENCE_BATCH:
                return head


def arrivals_for_user(session, username, *, after=None, limit=50, factory=Session):
    """Return visible current revisions sequenced after an arrival cursor.

    Committed arrivals are sequenced first in a separate transaction, so
    ``session`` should not have begun a read snapshot yet (a fresh session is
    ideal).  Without ``after`` this returns only a baseline cursor covering every
    revision committed before the call.  Items use the list API shape plus
    ``arrival``.  Superseded revisions and events hidden from the caller's
    current role are skipped while the cursor still advances past them.  A
    cursor beyond the head (``reset_reason='ahead'``) or older than the oldest
    retained arrival (``reset_reason='pruned'``) is reset to a fresh baseline,
    so the client resynchronizes from the authoritative list and count APIs
    instead of silently skipping pruned revisions.
    """
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('Notification limit must be between 1 and 100')
    if after is not None and (type(after) is not int or after < 0):
        raise ValueError('Notification arrival cursor must be a non-negative integer')
    sequence_arrivals(factory)
    user = _user(session, username)
    if not user:
        return None
    # The durable head, not max(seq), so pruning never moves the cursor back.
    head = session.scalar(select(NotificationArrivalHead.head)
                          .where(NotificationArrivalHead.id == 1)) or 0
    if after is None:
        return {'items': [], 'cursor': head, 'more': False, 'reset': False}
    if after > head:
        return {'items': [], 'cursor': head, 'more': False, 'reset': True,
                'reset_reason': 'ahead'}
    if head == after:
        return {'items': [], 'cursor': after, 'more': False, 'reset': False}
    # Arrivals are numbered densely from 1 and pruned only as an oldest prefix,
    # so a cursor below the oldest retained arrival has missed pruned revisions.
    oldest = session.scalar(select(func.min(NotificationArrival.seq))
                            .where(NotificationArrival.seq.is_not(None)))
    if oldest is None or oldest > after + 1:
        return {'items': [], 'cursor': head, 'more': False, 'reset': True,
                'reset_reason': 'pruned'}
    own_state = and_(
        NotificationUserState.event_id == NotificationEvent.id,
        NotificationUserState.username == username)
    current = and_(
        NotificationRevision.event_id == NotificationEvent.id,
        NotificationRevision.revision == NotificationEvent.revision)
    found = session.execute(
        select(NotificationArrival.seq, NotificationEvent, NotificationRevision,
               NotificationUserState)
        .join(NotificationEvent, and_(
            NotificationEvent.id == NotificationArrival.event_id,
            NotificationEvent.revision == NotificationArrival.revision))
        .join(NotificationRevision, current)
        .outerjoin(NotificationUserState, own_state)
        .where(NotificationArrival.seq > after, NotificationArrival.seq <= head,
               NotificationEvent.minimum_role.in_(_allowed_roles(user.role)))
        .order_by(NotificationArrival.seq).limit(limit + 1)).all()
    items = [_item(event, revision, state) | {'arrival': seq}
             for seq, event, revision, state in found[:limit]]
    if len(found) > limit:
        return {'items': items, 'cursor': items[-1]['arrival'], 'more': True,
                'reset': False}
    return {'items': items, 'cursor': head, 'more': False, 'reset': False}


ARRIVAL_PRUNE_BATCH = 5000


def prune_arrivals(cutoff, *, factory=Session, batch=ARRIVAL_PRUNE_BATCH):
    """Delete the oldest contiguous prefix of sequenced arrivals before ``cutoff``.

    Only rows already numbered at or below the durable head are eligible, and
    pruning stops at the first retained-age row, so a later row with a lagging
    controller clock never leaves a hole below newer retained arrivals.  The
    head row is untouched, keeping current cursors valid; cursors that fall
    below the retained prefix are reported as a disclosed ``pruned`` reset.
    Each batch commits separately.  Returns the number of rows deleted.
    """
    if type(batch) is not int or batch < 1:
        raise ValueError('Notification arrival prune batch must be positive')
    deleted = 0
    while True:
        with factory() as session:
            head = session.scalar(select(NotificationArrivalHead.head)
                                  .where(NotificationArrivalHead.id == 1))
            if not head:
                return deleted
            keep = session.scalar(
                select(func.min(NotificationArrival.seq))
                .where(NotificationArrival.seq.is_not(None),
                       NotificationArrival.created >= cutoff))
            limit = head if keep is None else min(head, keep - 1)
            oldest = session.scalar(select(func.min(NotificationArrival.seq))
                                    .where(NotificationArrival.seq.is_not(None)))
            if oldest is None or oldest > limit:
                return deleted
            upper = min(limit, oldest + batch - 1)
            result = session.execute(
                delete(NotificationArrival)
                .where(NotificationArrival.seq.is_not(None),
                       NotificationArrival.seq <= upper)
                .execution_options(synchronize_session=False))
            session.commit()
            deleted += result.rowcount or 0
            if upper >= limit:
                return deleted
