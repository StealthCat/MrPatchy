"""Durable, role-filtered in-app notification events and per-user state.

This module deliberately does not acknowledge operational alerts, transition
incidents, approve AI output, or execute response actions.  Producers publish a
safe summary of an already committed subject; transports and UI consume it in a
later milestone.
"""
import hashlib
import json
import re
import time

from sqlalchemy import Double, Integer, String, Text, and_, func, select
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, audit


ROLES = {'viewer': 0, 'operator': 1, 'admin': 2}
SEVERITIES = {'info', 'low', 'medium', 'high', 'critical'}
LIFECYCLES = {'active', 'resolved'}
IDENTIFIER = re.compile(r'^[a-z0-9][a-z0-9_.-]*$')


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
    return [{
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
    } for event, revision, state in rows]


def unread_count(session, username):
    return count_for_user(session, username, unread_only=True, include_dismissed=False)


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


def dismiss(session, username, event_id, revision, *, now=None):
    event, state = _state(session, username, event_id, revision)
    state.dismissed_revision = max(state.dismissed_revision, revision)
    state.read_revision = max(state.read_revision, revision)
    state.updated = time.time() if now is None else now
    audit(session, 'dismiss notification', f'{username} {event_id} revision {revision}')
    return state
