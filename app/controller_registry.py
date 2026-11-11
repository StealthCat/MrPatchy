"""Bounded controller web-instance self-reports for deployment health (roadmap H).

Display only: a record says a controller process reached the shared database recently. It is not
readiness, cluster membership, serving-role or failover evidence and authorizes nothing.
"""
import logging
import math
import os
import re
import threading
import time
import uuid
import hashlib
from sqlalchemy import select
from .coordination import Lock
from .db import Session, Setting, audit
from .worker_registry import FRESH_SECONDS, source_version

log = logging.getLogger(__name__)
PREFIX = 'controller-node:'  # 16 + 64 hex fits settings.key String(80)
INTERVAL = 15
SCAN_LIMIT = 2000  # bounded registration scan for newest-first ordering
IDENTITY = r'[A-Za-z0-9_.:-]{1,48}'
GAPS = [
    'Controller web instances self-report that they reached the shared database. HTTP serving, TLS/Caddy routing, readiness and load-balancer membership are not assessed.',
    'Expected controller identities come from MRPATCHY_EXPECTED_CONTROLLER_IDS on the instance answering this page; unconfigured controllers appear only after they register.',
    'Endpoint agents and GCP integration nodes are not inventoried here. A controller record carries no serving, failover or response authority.',
]


def record_key(identity):
    # ASCII hex avoids case/punctuation collation aliases in MySQL settings keys.
    return PREFIX + hashlib.sha256(identity.encode()).hexdigest()


class Presence:
    """Register this controller process and refresh its heartbeat from a daemon thread."""

    def __init__(self, scheduler):
        self.id = os.getenv('MRPATCHY_CONTROLLER_ID') or uuid.uuid4().hex
        if not re.fullmatch(IDENTITY, self.id):
            raise ValueError('MRPATCHY_CONTROLLER_ID must use 1-48 letters, numbers, dot, underscore, colon or hyphen')
        self.deployment = os.getenv('MRPATCHY_DEPLOYMENT_TYPE', 'process')
        if self.deployment not in ('docker', 'process'):
            raise ValueError('Unsupported reported deployment type')
        self.scheduler = 'embedded' if scheduler else 'disabled'
        self.boot = uuid.uuid4().hex
        self.started = time.time()
        self.monotonic = time.monotonic()
        self.version = source_version()
        self.lock = Lock('controller-identity:' + self.id)
        self.stop = threading.Event()
        self.thread = None

    def write(self, state, event=None):
        value = {'id': self.id, 'boot_id': self.boot, 'role': 'controller', 'deployment_type': self.deployment,
                 'version': self.version, 'scheduler': self.scheduler, 'started': self.started,
                 'heartbeat': time.time(), 'uptime_seconds': max(0, time.monotonic() - self.monotonic),
                 'state': state, 'readiness': 'not_assessed'}
        with Session() as s:
            s.merge(Setting(key=record_key(self.id), value=value))
            if event:
                audit(s, 'controller ' + event, self.id + ' ' + self.boot + ' ' + self.scheduler)
            s.commit()

    def loop(self):
        while not self.stop.wait(INTERVAL):
            try:
                self.write('reporting')
            except Exception:
                # A missed heartbeat surfaces as stale; it must never stop the web process.
                log.warning('Unable to refresh controller registration')

    def start(self):
        if not self.lock.acquire(False):
            raise ValueError('Controller identity is already in use; choose a unique MRPATCHY_CONTROLLER_ID')
        try:
            self.write('reporting', 'registered')
        except Exception:
            self.lock.release()
            raise
        self.thread = threading.Thread(target=self.loop, name='controller-registry', daemon=True)
        self.thread.start()
        return self

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(5)
        try:
            self.write('stopped', 'stopped')
        except Exception:
            log.warning('Unable to record controller shutdown')
        finally:
            try:
                self.lock.release()
            except Exception:
                log.warning('Unable to release controller identity lock')


def _number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0 else None


def _rank(value, now):
    heartbeat = _number(value.get('heartbeat')) if isinstance(value, dict) else None
    return heartbeat if heartbeat is not None and heartbeat <= now + 5 else -1


def report_state(data, now):
    heartbeat = _number(data.get('heartbeat'))
    age = now - heartbeat if heartbeat is not None else None
    if age is None or age < -5:
        return 'unknown', 'Heartbeat is missing, invalid or in the future; check clocks and controller logs.', age
    if data.get('state') == 'stopped':
        return 'stopped', 'Controller reported a graceful stop; this is retained registration history.', age
    if age > FRESH_SECONDS:
        return 'stale', 'Heartbeat expired; the controller may be stopped, unreachable or unable to write to this database.', age
    if data.get('state') != 'reporting':
        return 'unknown', 'Controller report state is not recognized.', age
    if not isinstance(data.get('version'), str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', data['version']):
        return 'unknown', 'Reported controller version is missing or unrecognized.', age
    if data['version'] != source_version():
        return 'version_mismatch', 'Reported controller version differs from the instance answering this page; compatibility is not certified.', age
    return 'reporting', 'Controller process wrote to the shared database recently; serving readiness is not assessed.', age


def page(offset=0, now=None):
    if offset < 0 or offset > 100000:
        raise ValueError('Invalid controller page')
    now = time.time() if now is None else now
    with Session() as s:
        # Order newest report first so a live controller is never pushed off the first page by retained
        # stopped/stale history (default installs register a new random identity on every start). Heartbeats
        # live in JSON, so sort a bounded scan in Python; a future or invalid heartbeat ranks last.
        scanned = list(s.scalars(select(Setting).where(Setting.key.startswith(PREFIX)).order_by(Setting.key).limit(SCAN_LIMIT + 1)))
        truncated = len(scanned) > SCAN_LIMIT
        scanned = sorted(scanned[:SCAN_LIMIT], key=lambda row: (-_rank(row.value, now), row.key))
        rows = scanned[offset:offset + 51]
        items = []
        for row in rows[:50]:
            data = row.value if isinstance(row.value, dict) else {}
            identity = data.get('id') if isinstance(data.get('id'), str) and re.fullmatch(IDENTITY, data['id']) else None
            item = {
                'id': identity or row.key[len(PREFIX):],
                'boot_id': data.get('boot_id') if re.fullmatch(r'[0-9a-f]{32}', str(data.get('boot_id', ''))) else None,
                'deployment_type': data.get('deployment_type') if data.get('deployment_type') in ('docker', 'process') else None,
                'scheduler': data.get('scheduler') if data.get('scheduler') in ('embedded', 'disabled') else None,
                'version': data.get('version') if isinstance(data.get('version'), str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', data['version']) else None,
                'started': _number(data.get('started')), 'heartbeat': _number(data.get('heartbeat')),
                'uptime_seconds': _number(data.get('uptime_seconds')),
            }
            state, reason, age = report_state(data, now)
            if identity is None or row.key != record_key(identity):
                state, reason = 'unknown', 'Registration record identity is invalid or does not match its key.'
            item.update(state=state, reason=reason, age_seconds=max(0, age) if age is not None else None, readiness='not_assessed')
            items.append(item)
    expected, error = expected_controllers(now)
    return {'items': items, 'more': len(rows) > 50, 'truncated': truncated, 'fresh_seconds': FRESH_SECONDS, 'gaps': GAPS,
            'expected': expected, 'expectation_error': error}


def expected_controllers(now):
    # Deployment configuration only. Never infer an absent process is stopped.
    raw = os.getenv('MRPATCHY_EXPECTED_CONTROLLER_IDS', '')
    if not raw.strip():
        return [], None
    identities = [value.strip() for value in raw.split(',')]
    if len(raw) > 5000 or len(identities) > 100 or any(not re.fullmatch(IDENTITY, v) for v in identities) or len(set(identities)) != len(identities):
        return [], ('Expected-controller configuration is invalid. Use at most 100 unique, case-sensitive controller IDs '
                    '(1–48 letters, numbers, dot, underscore, colon or hyphen), separated by commas.')
    items = []
    with Session() as s:
        for identity in identities:
            row = s.get(Setting, record_key(identity))
            data = row.value if row and isinstance(row.value, dict) else {}
            registered = data.get('id') == identity
            if registered:
                state, reason, age = report_state(data, now)
            else:
                state, reason, age = 'missing', 'No matching registration is available. The controller may be absent, misconfigured or unable to reach this database.', None
            items.append({'id': identity, 'registered': registered, 'state': state, 'reason': reason,
                          'age_seconds': max(0, age) if age is not None else None, 'readiness': 'not_assessed'})
    return items, None
