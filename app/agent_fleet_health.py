"""Read-only, redacted fleet view of managed endpoint-agent health (roadmap H).

The view reuses the retained per-server agent verification written by
``agent_maintenance.inspect`` and the telemetry collection time. It never runs
an inspection, queues a repair, or changes policy or authorization.
"""
import math
import time

from sqlalchemy import select
from sqlalchemy.orm import load_only

from .agent_spool_health import STALE_SECONDS as TELEMETRY_STALE_SECONDS
from .db import Host, Session, Setting

PAGE_SIZE = 50
VERIFICATION_STALE_SECONDS = 600
CLOCK_SKEW_SECONDS = 120
SYSTEMD_UNIT = '/etc/systemd/system/mrpatchy-agent.service'
HEALTH_ORDER = ('offline', 'degraded', 'unknown', 'healthy')
_RANK = {name: index for index, name in enumerate(HEALTH_ORDER)}
VERIFICATION_STATES = ('current', 'outdated', 'drifted', 'blocked', 'unavailable')
GAPS = [
    'Only enabled, non-deleted servers are listed. Disabled servers are not monitored.',
    'Verification is a periodic read-only receipt over the management connection, not independent attestation of a compromised host.',
    'Deployment type is shown only when the retained receipt names the expected systemd unit; otherwise it is not verified.',
    'Resource metrics, readiness and alerts for endpoint agents are not assessed here.',
]


def _timestamp(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) and value > 0 else None


def _deployment_type(status):
    report = status.get('report') if isinstance(status, dict) else None
    if isinstance(report, dict) and report.get('unit_path') == SYSTEMD_UNIT and status.get('state') != 'unavailable':
        return 'systemd'
    return None


def classify(host, status, now):
    """Classify one server's agent from retained records. Pure; returns redacted fields only."""
    collected = _timestamp((host.telemetry or {}).get('collected') if isinstance(host.telemetry, dict) else None)
    if collected is not None and collected > now + CLOCK_SKEW_SECONDS:
        telemetry = 'invalid'
    elif collected is None:
        telemetry = 'missing'
    else:
        telemetry = 'stale' if now - collected > TELEMETRY_STALE_SECONDS else 'fresh'
    status = status if isinstance(status, dict) else None
    state = status.get('state') if status else None
    state = state if state in VERIFICATION_STATES else None
    checked = _timestamp(status.get('checked')) if status else None
    issues = status.get('issues') if status else None
    issue_count = len(issues) if isinstance(issues, list) else 0
    age = None if checked is None else max(0.0, now - checked)
    row = {
        'host_id': host.id, 'name': host.name,
        'deployment_type': _deployment_type(status),
        'verification': {'state': state, 'checked': checked, 'age_seconds': None if age is None else math.floor(age),
                         'issue_count': issue_count},
        'telemetry': {'state': telemetry, 'collected': collected if telemetry != 'invalid' else None},
    }

    def result(health, reason):
        row['health'] = health
        row['reason'] = reason
        return row

    if host.state == 'enrolling':
        return result('unknown', 'Enrollment is incomplete, so the agent has not been verified yet.')
    if state == 'unavailable':
        return result('offline', 'The last live agent verification could not be completed over the management connection.')
    if host.state == 'offline':
        return result('offline', 'The last telemetry collection failed; the server is marked offline.')
    if status is None or state is None or checked is None:
        return result('unknown', 'No valid agent verification has been recorded yet.')
    if checked > now + CLOCK_SKEW_SECONDS:
        return result('unknown', 'The recorded verification time is in the future; the current state cannot be trusted.')
    if age > VERIFICATION_STALE_SECONDS:
        return result('unknown', f'The last verification is older than {VERIFICATION_STALE_SECONDS} seconds; the current state is unknown.')
    if state == 'blocked':
        return result('degraded', 'Verification found changes that need administrator review before repair.')
    if state == 'drifted':
        return result('degraded', 'Verification found unexpected managed-file or service drift.')
    if state == 'outdated':
        return result('degraded', 'Managed helpers are verified but outdated.')
    if telemetry == 'invalid':
        return result('unknown', 'Telemetry reports a future collection time; freshness cannot be verified.')
    if telemetry != 'fresh':
        return result('degraded', f'The agent is verified, but telemetry is {telemetry} (older than {TELEMETRY_STALE_SECONDS} seconds or absent).')
    return result('healthy', 'The agent is verified current and telemetry is fresh.')


def page(offset=0, now=None):
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError('Offset must be a non-negative integer')
    now = time.time() if now is None else now
    with Session() as s:
        query = select(Host).options(load_only(Host.id, Host.name, Host.state, Host.telemetry)).where(
            Host.deleted_at == 0, Host.enabled == True)  # noqa: E712
        hosts = s.scalars(query).all()
        keys = ['agent-status:' + host.id for host in hosts]
        statuses = {}
        for start in range(0, len(keys), 500):
            for row in s.scalars(select(Setting).where(Setting.key.in_(keys[start:start + 500]))):
                statuses[row.key[len('agent-status:'):]] = row.value
        rows = [classify(host, statuses.get(host.id), now) for host in hosts]
    rows.sort(key=lambda row: (_RANK[row['health']], (row['name'] or '').lower(), row['host_id']))
    counts = {name: 0 for name in HEALTH_ORDER}
    for row in rows:
        counts[row['health']] += 1
    items = rows[offset:offset + PAGE_SIZE]
    return {'generated_at': now, 'items': items, 'offset': offset, 'limit': PAGE_SIZE, 'total': len(rows),
            'more': offset + PAGE_SIZE < len(rows), 'counts': counts,
            'verification_stale_seconds': VERIFICATION_STALE_SECONDS,
            'telemetry_stale_seconds': TELEMETRY_STALE_SECONDS, 'gaps': GAPS}
