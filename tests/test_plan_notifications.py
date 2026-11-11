"""Admin-only notifications for AI response plans awaiting review (#706)."""
import time

from sqlalchemy import func, select

from app import notifications, plan_notifications
from app.db import Host, Session
from app.identity import User
from app.incidents import Incident, PersistenceIncident, Plan


NOW = 1_000_000.0


def seed(session, *, host='plan-host', kind='security', plan_id='plan-1', created=NOW - 60, state='draft'):
    if not session.get(Host, host):
        session.add(Host(id=host, name=host, address='192.0.2.10', fingerprint='test'))
    incident_id = (kind + '-' + plan_id).ljust(64, '0')
    if kind == 'security':
        session.add(Incident(id=incident_id, host_id=host, scan_id='scan-1',
                             evidence={'path': '/tmp/evil', 'sha256': 'ab' * 32}))
    else:
        session.add(PersistenceIncident(id=incident_id, host_id=host, baseline_id='base-1',
                                        evidence={'path': '/etc/cron.d/x'}))
    session.add(Plan(id=plan_id, incident_id=incident_id, created=created, state=state,
                     evidence_digest='d' * 64,
                     content={'summary': 'AI says rm -rf / is fine', 'severity': 'critical',
                              'uncertainty': 'x', 'steps': []}))
    session.commit()


def revisions(session, plan_id='plan-1'):
    event = session.scalar(select(notifications.NotificationEvent).where(
        notifications.NotificationEvent.source == 'ai-plans',
        notifications.NotificationEvent.subject_id == plan_id))
    if event is None:
        return None, []
    rows = list(session.scalars(select(notifications.NotificationRevision).where(
        notifications.NotificationRevision.event_id == event.id).order_by(
        notifications.NotificationRevision.revision)))
    return event, rows


def sync(session, now=NOW):
    result = plan_notifications.sync(session, now)
    session.commit()
    return result


def test_draft_plans_publish_fixed_admin_only_review_notifications(admin):
    with Session() as s:
        seed(s, plan_id='plan-1')
        seed(s, kind='startup', plan_id='plan-2')
        assert sync(s) == (2, 0)
        event, rows = revisions(s, 'plan-1')
        assert event.kind == 'security-plan' and event.host_id == 'plan-host'
        assert event.minimum_role == 'admin' and event.subject_type == 'response-plan'
        assert [(r.lifecycle, r.severity) for r in rows] == [('active', 'medium')]
        assert rows[0].deep_link == '#servers/plan-host/security'
        # AI text and AI severity never reach the payload.
        assert 'rm -rf' not in rows[0].reason and 'critical' not in rows[0].reason
        startup, startup_rows = revisions(s, 'plan-2')
        assert startup.kind == 'startup-plan'
        # Startup-change plans are reviewed on the File integrity tab.
        assert startup_rows[0].deep_link == '#servers/plan-host/integrity'
        # Repeated passes over unchanged plans publish nothing new.
        assert sync(s, NOW + 30) == (0, 0)
        assert s.scalar(select(func.count()).select_from(notifications.NotificationRevision)) == 2
        s.add_all([User(username='viewer', password='x', role='viewer'),
                   User(username='operator', password='x', role='operator')])
        s.commit()
        assert notifications.list_for_user(s, 'viewer') == []
        assert notifications.list_for_user(s, 'operator') == []
        assert len(notifications.list_for_user(s, 'admin')) == 2


def test_approval_supersession_and_expiry_resolve_exactly_once(admin):
    with Session() as s:
        seed(s, plan_id='approved')
        seed(s, plan_id='superseded')
        seed(s, plan_id='expiring', created=NOW - plan_notifications.REVIEW_WINDOW + 100)
        assert sync(s) == (3, 0)
        s.get(Plan, 'approved').state = 'approved'
        s.get(Plan, 'superseded').state = 'superseded'
        s.commit()
        assert sync(s, NOW + 200) == (0, 3)
        expected = {'approved': 'approved', 'superseded': 'superseded', 'expiring': 'expired'}
        for plan_id, outcome in expected.items():
            _, rows = revisions(s, plan_id)
            assert [r.lifecycle for r in rows] == ['active', 'resolved']
            assert rows[-1].reason == plan_notifications.RESOLVED_REASON[outcome]
            assert rows[-1].severity == 'info'
        assert sync(s, NOW + 400) == (0, 0)


def test_deleted_server_or_plan_resolves_and_inactive_servers_never_publish(admin):
    with Session() as s:
        seed(s, host='gone-host', plan_id='host-deleted')
        seed(s, host='gone-host', plan_id='plan-deleted')
        assert sync(s) == (2, 0)
        s.get(Host, 'gone-host').deleted_at = NOW
        s.delete(s.get(Plan, 'plan-deleted'))
        s.commit()
        assert sync(s, NOW + 10) == (0, 2)
        for plan_id in ('host-deleted', 'plan-deleted'):
            _, rows = revisions(s, plan_id)
            assert rows[-1].lifecycle == 'resolved'
            assert rows[-1].reason == plan_notifications.RESOLVED_REASON['unavailable']
        seed(s, host='off-host', plan_id='disabled-host')
        s.get(Host, 'off-host').enabled = False
        s.commit()
        assert sync(s, NOW + 20) == (0, 0)
        assert revisions(s, 'disabled-host') == (None, [])


def test_read_dismiss_and_reconcile_never_change_plan_or_incident_state(admin):
    with Session() as s:
        seed(s, plan_id='plan-1')
        incident_id = s.get(Plan, 'plan-1').incident_id
        sync(s)
        event, _ = revisions(s)
        notifications.mark_read(s, 'admin', event.id, event.revision)
        notifications.dismiss(s, 'admin', event.id, event.revision)
        s.commit()
        sync(s, NOW + 30)
    with Session() as s:
        plan = s.get(Plan, 'plan-1')
        assert plan.state == 'draft' and plan.approved_by == '' and plan.expires == 0
        assert s.get(Incident, incident_id).state == 'open'
        _, rows = revisions(s)
        assert [r.lifecycle for r in rows] == ['active']


def test_still_reviewable_plans_beyond_the_batch_are_not_resolved(admin, monkeypatch):
    with Session() as s:
        seed(s, plan_id='a-plan', created=NOW - 200)
        seed(s, plan_id='b-plan', created=NOW - 100)
        assert sync(s) == (2, 0)
        monkeypatch.setattr(plan_notifications, 'BATCH', 1)
        # Only the oldest draft fits the window; the other must stay active.
        assert sync(s, NOW + 5) == (0, 0)
        for plan_id in ('a-plan', 'b-plan'):
            _, rows = revisions(s, plan_id)
            assert [r.lifecycle for r in rows] == ['active']


def test_bounded_scans_progress_past_unchanged_pages(admin, monkeypatch):
    # Unchanged drafts and still-reviewable active events must not hold the
    # bounded page forever: newer drafts publish and approvals resolve.
    monkeypatch.setattr(plan_notifications, 'BATCH', 1)
    with Session() as s:
        seed(s, plan_id='a', created=NOW - 300)
        assert sync(s) == (1, 0)
        seed(s, plan_id='b', created=NOW - 200)
        assert sync(s, NOW + 1) == (1, 0)
        s.get(Plan, 'b').state = 'approved'
        s.commit()
        seed(s, plan_id='c', created=NOW - 100)
        results = [sync(s, NOW + 2 + tick) for tick in range(3)]
        assert results == [(1, 1), (0, 0), (0, 0)]
        assert [r.lifecycle for r in revisions(s, 'a')[1]] == ['active']
        assert [r.lifecycle for r in revisions(s, 'b')[1]] == ['active', 'resolved']
        assert [r.lifecycle for r in revisions(s, 'c')[1]] == ['active']


def test_reenabled_server_reopens_its_still_reviewable_plan(admin):
    with Session() as s:
        seed(s, host='flappy', plan_id='plan-1')
        assert sync(s) == (1, 0)
        s.get(Host, 'flappy').enabled = False
        s.commit()
        assert sync(s, NOW + 10) == (0, 1)
        s.get(Host, 'flappy').enabled = True
        s.commit()
        assert sync(s, NOW + 20) == (1, 0)
        assert sync(s, NOW + 30) == (0, 0)
        assert [r.lifecycle for r in revisions(s)[1]] == ['active', 'resolved', 'active']


def test_tick_commits_its_own_session(admin):
    with Session() as s:
        seed(s, plan_id='plan-1', created=time.time() - 60)
    plan_notifications.tick(time.time())
    with Session() as s:
        event, rows = revisions(s)
        assert event is not None and [r.lifecycle for r in rows] == ['active']
