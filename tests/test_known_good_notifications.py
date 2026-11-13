import pytest
from sqlalchemy import func, select

from app import known_good, known_good_notifications, notifications
from app.db import Session
from app.identity import User
from app.operations import Alert

from tests.test_known_good import complete, retained, sha

CONTRADICTION_ID = '33333333-3333-3333-3333-333333333333'


def contradicting(risk='high', snapshot=None, requested=None):
    return retained(CONTRADICTION_ID, 'host-two', 'behavior-two', snapshot or complete(), {
        'risk': risk, 'explanation': 'Fresh /usr/bin/fixture evidence <script> contradicts it',
        'recommended_checks': 'Review evidence', 'requested_checks': requested or []})


def seed_users(s):
    for name, role in (('admin-two', 'admin'), ('operator', 'operator'), ('viewer', 'viewer')):
        s.add(User(username=name, password='x', role=role))


def revisions(s):
    return list(s.scalars(select(notifications.NotificationRevision)
                          .order_by(notifications.NotificationRevision.revision)))


@pytest.mark.parametrize('risk,severity', [('high', 'high'), ('medium', 'medium'), ('unknown', 'medium')])
def test_automatic_contradiction_publishes_one_safe_admin_fleet_event(client, risk, severity):
    source = retained()
    row = contradicting(risk)
    with Session() as s:
        seed_users(s)
        s.add_all([source, row])
        published = known_good.publish(s, source)
        s.flush()
        revoked = known_good.invalidate_contradiction(s, row, revoked_at=500)
        s.commit()
        assert revoked['source_assessment_id'] == 'assessment-one'
        assert revoked['source_subject'] == 'behavior-one'
        # Already revoked: a repeated contradiction finds no active exact match.
        assert known_good.invalidate_contradiction(s, row) is None
        s.commit()
        saved = revisions(s)
        s_event = list(s.scalars(select(notifications.NotificationEvent)))
        admin_items = notifications.list_for_user(s, 'admin-two')
        hidden = (notifications.list_for_user(s, 'operator'), notifications.list_for_user(s, 'viewer'),
                  notifications.unread_count(s, 'operator'), notifications.unread_count(s, 'viewer'))
        alerts = s.scalar(select(func.count()).select_from(Alert))
    assert len(saved) == 1
    revision = saved[0]
    assert revision.severity == severity and revision.lifecycle == 'active'
    assert len(s_event) == 1
    event = s_event[0]
    assert event.minimum_role == 'admin' and event.host_id == ''
    assert revision.subject_revision == 'revoked:v' + str(published['version']) + ':' + CONTRADICTION_ID
    assert revision.deep_link == '#investigations/item/behavior-one/history/assessment-one'
    assert risk + ' risk' in revision.reason and '1 linked assessment(s)' in revision.reason
    for unsafe in ('/usr/bin', 'fixture', 'host-one', 'host-two', '<script>', 'Review evidence'):
        assert unsafe not in revision.reason
    assert len(admin_items) == 1
    item = admin_items[0]
    assert item['source'] == 'ai-known-good' and item['kind'] == 'candidate-contradicted'
    assert item['subject_id'] == published['fingerprint'] and item['host_id'] == ''
    assert hidden == ([], [], 0, 0)
    assert alerts == 0


def test_calls_that_revoke_nothing_publish_nothing(client):
    source = retained()
    changed = complete()
    changed['investigation']['details']['known_good_context']['behavior']['network_sha256'] = sha('0')
    with Session() as s:
        s.add(source)
        published = known_good.publish(s, source)
        s.flush()
        for row in (contradicting('low'), contradicting('high', requested=['executable']),
                    contradicting('high', snapshot=changed)):
            assert known_good.invalidate_contradiction(s, row) is None
        s.commit()
        assert s.get(known_good.Entry, published['fingerprint']).active
        assert revisions(s) == []


def test_rolled_back_contradiction_publishes_nothing(client):
    source = retained()
    with Session() as s:
        s.add(source)
        published = known_good.publish(s, source)
        s.commit()
        assert known_good.invalidate_contradiction(s, contradicting('high'))
        s.rollback()
    with Session() as s:
        assert s.get(known_good.Entry, published['fingerprint']).active
        assert revisions(s) == []


def test_concurrent_contradiction_after_unlocked_lookup_publishes_once(client, monkeypatch):
    """A contradiction that finds the candidate already revoked under the row
    lock (#759 idempotency) changes nothing and must announce nothing."""
    source = retained()
    with Session() as s:
        s.add(source)
        published = known_good.publish(s, source)
        s.commit()
    first = contradicting('high')
    second = retained('44444444-4444-4444-4444-444444444444', 'host-three', 'behavior-three',
                      complete(), {'risk': 'medium', 'explanation': 'Also unsafe',
                                   'recommended_checks': 'Review evidence', 'requested_checks': []})
    original, done = known_good.lookup, []

    def interleaved(s, *args, **kwargs):
        hit = original(s, *args, **kwargs)
        if not done:
            done.append(True)
            with Session() as other:
                other.add(first)
                assert known_good.invalidate_contradiction(other, first)
                other.commit()
        return hit

    monkeypatch.setattr(known_good, 'lookup', interleaved)
    with Session() as s:
        assert known_good.invalidate_contradiction(s, second) is None
        s.add(second)
        s.commit()
    with Session() as s:
        assert done and not s.get(known_good.Entry, published['fingerprint']).active
        rows = revisions(s)
        assert len(rows) == 1
        assert rows[0].subject_revision.endswith(CONTRADICTION_ID)


def revoke(admin, fingerprint, version, reason='Administrator review of <script>/usr/bin/fixture'):
    return admin.post('/api/ai/known-good/' + fingerprint + '/revoke',
                      json={'expected_version': version, 'reason': reason})


def test_administrator_revocation_publishes_one_safe_admin_fleet_event(admin):
    source = retained()
    with Session() as s:
        seed_users(s)
        s.add(source)
        published = known_good.publish(s, source)
        s.commit()
    response = revoke(admin, published['fingerprint'], published['version'])
    assert response.status_code == 200, response.text
    with Session() as s:
        assert not s.get(known_good.Entry, published['fingerprint']).active
        actor = s.get(known_good.Entry, published['fingerprint']).revoked_by
        saved = revisions(s)
        events = list(s.scalars(select(notifications.NotificationEvent)))
        admin_items = notifications.list_for_user(s, 'admin-two')
        hidden = (notifications.list_for_user(s, 'operator'), notifications.list_for_user(s, 'viewer'),
                  notifications.unread_count(s, 'operator'), notifications.unread_count(s, 'viewer'))
        alerts = s.scalar(select(func.count()).select_from(Alert))
    assert len(saved) == 1 and len(events) == 1
    revision, event = saved[0], events[0]
    assert event.minimum_role == 'admin' and event.host_id == ''
    assert revision.severity == 'medium' and revision.lifecycle == 'active'
    assert revision.subject_revision == 'revoked:v' + str(published['version']) + ':admin'
    assert revision.deep_link == '#investigations/item/behavior-one/history/assessment-one'
    assert revision.reason.startswith('Administrator ' + actor + ' revoked')
    assert '1 linked assessment(s)' in revision.reason
    # The free-form reason stays in the audit log and on the assessment history.
    for unsafe in ('Administrator review', '<script>', '/usr/bin', 'fixture', 'host-one'):
        assert unsafe not in revision.reason
    assert len(admin_items) == 1
    item = admin_items[0]
    assert item['source'] == 'ai-known-good' and item['kind'] == 'candidate-revoked'
    assert item['subject_id'] == published['fingerprint']
    assert hidden == ([], [], 0, 0)
    assert alerts == 0


def test_failed_administrator_revocations_publish_nothing(admin):
    source = retained()
    with Session() as s:
        s.add(source)
        published = known_good.publish(s, source)
        s.commit()
    assert revoke(admin, 'f' * 64, 1).status_code == 404
    assert revoke(admin, published['fingerprint'], published['version'] + 1).status_code == 409
    with Session() as s:
        assert s.get(known_good.Entry, published['fingerprint']).active
        assert revisions(s) == []
    assert revoke(admin, published['fingerprint'], published['version']).status_code == 200
    # Already revoked: the repeat is rejected and adds no second revision.
    assert revoke(admin, published['fingerprint'], published['version']).status_code == 409
    with Session() as s:
        assert len(revisions(s)) == 1


def test_contradiction_after_administrator_revocation_adds_no_contradiction_event(admin):
    source = retained()
    row = contradicting('high')
    with Session() as s:
        s.add(source)
        published = known_good.publish(s, source)
        s.commit()
    assert revoke(admin, published['fingerprint'], published['version']).status_code == 200
    with Session() as s:
        s.add(row)
        assert known_good.invalidate_contradiction(s, row) is None
        s.commit()
        kinds = [event.kind for event in s.scalars(select(notifications.NotificationEvent))]
    assert kinds == ['candidate-revoked']


def test_producer_ignores_missing_revocation_or_unsupported_risk(client):
    with Session() as s:
        assert known_good_notifications.publish_contradiction(s, None, 'high') is False
        assert known_good_notifications.publish_contradiction(
            s, {'fingerprint': 'f' * 64, 'version': 1}, 'low') is False
        assert revisions(s) == []
        assert known_good_notifications.publish_revocation(s, None, 'admin') is False
        assert known_good_notifications.publish_revocation(
            s, {'fingerprint': 'f' * 64, 'version': 1}, '  ') is False
        assert revisions(s) == []
