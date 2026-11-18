"""Administrator review completion for revoked fleet known-good candidates (#781)."""

from sqlalchemy import func, select

from app import ai_assessments, known_good, known_good_review, notifications, worker
from app.db import Audit, Behavior, Host, Session
from app.identity import User

from tests.test_known_good import complete, retained, sha
from tests.test_known_good_notifications import contradicting

SUMMARY = '/api/ai/known-good/summary'
NOTE = 'Checked both hosts; no follow-up needed'


def seed_reuse():
    """Publish a candidate on host-one and reuse it on host-two."""
    current = complete()
    current['host_id'] = 'host-two'
    current['investigation']['details']['known_good_context']['observation'] = {
        'host_id': 'host-two', 'pid': 99, 'start_ticks': 88, 'collected': 900}
    source = retained()
    with Session() as s:
        s.add_all([Host(id='host-one', name='Source', address='192.0.2.1', fingerprint=''),
                   Host(id='host-two', name='Current', address='192.0.2.2', fingerprint=''),
                   Behavior(id='behavior-one', host_id='host-one', evidence=complete(), verdict='low'),
                   Behavior(id='behavior-two', host_id='host-two', evidence=current, verdict='low'),
                   source])
        published = known_good.publish(s, source)
        s.flush()
        hit = known_good.lookup(s, current, 'gpt-fixture', [sha('9')])
        reused = ai_assessments.record_reuse(s, s.get(Behavior, 'behavior-two'), hit)
        s.flush()
        known_good.link_reuse(s, reused, hit)
        s.commit()
        return published, source.id, reused.id


def revoke(admin, published):
    response = admin.post('/api/ai/known-good/' + published['fingerprint'] + '/revoke',
                          json={'expected_version': published['version'],
                                'reason': 'A deterministic detector requires fleet review'})
    assert response.status_code == 200, response.text
    return response.json()


def review_path(published):
    return '/api/ai/known-good/' + published['fingerprint'] + '/review'


def status(admin, behavior, assessment):
    response = admin.get('/api/investigations/' + behavior + '/history/' + assessment)
    assert response.status_code == 200, response.text
    return response.json()['known_good']


def test_recorded_review_clears_review_required_without_restoring_trust(admin):
    published, source_id, reused_id = seed_reuse()
    revoked = revoke(admin, published)
    assert admin.get(SUMMARY).json()['reuse_assessments_pending_review'] == 1
    before = status(admin, 'behavior-two', reused_id)
    assert before['review_required'] and 'review_completed_at' not in before

    body = {'expected_version': published['version'],
            'expected_revoked_at': before['revoked_at'], 'note': NOTE}
    response = admin.post(review_path(published), json=body)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data['review_required'] is False and data['linked_assessments'] == 2
    assert data['review_completed_by'] == 'admin' and data['review_note'] == NOTE
    assert 'stays revoked' in data['detail']

    for behavior, assessment in (('behavior-one', source_id), ('behavior-two', reused_id)):
        after = status(admin, behavior, assessment)
        assert after['review_required'] is False
        assert after['active'] is False and after['published'] is False
        assert after['review_completed_by'] == 'admin' and after['review_note'] == NOTE
        assert after['reviewed_linked_assessments'] == 2
        assert after['revoked_reason'] == revoked['revoked_reason']
    summary = admin.get(SUMMARY).json()
    assert summary['reuse_assessments_on_revoked_entries'] == 1
    assert summary['reuse_assessments_pending_review'] == 0

    with Session() as s:
        entry = s.get(known_good.Entry, published['fingerprint'])
        assert not entry.active  # review never reactivates reuse
        current = complete()
        current['host_id'] = 'host-two'
        assert known_good.lookup(s, current, 'gpt-fixture', [sha('9')]) is None
        assert not s.get(Behavior, 'behavior-two').approved
        event = s.scalar(select(Audit).where(Audit.action == 'review revoked known-good candidate'))
        assert event and published['fingerprint'] in event.detail and 'linked=2' in event.detail
    # A repeated review of the same revocation is refused.
    assert admin.post(review_path(published), json=body).status_code == 409


def test_review_is_bound_to_revocation_version_and_linked_count(admin):
    published, _, reused_id = seed_reuse()
    revoke(admin, published)
    revoked_at = status(admin, 'behavior-two', reused_id)['revoked_at']
    path = review_path(published)
    body = {'expected_version': published['version'], 'expected_revoked_at': revoked_at, 'note': NOTE}
    assert admin.post(path, json={**body, 'expected_version': published['version'] + 1}).status_code == 409
    assert admin.post(path, json={**body, 'expected_revoked_at': revoked_at + 1}).status_code == 409
    assert admin.post(path, json=body).status_code == 200

    # An additional linked assessment (for example a late link) requires review again.
    with Session() as s:
        s.add(known_good.Observation(assessment_id='late-assessment', fingerprint=published['fingerprint'],
                                     host_id='host-three', subject='behavior-three', created=1000,
                                     observation={'host_id': 'host-three'}))
        s.commit()
    again = status(admin, 'behavior-two', reused_id)
    assert again['review_required'] is True and 'review_completed_at' not in again
    assert admin.get(SUMMARY).json()['reuse_assessments_pending_review'] == 1
    assert admin.post(path, json=body).status_code == 200
    assert status(admin, 'behavior-two', reused_id)['reviewed_linked_assessments'] == 3
    assert admin.get(SUMMARY).json()['reuse_assessments_pending_review'] == 0


def test_review_rejects_active_unknown_and_malformed_candidates_and_enforces_role_csrf_lock(admin):
    row = retained()
    with Session() as s:
        s.add(row)
        published = known_good.publish(s, row)
        s.commit()
    path = review_path(published)
    body = {'expected_version': 1, 'expected_revoked_at': 1.5, 'note': NOTE}
    assert admin.post(path, json=body).status_code == 409  # active candidate
    assert admin.post('/api/ai/known-good/' + 'e' * 64 + '/review', json=body).status_code == 404
    assert admin.post('/api/ai/known-good/not-a-fingerprint/review', json=body).status_code == 400
    assert admin.post(path, json={**body, 'note': ' short '}).status_code == 422
    assert admin.post(path, json={**body, 'note': '          x'}).status_code == 400
    assert admin.post(path, json=body, headers={'X-CSRF-Token': 'wrong'}).status_code == 403
    with Session() as s:
        s.get(User, 'admin').role = 'operator'
        s.commit()
    assert admin.post(path, json=body).status_code == 403
    with Session() as s:
        s.get(User, 'admin').role = 'admin'
        s.commit()
    lock = worker.Lock('ai-triage')
    assert lock.acquire(False)
    try:
        assert admin.post(path, json=body).status_code == 409
    finally:
        lock.release()
    with Session() as s:
        assert s.scalar(select(func.count()).select_from(known_good_review.Review)) == 0


def test_review_resolves_active_contradiction_notification_once(client):
    source = retained()
    row = contradicting('high')
    with Session() as s:
        s.add(User(username='admin-two', password='x', role='admin'))
        s.add_all([source, row])
        published = known_good.publish(s, source)
        s.flush()
        revoked = known_good.invalidate_contradiction(s, row, revoked_at=500)
        s.commit()
        result = known_good_review.record(s, published['fingerprint'], revoked['version'], 500.0,
                                          'admin', NOTE, now=600)
        s.commit()
        assert result['resolved_notifications'] == 1
        items = notifications.list_for_user(s, 'admin-two')
        revisions = list(s.scalars(select(notifications.NotificationRevision)
                                   .order_by(notifications.NotificationRevision.revision)))
    assert [r.lifecycle for r in revisions] == ['active', 'resolved']
    assert revisions[1].reason == known_good_review.RESOLVED_REASON
    assert revisions[1].deep_link == revisions[0].deep_link
    assert NOTE not in revisions[1].reason
    assert len(items) == 1 and items[0]['lifecycle'] == 'resolved'


def test_review_without_notification_publishes_nothing(admin):
    published, _, reused_id = seed_reuse()
    revoke(admin, published)
    revoked_at = status(admin, 'behavior-two', reused_id)['revoked_at']
    revision = notifications.NotificationRevision

    def counts():
        with Session() as s:
            return {lifecycle: s.scalar(select(func.count()).select_from(revision).where(
                revision.lifecycle == lifecycle)) for lifecycle in ('active', 'resolved')}

    # Revocation itself may publish an administrator notification (#779/#780);
    # recording the review must never publish a new active one, and may only
    # resolve whatever revocation notification already exists.
    before = counts()
    response = admin.post(review_path(published), json={
        'expected_version': published['version'], 'expected_revoked_at': revoked_at, 'note': NOTE})
    assert response.status_code == 200
    after = counts()
    assert after['active'] == before['active']
    assert response.json()['resolved_notifications'] == after['resolved'] - before['resolved']
    assert response.json()['resolved_notifications'] == before['active']
