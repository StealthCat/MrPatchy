import copy

from sqlalchemy import func, select

from app import ai_assessments, known_good
from app.db import Audit, Behavior, Host, Session
from tests.test_known_good import complete, retained, sha


def other_host(host_id, pid):
    snapshot = complete();snapshot['host_id'] = host_id
    snapshot['investigation']['details']['context']['process'] = {'pid': pid, 'start_ticks': pid}
    snapshot['investigation']['details']['known_good_context']['observation'] = {
        'host_id': host_id, 'pid': pid, 'start_ticks': pid, 'collected': 900 + pid}
    return snapshot


def seed():
    """Origin on host-one, an exact reuse on host-two and an independent link on host-three."""
    with Session() as s:
        s.add_all([Host(id='host-one', name='Origin <one>', address='192.0.2.1', fingerprint=''),
            Host(id='host-two', name='Reuser', address='192.0.2.2', fingerprint=''),
            Host(id='host-three', name='Retired', address='192.0.2.3', fingerprint='',
                enabled=False)])
        origin = retained();origin.created = 100
        s.add_all([origin, Behavior(id='behavior-one', host_id='host-one',
            evidence=complete(), verdict='low')])
        published = known_good.publish(s, origin);s.flush()
        current = other_host('host-two', 99)
        behavior = Behavior(id='behavior-two', host_id='host-two', evidence=current, verdict='low')
        s.add(behavior);s.flush()
        hit = known_good.lookup(s, current, 'gpt-fixture', [sha('9')])
        reused = ai_assessments.record_reuse(s, behavior, hit);reused.created = 300;s.flush()
        known_good.link_reuse(s, reused, hit)
        independent = retained('assessment-three', 'host-three', 'behavior-three',
            other_host('host-three', 77));independent.created = 200
        s.add(independent);known_good.publish(s, independent);s.commit()
        return published['fingerprint'], origin.id, reused.id


def url(fingerprint, query=''):
    return f'/api/ai/known-good/{fingerprint}/observations{query}'


def test_lists_origin_reuse_and_independent_links_newest_first_without_evidence(admin):
    fingerprint, origin, reused = seed()
    with Session() as s:
        audits = s.scalar(select(func.count(Audit.id)))
    response = admin.get(url(fingerprint))
    assert response.status_code == 200
    body = response.json()
    assert body['fingerprint'] == fingerprint and body['version'] == 1 and body['active']
    assert body['total'] == 3 and not body['more'] and body['offset'] == 0
    assert body['origin_assessment_id'] == origin
    assert body['origin'] == {'host_id': 'host-one', 'host_name': 'Origin <one>', 'host_active': True}
    assert [(i['assessment_id'], i['role'], i['host_id'], i['host_active']) for i in body['items']] == [
        (reused, 'reuse', 'host-two', True),
        ('assessment-three', 'linked', 'host-three', False),
        (origin, 'origin', 'host-one', True)]
    assert body['items'][0]['subject'] == 'behavior-two'
    for item in body['items']:
        assert set(item) == {'assessment_id', 'subject', 'created', 'role',
            'host_id', 'host_name', 'host_active'}
    text = response.text
    for forbidden in ('pid', 'start_ticks', 'snapshot', 'explanation', 'ephemeral', 'contract'):
        assert forbidden not in text
    with Session() as s:
        assert s.scalar(select(func.count(Audit.id))) == audits


def test_pagination_is_stable_and_bounded(admin):
    fingerprint, origin, reused = seed()
    first = admin.get(url(fingerprint, '?limit=2')).json()
    second = admin.get(url(fingerprint, '?offset=2&limit=2')).json()
    assert [i['assessment_id'] for i in first['items']] == [reused, 'assessment-three']
    assert first['more'] and not second['more'] and second['offset'] == 2
    assert [i['assessment_id'] for i in second['items']] == [origin]
    for query in ('?offset=-1', '?limit=0', '?limit=51'):
        assert admin.get(url(fingerprint, query)).status_code == 400


def test_equal_timestamps_break_ties_by_assessment_id(admin):
    fingerprint, origin, reused = seed()
    with Session() as s:
        for row in s.scalars(select(known_good.Observation)):
            row.created = 50
        s.commit()
    items = admin.get(url(fingerprint)).json()['items']
    assert [i['assessment_id'] for i in items] == sorted([origin, reused, 'assessment-three'])


def test_revoked_candidate_still_lists_links_for_review(admin):
    fingerprint, origin, reused = seed()
    response = admin.post(f'/api/ai/known-good/{fingerprint}/revoke', json={
        'expected_version': 1, 'reason': 'Fleet review after a new detector'})
    assert response.status_code == 200
    body = admin.get(url(fingerprint)).json()
    assert not body['active'] and body['revoked_at'] > 0 and body['total'] == 3


def test_invalid_and_unknown_fingerprints(admin):
    assert admin.get(url('not-a-fingerprint')).status_code == 400
    assert admin.get(url('A' * 64)).status_code == 400
    response = admin.get(url('f' * 64))
    assert response.status_code == 404 and response.json()['detail'] == 'Known-good candidate not found'


def test_requires_authentication(client):
    assert client.get(url('f' * 64)).status_code == 401


def test_page_reports_deleted_host_without_name(client):
    fingerprint, origin, reused = seed()
    with Session() as s:
        s.delete(s.get(Host, 'host-two'));s.commit()
        from app import known_good_links
        body = known_good_links.page(s, fingerprint)
    reuse = next(i for i in body['items'] if i['assessment_id'] == reused)
    assert reuse['host_name'] == '' and reuse['host_active'] is False
    assert copy.deepcopy(body)['total'] == 3
