from sqlalchemy import func, select

from app import ai_assessments, known_good
from app.db import Audit, Behavior, Host, Session
from tests.test_known_good import complete, retained, sha

URL = '/api/ai/known-good/candidates'


def variant(host_id, pid, executable_sha):
    """A complete snapshot for another host; a different artifact hash gives a new fingerprint."""
    snapshot = complete();snapshot['host_id'] = host_id
    snapshot['investigation']['details']['context']['process'] = {'pid': pid, 'start_ticks': pid}
    snapshot['investigation']['details']['known_good_context']['observation'] = {
        'host_id': host_id, 'pid': pid, 'start_ticks': pid, 'collected': 900 + pid}
    if executable_sha:
        snapshot['sha256'] = executable_sha
        snapshot['investigation']['details']['known_good_context']['artifact']['sha256'] = executable_sha
    return snapshot


def seed():
    """Candidate A (host-one, reused on host-two) and newer candidate B (inactive host-three)."""
    with Session() as s:
        s.add_all([Host(id='host-one', name='Origin <one>', address='192.0.2.1', fingerprint=''),
            Host(id='host-two', name='Reuser', address='192.0.2.2', fingerprint=''),
            Host(id='host-three', name='Retired', address='192.0.2.3', fingerprint='', enabled=False)])
        origin = retained();origin.created = 100
        s.add_all([origin, Behavior(id='behavior-one', host_id='host-one', evidence=complete(), verdict='low')])
        first = known_good.publish(s, origin)['fingerprint'];s.flush()
        current = variant('host-two', 99, None)
        behavior = Behavior(id='behavior-two', host_id='host-two', evidence=current, verdict='low')
        s.add(behavior);s.flush()
        hit = known_good.lookup(s, current, 'gpt-fixture', [sha('9')])
        assert hit
        reused = ai_assessments.record_reuse(s, behavior, hit);reused.created = 300;s.flush()
        known_good.link_reuse(s, reused, hit)
        other = retained('assessment-three', 'host-three', 'behavior-three',
            variant('host-three', 77, sha('c')));other.created = 200
        s.add(other);second = known_good.publish(s, other)['fingerprint'];s.commit()
        assert first != second
        return first, second


def test_lists_newest_first_with_counts_and_no_evidence(admin):
    first, second = seed()
    with Session() as s:
        audits = s.scalar(select(func.count(Audit.id)))
    response = admin.get(URL + '?state=all')
    assert response.status_code == 200
    body = response.json()
    assert body['state'] == 'all' and body['offset'] == 0 and not body['more']
    assert [i['fingerprint'] for i in body['items']] == [second, first]
    newer, older = body['items']
    assert newer['origin'] == {'host_id': 'host-three', 'host_name': 'Retired', 'host_active': False}
    assert (newer['linked'], newer['reused']) == (1, 0)
    assert older['origin'] == {'host_id': 'host-one', 'host_name': 'Origin <one>', 'host_active': True}
    assert older['origin_assessment_id'] == 'assessment-one' and older['origin_subject'] == 'behavior-one'
    assert (older['linked'], older['reused']) == (2, 1)
    assert older['active'] and older['revoked_at'] == 0 and older['revoked_by'] == ''
    assert older['version'] == 1 and older['model'] == 'gpt-fixture' and older['classification_source'] == 'ai'
    for item in body['items']:
        assert set(item) == {'fingerprint', 'version', 'created', 'classification_source', 'model',
            'origin_assessment_id', 'origin_subject', 'origin', 'active', 'revoked_at',
            'revoked_by', 'revoked_reason', 'linked', 'reused'}
    for forbidden in ('contract', 'snapshot', 'explanation', 'start_ticks', 'pid', 'manifest'):
        assert forbidden not in response.text
    with Session() as s:
        assert s.scalar(select(func.count(Audit.id))) == audits


def test_state_filter_and_revocation_metadata(admin):
    first, second = seed()
    assert [i['fingerprint'] for i in admin.get(URL).json()['items']] == [second, first]
    assert admin.get(URL + '?state=revoked').json()['items'] == []
    revoked = admin.post(f'/api/ai/known-good/{first}/revoke', json={
        'expected_version': 1, 'reason': 'Fleet review after a new detector'})
    assert revoked.status_code == 200
    assert [i['fingerprint'] for i in admin.get(URL + '?state=active').json()['items']] == [second]
    items = admin.get(URL + '?state=revoked').json()['items']
    assert [i['fingerprint'] for i in items] == [first]
    assert not items[0]['active'] and items[0]['revoked_at'] > 0
    assert items[0]['revoked_by'] == 'admin' and items[0]['revoked_reason'] == 'Fleet review after a new detector'
    assert (items[0]['linked'], items[0]['reused']) == (2, 1)


def test_pagination_is_stable_bounded_and_ties_break_by_fingerprint(admin):
    first, second = seed()
    with Session() as s:
        for row in s.scalars(select(known_good.Entry)):
            row.created = 50
        s.commit()
    one = admin.get(URL + '?state=all&limit=1').json()
    two = admin.get(URL + '?state=all&offset=1&limit=1').json()
    assert one['more'] and not two['more'] and two['offset'] == 1
    assert [one['items'][0]['fingerprint'], two['items'][0]['fingerprint']] == sorted([first, second])
    for query in ('?offset=-1', '?limit=0', '?limit=51', '?state=expired', '?state=ACTIVE'):
        assert admin.get(URL + query).status_code == 400


def test_missing_origin_assessment_and_deleted_host(admin):
    first, second = seed()
    with Session() as s:
        s.delete(s.get(ai_assessments.Assessment, 'assessment-three'))
        s.delete(s.get(Host, 'host-three'));s.commit()
    item = next(i for i in admin.get(URL).json()['items'] if i['fingerprint'] == second)
    assert item['origin_subject'] == '' and item['origin']['host_name'] == ''
    assert item['origin']['host_active'] is False


def test_empty_cache(admin):
    assert admin.get(URL + '?state=all').json() == {'state': 'all', 'offset': 0, 'items': [], 'more': False}


def test_requires_admin(client, admin):
    from app.identity import User
    with Session() as s:
        s.get(User, 'admin').role = 'viewer';s.commit()
    assert admin.get(URL).status_code == 403
    with Session() as s:
        s.get(User, 'admin').role = 'operator';s.commit()
    assert admin.get(URL).status_code == 403
    admin.cookies.clear()
    assert admin.get(URL).status_code == 401
