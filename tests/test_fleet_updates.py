"""Fleet-wide Available patches API (#512): same scope as the Overview count, fully pageable."""
import time
from app.db import Session, Host, Package
from app.identity import User


def host(s, id, name=None, **kw):
    s.add(Host(id=id, name=name or id, address='192.0.2.1', fingerprint='', state=kw.pop('state', 'online'),
               last_seen=kw.pop('last_seen', time.time()), inventory={}, **kw))


def seed(extra=0):
    with Session() as s:
        host(s, 'h0', 'alpha'); host(s, 'h1', 'beta'); host(s, 'stale', 'gamma', last_seen=time.time() - 3600)
        host(s, 'off', 'off', enabled=False); host(s, 'gone', 'gone', deleted_at=1)
        s.add_all([
            Package(id='h0:bash', host_id='h0', name='bash', installed='1', candidate='2', priority='critical'),
            Package(id='h1:bash', host_id='h1', name='bash', installed='1', candidate='2', priority='critical'),
            Package(id='h0:curl:arm64', host_id='h0', name='curl:arm64', installed='1', candidate='3', priority='low', held=True),
            Package(id='h0:none', host_id='h0', name='none', installed='1', candidate=''),
            Package(id='stale:vim', host_id='stale', name='vim', installed='1', candidate='9', priority='normal'),
            Package(id='off:x', host_id='off', name='x', installed='1', candidate='2'),
            Package(id='gone:y', host_id='gone', name='y', installed='1', candidate='2'),
        ] + [Package(id=f'h1:p{i:03}', host_id='h1', name=f'p{i:03}', installed='1', candidate='2', priority='normal') for i in range(extra)])
        s.commit()


def test_total_matches_overview_and_rows_cover_every_host(admin):
    seed()
    body = admin.get('/api/fleet/updates').json()
    assert body['total'] == admin.get('/api/dashboard').json()['updates'] == 4
    assert [(r['host_name'], r['name']) for r in body['items']] == [
        ('alpha', 'bash'), ('beta', 'bash'), ('gamma', 'vim'), ('alpha', 'curl:arm64')]  # same package on two servers
    assert {r['host_id'] for r in body['items']}.isdisjoint({'off', 'gone'})
    stale = next(r for r in body['items'] if r['host_id'] == 'stale')
    assert stale['contact_stale'] and not body['items'][0]['contact_stale']
    assert next(r for r in body['items'] if r['held'])['candidate'] == '3'


def test_pagination_reaches_every_candidate_beyond_one_page(admin):
    seed(extra=250)
    seen = []
    for offset in (0, 200):
        page = admin.get('/api/fleet/updates', params={'limit': 200, 'offset': offset}).json()
        assert page['total'] == 254
        seen += [r['id'] for r in page['items']]
    assert len(seen) == len(set(seen)) == 254
    assert admin.get('/api/fleet/updates', params={'limit': 5000}).json()['limit'] == 200


def test_filters_and_zero_results(admin):
    seed()
    get = lambda **p: admin.get('/api/fleet/updates', params=p).json()
    assert get(host_id='h1')['total'] == 1
    assert get(q='bash')['total'] == 2
    assert get(priority='low')['total'] == 1
    assert get(status='held')['total'] == 1 and get(status='installable')['total'] == 3
    assert get(q='no-such-package') == {'items': [], 'total': 0, 'offset': 0, 'limit': 50, 'scope': 'active'}
    assert admin.get('/api/fleet/updates', params={'priority': 'urgent'}).status_code == 400
    assert admin.get('/api/fleet/updates', params={'status': 'x'}).status_code == 400


def test_viewer_can_read_and_view_is_read_only(admin):
    seed()
    with Session() as s: s.get(User, 'admin').role = 'viewer'; s.commit()
    with Session() as s: before = [(p.id, p.candidate, p.priority, p.held) for p in s.query(Package).order_by(Package.id)]
    assert admin.get('/api/fleet/updates', params={'q': 'bash', 'status': 'held'}).status_code == 200
    with Session() as s: assert before == [(p.id, p.candidate, p.priority, p.held) for p in s.query(Package).order_by(Package.id)]


def test_inactive_scope_lists_disabled_server_candidates_outside_active_totals(admin):
    seed()
    inactive = admin.get('/api/fleet/updates', params={'scope': 'inactive'}).json()
    assert inactive['scope'] == 'inactive' and inactive['total'] == 1
    assert [(r['id'], r['host_active']) for r in inactive['items']] == [('off:x', False)]  # deleted 'gone' stays hidden
    assert admin.get('/api/fleet/updates', params={'scope': 'inactive', 'host_id': 'off'}).json()['total'] == 1
    assert admin.get('/api/fleet/updates', params={'scope': 'inactive', 'host_id': 'gone'}).json()['total'] == 0
    assert admin.get('/api/fleet/updates', params={'host_id': 'off'}).json()['total'] == 0
    assert admin.get('/api/fleet/updates').json()['total'] == admin.get('/api/dashboard').json()['updates'] == 4
    assert admin.get('/api/fleet/updates', params={'scope': 'all'}).status_code == 400


def test_repository_freshness_and_candidate_status_are_distinguished(admin):
    from app.db import Job
    from app.update_scores import UpdateScore
    seed()
    now = time.time()
    with Session() as s:
        s.get(Host, 'h0').last_repo = now
        s.get(Host, 'h1').last_repo = now - 3 * 3600   # older than 2x the 60-minute repository interval
        s.get(Host, 'stale').last_repo = now; s.get(Host, 'stale').repo_error = 'mirror unreachable'
        s.get(Package, 'h0:bash').dpkg_state = 'install ok half-configured'
        s.add(Package(id='h1:zlib', host_id='h1', name='zlib', installed='1', candidate='2', priority='low'))
        s.add(Job(id='j1', host_id='h1', action='patch', state='queued', payload={'packages': ['bash=2']}))
        s.add(Job(id='j2', host_id='h1', action='patch', state='done', payload={'packages': ['zlib=2']}))
        s.add(UpdateScore(id='u1', host_id='h1', name='zlib', installed='1', candidate='2', state='deferred'))
        s.commit()
    rows = {r['id']: r for r in admin.get('/api/fleet/updates').json()['items']}
    assert rows['h1:bash']['status'] == 'queued'
    assert rows['h0:bash']['status'] == 'ineligible'
    assert rows['h0:curl:arm64']['status'] == 'held'
    assert rows['h1:zlib']['status'] == 'available' and rows['h1:zlib']['priority_deferred']
    assert not rows['h1:bash']['priority_deferred']
    assert rows['h0:bash']['repo_state'] == 'current' and rows['h1:bash']['repo_state'] == 'stale'
    assert rows['stale:vim']['repo_state'] == 'failed' and rows['stale:vim']['repo_error'] == 'mirror unreachable'
    with Session() as s: s.get(Host, 'h0').last_repo = 0; s.commit()
    assert {r['id']: r for r in admin.get('/api/fleet/updates').json()['items']}['h0:bash']['repo_state'] == 'unknown'
