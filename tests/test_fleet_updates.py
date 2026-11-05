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


def test_apt_and_rpm_candidates_keep_native_version_and_architecture_identity(admin):
    seed()
    with Session() as s:
        s.add_all([
            Package(id='h1:libssl3:amd64', host_id='h1', name='libssl3:amd64', installed='3.0.2-0ubuntu1.15', candidate='3.0.2-0ubuntu1.18', priority='high'),
            Package(id='h1:kernel:x86_64', host_id='h1', name='kernel:x86_64', installed='0:5.14.0-427.el9', candidate='1:5.14.0-503.el9', priority='high'),
        ]); s.commit()
    rows = {r['id']: r for r in admin.get('/api/fleet/updates', params={'priority': 'high'}).json()['items']}
    assert (rows['h1:libssl3:amd64']['name'], rows['h1:libssl3:amd64']['candidate']) == ('libssl3:amd64', '3.0.2-0ubuntu1.18')
    assert (rows['h1:kernel:x86_64']['installed'], rows['h1:kernel:x86_64']['candidate']) == ('0:5.14.0-427.el9', '1:5.14.0-503.el9')
    assert rows['h1:kernel:x86_64']['status'] == 'available' and rows['h1:kernel:x86_64']['name'] == 'kernel:x86_64'


def _status_fixture():
    from app.db import Job
    seed()
    with Session() as s:
        s.get(Package, 'h0:bash').dpkg_state = 'install ok half-configured'
        s.add(Package(id='h1:zlib', host_id='h1', name='zlib', installed='1', candidate='2', priority='low'))
        s.add(Package(id='h0:held-broken', host_id='h0', name='held-broken', installed='1', candidate='2', priority='low',
                      held=True, dpkg_state='install ok half-configured'))
        s.add(Job(id='j1', host_id='h1', action='patch', state='queued', payload={'packages': ['bash=2']}))
        s.add(Job(id='j2', host_id='h1', action='patch', state='running', payload={'packages': ['zlib=1']}))  # other version: not queued
        s.add(Job(id='j3', host_id='stale', action='patch', state='done', payload={'packages': ['vim=9']}))
        s.commit()


def test_status_filters_match_returned_row_states_and_totals(admin):
    _status_fixture()
    get = lambda **p: admin.get('/api/fleet/updates', params=p).json()
    every = {r['id']: r['status'] for r in get(limit=200)['items']}
    assert every == {'h0:bash': 'ineligible', 'h1:bash': 'queued', 'h0:curl:arm64': 'held', 'h0:held-broken': 'held',
                     'stale:vim': 'available', 'h1:zlib': 'available'}
    for state in ('available', 'queued', 'held', 'ineligible'):
        body = get(status=state)
        assert body['total'] == sum(v == state for v in every.values())
        assert {r['status'] for r in body['items']} <= {state}
        # Page boundaries: one row per page reaches exactly the filtered set.
        seen = [get(status=state, limit=1, offset=o)['items'][0]['id'] for o in range(body['total'])]
        assert sorted(seen) == sorted(k for k, v in every.items() if v == state)
        assert get(status=state, limit=1, offset=body['total'])['items'] == []
    installable = get(status='installable')
    assert installable['total'] == 3 and {r['status'] for r in installable['items']} == {'available', 'queued'}
    assert get(status='queued', host_id='h1')['total'] == 1 and get(status='queued', host_id='h0')['total'] == 0
    assert sum(get(status=s)['total'] for s in ('available', 'queued', 'held', 'ineligible')) == get()['total']


def test_page_query_projects_small_host_fields_only(admin):
    from sqlalchemy import event
    from app.db import engine
    _status_fixture()
    with Session() as s:
        h = s.get(Host, 'h0'); h.inventory = {'big': 'x' * 1000}; h.telemetry = {'t': 1}; h.baseline = {'b': 1}
        s.commit()
    statements = []
    capture = lambda conn, cursor, statement, *a: statements.append(statement)
    event.listen(engine, 'before_cursor_execute', capture)
    try:
        for params in ({}, {'status': 'queued'}, {'status': 'available', 'limit': 2}, {'scope': 'inactive'}):
            assert admin.get('/api/fleet/updates', params=params).status_code == 200
    finally:
        event.remove(engine, 'before_cursor_execute', capture)
    related = [st for st in statements if 'packages' in st or 'update_scores' in st or 'jobs' in st]
    assert related
    for st in related:
        for heavy in ('hosts.inventory', 'hosts.telemetry', 'hosts.baseline', 'hosts.integrity', 'jobs.output'):
            assert heavy not in st, (heavy, st)
