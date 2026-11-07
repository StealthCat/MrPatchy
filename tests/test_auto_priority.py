from app import apt
from sqlalchemy import select
from app.db import Session, Package
from tests.test_api import host


def test_auto_priority_requires_a_newer_candidate():
    assert apt.auto_priority('http://deb.debian.org/debian-security', '2.0') == 'high'
    assert apt.auto_priority('http://deb.debian.org/debian-security', '') == 'normal'
    assert apt.auto_priority('http://deb.debian.org/debian', '2.0') == 'normal'


def test_set_priority_auto_ignores_security_origin_without_candidate(admin):
    id = host(admin)
    with Session() as s:
        s.add(Package(id=id + ':nocand', host_id=id, name='nocand', installed='1', candidate='', origin='x/security', priority='low', priority_manual=True))
        s.add(Package(id=id + ':withcand', host_id=id, name='withcand', installed='1', candidate='2', origin='x/security', priority='low', priority_manual=True))
        s.commit()
    for name, want in (('nocand', 'normal'), ('withcand', 'high')):
        assert admin.put(f'/api/hosts/{id}/priority', json={'name': name, 'priority': 'auto'}).status_code == 200
        with Session() as s:
            p = s.get(Package, id + ':' + name)
            assert (p.priority, p.priority_manual) == (want, False)


def _rpm_host(id, manager='rpm'):
    from app.db import Host
    with Session() as s:
        h = s.get(Host, id)
        h.inventory = {**(h.inventory or {}), 'package_manager': manager}
        h.last_repo = 123.0
        s.commit()


def test_set_priority_auto_restores_stored_repository_priority_on_rpm(admin):
    id = host(admin)
    _rpm_host(id)
    with Session() as s:
        s.add(Package(id=id + ':openssl', host_id=id, name='openssl', installed='1', candidate='2', origin='baseos', priority='low', priority_manual=True, repository_priority='critical'))
        s.add(Package(id=id + ':legacy', host_id=id, name='legacy', installed='1', candidate='2', origin='baseos', priority='low', priority_manual=True))
        s.commit()
    assert admin.put(f'/api/hosts/{id}/priority', json={'name': 'openssl', 'priority': 'auto'}).status_code == 200
    with Session() as s:
        p = s.get(Package, id + ':openssl')
        assert (p.priority, p.priority_manual) == ('critical', False)
    # No stored classification: never apply the APT origin rule to RPM; force a refresh.
    assert admin.put(f'/api/hosts/{id}/priority', json={'name': 'legacy', 'priority': 'auto'}).status_code == 200
    from app.db import Host
    with Session() as s:
        p = s.get(Package, id + ':legacy')
        assert (p.priority, p.priority_manual) == ('low', False)
        assert s.get(Host, id).last_repo == 0


def _sequence_host(admin, monkeypatch, manager):
    from app import worker
    from app.db import Host
    id = host(admin)
    inv = {'package_manager': manager, 'status': 'fixture', 'files': {}, 'keys': {}}
    with Session() as s:
        h = s.get(Host, id)
        h.inventory = inv; h.state = 'offline'
        s.add(Package(id=id + ':openssl', host_id=id, name='openssl', installed='1'))
        s.commit()
    state = {'installed': '1', 'refresh': []}
    monkeypatch.setattr(worker.package_backend, 'installed', lambda inv: [{'name': 'openssl', 'installed': state['installed'], 'held': False, 'dpkg_state': 'install ok installed'}])
    monkeypatch.setattr(worker.package_backend, 'newer_flags', lambda inv, pairs: [False for _ in pairs])
    monkeypatch.setattr(worker.package_backend, 'refresh', lambda *a: (state['refresh'], ''))

    def refresh(item):
        state['refresh'] = [item]
        with Session() as s:
            worker.update_repos(s, s.get(Host, id))

    def install(version):
        state['installed'] = version
        with Session() as s:
            worker.save_inventory(s, s.get(Host, id), inv); s.commit()

    def set_priority(value):
        assert admin.put(f'/api/hosts/{id}/priority', json={'name': 'openssl', 'priority': value}).status_code == 200
        with Session() as s:
            p = s.get(Package, id + ':openssl')
            return p.priority, p.priority_manual

    return refresh, install, set_priority


def test_apt_auto_reset_after_install_ignores_stale_repository_classification(admin, monkeypatch):
    refresh, install, set_priority = _sequence_host(admin, monkeypatch, 'apt')
    refresh({'name': 'openssl', 'candidate': '2', 'origin': 'x/security', 'priority': 'high'})
    assert set_priority('low') == ('low', True)
    refresh({'name': 'openssl', 'candidate': '2', 'origin': 'x/security', 'priority': 'high'})
    assert set_priority('auto') == ('high', False)
    assert set_priority('low') == ('low', True)
    # Installing the candidate clears it; the cached classification must not survive.
    install('2')
    with Session() as s:
        assert s.get(Package, s.scalars(select(Package.id).where(Package.name == 'openssl')).first()).repository_priority == ''
    assert set_priority('auto') == ('normal', False)


def test_apt_auto_reset_uses_current_candidate_origin_not_cache(admin):
    id = host(admin)
    with Session() as s:
        s.add(Package(id=id + ':stale', host_id=id, name='stale', installed='1', candidate='3', origin='x/main', priority='low', priority_manual=True, repository_priority='high'))
        s.commit()
    assert admin.put(f'/api/hosts/{id}/priority', json={'name': 'stale', 'priority': 'auto'}).status_code == 200
    with Session() as s:
        p = s.get(Package, id + ':stale')
        assert (p.priority, p.priority_manual) == ('normal', False)


def test_rpm_auto_reset_restores_classification_until_candidate_is_installed(admin, monkeypatch):
    refresh, install, set_priority = _sequence_host(admin, monkeypatch, 'rpm')
    refresh({'name': 'openssl', 'candidate': '2', 'origin': 'baseos', 'priority': 'critical'})
    assert set_priority('low') == ('low', True)
    # A refresh under a manual override keeps the override but records the classification.
    refresh({'name': 'openssl', 'candidate': '2', 'origin': 'baseos', 'priority': 'critical'})
    assert set_priority('auto') == ('critical', False)
    assert set_priority('low') == ('low', True)
    install('2')
    assert set_priority('auto') == ('normal', False)
