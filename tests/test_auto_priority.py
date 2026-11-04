from app import apt
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
