from uuid import UUID

import pytest

from app.db import Host, Package, Session
from app.identity import User


def seed_host(admin, manager='deb', populated=True):
    host_id=admin.post('/api/hosts',json={'name':'SBOM fixture','address':'192.0.2.21'}).json()['id']
    with Session() as s:
        s.get(Host,host_id).inventory={'package_manager':manager}
        if populated:
            name='Example_pkg:x86_64' if manager=='rpm' else 'example-pkg:amd64'
            s.add(Package(id=host_id+':'+name,host_id=host_id,name=name,installed='1:2.0+fix-3'))
        s.commit()
    return host_id


@pytest.mark.parametrize('manager,name,purl',[
    ('deb','example-pkg:amd64','pkg:deb/example-pkg@1%3A2.0%2Bfix-3?arch=amd64'),
    ('rpm','Example_pkg:x86_64','pkg:rpm/Example_pkg@1%3A2.0%2Bfix-3?arch=x86_64'),
])
def test_populated_sbom(admin,manager,name,purl):
    host_id=seed_host(admin,manager)
    seed_host(admin,manager)  # Another server's packages must not leak into this export.
    response=admin.get(f'/api/hosts/{host_id}/sbom')
    assert response.status_code==200
    bom=response.json()
    assert bom['bomFormat']=='CycloneDX' and bom['specVersion']=='1.5' and bom['version']==1
    UUID(bom['serialNumber'].removeprefix('urn:uuid:'))
    assert bom['components']==[{'type':'library','name':name,'version':'1:2.0+fix-3','purl':purl}]


def test_empty_and_missing_sbom(admin):
    host_id=seed_host(admin,populated=False)
    response=admin.get(f'/api/hosts/{host_id}/sbom')
    assert response.status_code==200 and response.json()['components']==[]
    assert admin.get('/api/hosts/missing/sbom').status_code==404


@pytest.mark.parametrize('role',['admin','operator','viewer'])
def test_sbom_role_and_lifecycle_access(admin,role):
    host_id=seed_host(admin)
    with Session() as s:
        s.get(User,'admin').role=role
        s.commit()
    assert admin.get(f'/api/hosts/{host_id}/sbom').status_code==200
    with Session() as s:
        s.get(Host,host_id).enabled=False
        s.commit()
    assert admin.get(f'/api/hosts/{host_id}/sbom').status_code==200
    with Session() as s:
        s.get(Host,host_id).deleted_at=1
        s.commit()
    assert admin.get(f'/api/hosts/{host_id}/sbom').status_code==(200 if role=='admin' else 403)
    admin.cookies.clear()
    assert admin.get(f'/api/hosts/{host_id}/sbom').status_code==401
