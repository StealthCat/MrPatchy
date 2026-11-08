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


@pytest.mark.parametrize('manager,name,version,purl',[
    ('deb','example-pkg','1:2.0+fix-3','pkg:deb/example-pkg@1%3A2.0%2Bfix-3?arch=amd64'),
    ('rpm','Example_pkg','2.0+fix-3','pkg:rpm/Example_pkg@2.0%2Bfix-3?arch=x86_64&epoch=1'),
])
def test_populated_sbom(admin,manager,name,version,purl):
    host_id=seed_host(admin,manager)
    seed_host(admin,manager)  # Another server's packages must not leak into this export.
    response=admin.get(f'/api/hosts/{host_id}/sbom')
    assert response.status_code==200
    bom=response.json()
    assert bom['bomFormat']=='CycloneDX' and bom['specVersion']=='1.5' and bom['version']==1
    UUID(bom['serialNumber'].removeprefix('urn:uuid:'))
    assert bom['components']==[{'type':'library','name':name,'version':version,'purl':purl}]


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


def test_rpm_sbom_lists_every_installed_version_with_distro_purls(admin):
    host_id=seed_host(admin,'rpm')
    with Session() as s:
        s.get(Host,host_id).inventory={'package_manager':'rpm','os':'ID="rocky"\nVERSION_ID="9.4"\n','rpm_packages':[
            {'name':'kernel','arch':'x86_64','evr':'0:5.14.0-427.el9'},
            {'name':'kernel','arch':'x86_64','evr':'0:5.14.0-503.el9'},
            {'name':'bash','arch':'x86_64','evr':'2:5.1-1.el9'}]}
        s.commit()
    components=admin.get(f'/api/hosts/{host_id}/sbom').json()['components']
    assert [(c['name'],c['version']) for c in components]==[('bash','5.1-1.el9'),('kernel','5.14.0-427.el9'),('kernel','5.14.0-503.el9')]
    assert components[0]['purl']=='pkg:rpm/rocky/bash@5.1-1.el9?arch=x86_64&epoch=2&distro=rocky-9.4'
    assert components[2]['purl']=='pkg:rpm/rocky/kernel@5.14.0-503.el9?arch=x86_64&distro=rocky-9.4'


def test_deb_sbom_purl_has_vendor_namespace_and_distro(admin):
    host_id=seed_host(admin,'deb')
    with Session() as s:
        s.get(Host,host_id).inventory={'package_manager':'deb','os':'ID=debian\nVERSION_ID="12"\n'}
        s.commit()
    component=admin.get(f'/api/hosts/{host_id}/sbom').json()['components'][0]
    assert component['purl']=='pkg:deb/debian/example-pkg@1%3A2.0%2Bfix-3?arch=amd64&distro=debian-12'
