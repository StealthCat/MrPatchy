import pytest
from sqlalchemy import select

from app.db import Session, Host, Job, Setting


@pytest.mark.parametrize('method,suffix,extra',[
    ('post','',{}),('post','/yara',{'bundle_id':'fixture'}),
    ('put','/policy',{'enabled':True}),
    ('put','/execution-scans',{'enabled':True,'reason':'Reviewed scoped execution scanning'}),
])
def test_del_is_rejected_before_job_or_policy_write(admin,method,suffix,extra):
    with Session() as session:
        session.add(Host(id='path-host',name='Path',address='192.0.2.1',fingerprint=''))
        session.commit()
    response=getattr(admin,method)('/api/hosts/path-host/security'+suffix,
        json={'paths':['/tmp/review\x7fdir'],**extra})
    assert response.status_code==400
    with Session() as session:
        assert not list(session.scalars(select(Job)))
        assert session.get(Setting,'security-policy:path-host') is None
        assert session.get(Setting,'execution-scan-policy:path-host') is None
