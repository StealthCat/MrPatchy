import pytest
from sqlalchemy import select
from app.admin_reset import reset
from app.db import Session, Setting, Audit
from app.identity import User
from app.security import verify


def test_reset_revokes_sessions_and_preserves_mfa(admin):
    with Session() as s:
        u=s.get(User,'admin');u.otp_secret='preserved';u.generation=7;s.commit()
    reset('admin','replacement-password-long')
    with Session() as s:
        u=s.get(User,'admin');assert verify('replacement-password-long',u.password)
        assert u.generation==8 and u.otp_secret=='preserved'
        assert verify('replacement-password-long',s.get(Setting,'admin').value['hash'])
        assert not list(s.scalars(select(Setting).where(Setting.key.like('session:%'))))
        assert 'replacement-password-long' not in str([(a.action,a.detail) for a in s.scalars(select(Audit))])
    assert admin.get('/api/identity').status_code==401


def test_reset_explicit_mfa_and_disabled_account_recovery(admin):
    with Session() as s:
        u=s.get(User,'admin');u.enabled=False;u.otp_secret='old';u.otp_pending='pending';u.otp_counter=44;s.commit()
    reset('admin','replacement-password-long',reset_mfa=True,enable=True)
    assert admin.post('/api/login',json={'password':'replacement-password-long'}).status_code==200
    with Session() as s:
        u=s.get(User,'admin');assert u.enabled and not u.otp_secret and not u.otp_pending and u.otp_counter==-1


def test_reset_refuses_missing_nonadmin_and_weak_password(admin):
    for username,password in [('missing','replacement-password-long'),('admin','weak')]:
        with pytest.raises(ValueError):reset(username,password)
    with Session() as s:
        u=s.get(User,'admin');u.role='viewer';s.commit()
    with pytest.raises(ValueError):reset('admin','replacement-password-long')


def test_user_management_audit_records_role_enabled_and_password(admin):
    assert admin.put('/api/users',json={'username':'bob','role':'viewer','password':'bob-password-long-1'}).status_code==200
    assert admin.put('/api/users',json={'username':'bob','role':'admin','enabled':False}).status_code==200
    with Session() as s:
        details=[a.detail for a in s.scalars(select(Audit).where(Audit.action=='manage user'))]
    assert any('bob' in d and 'role new → viewer' in d and 'password set: yes' in d for d in details)
    assert any('bob' in d and 'role viewer → admin' in d and 'enabled true → false' in d and 'password set: no' in d for d in details)
    assert 'bob-password-long-1' not in str(details)
