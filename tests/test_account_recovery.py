import os
from app import sso
from app.db import Audit,Session,Setting
from app.identity import User
from app.security import password_hash
from sqlalchemy import select

def add_user(admin,name='carol'):
    assert admin.put('/api/users',json={'username':name,'role':'viewer','password':'carol-password-long-1'}).status_code==200
    with Session() as s:
        row=s.get(User,name);row.otp_secret='sealed';row.otp_pending='pending';row.otp_counter=7;s.commit()

def test_admin_resets_non_admin_mfa(admin):
    add_user(admin)
    with Session() as s:gen=s.get(User,'carol').generation
    pw=os.environ['ADMIN_PASSWORD']
    assert admin.post('/api/users/carol/mfa/reset',json={'password':'wrong-password-xx'}).status_code==403
    with Session() as s:assert s.get(User,'carol').otp_secret=='sealed'
    r=admin.post('/api/users/carol/mfa/reset',json={'password':pw})
    assert r.status_code==200 and r.json()['had_mfa'] is True
    with Session() as s:
        row=s.get(User,'carol')
        assert (row.otp_secret,row.otp_pending,row.otp_counter)==('','',-1) and row.generation==gen+1
        assert any(a.action=='reset user MFA' and 'carol' in a.detail for a in s.scalars(select(Audit)))
    assert admin.post('/api/users/nobody/mfa/reset',json={'password':pw}).status_code==404
    assert admin.post('/api/users/admin/mfa/reset',json={'password':pw}).status_code==400

def test_sso_bindings_list_replace_confirmation_and_delete(admin,monkeypatch):
    monkeypatch.setattr(sso,'issuer','https://issuer.example')
    add_user(admin,'carol');add_user(admin,'dave')
    r=admin.put('/api/operations/sso-binding',json={'subject':'sub-1','username':'carol'})
    assert r.status_code==200;digest=r.json()['subject_digest']
    assert admin.get('/api/operations/sso-bindings').json()==[{'subject_digest':digest,'username':'carol'}]
    assert admin.put('/api/operations/sso-binding',json={'subject':'sub-1','username':'dave'}).status_code==409
    assert admin.get('/api/operations/sso-bindings').json()[0]['username']=='carol'
    assert admin.put('/api/operations/sso-binding',json={'subject':'sub-1','username':'dave','replace_username':'carol'}).status_code==200
    with Session() as s:
        assert any(a.action=='bind SSO identity' and digest in a.detail and 'previous carol' in a.detail for a in s.scalars(select(Audit)))
    assert admin.delete('/api/operations/sso-bindings/zzzz').status_code==400
    assert admin.delete('/api/operations/sso-bindings/'+'0'*16).status_code==404
    assert admin.delete('/api/operations/sso-bindings/'+digest).status_code==200
    assert admin.get('/api/operations/sso-bindings').json()==[]
    with Session() as s:
        assert any(a.action=='remove SSO binding' and digest in a.detail for a in s.scalars(select(Audit)))
