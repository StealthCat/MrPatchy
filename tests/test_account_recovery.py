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

def test_concurrent_sso_replacements_confirming_same_binding_conflict(admin,monkeypatch):
    # Two administrators both confirm replacing the same 'original' binding; only one may win.
    import threading
    from fastapi import HTTPException
    from app import main
    monkeypatch.setattr(sso,'issuer','https://issuer.example')
    for name in ('original','one','two'):add_user(admin,name)
    assert admin.put('/api/operations/sso-binding',json={'subject':'sub-race','username':'original'}).status_code==200
    first_in=threading.Event();release=threading.Event();real_audit=main.audit
    def slow_audit(s,action,detail):
        if action=='bind SSO identity' and '→ one' in detail:
            first_in.set();release.wait(10)
        return real_audit(s,action,detail)
    monkeypatch.setattr(main,'audit',slow_audit)
    results={}
    def run(target):
        try:results[target]=main.bind_sso(main.SSOBinding(subject='sub-race',username=target,replace_username='original'),{'username':'admin'})['ok']
        except HTTPException as exc:results[target]=exc.status_code
    a=threading.Thread(target=run,args=('one',));a.start()
    assert first_in.wait(10)
    b=threading.Thread(target=run,args=('two',));b.start()
    b.join(0.5);release.set();a.join(20);b.join(20)
    assert results=={'one':True,'two':409}
    with Session() as s:
        assert s.get(Setting,sso.binding_key('sub-race')).value=={'username':'one'}
        details=[a.detail for a in s.scalars(select(Audit)) if a.action=='bind SSO identity']
        assert sum('previous original' in d for d in details)==1

def test_stale_replacement_after_removal_conflicts_and_does_not_recreate(admin,monkeypatch):
    monkeypatch.setattr(sso,'issuer','https://issuer.example')
    for name in ('original','replacement','other'):add_user(admin,name)
    r=admin.put('/api/operations/sso-binding',json={'subject':'sub-stale','username':'original'});digest=r.json()['subject_digest']
    assert admin.delete('/api/operations/sso-bindings/'+digest).status_code==200
    stale=admin.put('/api/operations/sso-binding',json={'subject':'sub-stale','username':'replacement','replace_username':'original'})
    assert stale.status_code==409
    with Session() as s:
        assert s.get(Setting,sso.binding_key('sub-stale')) is None
        details=[a.detail for a in s.scalars(select(Audit)) if a.action=='bind SSO identity' and digest in a.detail]
        assert not any('→ replacement' in d for d in details)
    # A confirmation naming a different current binding also conflicts.
    assert admin.put('/api/operations/sso-binding',json={'subject':'sub-stale','username':'original'}).status_code==200
    assert admin.put('/api/operations/sso-binding',json={'subject':'sub-stale','username':'replacement','replace_username':'other'}).status_code==409
    with Session() as s:assert s.get(Setting,sso.binding_key('sub-stale')).value=={'username':'original'}
    # The fresh unbound-create path is unchanged.
    assert admin.put('/api/operations/sso-binding',json={'subject':'sub-new','username':'other'}).status_code==200
    with Session() as s:assert s.get(Setting,sso.binding_key('sub-new')).value=={'username':'other'}

def test_removal_and_replacement_of_same_subject_are_serialized_with_accurate_audit(admin,monkeypatch):
    import threading
    from fastapi import HTTPException
    from app import main
    monkeypatch.setattr(sso,'issuer','https://issuer.example')
    for name in ('original','updated'):add_user(admin,name)
    digest=admin.put('/api/operations/sso-binding',json={'subject':'sub-del','username':'original'}).json()['subject_digest']
    paused=threading.Event();release=threading.Event();real_audit=main.audit
    def slow_audit(s,action,detail):
        if action=='remove SSO binding':
            paused.set();release.wait(10)
        return real_audit(s,action,detail)
    monkeypatch.setattr(main,'audit',slow_audit)
    results={}
    def remove():
        try:results['remove']=main.delete_sso_binding(digest,{'username':'admin'})['ok']
        except HTTPException as exc:results['remove']=exc.status_code
    def replace():
        try:results['replace']=main.bind_sso(main.SSOBinding(subject='sub-del',username='updated',replace_username='original'),{'username':'admin'})['ok']
        except HTTPException as exc:results['replace']=exc.status_code
    a=threading.Thread(target=remove);a.start()
    assert paused.wait(10)
    b=threading.Thread(target=replace);b.start()
    b.join(0.5);release.set();a.join(20);b.join(20)
    assert results=={'remove':True,'replace':409}
    with Session() as s:
        assert s.get(Setting,sso.binding_key('sub-del')) is None
        removals=[a.detail for a in s.scalars(select(Audit)) if a.action=='remove SSO binding' and digest in a.detail]
        assert removals==['admin removed subject '+digest+' → original']
        assert not any(a.action=='bind SSO identity' and '→ updated' in a.detail for a in s.scalars(select(Audit)))
