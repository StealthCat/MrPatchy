import json
import time
from types import SimpleNamespace
import pytest
from app import worker,identity
from app.db import Session,Setting,Behavior
from app.main import login_attempts
from app.security import seal,unseal

@pytest.mark.parametrize('route,method,body',[
 ('/api/identity/mfa','post',{'password':'incorrect'}),
 ('/api/identity/password','put',{'password':'incorrect','new_password':'replacement-password'}),
 ('/api/identity/sessions','delete',{'password':'incorrect'}),
 ('/api/identity/mfa/confirm','post',{'otp':'000000'})])
def test_sensitive_account_verification_is_throttled(admin,route,method,body):
 for _ in range(10):
  assert admin.request(method,route,json=body).status_code in (400,403)
 assert admin.request(method,route,json=body).status_code==429
 # A typo is a failed step-up check, not an expired session.
 assert admin.get('/api/identity').status_code==200


def test_account_attempt_limit_is_shared_between_sensitive_endpoints(admin):
 for _ in range(5):
  assert admin.post('/api/identity/mfa',json={'password':'incorrect'}).status_code==403
  assert admin.post('/api/identity/mfa/confirm',json={'otp':'000000'}).status_code==400
 assert admin.request('DELETE','/api/identity/sessions',json={'password':'incorrect'}).status_code==429
 login_attempts['account:admin']=[time.time()-301]*10
 assert admin.post('/api/identity/mfa',json={'password':'incorrect'}).status_code==403


def test_replacement_mfa_secret_can_confirm_in_same_timestep():
 old=identity.new_secret();new=identity.new_secret();counter=100
 user=SimpleNamespace(otp_secret=seal(old),otp_pending=seal(new),otp_counter=-1)
 assert identity.consume_otp(user,identity.code(old,counter),now=counter*30)
 assert identity.consume_otp(user,identity.code(new,counter),now=counter*30,pending=True)
 user.otp_secret=user.otp_pending;user.otp_pending=''
 assert not identity.consume_otp(user,identity.code(new,counter),now=counter*30)


def notification_value():
 with Session() as s:return json.loads(unseal(s.get(Setting,'notifications').value['encrypted']))


def test_webhook_round_trip_never_discloses_or_silently_erases_token(admin):
 url='/api/operations/notifications';body={'url':'https://alerts.example.test/events','enabled':True,'token':'private-webhook-token'}
 assert admin.put(url,json=body).status_code==200
 public=admin.get(url).json()
 assert public['url']==body['url'] and public['enabled'] and public['token_configured']
 assert 'private-webhook-token' not in json.dumps(public) and 'token' not in public
 assert admin.put(url,json={**body,'token':''}).status_code==200
 assert notification_value()['token']==body['token']
 assert admin.put(url,json={**body,'token':'','url':'https://different.example.test/'}).status_code==400
 assert notification_value()['url']==body['url']
 assert admin.put(url,json={**body,'token':'','clear_token':True}).status_code==200
 assert notification_value()['token']==''


def test_smtp_round_trip_preserves_secret_only_for_same_account(admin):
 body={'host':'mail.example.test','port':587,'mode':'starttls','sender':'a@example.test','recipients':['b@example.test'],
       'username':'mailer','password':'private-smtp-password','enabled':True}
 assert admin.put('/api/operations/smtp',json=body).status_code==200
 public=admin.get('/api/operations/notifications').json()
 assert public['channel']=='smtp' and public['password_configured']
 assert 'password' not in public and 'private-smtp-password' not in json.dumps(public)
 assert admin.put('/api/operations/smtp',json={**body,'password':'','recipients':['c@example.test']}).status_code==200
 assert notification_value()['password']==body['password']
 for change in ({'host':'other.example.test'},{'username':'other'},{'port':465},{'mode':'tls'}):
  assert admin.put('/api/operations/smtp',json={**body,**change,'password':''}).status_code==400
 assert admin.put('/api/operations/smtp',json={**body,'password':'','clear_password':True}).status_code==200
 assert notification_value()['password']==''


def test_notification_channels_do_not_reuse_each_others_secret(admin):
 assert admin.put('/api/operations/notifications',json={'url':'https://alerts.example.test','token':'webhook-secret','enabled':True}).status_code==200
 assert admin.put('/api/operations/smtp',json={'host':'mail.example.test','sender':'a@example.test','recipients':['b@example.test']}).status_code==200
 assert notification_value()['channel']=='smtp' and 'token' not in notification_value()


@pytest.mark.parametrize('role',['viewer','operator'])
def test_notification_metadata_remains_administrator_only(admin,role):
 assert admin.put('/api/users',json={'username':role,'role':role,'password':'role-password-long'}).status_code==200
 assert admin.post('/api/logout').status_code==200
 assert admin.get('/api/operations/notifications').status_code==401
 assert admin.post('/api/login',json={'username':role,'password':'role-password-long'}).status_code==200
 assert admin.get('/api/operations/notifications').status_code==403


def test_explicit_notification_clear_wins_when_switching_channel(admin):
 assert admin.put('/api/operations/notifications',json={'url':'https://alerts.example.test','token':'webhook-secret'}).status_code==200
 assert admin.put('/api/operations/smtp',json={'host':'mail.example.test','sender':'a@example.test','recipients':['b@example.test'],'password':'discard','clear_password':True}).status_code==200
 assert notification_value()['password']==''
 assert admin.put('/api/operations/notifications',json={'url':'https://alerts.example.test','token':'discard','clear_token':True}).status_code==200
 assert notification_value()['token']==''


def test_unverified_process_investigation_completes_with_explicit_uncertainty(admin,monkeypatch):
 with Session() as s:
  s.merge(Setting(key='config',value={'ai_enabled':True,'ai_model':'fixture','ai_hourly_limit':20}))
  s.merge(Setting(key='openai_key',value={'encrypted':seal('fake-key')}))
  s.add(Behavior(id='unverified',host_id='missing-host',evidence={'executable':'/tmp/exited','sha256':'unavailable','uid':'0','identity_verified':False}));s.commit()
 requests=[]
 class Response:
  def raise_for_status(self):pass
  def json(self):return {'status':'completed','output':[{'content':[{'type':'output_text','text':json.dumps({'risk':'unknown','explanation':'Identity cannot be verified','recommended_checks':'Review locally','requested_checks':['executable']})}]}]}
 def call(*a,**kw):requests.append(kw['json']);return Response()
 monkeypatch.setattr(worker.ai.transport,'post',call)
 monkeypatch.setattr(worker.ssh,'call',lambda *a,**kw:pytest.fail('Unverified identity must not request SSH evidence'))
 worker.investigate_one()
 assert len(requests)==2
 followup=json.loads(requests[1]['input'])['investigation']['details']
 assert followup['identity_verified'] is False and 'no remote evidence request' in followup['reason']
 with Session() as s:
  row=s.get(Behavior,'unverified');assert row.verdict=='unknown' and not row.approved
