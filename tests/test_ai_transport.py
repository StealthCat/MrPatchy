import json
import gzip
import threading
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import httpx
import pytest
from app import ai_transport as transport


@pytest.fixture
def provider(monkeypatch, request):
    transport.close()
    real_client=httpx.Client; clients=[]; calls=[]; release=threading.Event(); release.set()
    def factory(**kwargs):
        if hasattr(request, 'param'):
            kwargs['limits'] = httpx.Limits(max_connections=request.param)
        client=real_client(**kwargs,trust_env=False);clients.append((client,kwargs));return client
    monkeypatch.setattr(transport.httpx,'Client',factory)
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*args):pass
        def do_POST(self):
            body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            calls.append((self.client_address,self.headers,body));release.wait(10)
            size=body.get('response_size')
            data=(b'x'*size if type(size) is int and size>=0 else b'{"ok":true}')
            if body.get('gzip'):data=gzip.compress(data)
            self.send_response(503 if body.get('fail') else 302 if body.get('redirect') else 200)
            if body.get('gzip'):self.send_header('Content-Encoding','gzip')
            self.send_header('Content-Length',str(len(data)));self.send_header('Set-Cookie','provider-session=must-not-be-reused')
            self.send_header('Location','/unexpected-redirect');self.end_headers()
            try:self.wfile.write(data);self.wfile.flush()
            except ConnectionError:pass
        def do_GET(self):
            calls.append((self.client_address,self.headers,None));release.wait(10)
            data=b'{"data":[]}'
            self.send_response(302 if self.path.endswith('/redirect') else 200)
            self.send_header('Content-Length',str(len(data)));self.send_header('Location','/unexpected-redirect')
            self.send_header('Set-Cookie','provider-session=must-not-be-reused');self.end_headers()
            try:self.wfile.write(data);self.wfile.flush()
            except ConnectionError:pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    yield 'http://127.0.0.1:'+str(server.server_port),calls,clients,release
    release.set();transport.close();server.shutdown();server.server_close();thread.join()


def send(url,key='fixture-one',**body):
    return transport.post(url,headers={'Authorization':'Bearer '+key},json=body,timeout=5)


def test_reuses_socket_but_not_credentials_cookies_or_redirects(provider):
    url,calls,clients,_=provider
    assert send(url).status_code==200
    assert send(url,'fixture-two').status_code==200
    assert send(url,redirect=True).status_code==302
    assert send(url,fail=True).status_code==503
    assert len(calls)==4 and len({c[0] for c in calls})==1
    assert [c[1]['Authorization'] for c in calls]==['Bearer fixture-one','Bearer fixture-two','Bearer fixture-one','Bearer fixture-one']
    assert all('Cookie' not in c[1] for c in calls)
    assert all(c[1]['Accept']=='*/*' and c[1]['Accept-Encoding']=='gzip' and c[1]['User-Agent'].startswith('python-httpx/') for c in calls)
    assert not clients[0][0].cookies
    limits=clients[0][1]['limits']
    assert limits.max_connections==limits.max_keepalive_connections==16 and limits.keepalive_expiry==30
    assert clients[0][0].headers.get('Authorization') is None
    assert clients[0][0].is_closed is False
    transport.close();assert clients[0][0].is_closed
    assert send(url).status_code==200 and len(clients)==2


def test_get_shares_socket_without_body_credentials_or_cookies(provider):
    url,calls,clients,_=provider
    assert transport.get(url,headers={'Authorization':'Bearer discovery-one'},timeout=20).status_code==200
    assert send(url,'fixture-two').status_code==200
    assert transport.get(url,headers={'Authorization':'Bearer discovery-three'},timeout=20).status_code==200
    assert transport.get(url+'/redirect',headers={'Authorization':'Bearer discovery-four'},timeout=20).status_code==302
    assert len(clients)==1 and len({call[0] for call in calls})==1
    assert [headers['Authorization'] for _,headers,_ in calls]==[
        'Bearer discovery-one','Bearer fixture-two','Bearer discovery-three','Bearer discovery-four']
    assert calls[0][2] is None and calls[2][2] is None and calls[3][2] is None
    assert all('Cookie' not in headers for _,headers,_ in calls)
    assert all('Content-Length' not in headers for _,headers,body in calls if body is None)
    assert not clients[0][0].cookies


def test_parallel_requests_isolate_auth_and_shutdown_waits_for_inflight(provider):
    url,calls,clients,release=provider;release.clear()
    def request(index):
        if index%2:return send(url,'fixture-'+str(index),index=index)
        return transport.get(url,headers={'Authorization':'Bearer fixture-'+str(index)},timeout=5)
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures=[executor.submit(request,i) for i in range(4)]
        with transport._condition:
            assert transport._condition.wait_for(lambda:transport._active==4,timeout=5)
        assert transport.close(wait=False) is False
        closing=executor.submit(transport.close)
        with transport._condition:
            assert transport._condition.wait_for(lambda:transport._closing,timeout=5)
        assert not closing.done() and not clients[0][0].is_closed
        release.set()
        assert all(f.result(timeout=10).status_code==200 for f in futures)
        assert closing.result(timeout=10) and clients[0][0].is_closed
    assert len(calls)==4
    assert sorted(headers['Authorization'] for _,headers,_ in calls)==[
        'Bearer fixture-0','Bearer fixture-1','Bearer fixture-2','Bearer fixture-3']
    assert sum(body is None for _,_,body in calls)==2
    assert all('Cookie' not in headers for _,headers,_ in calls)


def test_timeout_bounds_are_per_request_and_errors_are_not_retried(monkeypatch):
    seen=[]
    class Client:
        headers=httpx.Headers()
        cookies=httpx.Cookies()
        def send(self,request,**kwargs):
            seen.append(request);raise httpx.ReadTimeout('fixture timeout')
        def close(self):pass
    transport.close();monkeypatch.setattr(transport.httpx,'Client',lambda **kwargs:Client())
    try:
        with pytest.raises(httpx.ReadTimeout):send('https://example.invalid')
        assert len(seen)==1 and seen[0].extensions['timeout']=={'connect':5,'pool':5,'read':5,'write':5}
        with pytest.raises(httpx.ReadTimeout):transport.post('https://example.invalid',headers={},json={},timeout=60)
        assert seen[-1].extensions['timeout']=={'connect':10,'pool':5,'read':60,'write':60}
        with pytest.raises(httpx.ReadTimeout):transport.get('https://example.invalid',headers={},timeout=20)
        assert len(seen)==3 and seen[-1].method=='GET' and seen[-1].content==b''
        assert seen[-1].extensions['timeout']=={'connect':10,'pool':5,'read':20,'write':20}
    finally:transport.close()


def test_worker_exit_closes_an_open_pool_after_loop_failure(provider,admin,monkeypatch):
    from app import worker
    url,_,clients,_=provider
    def fail_after_send(reporter):
        assert send(url).status_code==200
        assert not clients[0][0].is_closed
        raise RuntimeError('fixture worker exit')
    monkeypatch.setattr(worker,'_loop',fail_after_send)
    with pytest.raises(RuntimeError,match='fixture worker exit'):worker.loop(role='worker')
    assert clients[0][0].is_closed



def test_real_response_timeout_is_preserved_without_retry(provider):
    url,calls,_,release=provider;release.clear()
    try:
        with pytest.raises(httpx.ReadTimeout):
            transport.post(url,headers={'Authorization':'Bearer fixture'},json={},timeout=.1)
        assert len(calls)==1
    finally:release.set()


def test_decoded_response_body_stops_at_the_configured_limit(provider,monkeypatch):
    url,calls,clients,_=provider
    monkeypatch.setattr(transport,'MAX_RESPONSE_BYTES',64,raising=False)
    assert len(send(url,response_size=64).content)==64
    assert len(send(url,response_size=32,gzip=True).content)==32
    assert calls[0][0]==calls[1][0]
    with pytest.raises(httpx.RequestError):send(url,response_size=65)
    with pytest.raises(httpx.RequestError):send(url,response_size=65,gzip=True)
    assert send(url).json()=={'ok':True}
    assert len(calls)==5 and len(clients)==1 and not clients[0][0].cookies


def test_split_gzip_response_is_decoded_without_advertising_unsupported_encodings(monkeypatch):
    wire=gzip.compress(b'hello world')
    chunks=[wire[:1],wire[1:3],wire[3:8],wire[8:13],wire[13:]]
    state={'closed':False}
    class Stream(httpx.SyncByteStream):
        def __iter__(self):yield from chunks
        def close(self):state['closed']=True
    class Client:
        headers=httpx.Headers({'accept':'*/*','accept-encoding':'gzip, deflate, br, zstd','user-agent':'fixture'})
        cookies=httpx.Cookies()
        def send(self,request,**kwargs):
            assert request.headers['accept-encoding']=='gzip'
            return httpx.Response(200,headers={'content-encoding':'gzip'},stream=Stream(),request=request)
        def close(self):pass
    transport.close();monkeypatch.setattr(transport.httpx,'Client',lambda **kwargs:Client())
    try:
        response=send('https://example.invalid')
        assert response.content==b'hello world'
        assert 'content-encoding' not in response.headers
        assert response.headers['content-length']=='11'
        assert state['closed']
    finally:transport.close()


def test_gzip_expansion_is_rejected_without_materializing_the_expanded_body(monkeypatch):
    wire=gzip.compress(b'x'*(16*1024*1024))
    state={'closed':False}
    class Stream(httpx.SyncByteStream):
        def __iter__(self):yield wire
        def close(self):state['closed']=True
    class Client:
        headers=httpx.Headers({'accept-encoding':'gzip'})
        cookies=httpx.Cookies()
        def send(self,request,**kwargs):
            return httpx.Response(200,headers={'content-encoding':'gzip'},stream=Stream(),request=request)
        def close(self):pass
    transport.close();monkeypatch.setattr(transport.httpx,'Client',lambda **kwargs:Client())
    tracemalloc.start()
    try:
        with pytest.raises(transport.ResponseTooLarge):send('https://example.invalid')
        _,peak=tracemalloc.get_traced_memory()
        assert peak<12_000_000
        assert state['closed']
    finally:
        tracemalloc.stop();transport.close()


@pytest.mark.parametrize('wire,expected',[
    (gzip.compress(b'first')+gzip.compress(b'second'),b'firstsecond'),
    (gzip.compress(b'x'*64),b'x'*64),
])
def test_gzip_members_and_exact_decoded_limit_are_accepted(monkeypatch,wire,expected):
    state={'closed':False}
    class Stream(httpx.SyncByteStream):
        def __iter__(self):yield from (wire[:7],wire[7:])
        def close(self):state['closed']=True
    class Client:
        headers=httpx.Headers()
        cookies=httpx.Cookies()
        def send(self,request,**kwargs):
            return httpx.Response(200,headers={'content-encoding':'gzip'},stream=Stream(),request=request)
        def close(self):pass
    transport.close();monkeypatch.setattr(transport,'MAX_RESPONSE_BYTES',64)
    monkeypatch.setattr(transport.httpx,'Client',lambda **kwargs:Client())
    try:
        response=send('https://example.invalid')
        assert response.content==expected and response.headers['content-length']==str(len(expected))
        assert state['closed']
    finally:transport.close()


@pytest.mark.parametrize('encoding,wire',[
    ('gzip',gzip.compress(b'partial')[:-3]),
    ('gzip',b'not-a-gzip-stream'),
    ('br',b'unsupported'),
    ('gzip, identity',gzip.compress(b'ambiguous')),
])
def test_invalid_or_unsupported_encoding_is_redacted_and_closed(monkeypatch,encoding,wire):
    state={'closed':False}
    class Stream(httpx.SyncByteStream):
        def __iter__(self):yield wire
        def close(self):state['closed']=True
    class Client:
        headers=httpx.Headers()
        cookies=httpx.Cookies()
        def send(self,request,**kwargs):
            return httpx.Response(502,headers={'content-encoding':encoding,'x-private':'secret-value'},
                stream=Stream(),request=request)
        def close(self):pass
    transport.close();monkeypatch.setattr(transport.httpx,'Client',lambda **kwargs:Client())
    try:
        with pytest.raises(transport.ResponseDecodeError) as raised:
            send('https://example.invalid')
        assert raised.value.response.status_code==502 and raised.value.response.content==b''
        assert 'x-private' not in raised.value.response.headers
        assert 'secret-value' not in str(raised.value)
        assert state['closed']
    finally:transport.close()


def test_identity_response_preserves_bytes_and_normalizes_framing(monkeypatch):
    state={'closed':False}
    class Stream(httpx.SyncByteStream):
        def __iter__(self):yield from (b'plain',b'-text')
        def close(self):state['closed']=True
    class Client:
        headers=httpx.Headers()
        cookies=httpx.Cookies()
        def send(self,request,**kwargs):
            return httpx.Response(200,headers={'content-encoding':'identity','transfer-encoding':'chunked'},
                stream=Stream(),request=request)
        def close(self):pass
    transport.close();monkeypatch.setattr(transport.httpx,'Client',lambda **kwargs:Client())
    try:
        response=send('https://example.invalid')
        assert response.content==b'plain-text'
        assert response.headers['content-length']=='10'
        assert 'content-encoding' not in response.headers and 'transfer-encoding' not in response.headers
        assert state['closed']
    finally:transport.close()


@pytest.mark.parametrize('declared,chunks,expected_reads',[
    ('65',[b'unread'],0),
    ('9'*5000,[b'unread'],0),
    ('invalid',[b'a'*32,b'b'*34,b'unread'],2),
])
def test_declared_and_streamed_overflow_close_without_exposing_content(monkeypatch,declared,chunks,expected_reads):
    state={'reads':0,'closed':False}
    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            for chunk in chunks:
                state['reads']+=1;yield chunk
        def close(self):state['closed']=True
    class Client:
        headers=httpx.Headers()
        cookies=httpx.Cookies()
        def send(self,request,**kwargs):
            assert kwargs=={'follow_redirects':False,'stream':True}
            return httpx.Response(200,headers={'content-length':declared,'x-private':'secret-value'},
                stream=Stream(),request=request)
        def close(self):pass
    transport.close();monkeypatch.setattr(transport,'MAX_RESPONSE_BYTES',64)
    monkeypatch.setattr(transport.httpx,'Client',lambda **kwargs:Client())
    try:
        with pytest.raises(transport.ResponseTooLarge) as raised:
            send('https://example.invalid')
        assert state=={'reads':expected_reads,'closed':True}
        assert raised.value.response.status_code==200 and raised.value.response.content==b''
        assert 'x-private' not in raised.value.response.headers
        assert 'secret-value' not in str(raised.value)
    finally:transport.close()


@pytest.mark.parametrize('provider', [1], indirect=True)
def test_saturated_pool_releases_daily_cap_without_sending(provider, admin, monkeypatch):
    from decimal import Decimal
    from app import ai, ai_budget, ai_pricing, ai_runs
    from app.db import Session, Setting

    url, calls, clients, _ = provider
    monkeypatch.setattr(ai, 'URL', url)
    monkeypatch.setattr(ai_pricing.time, 'time', lambda: 1793404800.0)
    payload = {'model': 'gpt-6-luna', 'input': 'fixture', 'max_output_tokens': 1000}
    quote = ai_pricing.reservation(payload)['amount_usd']
    with Session() as session:
        session.merge(Setting(key='config', value={
            'ai_enabled': True, 'ai_control_mode': 'daily_cap',
            'ai_daily_cap_usd': float(quote + Decimal('0.000001')), 'ai_budget_timezone': 'UTC',
        }))
        session.commit()

    assert send(url).status_code == 200
    with clients[0][0].stream('POST', url, json={}) as held:
        assert held.status_code == 200
        with pytest.raises(ai.AIError) as error:
            with ai_runs.track('test', payload['model']) as run_id:
                ai.request(payload, 'fixture-key', timeout=0.1)
        assert error.value.transient
        assert error.value.retry_after > 0
        assert len(calls) == 2
        held.read()

    with Session() as session:
        entry = session.query(ai_budget.BudgetEntry).one()
        assert entry.status == 'released'
        assert entry.reason == 'The local AI connection pool timed out before sending the request.'
        receipt = session.query(ai_runs.AICall).filter_by(run_id=run_id).one()
        assert entry.call_id == receipt.id
        assert session.get(ai_runs.AIRun, run_id).message == entry.reason
        assert ai_budget.status(session)['counted_usd'] == '0'
    assert ai_budget.reserve(payload) is not None
