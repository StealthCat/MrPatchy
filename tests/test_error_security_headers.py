import app.main as main

def test_unhandled_exception_500_keeps_security_headers_and_hides_detail(client,monkeypatch):
    def boom(*a,**k): raise RuntimeError('secret internal detail')
    for route in main.app.routes:
        if getattr(route,'path','')=='/healthz': monkeypatch.setattr(route,'endpoint',boom); monkeypatch.setattr(route.dependant,'call',boom)
    response=client.get('/healthz')
    assert response.status_code==500
    assert 'secret internal detail' not in response.text
    assert response.headers['X-Content-Type-Options']=='nosniff'
    assert response.headers['X-Frame-Options']=='DENY'
    assert response.headers['Referrer-Policy']=='no-referrer'
    assert "frame-ancestors 'none'" in response.headers['Content-Security-Policy']
