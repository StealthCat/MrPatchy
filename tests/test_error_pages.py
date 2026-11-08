from pathlib import Path

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app import error_pages


def request(path='/missing', method='GET', accept='text/html', **headers):
    return Request({'type': 'http', 'method': method, 'path': path, 'scheme': 'https',
                    'server': ('patchy.test', 443), 'query_string': b'',
                    'headers': [(key.encode(), value.encode()) for key, value in {'accept': accept, **headers}.items()]})


@pytest.mark.parametrize('status', [300, 301, 302, 303, 305, 306, 307, 308, 399, 403, 404, 500, 501, 502, 503, 504, 507, 511, 599])
def test_branded_html_preserves_status_and_never_echoes_failure_detail(status):
    result = error_pages.decorate(request(), JSONResponse({'detail': 'secret <script>bad()</script>'}, status_code=status))
    assert result.status_code == status
    assert result.headers['content-type'].startswith('text/html')
    assert error_pages.artwork(status).encode() in result.body
    assert f'HTTP {status}'.encode() in result.body
    assert b'secret' not in result.body and b'<script>' not in result.body
    assert result.headers['cache-control'] == 'no-store'
    assert result.headers['vary'] == 'Accept'


@pytest.mark.parametrize('kwargs', [
    {'path': '/api/missing'}, {'path': '/api'}, {'path': '/healthz'}, {'path': '/enroll/token'},
    {'method': 'POST'}, {'accept': '*/*'}, {'accept': 'application/json'}, {'accept': 'text/html;q=0'},
    {'accept': 'text/html;q=invalid'}, {'accept': 'text/html;q=nan'}, {'sec-fetch-dest': 'image'},
    {'sec-fetch-dest': 'script'}, {'sec-fetch-dest': 'empty'},
])
def test_machine_requests_and_non_navigation_responses_are_unchanged(kwargs):
    original = JSONResponse({'detail': 'original'}, status_code=403)
    assert error_pages.decorate(request(**kwargs), original) is original


@pytest.mark.parametrize('status', [200, 204, 206, 304])
def test_success_and_bodyless_cache_responses_are_unchanged(status):
    original = Response(status_code=status, headers={'ETag': 'original'})
    assert error_pages.decorate(request(), original) is original


def test_redirect_preserves_headers_cookies_and_escapes_local_link():
    original = Response('old', status_code=307, headers={'Location': '/next?value="<test>', 'Retry-After': '30',
                        'Content-Encoding': 'gzip', 'ETag': 'old', 'Vary': 'Origin'})
    original.set_cookie('first', 'one'); original.set_cookie('second', 'two')
    result = error_pages.decorate(request(), original)
    assert result.headers['location'] == '/next?value="<test>'
    assert result.headers['retry-after'] == '30'
    assert len(result.headers.getlist('set-cookie')) == 2
    assert 'content-encoding' not in result.headers and 'etag' not in result.headers
    assert result.headers['vary'] == 'Origin, Accept'
    assert b'href="/next?value=&quot;&lt;test&gt;"' in result.body
    assert int(result.headers['content-length']) == len(result.body)


@pytest.mark.parametrize('location', ['//evil.test', '/\\evil.test', 'javascript:alert(1)', 'https://idp.test/auth', '/\n/evil.test'])
def test_unsafe_or_external_destination_is_not_a_rendered_link(location):
    assert 'Continue to destination' not in error_pages.render(302, location)


def test_head_retains_representation_length_but_no_body():
    response = error_pages.decorate(request(method='HEAD'), Response(status_code=404))
    assert response.body == b''
    assert int(response.headers['content-length']) == len(error_pages.render(404).encode())


def test_static_pages_match_live_renderer():
    root = Path(error_pages.__file__).parent / 'static' / 'errors'
    for status in error_pages.COPY:
        assert (root / f'{status}.html').read_text(encoding='utf-8') == error_pages.render(status)


@pytest.fixture
def browser_client():
    # Exercise the real middleware/routes without starting databases or workers:
    # public error pages must not depend on either service being initialized.
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    yield client
    client.close()


def test_real_unknown_browser_page_and_api_contract(browser_client):
    page = browser_client.get('/missing-page', headers={'Accept': 'text/html'})
    assert page.status_code == 404 and 'That page wandered off.' in page.text
    assert page.headers['x-content-type-options'] == 'nosniff'
    assert "script-src 'self'" in page.headers['content-security-policy']
    api = browser_client.get('/api/missing-page', headers={'Accept': 'text/html'})
    assert api.status_code == 404 and api.json() == {'detail': 'Not Found'}


def test_real_server_failure_is_branded_without_exception_details(browser_client, monkeypatch):
    from app import main
    def failed(*args, **kwargs):
        raise RuntimeError('private database credentials')
    monkeypatch.setattr(main, 'FileResponse', failed)
    result = browser_client.get('/', headers={'Accept': 'text/html'})
    assert result.status_code == 500 and 'A wrench in the works.' in result.text
    assert 'private database credentials' not in result.text
    assert result.headers['x-frame-options'] == 'DENY'
    result = browser_client.get('/', headers={'Accept': 'application/json'})
    assert result.status_code == 500 and result.json() == {'detail': 'Internal server error'}


def test_real_browser_redirect_keeps_destination(browser_client):
    result = browser_client.get('/auth/sso/', headers={'Accept': 'text/html'}, follow_redirects=False)
    assert result.status_code == 307 and result.headers['location'].endswith('/auth/sso')
    assert 'A temporary change of address.' in result.text


def test_real_forbidden_page_keeps_403_and_hides_detail(browser_client, monkeypatch):
    from app import main
    from fastapi import HTTPException
    def forbidden(*args, **kwargs):
        raise HTTPException(403, 'private access detail')
    monkeypatch.setattr(main, 'FileResponse', forbidden)
    response = browser_client.get('/', headers={'Accept': 'text/html'})
    assert response.status_code == 403 and 'This workbench is off limits.' in response.text
    assert 'private access detail' not in response.text
    assert 'mr-patchy-forbidden.webp' in response.text


def test_real_redirect_can_still_be_followed(browser_client, monkeypatch):
    from app import main
    from starlette.responses import RedirectResponse
    monkeypatch.setattr(main, 'FileResponse', lambda *args, **kwargs: RedirectResponse('/static/license.html', status_code=302))
    response = browser_client.get('/', headers={'Accept': 'text/html'}, follow_redirects=True)
    assert response.status_code == 200
    assert response.history[0].status_code == 302
    assert response.url.path == '/static/license.html'
