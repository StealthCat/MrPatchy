"""Public, database-independent HTML for browser HTTP failures and redirects."""
from html import escape
from pathlib import Path
from urllib.parse import urlsplit

from starlette.responses import HTMLResponse


COPY = {
    300: ('More than one way forward.', 'This address has more than one destination. Return to your workspace to choose where to go.'),
    301: ('This page has moved.', 'Mr Patchy has a new address for this page.'),
    302: ('Taking a short detour.', 'This page is temporarily available at another address.'),
    303: ('Your next stop is ready.', 'Continue to the result of your request.'),
    307: ('A temporary change of address.', 'Your browser can continue the request at its temporary destination.'),
    308: ('A new permanent home.', 'Your browser can continue the request at its new address.'),
    403: ('This workbench is off limits.', 'Your current access does not allow this page. Sign in with the appropriate account or ask your administrator for access.'),
    404: ('That page wandered off.', 'Mr Patchy looked everywhere, but this address does not lead to a page. Check the address or return to your workspace.'),
    500: ('A wrench in the works.', 'Something went wrong while loading this page. Try again in a moment. If it keeps happening, contact your administrator.'),
    501: ('That tool is not available.', 'This server does not support the requested operation. Return to your workspace or contact your administrator.'),
    502: ('The connection hit a snag.', 'A service returned an unexpected response. Please try again in a moment.'),
    503: ('The workbench needs a moment.', 'This service is temporarily unavailable. Please wait a little before trying again.'),
    504: ('That took longer than expected.', 'A service did not respond in time. Please try again in a moment.'),
}

POSES = {403: 'forbidden', 404: 'not-found', 501: 'not-implemented',
         502: 'bad-gateway', 503: 'maintenance', 504: 'timeout'}


def artwork(status):
    pose = 'redirect' if 300 <= status < 400 else POSES.get(status, 'error')
    return f'/static/mascot/mr-patchy-{pose}.webp'


def wants_page(request):
    """Only explicit HTML document requests; APIs and downloads keep their contracts."""
    if request.method not in ('GET', 'HEAD'):
        return False
    path = request.url.path
    if any(path == prefix or path.startswith(prefix + '/') for prefix in ('/api', '/healthz', '/enroll')):
        return False
    if request.headers.get('sec-fetch-dest', '') not in ('', 'document'):
        return False
    for item in request.headers.get('accept', '').lower().split(','):
        media, *params = item.strip().split(';')
        if media != 'text/html':
            continue
        quality = 1.0
        for param in params:
            key, _, value = param.strip().partition('=')
            if key == 'q':
                try:
                    quality = float(value)
                except ValueError:
                    quality = 0
        if 0 < quality <= 1:
            return True
    return False


def local_destination(location):
    # Redirect headers remain untouched; only a local, non-script link is rendered.
    if not location or not location.startswith('/') or location.startswith('//'):
        return ''
    if '\\' in location or any(ord(char) < 32 or ord(char) == 127 for char in location):
        return ''
    parsed = urlsplit(location)
    return location if not parsed.scheme and not parsed.netloc else ''


def render(status, location=''):
    title, message = COPY.get(status, (
        ('A change of direction.', 'Your browser may continue to a new destination. You can also return to your workspace.') if 300 <= status < 400 else
        ('A wrench in the works.', 'This service could not complete the request. Please try again later or contact your administrator.') if status >= 500 else
        ('Mr Patchy hit a snag.', 'This request could not be completed. Check the address or return to your workspace.')
    ))
    destination = local_destination(location)
    onward = f'<a class="button primary" href="{escape(destination, quote=True)}">Continue to destination</a>' if destination else ''
    redirect_note = '<p class="help">If your browser follows redirects automatically, it will continue to the destination.</p>' if 300 <= status < 400 else ''
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><meta name="theme-color" content="#0b171e">
<title>{status} · Mr Patchy</title><link rel="icon" href="/static/mascot/mr-patchy-welcome.png">
<link rel="stylesheet" href="/static/error.css"></head>
<body><main class="error-page" aria-labelledby="error-title">
<a class="brand" href="/">Mr Patchy<span>.</span></a>
<section class="error-card"><img class="error-mascot" src="{artwork(status)}" alt="" width="1218" height="1292">
<div class="error-copy"><p class="eyebrow">HTTP {status} · MR PATCHY'S WORKBENCH</p>
<h1 id="error-title">{escape(title)}</h1><p>{escape(message)}</p>{redirect_note}
<nav class="actions" aria-label="Recovery options">{onward}<a class="button" href="/">Return to workspace</a></nav>
<p class="help">Your administrator can help if you keep reaching this page.</p></div></section>
<footer>A little wild. A lot of care.</footer></main></body></html>'''


def decorate(request, response):
    status = response.status_code
    # 304 has no representation body. Do not rewrite successful or informational responses.
    if status == 304 or not 300 <= status <= 599 or not wants_page(request):
        return response
    if 'attachment' in response.headers.get('content-disposition', '').lower():
        return response
    replacement = HTMLResponse(render(status, response.headers.get('location', '')), status_code=status,
                               background=response.background)
    # Retain repeated Set-Cookie, Location, Retry-After and auth headers. Drop old body metadata.
    omitted = {b'content-type', b'content-length', b'content-encoding', b'content-range', b'etag',
               b'last-modified', b'content-md5', b'digest', b'content-disposition', b'cache-control'}
    replacement.raw_headers.extend((name, value) for name, value in response.raw_headers if name.lower() not in omitted)
    replacement.headers['Cache-Control'] = 'no-store'
    vary = replacement.headers.get('vary', '')
    if '*' not in vary and 'accept' not in [item.strip().lower() for item in vary.split(',')]:
        replacement.headers['Vary'] = (vary + ', ' if vary else '') + 'Accept'
    if request.method == 'HEAD':
        replacement.body = b''
    return replacement


def write_previews(directory=None):
    """Static pages also work without JavaScript; reusable by an external error handler."""
    directory = Path(directory) if directory else Path(__file__).parent / 'static' / 'errors'
    directory.mkdir(parents=True, exist_ok=True)
    for status in COPY:
        (directory / f'{status}.html').write_text(render(status), encoding='utf-8')
