"""Process-local bounded HTTP pool; request credentials and cookies are not reused.

No automatic retries: every potentially billable attempt must pass policy and have
its own receipt. Shutdown waits for admitted sends; drain only closes an idle pool.
"""
from contextlib import contextmanager
import atexit
import threading
import httpx

MAX_CONNECTIONS = 16
MAX_RESPONSE_BYTES = 2_000_000
READ_CHUNK_BYTES = 64 * 1024
_condition = threading.Condition()
_client = None
_active = 0
_closing = False


class ResponseTooLarge(httpx.RequestError):
    """A redacted bounded-response failure with safe status metadata only."""
    def __init__(self,response):
        headers={name:response.headers[name] for name in ('retry-after','x-request-id') if name in response.headers}
        snapshot=httpx.Response(response.status_code,headers=headers,content=b'',
            request=response.request,extensions=response.extensions)
        super().__init__('Provider response exceeded the decoded response limit.',request=response.request)
        self.response=snapshot


def _bounded(response):
    """Read decoded bytes to a fixed ceiling and always release the response."""
    try:
        declared=response.headers.get('content-length','')
        if declared.isascii() and declared.isdigit() and int(declared)>MAX_RESPONSE_BYTES:
            raise ResponseTooLarge(response)
        chunks=[];size=0
        for chunk in response.iter_bytes(chunk_size=min(READ_CHUNK_BYTES,MAX_RESPONSE_BYTES+1)):
            size+=len(chunk)
            if size>MAX_RESPONSE_BYTES:raise ResponseTooLarge(response)
            chunks.append(chunk)
        return httpx.Response(response.status_code,headers=response.headers,content=b''.join(chunks),
            request=response.request,extensions=response.extensions)
    finally:response.close()


@contextmanager
def _borrow():
    global _client, _active
    with _condition:
        _condition.wait_for(lambda: not _closing)
        if _client is None:
            _client = httpx.Client(limits=httpx.Limits(max_connections=MAX_CONNECTIONS,
                max_keepalive_connections=MAX_CONNECTIONS, keepalive_expiry=30), follow_redirects=False)
        client = _client
        _active += 1
        _condition.notify_all()
    try: yield client
    finally:
        with _condition:
            _active -= 1
            _condition.notify_all()


def post(url, *, headers, json, timeout):
    # Build directly, rather than Client.build_request: never merge a previous
    # response's cookies or any credential-bearing client defaults into a send.
    deadline = httpx.Timeout(timeout, connect=min(timeout, 10), pool=min(timeout, 5))
    with _borrow() as client:
        # Preserve HTTPX's public negotiation/user-agent defaults through a small
        # allowlist; never copy authorization, cookies or arbitrary client state.
        defaults = {name:client.headers[name] for name in
                    ('accept','accept-encoding','connection','user-agent') if name in client.headers}
        request = httpx.Request('POST', url, headers={**defaults, **headers}, json=json,
                                extensions={'timeout': deadline.as_dict()})
        try:return _bounded(client.send(request,follow_redirects=False,stream=True))
        finally: client.cookies.clear()


def close(*, wait=True):
    global _client, _closing
    with _condition:
        if not wait and (_active or _closing): return False
        _condition.wait_for(lambda: not _closing)
        _closing = True
        _condition.notify_all()
        _condition.wait_for(lambda: not _active)
        client, _client = _client, None
    try:
        if client is not None: client.close()
    finally:
        with _condition:
            _closing = False
            _condition.notify_all()
    return True


atexit.register(close)
