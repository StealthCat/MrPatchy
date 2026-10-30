"""Process-local bounded HTTP pool; request credentials and cookies are not reused.

No automatic retries: every potentially billable attempt must pass policy and have
its own receipt. Shutdown waits for admitted sends; drain only closes an idle pool.
"""
from contextlib import contextmanager
import atexit
import threading
import httpx

MAX_CONNECTIONS = 16
_condition = threading.Condition()
_client = None
_active = 0
_closing = False


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
        try: return client.send(request, follow_redirects=False)
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
