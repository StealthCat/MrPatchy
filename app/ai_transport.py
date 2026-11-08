"""Process-local bounded HTTP pool; request credentials and cookies are not reused.

No automatic retries: every potentially billable attempt must pass policy and have
its own receipt. Shutdown waits for admitted sends; drain only closes an idle pool.
"""
from contextlib import contextmanager
import atexit
import os
import re
import threading
import zlib
import httpx

DEFAULT_CONNECTIONS = 16
MAX_CONNECTIONS = 64
CONNECTIONS_ENV = 'MRPATCHY_AI_HTTP_CONNECTIONS'
MAX_RESPONSE_BYTES = 2_000_000
READ_CHUNK_BYTES = 64 * 1024
_condition = threading.Condition()
_client = None
_active = 0
_closing = False


def connection_limit():
    value=os.getenv(CONNECTIONS_ENV,str(DEFAULT_CONNECTIONS))
    if not re.fullmatch(r'[0-9]{1,2}',value) or not 1<=int(value)<=MAX_CONNECTIONS:
        raise ValueError(CONNECTIONS_ENV+' must be an integer from 1 to '+str(MAX_CONNECTIONS))
    return int(value)


def _safe_snapshot(response):
    headers={name:response.headers[name] for name in ('retry-after','x-request-id') if name in response.headers}
    return httpx.Response(response.status_code,headers=headers,content=b'',
        request=response.request,extensions=response.extensions)


class ResponseTooLarge(httpx.RequestError):
    """A redacted bounded-response failure with safe status metadata only."""
    def __init__(self,response):
        super().__init__('Provider response exceeded the decoded response limit.',request=response.request)
        self.response=_safe_snapshot(response)


class ResponseDecodeError(httpx.RequestError):
    """A redacted failure for unsupported or invalid provider encodings."""
    def __init__(self,response):
        super().__init__('Provider response encoding could not be decoded safely.',request=response.request)
        self.response=_safe_snapshot(response)


def _declared_over_limit(value):
    if not value.isascii() or not value.isdigit():return False
    normalized=value.lstrip('0') or '0';limit=str(MAX_RESPONSE_BYTES)
    return len(normalized)>len(limit) or (len(normalized)==len(limit) and normalized>limit)


def _append_bounded(chunks,size,chunk,response):
    size+=len(chunk)
    if size>MAX_RESPONSE_BYTES:raise ResponseTooLarge(response)
    if chunk:chunks.append(chunk)
    return size


def _read_identity(response):
    chunks=[];size=0
    for chunk in response.iter_raw(chunk_size=min(READ_CHUNK_BYTES,MAX_RESPONSE_BYTES+1)):
        size=_append_bounded(chunks,size,chunk,response)
    return b''.join(chunks)


def _read_gzip(response):
    chunks=[];size=0;decoder=None;complete=False
    try:
        for wire in response.iter_raw(chunk_size=min(READ_CHUNK_BYTES,MAX_RESPONSE_BYTES+1)):
            pending=wire
            while pending:
                if decoder is None:
                    decoder=zlib.decompressobj(16+zlib.MAX_WBITS);complete=False
                before=len(pending)
                decoded=decoder.decompress(pending,MAX_RESPONSE_BYTES-size+1)
                size=_append_bounded(chunks,size,decoded,response)
                if decoder.eof:
                    pending=decoder.unused_data;decoder=None;complete=True
                else:
                    pending=decoder.unconsumed_tail
                if pending and len(pending)==before and not decoded:
                    raise ResponseDecodeError(response)
    except zlib.error as exc:
        raise ResponseDecodeError(response) from exc
    if decoder is not None or not complete:raise ResponseDecodeError(response)
    return b''.join(chunks)


def _bounded(response):
    """Decode raw provider bytes to a fixed ceiling and release the response."""
    try:
        declared=response.headers.get('content-length','')
        if _declared_over_limit(declared):raise ResponseTooLarge(response)
        encoding=response.headers.get('content-encoding','').strip().lower()
        if encoding in ('','identity'):content=_read_identity(response)
        elif encoding=='gzip':content=_read_gzip(response)
        else:raise ResponseDecodeError(response)
        headers=[(name,value) for name,value in response.headers.multi_items()
            if name.lower() not in ('content-encoding','content-length','transfer-encoding')]
        headers.append(('content-length',str(len(content))))
        return httpx.Response(response.status_code,headers=headers,content=content,
            request=response.request,extensions=response.extensions)
    finally:response.close()


@contextmanager
def _borrow():
    global _client, _active
    with _condition:
        _condition.wait_for(lambda: not _closing)
        if _client is None:
            limit=connection_limit()
            _client = httpx.Client(limits=httpx.Limits(max_connections=limit,
                max_keepalive_connections=limit, keepalive_expiry=30), follow_redirects=False)
        client = _client
        _active += 1
        _condition.notify_all()
    try: yield client
    finally:
        with _condition:
            _active -= 1
            _condition.notify_all()


def _send(method, url, *, headers, timeout, json=None, encoded_body=None):
    # Build directly, rather than Client.build_request: never merge a previous
    # response's cookies or any credential-bearing client defaults into a send.
    deadline = httpx.Timeout(timeout, connect=min(timeout, 10), pool=min(timeout, 5))
    with _borrow() as client:
        # Preserve HTTPX's public negotiation/user-agent defaults through a small
        # allowlist; never copy authorization, cookies or arbitrary client state.
        defaults = {name:client.headers[name] for name in
                    ('accept','connection','user-agent') if name in client.headers}
        defaults['accept-encoding']='gzip'
        values={'headers':{**defaults, **headers},'extensions':{'timeout':deadline.as_dict()}}
        if json is not None:values['json']=json
        if encoded_body is not None:values['content']=encoded_body
        request = httpx.Request(method, url, **values)
        if encoded_body is not None:request.headers.setdefault('content-type','application/json')
        try:return _bounded(client.send(request,follow_redirects=False,stream=True))
        finally: client.cookies.clear()


def get(url, *, headers, timeout):
    return _send('GET',url,headers=headers,timeout=timeout)


def post(url, *, headers, json, timeout, encoded_body=None):
    return _send('POST',url,headers=headers,json=json,timeout=timeout,encoded_body=encoded_body)


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
