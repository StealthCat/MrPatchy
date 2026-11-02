"""Bound public installer generation while preserving interrupted-download retries."""
import ipaddress
import math
import time

from fastapi import HTTPException

from .coordination import Lock
from .db import Session, Setting, audit
from .security import token_hash

STATE_KEY = 'enrollment-download-rate'
WINDOW = 60
LIMIT = 10
SOURCE_LIMIT = 1024


def source_id(request):
    # Use the ASGI peer, like login; never trust raw forwarding headers here.
    # Proxy deployments must configure their trusted ASGI proxy peers correctly.
    address = request.client.host if request.client else 'unknown'
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        pass  # Test transports / absent-peer fallback still share a bounded bucket.
    return token_hash(address)


def admit(source):
    """Share a bounded sliding window across controller processes and restarts.

    One small settings row and a short existing cross-process lock avoid per-IP
    rows/lock files growing without bound. Do not evict active buckets: rotating
    sources must not reset a prior source's allowance. Fail before generation on
    contention rather than waiting in an unauthenticated request thread.
    """
    lock = Lock('enrollment-download-rate')
    if not lock.acquire(False):
        raise HTTPException(503, 'Enrollment downloads are busy. Retry shortly.', headers={'Retry-After': '1'})
    try:
        with Session() as session:
            now = time.time()
            row = session.get(Setting, STATE_KEY)
            sources = {key: recent for key, stamps in (row.value if row else {}).items()
                       if (recent := [stamp for stamp in stamps if stamp + WINDOW > now])}
            recent = sources.get(source, [])
            if len(recent) >= LIMIT or (not recent and len(sources) >= SOURCE_LIMIT):
                eligible = min(recent) + WINDOW if recent else min(max(v) for v in sources.values()) + WINDOW
                raise HTTPException(429, 'Too many enrollment downloads. Retry after the displayed delay.',
                                    headers={'Retry-After': str(max(1, math.ceil(eligible - now)))})
            sources[source] = recent + [now]
            if row:
                row.value = sources
            else:
                session.add(Setting(key=STATE_KEY, value=sources))
            session.commit()
    finally:
        lock.release()


def prepared(session, row, source):
    """Record preparation, not proof that a client received/executed the body."""
    uses = row.value.get('downloads', 0) + 1
    row.value = {**row.value, 'downloads': uses}
    audit(session, 'enrollment installer prepared',
          f"{row.value['host_id']} link={row.key.removeprefix('enroll:')[:16]} "
          f"source={source} use={uses} {'first' if uses == 1 else 'retry'}")
