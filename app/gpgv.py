"""Bounded OpenPGP verification with one strict status contract."""
from .process import bounded


class GPGVError(ValueError):
    """The signature command or its machine-readable status was unacceptable."""


STRONG_DIGESTS = frozenset({'8', '9', '10', '11'})


def valid_signers(status):
    """Return fingerprints only when every VALIDSIG uses a strong digest."""
    if not isinstance(status, str) or '\ufffd' in status:
        raise GPGVError('OpenPGP signature verification failed')
    rows = [line.split() for line in status.splitlines()
            if line.startswith('[GNUPG:] VALIDSIG ')]
    if not rows:
        raise GPGVError('OpenPGP signature verification failed')
    if any(len(row) < 10 or row[9] not in STRONG_DIGESTS for row in rows):
        raise GPGVError('OpenPGP signature requires a strong digest')
    return [row[2] for row in rows]


def verify(args, *, timeout=15, limit=64_000):
    """Run gpgv with bounded output and normalize all verification failures."""
    try:
        output, _ = bounded(args, timeout=timeout, limit=limit)
        return valid_signers(output)
    except GPGVError:
        raise
    except (OSError, RuntimeError, TimeoutError, UnicodeError):
        raise GPGVError('OpenPGP signature verification failed') from None
