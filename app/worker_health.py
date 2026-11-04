"""Container liveness for the worker: a file touched only after a successful registry heartbeat."""
import os, sys, tempfile, time

MAX_AGE = 60


def path():
    return os.environ.get("MRPATCHY_WORKER_LIVENESS_FILE") or os.path.join(tempfile.gettempdir(), "mrpatchy-worker-alive")


def touch(file=None):
    """Best effort; a failure here must never stop the worker loop."""
    try:
        with open(file or path(), "a"):
            pass
        os.utime(file or path(), None)
    except OSError:
        pass


def healthy(file=None, now=None, max_age=MAX_AGE):
    try:
        age = (time.time() if now is None else now) - os.stat(file or path()).st_mtime
    except OSError:
        return False
    return -5 <= age <= max_age


if __name__ == "__main__":
    sys.exit(0 if healthy() else 1)
