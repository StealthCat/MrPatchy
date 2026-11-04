import os
import re
import time
from pathlib import Path

from app import worker_health

ROOT = Path(__file__).resolve().parents[1]


def test_missing_stale_future_and_fresh_files(tmp_path):
    f = str(tmp_path / "alive")
    assert not worker_health.healthy(f)
    worker_health.touch(f)
    assert worker_health.healthy(f)
    old = time.time() - worker_health.MAX_AGE - 5
    os.utime(f, (old, old))
    assert not worker_health.healthy(f)
    future = time.time() + 3600
    os.utime(f, (future, future))
    assert not worker_health.healthy(f)


def test_touch_never_raises(tmp_path):
    worker_health.touch(str(tmp_path / "missing" / "alive"))


def test_loop_touches_only_after_a_successful_heartbeat():
    src = (ROOT / "app" / "worker.py").read_text()
    heartbeat = src.index("draining=reporter.heartbeat(")
    touch = src.index("worker_health.touch()")
    assert heartbeat < touch < src.index("if draining and is_leader")


def test_compose_worker_has_healthcheck_and_app_has_none_of_it():
    text = (ROOT / "compose.yaml").read_text()
    worker = re.search(r"^  worker:\n(.*?)(?=^  \w)", text, re.S | re.M).group(1)
    assert "python, -m, app.worker_health" in worker
    assert "healthcheck:" in worker
    assert "/tmp" in worker
