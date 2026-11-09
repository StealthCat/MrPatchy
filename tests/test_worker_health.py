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


def test_compose_worker_stop_grace_outlasts_longest_job_ssh_timeout():
    text = (ROOT / "compose.yaml").read_text()
    worker = re.search(r"^  worker:\n(.*?)(?=^  \w)", text, re.S | re.M).group(1)
    m = re.search(r"^    stop_grace_period: \$\{[A-Z_]+:-(\d+)s\}$", worker, re.M)
    assert m, "worker needs a stop_grace_period; Docker's 10 s default SIGKILLs running jobs"
    assert int(m.group(1)) > 7500


def test_compose_passes_bounded_ai_http_connections_to_app_and_worker():
    text = (ROOT / "compose.yaml").read_text()
    for service in ("app", "worker"):
        block = re.search(rf"^  {service}:\n(.*?)(?=^  \w)", text, re.S | re.M).group(1)
        assert "MRPATCHY_AI_HTTP_CONNECTIONS: ${MRPATCHY_AI_HTTP_CONNECTIONS:-16}" in block
