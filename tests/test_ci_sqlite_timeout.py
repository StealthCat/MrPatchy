"""Regression for #953: a passing SQLite suite must not be cancelled by the job timeout."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

# Observed on hosted runners (2026-11-15): the pytest step took up to 41 m 55 s and the
# setup and smoke steps around it about 4 minutes in total.
OBSERVED_PYTEST_MINUTES = 42
SMOKE_RESERVE_MINUTES = 10


def _tests_job():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    return workflow["jobs"]["tests"]


def _pytest_step_index(steps):
    found = [i for i, s in enumerate(steps) if s.get("run", "").startswith("python -m pytest -q")]
    assert len(found) == 1, "the tests job runs the whole SQLite suite in exactly one step"
    return found[0]


def test_sqlite_suite_step_has_headroom_over_observed_runtime():
    steps = _tests_job()["steps"]
    step = steps[_pytest_step_index(steps)]
    # A 45-minute pytest step must still complete; stay bounded so a hung suite fails.
    assert 45 < OBSERVED_PYTEST_MINUTES + 10 <= step["timeout-minutes"] <= 90


def test_job_timeout_reserves_time_for_smoke_steps_after_the_suite():
    job = _tests_job()
    steps = job["steps"]
    index = _pytest_step_index(steps)
    assert job["timeout-minutes"] >= steps[index]["timeout-minutes"] + SMOKE_RESERVE_MINUTES
    assert job["timeout-minutes"] <= 120
    # The reserve protects real work: the image build and Compose/Caddy checks still follow.
    later = " ".join(s.get("run", "") for s in steps[index + 1:])
    for needle in ("docker build -t mrpatchy:test .", "docker compose --env-file .env.ci up --build -d --wait",
                   "tests/integration_proxy.py", "tests/integration_tls.py", "-k native_caddy"):
        assert needle in later


def test_sqlite_suite_runs_every_test_serially_and_reports_slowest():
    steps = _tests_job()["steps"]
    step = steps[_pytest_step_index(steps)]
    assert step["run"] == "python -m pytest -q --durations=25"
    assert "MRPATCHY_TEST_SHARD" not in (_tests_job().get("env") or {})
