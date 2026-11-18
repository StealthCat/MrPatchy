"""Regression for #953 and the sharded SQLite suite.

The serial SQLite suite (28-42 minutes on one hosted runner) set the length of every
CI run. It now runs as four shards like the MySQL job, and the Docker/Compose/Caddy
checks that followed it run in their own `smoke` job. These tests keep every test
running exactly once, keep each shard bounded with headroom, and keep the smoke
checks in CI.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

# Observed on hosted runners (2026-11-15): the serial pytest step took up to 41 m 55 s.
# Four file-balanced shards should each take roughly a quarter of that; allow for an
# uneven split and slow runners while still failing a hung shard.
OBSERVED_SERIAL_PYTEST_MINUTES = 42
SHARDS = [1, 2, 3, 4]


def _workflow():
    return yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())


def _job(name):
    return _workflow()["jobs"][name]


def _pytest_steps(steps):
    return [s for s in steps if s.get("run", "").startswith("python -m pytest -q")]


def test_sqlite_suite_is_sharded_like_mysql():
    job = _job("tests")
    assert job["strategy"]["fail-fast"] is False
    assert job["strategy"]["matrix"]["shard"] == SHARDS
    assert job["strategy"]["matrix"]["shard"] == _job("mysql")["strategy"]["matrix"]["shard"]
    assert job["env"]["MRPATCHY_TEST_SHARD"] == "${{ matrix.shard }}/4"
    # SQLite shards must not point at the MySQL service.
    assert "TEST_DATABASE_URL" not in job["env"]


def test_each_shard_runs_its_files_and_reports_slowest():
    steps = _job("tests")["steps"]
    runs = _pytest_steps(steps)
    assert len(runs) == 1, "each shard runs its share of the suite in exactly one step"
    assert runs[0]["run"] == "python -m pytest -q --durations=25"


def test_shard_timeouts_keep_headroom_but_stay_bounded():
    job = _job("tests")
    step = _pytest_steps(job["steps"])[0]
    per_shard = OBSERVED_SERIAL_PYTEST_MINUTES / len(SHARDS)
    # Twice an even share covers an uneven split or a slow runner.
    assert 2 * per_shard <= step["timeout-minutes"] <= 45
    assert job["timeout-minutes"] >= step["timeout-minutes"] + 5
    assert job["timeout-minutes"] <= 60


def test_restic_drills_still_run_in_sqlite_shards():
    steps = _job("tests")["steps"]
    assert any("restic" in s.get("run", "") and s.get("timeout-minutes", 99) <= 5 for s in steps)


def test_smoke_checks_moved_out_of_the_shards_and_still_run():
    tests_runs = " ".join(s.get("run", "") for s in _job("tests")["steps"])
    assert "docker" not in tests_runs
    smoke = _job("smoke")
    assert smoke["timeout-minutes"] <= 30
    assert "strategy" not in smoke, "the smoke checks run once, not per shard"
    runs = " ".join(s.get("run", "") for s in smoke["steps"])
    for needle in ("pip install -r requirements-dev.txt", "docker build -t mrpatchy:test .",
                   "docker compose --env-file .env.ci up --build -d --wait",
                   "tests/integration_proxy.py", "tests/integration_tls.py", "-k native_caddy",
                   "docker compose --env-file .env.ci down -v"):
        assert needle in runs
    cleanup = [s for s in smoke["steps"] if s.get("name") == "Compose diagnostics and cleanup"]
    assert cleanup and cleanup[0].get("if") == "always()"


def test_main_runs_supersede_but_manual_runs_do_not():
    group = _workflow()["concurrency"]["group"]
    assert "format('pr-{0}', github.event.pull_request.number)" in group
    assert "format('push-{0}', github.ref)" in group
    assert group.rstrip("}").rstrip().endswith("github.run_id")
    assert _workflow()["concurrency"]["cancel-in-progress"] is True
