"""Regression for #666: MySQL shards must not be cancelled while still progressing."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _mysql_job():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    return workflow["jobs"]["mysql"]


def test_mysql_shards_have_headroom_over_observed_runtimes():
    job = _mysql_job()
    # Observed whole-job durations reached ~19 minutes and passing runs were
    # cancelled at the old 20-minute bound. Keep headroom, but stay bounded.
    assert 30 <= job["timeout-minutes"] <= 45
    assert job["strategy"]["fail-fast"] is False
    assert job["strategy"]["matrix"]["shard"] == [1, 2, 3, 4]


def test_mysql_setup_steps_remain_individually_bounded():
    steps = _mysql_job()["steps"]
    apt = [s for s in steps if "apt-get" in s.get("run", "")]
    assert apt and all(s.get("timeout-minutes", 99) <= 5 for s in apt)


def test_mysql_pytest_reports_slowest_tests_without_deselecting_any():
    runs = [s["run"] for s in _mysql_job()["steps"] if "pytest" in s.get("run", "")]
    assert runs == ["python -m pytest -q --durations=25"]
