"""Regression for #666, #972 and #1583: MySQL shards must not be cancelled while still progressing."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
# The #1583 jobs ran out of time at 45 minutes while pytest was active.
# The smallest whole-minute budget that could have let them finish is 46.
MINIMUM_OBSERVED_BUDGET_MINUTES = 46


def _mysql_job():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    return workflow["jobs"]["mysql"]


def test_mysql_shards_have_headroom_over_observed_runtimes():
    job = _mysql_job()
    # Keep at least ten minutes of headroom over the lower bound from #1583,
    # with a hard one-hour limit for jobs that do stall.
    assert MINIMUM_OBSERVED_BUDGET_MINUTES + 10 <= job["timeout-minutes"] <= 60
    assert job["strategy"]["fail-fast"] is False
    assert job["strategy"]["matrix"]["shard"] == [1, 2, 3, 4]
    assert job["env"]["MRPATCHY_TEST_SHARD"] == "${{ matrix.shard }}/4"


def test_mysql_setup_steps_remain_individually_bounded():
    steps = _mysql_job()["steps"]
    apt = [s for s in steps if "apt-get" in s.get("run", "")]
    assert apt and all(s.get("timeout-minutes", 99) <= 5 for s in apt)


def test_mysql_pytest_reports_slowest_tests_without_deselecting_any():
    runs = [s["run"] for s in _mysql_job()["steps"] if "pytest" in s.get("run", "")]
    assert runs == ["python -m pytest -q --durations=25"]
