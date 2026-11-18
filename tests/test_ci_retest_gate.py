"""The main-push retest gate skips only merges whose tree equals an already-tested PR head."""
import os
from pathlib import Path
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
GATED = ["static", "tests", "smoke", "mysql", "ssh-enrollment", "browser", "rpm", "gcp-runtime"]


def _jobs():
    return yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())["jobs"]


def _script():
    steps = _jobs()["retest"]["steps"]
    return next(s["run"] for s in steps if s.get("id") == "tree")


def test_every_validation_job_waits_for_the_gate():
    jobs = _jobs()
    for name in GATED:
        assert jobs[name]["needs"] == "retest", name
        assert jobs[name]["if"] == "needs.retest.outputs.needed == 'true'", name
    # The PR-only version gate never depends on it.
    assert "needs" not in jobs["integration-version"]
    assert jobs["retest"]["steps"][0]["with"]["fetch-depth"] == 2


def _git(repo, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    return subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True, text=True).stdout


def _run_gate(repo, event):
    out = repo / "out"
    out.write_text("")
    subprocess.run(["bash", "-ec", _script()], cwd=repo, check=True, capture_output=True, text=True,
                   env={**os.environ, "GITHUB_EVENT_NAME": event, "GITHUB_OUTPUT": str(out)})
    return out.read_text().strip()


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "a").write_text("1")
    _git(tmp_path, "add", "a")
    _git(tmp_path, "commit", "-qm", "base")
    return tmp_path


def _merge_tested_head(repo, *, head_contains_main):
    _git(repo, "checkout", "-qb", "pr")
    (repo / "b").write_text("pr")
    _git(repo, "add", "b")
    _git(repo, "commit", "-qm", "pr work")
    _git(repo, "checkout", "-q", "main")
    if not head_contains_main:
        (repo / "c").write_text("main moved")
        _git(repo, "add", "c")
        _git(repo, "commit", "-qm", "main moved")
    _git(repo, "merge", "-q", "--no-ff", "-m", "merge", "pr")


def test_push_of_merge_equal_to_tested_head_is_skipped(repo):
    _merge_tested_head(repo, head_contains_main=True)
    assert _run_gate(repo, "push") == "needed=false"


def test_push_of_merge_that_changes_the_tree_runs_everything(repo):
    _merge_tested_head(repo, head_contains_main=False)
    assert _run_gate(repo, "push") == "needed=true"


def test_non_merge_push_runs_everything(repo):
    (repo / "a").write_text("2")
    _git(repo, "commit", "-qam", "direct")
    assert _run_gate(repo, "push") == "needed=true"


@pytest.mark.parametrize("event", ["pull_request", "workflow_dispatch"])
def test_pull_requests_and_manual_runs_always_run_everything(repo, event):
    # A PR's merge ref also has its head as second parent with an equal tree; it must still run.
    _merge_tested_head(repo, head_contains_main=True)
    assert _run_gate(repo, event) == "needed=true"
