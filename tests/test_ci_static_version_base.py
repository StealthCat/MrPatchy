"""The static job's version step compares a PR merge commit with its own base (issue #1500)."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
STEP = "Source version and changelog consistency"
ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}


def _static():
    return yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())["jobs"]["static"]


def _step():
    return next(s for s in _static()["steps"] if s.get("name") == STEP)


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, env=ENV, check=True, capture_output=True, text=True).stdout.strip()


def _write_release(repo, version, message):
    (repo / "app").mkdir(exist_ok=True)
    (repo / "app" / "main.py").write_text(
        f"APP_VERSION = '{version}'\napp = FastAPI(version=APP_VERSION)\nhealth = {{'version':APP_VERSION}}\n")
    log = repo / "CHANGELOG.md"
    old = log.read_text() if log.exists() else "# Changelog\n\n"
    head, _, rest = old.partition("\n\n")
    log.write_text(f"{head}\n\n## {version} — {message}\n\n1. {message}.\n\n{rest}")


def _release(repo, version, message):
    _write_release(repo, version, message)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def upstream(tmp_path):
    repo = tmp_path / "upstream"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "tools").mkdir()
    shutil.copy(ROOT / "tools" / "check_version.py", repo / "tools" / "check_version.py")
    (repo / "README.md").write_text("Mr Patchy\n")
    _release(repo, "1.86.0", "base release")
    return repo


def _merge_commit(upstream, base, change):
    """Build a GitHub-style PR merge commit on ``base`` and return its SHA."""
    _git(upstream, "checkout", "-q", "--detach", base)
    change(upstream)
    _git(upstream, "add", "-A")
    _git(upstream, "commit", "-qm", "worker change")
    head = _git(upstream, "rev-parse", "HEAD")
    _git(upstream, "checkout", "-q", "--detach", base)
    _git(upstream, "merge", "-q", "--no-ff", "--no-edit", head)
    merge = _git(upstream, "rev-parse", "HEAD")
    _git(upstream, "checkout", "-q", "main")
    return merge


def _checkout(tmp_path, upstream, sha):
    """Clone like actions/checkout with this step's fetch depth, at ``sha``."""
    work = tmp_path / "work"
    # actions/checkout fetches one commit unless the job asks for more.
    depth = str(_static()["steps"][0].get("with", {}).get("fetch-depth", 1))
    _git(tmp_path, "init", "-q", str(work))
    _git(work, "remote", "add", "origin", upstream.resolve().as_uri())
    _git(work, "-c", "protocol.file.allow=always", "fetch", "-q", "--no-tags", f"--depth={depth}", "origin", sha)
    _git(work, "checkout", "-q", "--detach", sha)
    return work


def _run(work, event, before=""):
    env = {**ENV, "GITHUB_EVENT_NAME": event, "VERSION_BASE": before, "GIT_ALLOW_PROTOCOL": "file",
           # The base branch the workflow used to re-fetch (still the event value).
           "BASE_REF": "main"}
    return subprocess.run(["bash", "-ec", _step()["run"]], cwd=work, env=env, capture_output=True, text=True)


def _feature(repo):
    (repo / "feature.py").write_text("x = 1\n")


def test_pr_merge_commit_passes_after_main_releases_a_newer_version(tmp_path, upstream):
    base = _git(upstream, "rev-parse", "HEAD")
    merge = _merge_commit(upstream, base, _feature)
    newer_main = _release(upstream, "1.87.0", "newer release while the PR run was queued")
    work = _checkout(tmp_path, upstream, merge)
    # The failure the issue reports: comparing this merge commit with the live main.
    _git(work, "-c", "protocol.file.allow=always", "fetch", "-q", "--depth=1", "origin", newer_main)
    stale = subprocess.run(["python", "tools/check_version.py", "--base-ref", newer_main, "--allow-unversioned"],
                           cwd=work, capture_output=True, text=True)
    assert stale.returncode == 1 and "must increase source version" in stale.stderr
    result = _run(work, "pull_request")
    assert result.returncode == 0, result.stderr
    assert "Source version 1.86.0 is consistent" in result.stdout


def test_pr_that_lowers_the_version_from_its_own_base_still_fails(tmp_path, upstream):
    base = _git(upstream, "rev-parse", "HEAD")
    merge = _merge_commit(upstream, base, lambda repo: _write_release(repo, "1.85.9", "downgrade"))
    result = _run(_checkout(tmp_path, upstream, merge), "pull_request")
    assert result.returncode == 1
    assert "must increase source version" in result.stderr


def test_pr_that_edits_the_shared_changelog_without_a_version_still_fails(tmp_path, upstream):
    base = _git(upstream, "rev-parse", "HEAD")
    merge = _merge_commit(upstream, base, lambda repo: (repo / "CHANGELOG.md").write_text(
        (repo / "CHANGELOG.md").read_text() + "\n- worker note\n"))
    result = _run(_checkout(tmp_path, upstream, merge), "pull_request")
    assert result.returncode == 1
    assert "leave the shared changelog unchanged" in result.stderr


def test_push_still_compares_with_the_previous_main_commit(tmp_path, upstream):
    before = _git(upstream, "rev-parse", "HEAD")
    released = _release(upstream, "1.87.0", "integration")
    assert _run(_checkout(tmp_path, upstream, released), "push", before).returncode == 0
    (upstream / "feature.py").write_text("x = 1\n")
    _git(upstream, "add", "-A")
    _git(upstream, "commit", "-qm", "unversioned direct push")
    unversioned = _git(upstream, "rev-parse", "HEAD")
    shutil.rmtree(tmp_path / "work")
    result = _run(_checkout(tmp_path, upstream, unversioned), "push", released)
    assert result.returncode == 1 and "must increase source version" in result.stderr


def test_step_never_refetches_the_live_base_branch():
    step = _step()
    assert "refs/heads" not in step["run"] and "BASE_REF" not in step.get("env", {})
    assert "HEAD^1" in step["run"]
    assert _static()["steps"][0]["with"]["fetch-depth"] == 2
