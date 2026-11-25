"""Superseded pull-request runs are cancelled in every PR workflow (issue #1514)."""
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"


def _load(name):
    return yaml.safe_load((WORKFLOWS / name).read_text())


def _triggers(doc):
    # PyYAML reads the bare key `on` as boolean True.
    return doc.get("on", doc.get(True)) or {}


@pytest.mark.parametrize("name", ["ci.yml", "codeql.yml"])
def test_pull_request_runs_supersede_each_other(name):
    doc = _load(name)
    assert "pull_request" in _triggers(doc)
    concurrency = doc["concurrency"]
    assert concurrency["cancel-in-progress"] is True
    group = concurrency["group"]
    assert group.startswith("${{ github.workflow }}-")
    assert "format('pr-{0}', github.event.pull_request.number)" in group
    assert "format('push-{0}', github.ref)" in group
    # Scheduled and manual runs fall through to their own unique group.
    assert group.rstrip("} ").endswith("|| github.run_id")


def test_codeql_grouping_matches_validate():
    assert _load("codeql.yml")["concurrency"] == _load("ci.yml")["concurrency"]


def test_codeql_analysis_is_otherwise_unchanged():
    doc = _load("codeql.yml")
    triggers = _triggers(doc)
    assert triggers["push"] == {"branches": ["main"]}
    assert triggers["pull_request"] == {"branches": ["main"]}
    assert "schedule" in triggers
    job = doc["jobs"]["analyze-python"]
    init = next(s for s in job["steps"] if s.get("name") == "Initialize CodeQL")
    assert init["with"] == {"languages": "python", "queries": "security-extended"}
