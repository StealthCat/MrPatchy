import datetime as dt
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("dependency_policy", ROOT / "tools" / "dependency_policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

TODAY = dt.date(2026, 11, 4)


def report(*vulns):
    return {"dependencies": [{"name": "pkg", "version": "1.0", "vulns": list(vulns)}, {"name": "ok", "version": "2", "vulns": []}]}


def exc(**kw):
    item = {"id": "GHSA-aaaa", "owner": "ops", "reason": "no fix yet", "expires": "2026-12-01"}
    item.update(kw)
    return {"exceptions": [item]}


VULN = {"id": "PYSEC-1", "aliases": ["GHSA-aaaa"], "fix_versions": ["1.1"]}


def test_clean_report_passes():
    assert policy.evaluate(report(), {"exceptions": []}, TODAY) == ([], [])


def test_unexcepted_vulnerability_fails():
    problems, _ = policy.evaluate(report(VULN), {"exceptions": []}, TODAY)
    assert problems and "PYSEC-1" in problems[0] and "1.1" in problems[0]


def test_active_exception_matches_alias():
    problems, accepted = policy.evaluate(report(VULN), exc(), TODAY)
    assert problems == [] and "GHSA-aaaa" in accepted[0]


def test_expired_exception_fails_and_does_not_accept():
    problems, accepted = policy.evaluate(report(VULN), exc(expires="2026-11-03"), TODAY)
    assert accepted == [] and any("expired" in p for p in problems) and any("unresolved" in p for p in problems)


def test_malformed_and_overlong_exceptions_fail():
    assert any("owner" in p for p in policy.evaluate(report(), exc(owner=" "), TODAY)[0])
    assert any("invalid expiry" in p for p in policy.evaluate(report(), exc(expires="soon"), TODAY)[0])
    assert any("90 days" in p for p in policy.evaluate(report(), exc(expires="2027-06-01"), TODAY)[0])


def test_unused_exception_fails():
    assert any("matches no finding" in p for p in policy.evaluate(report(), exc(), TODAY)[0])


def test_non_audit_report_fails():
    assert policy.evaluate({"oops": 1}, {"exceptions": []}, TODAY)[0]


def test_committed_exceptions_file_is_valid_and_ci_runs_gate():
    data = json.loads((ROOT / "docs" / "dependency-exceptions.json").read_text())
    assert policy.load_exceptions(data, dt.datetime.now(dt.timezone.utc).date())[0] == []
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "pip-audit" in ci and "tools/dependency_policy.py" in ci and "--require-hashes" in ci
