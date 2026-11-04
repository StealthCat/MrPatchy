#!/usr/bin/env python3
"""Enforce the dependency-vulnerability policy (issue #201).

Reads a ``pip-audit --format json`` report and ``docs/dependency-exceptions.json``.
Fails when a vulnerability has no active exception, when an exception is malformed,
expired or unused, or when the report is not a recognisable pip-audit report.
Accepted exceptions need an owner, a reason and an expiry (at most 90 days ahead).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

MAX_EXCEPTION_DAYS = 90
REQUIRED = ("id", "owner", "reason", "expires")


def load_exceptions(data, today):
    problems, active = [], {}
    if not isinstance(data, dict) or not isinstance(data.get("exceptions"), list):
        return ['exceptions file must be an object with an "exceptions" list'], active
    for index, item in enumerate(data["exceptions"]):
        label = f"exception #{index + 1}"
        if not isinstance(item, dict):
            problems.append(f"{label} is not an object")
            continue
        missing = [k for k in REQUIRED if not isinstance(item.get(k), str) or not item[k].strip()]
        if missing:
            problems.append(f"{label} is missing {', '.join(missing)}")
            continue
        label = f"exception {item['id']}"
        try:
            expires = dt.date.fromisoformat(item["expires"])
        except ValueError:
            problems.append(f"{label} has an invalid expiry date {item['expires']!r}")
            continue
        if expires < today:
            problems.append(f"{label} expired on {expires}; fix the dependency or renew with review")
        elif (expires - today).days > MAX_EXCEPTION_DAYS:
            problems.append(f"{label} expires more than {MAX_EXCEPTION_DAYS} days ahead")
        else:
            active[item["id"]] = item
    return problems, active


def evaluate(report, exceptions, today):
    """Return (problems, accepted) for a pip-audit report and exceptions document."""
    problems, active = load_exceptions(exceptions, today)
    if not isinstance(report, dict) or not isinstance(report.get("dependencies"), list):
        return problems + ["audit report is not a pip-audit JSON report"], []
    accepted, used = [], set()
    for dep in report["dependencies"]:
        for vuln in dep.get("vulns") or []:
            ids = [vuln.get("id"), *(vuln.get("aliases") or [])]
            hit = next((i for i in ids if i in active), None)
            name = f"{dep.get('name')} {dep.get('version')}"
            if hit:
                used.add(hit)
                accepted.append(f"{name}: {hit} accepted until {active[hit]['expires']} (owner {active[hit]['owner']})")
            else:
                fixes = ", ".join(vuln.get("fix_versions") or []) or "none published"
                problems.append(f"{name}: {vuln.get('id')} is unresolved (fixed in: {fixes})")
    for ident in sorted(set(active) - used):
        problems.append(f"exception {ident} matches no finding; remove it")
    return problems, accepted


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="pip-audit --format json output")
    parser.add_argument("--exceptions", type=Path, default=Path("docs/dependency-exceptions.json"))
    args = parser.parse_args(argv)
    try:
        report = json.loads(args.report.read_text())
        exceptions = json.loads(args.exceptions.read_text())
    except (OSError, ValueError) as exc:
        print(f"dependency policy: cannot read inputs: {exc}", file=sys.stderr)
        return 2
    problems, accepted = evaluate(report, exceptions, dt.datetime.now(dt.timezone.utc).date())
    for line in accepted:
        print(f"accepted: {line}")
    for line in problems:
        print(f"FAIL: {line}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
