# Contributing to Mr Patchy

Please read [LICENSE](LICENSE) and [COMMERCIAL.md](COMMERCIAL.md) before contributing.
Mr Patchy is free for personal, noncommercial use; commercial and organizational
operation requires a separate paid agreement. Source availability does not remove
that requirement.

## Rights in new contributions

By intentionally submitting an original contribution for inclusion in this project
after these terms are published, you represent that you own the contribution or
have authority to grant the following rights. You retain ownership and grant
Robert Cronin a perpetual, worldwide, nonexclusive, royalty-free, irrevocable
copyright license to use, reproduce, modify, display, distribute and sublicense
the contribution as part of Mr Patchy under the project's personal-use license,
separate paid commercial agreements, and future licensing terms. This grant does
not transfer ownership and does not cover unrelated work you have not submitted.

Do not submit employer-owned material without authorization. Identify any
third-party code, its source, license and notices before inclusion; do not treat
it as your original work. If these terms do not fit your contribution, contact
the maintainer before submitting it for inclusion. Existing contributions are
not retroactively subject to this grant.

## Development

Use focused changes and relevant tests. Keep the current theme, mascot, role
checks, audit history and explicit operational approval boundaries intact.
Follow repository instructions and the README's validation commands. Never
include live credentials, customer data or private endpoint evidence in a patch.


Independent workers may develop in parallel in isolated issue-owned branches,
initially with at most two active implementation streams. Workers submit focused,
tested PRs and record change notes and compatibility impacts in the PR body. They
leave application versioning and all README.md/CHANGELOG.md notes and updates to
the single integration coordinator;
README has no current-version field. Worker commits and draft PR titles do not
require version prefixes.

The coordinator accepts an explicit ready handoff, integrates current main,
allocates the final major-1 version, updates README documentation from the PR
notes, prepends a numbered PR-linked changelog entry,
and merges only after all applicable checks pass on the final integrated commit.
The `integration-version` check deliberately fails on an unversioned development PR
until that preparation is complete. Workers must still pass the other applicable
checks. See [AGENTS.md](AGENTS.md) for ownership and authorization rules and
[the coordinator guide](docs/DEVELOPMENT_COORDINATOR.md) for the copyable prompt.
