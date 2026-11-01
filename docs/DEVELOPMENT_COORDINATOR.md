# Parallel development and integration

Independent workers implement and test changes; one designated coordinator
integrates, versions and merges them. This policy follows the user's 2026-10-31
instruction and replaces version allocation and self-merging by every worker.
Keep the existing development schedules. Start with two active implementation
streams; extra runs can resume their stream, review, or report available capacity.
Ready PRs waiting for integration do not count as active implementation streams.

## Worker handoff

Use an isolated issue-owned branch and a focused PR targeting main. Keep
APP_VERSION, README.md and CHANGELOG.md unchanged, and put change notes, compatibility
impacts, issue links and exact-commit validation in the PR body. There is no shared
Unreleased section for workers to edit and no current-version field in README.
All README/changelog notes and updates belong to the coordinator; workers include
proposed documentation text in their PR description. Workers do not merge, enable
auto-merge or close implementation issues/PRs.

Run relevant checks and:

```bash
python tools/check_version.py --base-ref <current-main-commit> --allow-unversioned
```

When code checks pass, mark the PR ready for review and record:

```text
Ready for coordinator: <exact PR head SHA>
Delivered acceptance criteria: ...
Validation and check links: ...
Dependencies, compatibility impacts and remaining limits: ...
The designated coordinator may append integration/version/conflict-resolution
commits to this branch, preserving the implementation and existing history.
Worker edits are paused until integration completes or readiness is withdrawn.
```

The CI `static` job permits unchanged development metadata and requires workers
to leave README.md and CHANGELOG.md unchanged. The separate
`integration-version` job intentionally fails until coordinator preparation.
This expected version-gate failure is distinct from a failed code/test check;
every applicable check must pass before the coordinator merges.

## Coordinator ownership and integration

Designate one coordinator, not one coordinator per worker. Use a persistent
GitHub coordination issue for session identity, UTC checkpoints, active PR,
head/base, validation and explicit handoffs. Never overlap coordinator sessions.
Comments and AGENTS.md are advisory coordination, not atomic locks or changes to
GitHub permissions. Requiring `integration-version` and the other applicable CI
checks in repository protection would enforce the check requirement at GitHub;
this workflow does not itself configure repository protection.

Accept a worker's ready handoff and prepare one PR at a time. Review actual scope
and dependencies, merge current main into the branch without rewriting commits,
and resolve only understood conflicts. Return substantive or ambiguous fixes to
the worker. Handle every README/changelog update from the PR notes, validating
features/installation/usage against the delivered code without adding a current
version to README. Set a version newer than current main, retaining major 1, and prepend
one numbered changelog entry with the exact PR link, for example:

```markdown
## 1.MINOR.PATCH — YYYY-MM-DD

1. [PR #N](https://github.com/StealthCat/MrPatchy/pull/N): describe delivered behavior.
2. Describe any compatibility impact and material limits.
```

Preserve all existing main changelog entries verbatim. Give the integration
commit, final PR title and merge/squash subject the `[vX.Y.Z]` prefix; worker
commits do not need it. Add a matching version label where supported. Skip tags.
The application still derives runtime metadata from APP_VERSION; a source version
does not imply that a Docker image was published.

Run all applicable checks on the exact integrated head, including:

```bash
python tools/check_version.py --base-ref <current-main-commit> --pr-number <PR-number>
```

Immediately before merging, confirm current main is included, the head and ready
handoff are unchanged, and all applicable final-head checks/reviews are satisfied.
Use an expected-head SHA for the merge. If main advances or the head changes,
reconcile the integration/version and rerun affected checks. After merging,
verify the actual main commit, version, changelog and closure of fully resolved
issues. Record the result before selecting the next PR. Leave incomplete issues
open. Never close blocked work merely to empty the queue.

## Existing PRs and transition

Do not abandon existing PRs or rewrite their versioned commits. Ask their owners
for the same ready handoff. During authorized integration, replace unmerged
candidate version/changelog metadata with one entry/version based on current
main, preserving all merged history and substantive work. Old candidate prefixes
are not version reservations. A handoff does not grant permission for unrelated
changes or runtime response actions.

Development automation prompts must follow the worker role and retain their
roadmap, issue-first priorities, budget, completion gate and schedule. A
coordinator prompt is a separate role; choosing its schedule is independent of
updating those worker prompts. Already running sessions may still have older
instructions and must reconcile this policy at their next checkpoint.

## Copyable coordinator prompt

Act as the sole integration coordinator for https://github.com/StealthCat/MrPatchy.
Read current main, AGENTS.md, CONTRIBUTING.md, docs/DEVELOPMENT_COORDINATOR.md and
docs/SECURITY_IMPLEMENTATION.md. Follow the coordinator role rather than the
implementation-worker role.

Refresh all open issues/PRs, ownership checkpoints, comments, reviews, dependencies
and CI results. Record your session identity and UTC checkpoint in the persistent
coordination issue. If another coordinator is active, obtain an explicit handoff
before integrating; never run two integrations concurrently.

Process ready PRs one at a time, prioritizing reproducible defects and dependency
order. Require an exact-head ready handoff before writing a worker branch.
Review actual changes and acceptance criteria. Integrate current main without
rewriting history or discarding other work; return substantive missing work or
ambiguous conflicts to the owner.

Handle all README.md and CHANGELOG.md notes and updates from the PR description,
checking documentation against the delivered implementation. Assign the final next
major-1 version in APP_VERSION and prepend one numbered, PR-linked changelog entry
preserving existing history. Keep version tracking out of README. Version the integration commit, final PR title and merge subject; add
the matching label when possible and skip Git tags.

Run the strict version checker with the current main commit and PR number, and
require all applicable checks on the exact final head, including
integration-version. Recheck main, head, readiness and reviews immediately before
merging, using an expected-head SHA. Reintegrate and rerun affected checks if
anything changes. Never merge failed, pending, unversioned or incomplete work.

After merging, verify main/version/changelog and closure of fully resolved issues.
Keep partially delivered issues open and document blockers. Close an unmerged PR
only when demonstrably duplicate or superseded, with evidence and links. Report
merged PRs/versions, validation and issue status, or a concise checkpoint when
blocked. Do not invent feature work or empty version bumps to fill the run.
