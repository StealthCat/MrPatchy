# Capability and delivery-status matrix

This is the one current index of what Mr Patchy has delivered and what remains,
for open issues and the roadmap. It links each capability to its source, merged
PR and remaining acceptance. Historical review documents (for example
`docs/REVIEW.md`, `docs/COMPLETION_REVIEW.md` and the dated code reviews) keep
their text unchanged as checkpoints. Where they list a capability as unfinished,
this matrix states the current position.

Status as of main `3ac8f68` (v1.37.10), 2026-11-03. Tracks issue
[#347](https://github.com/StealthCat/MrPatchy/issues/347).

## How to read it

| Status | Meaning |
| --- | --- |
| **Delivered** | Merged to main. The cited PR is in `CHANGELOG.md`. |
| **Partial** | Some slices merged. The remaining acceptance is listed. The issue stays open. |
| **In review** | An open PR exists. It is **not** delivered behavior until merged. |
| **Planned** | The issue has acceptance criteria but no merged or open implementation. |
| **Blocked** | Waiting on a decision, access or another slice. The blocker is named. |

Three distinctions apply throughout:

- An **open issue** does not mean outstanding implementation. Some are only
  waiting for the coordinator to reconcile and close them.
- An **unmerged PR** is not delivered behavior, whatever its CI state.
- **Synthetic validation** (disposable SQLite/MySQL fixtures, stubbed providers,
  unit tests) is not real-target acceptance. A row's *Coverage limits* column says
  which of the two backs it.

Ownership and capacity are recorded on each issue and on coordinator issue
[#222](https://github.com/StealthCat/MrPatchy/issues/222), not here. Versioning,
README/CHANGELOG updates, merging and issue closure stay with the coordinator.
Nothing in this file authorizes a runtime response action.

## Initial reconciled set

| Capability | Issue | Status | Delivered (merged) | Remaining acceptance | Coverage limits |
| --- | --- | --- | --- | --- | --- |
| Distribution/major OS upgrade availability on server dashboards | [#96](https://github.com/StealthCat/MrPatchy/issues/96), [#305](https://github.com/StealthCat/MrPatchy/issues/305) | Partial | Release-planning path already runs read-only `do-release-upgrade -c` in `target/release.py`. | Controller and UI delivery in open [PR #304](https://github.com/StealthCat/MrPatchy/pull/304) (**In review**, with a review blocker on its status projection). Bounded Ubuntu offer probe with available / not-offered / unknown states (#305). RPM families and remaining UI locations. | Synthetic only. No native Ubuntu or RPM offer probe has been recorded. Read-only. No upgrade is started. |
| Agent spool observability: utilization, delivery lag, lost-observation counters | [#108](https://github.com/StealthCat/MrPatchy/issues/108), related [#106](https://github.com/StealthCat/MrPatchy/issues/106), [#107](https://github.com/StealthCat/MrPatchy/issues/107) | Partial | [PR #326](https://github.com/StealthCat/MrPatchy/pull/326): read-only per-server spool-health API. | Server Overview display in open [PR #332](https://github.com/StealthCat/MrPatchy/pull/332) and fleet summary in [PR #333](https://github.com/StealthCat/MrPatchy/pull/333) (**In review**). #333 has a full-host materialization blocker. #106 and #107 (adaptive batching, durable spool configuration) still need a design decision. | API is source-derived and tested synthetically. Not exercised against a loaded real fleet. |
| Shared target-agent helper logic | [#190](https://github.com/StealthCat/MrPatchy/issues/190) | Partial | [PR #286](https://github.com/StealthCat/MrPatchy/pull/286): `atomic()` refuses symlink destinations and fsyncs the directory. Managed-file hashing and metadata come from one descriptor. | Shared target module, ancestor walkers, os-release / boot-id / rpm detection and import cleanup. | Unit tests only. |
| Container and supply-chain hardening | [#201](https://github.com/StealthCat/MrPatchy/issues/201) | Partial | [PR #303](https://github.com/StealthCat/MrPatchy/pull/303): pinned image digests. [PR #306](https://github.com/StealthCat/MrPatchy/pull/306): hash-locked runtime Python install. [PR #302](https://github.com/StealthCat/MrPatchy/pull/302): CodeQL `security-extended` scanning. CodeQL findings fixed by PRs #312, #314, #315, #316, #317. | Dependency-vulnerability policy, compose sandbox and resource controls, apt and GCP CLI locking, development and test lock scope. | Source scans are clean on main at the last recorded run. **Live code-scanning alert state could not be read** (API access blocked), so alert closure is unverified. |
| Multi-provider AI engine with per-feature routing | [#290](https://github.com/StealthCat/MrPatchy/issues/290) | Partial | Shared pricing, rate admission, backoff and deferral foundations (see README AI sections). | Per-feature provider and model routing and its scoring-route slice. | Provider calls are stubbed in tests. No live-provider acceptance is recorded here. |
| Duplicated AI pricing, plan generation and response logic | [#189](https://github.com/StealthCat/MrPatchy/issues/189) | Partial | [PR #301](https://github.com/StealthCat/MrPatchy/pull/301) (behavior-preserving consolidation). | Shared tier-multiplier table in open [PR #283](https://github.com/StealthCat/MrPatchy/pull/283) (**In review**). Intentional scanner/startup differences are preserved. | Refactor only. No behavior change claimed. |
| Enrollment throttling and route-error headers | [#202](https://github.com/StealthCat/MrPatchy/issues/202) | Needs owner reconciliation | Enrollment throttling and [PR #264](https://github.com/StealthCat/MrPatchy/pull/264) (security headers on unhandled route errors) are on main. | The issue is still open although its reported behavior is in the reviewed tree. Its owner or the coordinator should confirm against the source and close it. | Evidence-based reconciliation is outstanding. This matrix does not close it. |
| Bug priority-label policy (P1–P3) | [#318](https://github.com/StealthCat/MrPatchy/issues/318) | In review | None. | Open [PR #319](https://github.com/StealthCat/MrPatchy/pull/319) updates `AGENTS.md`. | Policy document only. |
| Device health: root filesystem, pressure and expiry signals | [#342](https://github.com/StealthCat/MrPatchy/issues/342) | In review (first slice) | None. | Open draft [PR #348](https://github.com/StealthCat/MrPatchy/pull/348) adds root filesystem byte and inode telemetry. CPU and memory pressure, time-sync, certificate expiry, history, alerts, UI and patch preflight remain. | Telemetry only. Unit tests only. |
| Incident review state versus deferred security plans | [#103](https://github.com/StealthCat/MrPatchy/issues/103) | Blocked | None. | The current behavior is reproduced: a manual plan is approved after its incident closes. A maintainer must choose whether to allow retrospective plans or bind the plan to incident state. | Reproduced on disposable synthetic data. This is a policy decision, not a defect fix. |

## Unclaimed planned work

These issues have scope and acceptance criteria but no implementation, claim or
open PR. They are *Planned*, not partial.

| Issue | Capability |
| --- | --- |
| [#334](https://github.com/StealthCat/MrPatchy/issues/334) | Asset groups, policy inheritance and scoped administration |
| [#335](https://github.com/StealthCat/MrPatchy/issues/335) | Read-only security posture and configuration compliance |
| [#336](https://github.com/StealthCat/MrPatchy/issues/336) | Container and application dependency inventory with workload attribution |
| [#337](https://github.com/StealthCat/MrPatchy/issues/337) | Scoped service credentials and reliable external integrations |
| [#338](https://github.com/StealthCat/MrPatchy/issues/338) | Application-aware health gates for patch and reboot workflows |
| [#339](https://github.com/StealthCat/MrPatchy/issues/339) | Rollout rings, soak gates and service availability limits |
| [#340](https://github.com/StealthCat/MrPatchy/issues/340) | Change freezes, holiday calendars and expiring patch exceptions |
| [#341](https://github.com/StealthCat/MrPatchy/issues/341) | Verified OS support lifecycle and migration planning queue |
| [#343](https://github.com/StealthCat/MrPatchy/issues/343) | Incident case ownership, investigation notes and scoped exceptions |
| [#344](https://github.com/StealthCat/MrPatchy/issues/344) | Saved fleet queries and evidence-backed patch compliance reports |
| [#345](https://github.com/StealthCat/MrPatchy/issues/345) | Recovery readiness dashboard and verifiable restore evidence |
| [#346](https://github.com/StealthCat/MrPatchy/issues/346) | External secret custody and recoverable encryption-key rotation |
| [#347](https://github.com/StealthCat/MrPatchy/issues/347) | This matrix (first slice delivered by the PR that adds this file) |

## Maintenance

- Update the matrix in the same handoff as the PR that changes a row. A worker
  proposes the row change in the PR body. The coordinator applies it with the
  README and changelog notes.
- Change a status to **Delivered** only after the PR is merged and listed in
  `CHANGELOG.md`. Link the PR. Do not rewrite historical checkpoint text.
- The remaining open-PR rows go stale quickly. When a PR merges, move its
  contribution into the *Delivered* column and shorten *Remaining acceptance*.
