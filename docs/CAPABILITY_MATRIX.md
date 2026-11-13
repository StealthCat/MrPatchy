# Capability and delivery-status matrix

This is the one current index of what Mr Patchy has delivered and what remains,
for open issues and the roadmap. It links each capability to its source, merged
PR and remaining acceptance. Historical review documents (for example
`docs/REVIEW.md`, `docs/COMPLETION_REVIEW.md` and the dated code reviews) keep
their text unchanged as checkpoints. Where they list a capability as unfinished,
this matrix states the current position.

Status as of v1.59.74, 2026-11-13. First written against
`3ac8f68` (v1.37.10) and reconciled by the coordinator at integration. Tracks
issue [#347](https://github.com/StealthCat/MrPatchy/issues/347).

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

## Reconciled set

| Capability | Issue | Status | Delivered (merged) | Remaining acceptance | Coverage limits |
| --- | --- | --- | --- | --- | --- |
| Distribution/major OS upgrade availability on server dashboards | [#96](https://github.com/StealthCat/MrPatchy/issues/96), [#305](https://github.com/StealthCat/MrPatchy/issues/305) | Partial | [PR #304](https://github.com/StealthCat/MrPatchy/pull/304) (v1.44.0): shared `os_upgrade` status in the hosts and host-summary APIs, a badge beside eligible Debian server names and a report-only Overview notice for fresh online Debian 11→12 and 12→13 paths. The release-planning path runs read-only `do-release-upgrade -c` in `target/release.py`. | Bounded Ubuntu offer probe with available / not-offered / unknown states (#305), RPM-family detection, remaining server references and fleet notification. | Synthetic fixtures only. No native Ubuntu or RPM offer probe has been recorded. Detection is read-only and starts no upgrade. |
| Agent spool observability: utilization, delivery lag, lost-observation counters | [#108](https://github.com/StealthCat/MrPatchy/issues/108), related [#106](https://github.com/StealthCat/MrPatchy/issues/106), [#107](https://github.com/StealthCat/MrPatchy/issues/107) | Partial | [PR #326](https://github.com/StealthCat/MrPatchy/pull/326) (v1.37.1): per-server spool-health API. [PR #332](https://github.com/StealthCat/MrPatchy/pull/332) (v1.38.2): server Overview card. [PR #333](https://github.com/StealthCat/MrPatchy/pull/333) (v1.38.3): fleet spool-health API and Overview card. [PR #274](https://github.com/StealthCat/MrPatchy/pull/274) (v1.42.5): transactional running spool totals. [PR #519](https://github.com/StealthCat/MrPatchy/pull/519) (v1.48.0): per-server observation-batch ceiling. [PR #521](https://github.com/StealthCat/MrPatchy/pull/521) (v1.59.25): pure spool capacity-admission contract for #107 (unwired). | #108: oldest-observation age, ingest/flush rates, retries, delivery latency, counter continuity, alert producers and durable loss history. #106/#107: adaptive or scheduled flushing, compression, durable capacity expansion, shutdown/replay guarantees and wiring of the admission contract. | Source-derived and tested synthetically. Not exercised against a loaded real fleet. |
| Shared target-agent helper logic | [#190](https://github.com/StealthCat/MrPatchy/issues/190) | Partial | [PR #286](https://github.com/StealthCat/MrPatchy/pull/286) (v1.37.8): `atomic()` refuses symlink destinations and fsyncs the directory; managed-file hashing and metadata come from one descriptor. [PR #356](https://github.com/StealthCat/MrPatchy/pull/356) (v1.39.1): one bounded boot-identity parser. [PR #365](https://github.com/StealthCat/MrPatchy/pull/365) (v1.39.3): aligned os-release parsers. [PR #387](https://github.com/StealthCat/MrPatchy/pull/387) (v1.42.3): CI drift guard for managed-file lists and the observability drop-in path. [PR #395](https://github.com/StealthCat/MrPatchy/pull/395) (v1.44.9): shared RPM/Debian detection for security inspection. [PR #403](https://github.com/StealthCat/MrPatchy/pull/403) (v1.46.2): boot identity validated before reboot-requiring RPM transactions. | Shared target module, hash loops, ancestor walkers, the remaining duplicated reads and import cleanup. | Unit and fixture tests only. |
| Container and supply-chain hardening | [#201](https://github.com/StealthCat/MrPatchy/issues/201) | Partial | [PR #302](https://github.com/StealthCat/MrPatchy/pull/302), [#303](https://github.com/StealthCat/MrPatchy/pull/303), [#306](https://github.com/StealthCat/MrPatchy/pull/306) (v1.35.95–v1.35.99): CodeQL scanning, pinned image digests and hash-locked runtime installs. CodeQL findings fixed by PRs #312, #314, #315, #316 and #317. [PR #369](https://github.com/StealthCat/MrPatchy/pull/369) (v1.40.1): `pip-audit` gate with expiring exceptions. [PR #368](https://github.com/StealthCat/MrPatchy/pull/368) (v1.40.2): dropped Linux capabilities. [PR #376](https://github.com/StealthCat/MrPatchy/pull/376) (v1.40.5): worker healthcheck. [PR #378](https://github.com/StealthCat/MrPatchy/pull/378) (v1.40.6): PID limits. [PR #381](https://github.com/StealthCat/MrPatchy/pull/381) (v1.41.1): memory limits. [PR #385](https://github.com/StealthCat/MrPatchy/pull/385) (v1.42.2): read-only root filesystems. [PR #493](https://github.com/StealthCat/MrPatchy/pull/493) (v1.49.6): GCP override hardening guard. [PR #287](https://github.com/StealthCat/MrPatchy/pull/287) (v1.55.9): Python 3.15 runtime with hash-pinned build inputs. | The last item recorded on the issue was the live code-scanning alert inventory, which was verified on 2026-11-08. The dependency gate still does not cover npm tooling or base-image packages. Closure needs a maintainer or coordinator decision. | The signed-in code-scanning inventory on 2026-11-08 showed zero open alerts on every branch and 12 fixed alerts on `main`. Compose hardening is checked by regression tests, not against a live deployment. |
| Multi-provider AI engine with per-feature routing | [#290](https://github.com/StealthCat/MrPatchy/issues/290) | Partial | Shared pricing, rate admission, backoff and deferral foundations (see README AI sections). [PR #510](https://github.com/StealthCat/MrPatchy/pull/510) (v1.59.17): pure feature-route resolution contract with frozen-route revalidation (unwired). [PR #520](https://github.com/StealthCat/MrPatchy/pull/520) (v1.59.22): administrator-only read-only inventory of the saved connection and the model each feature inherits. | Runtime per-feature provider and model routing, provider adapters, named connections, migration, per-item overrides and the Settings UI. | Provider calls are stubbed in tests. No live-provider acceptance is recorded here. |
| Duplicated AI pricing, plan generation and response logic | [#189](https://github.com/StealthCat/MrPatchy/issues/189) | Partial | [PR #301](https://github.com/StealthCat/MrPatchy/pull/301) (v1.35.94): behavior-preserving consolidation. [PR #283](https://github.com/StealthCat/MrPatchy/pull/283) (v1.43.2): one shared tier-multiplier table. | The duplicated advisory-plan generator, response failure and latest-record helpers, the original-file stub and gpgv validation. Intentional scanner/startup differences are preserved. | Refactor only. No behavior change claimed. |
| Enrollment throttling and route-error headers | [#202](https://github.com/StealthCat/MrPatchy/issues/202) | Delivered | [PR #313](https://github.com/StealthCat/MrPatchy/pull/313) (v1.35.100): bounded, retry-preserving enrollment preparation quota. [PR #264](https://github.com/StealthCat/MrPatchy/pull/264) (v1.37.6): security headers on unhandled route errors. The coordinator verified both against source and closed the issue as completed on 2026-11-03. | None. | Shared NAT and proxy-trust limits on the quota remain documented. Preparing an enrollment link is not proof that it was downloaded or run. |
| Bug priority-label policy (P1–P3) | [#318](https://github.com/StealthCat/MrPatchy/issues/318) | Delivered | [PR #319](https://github.com/StealthCat/MrPatchy/pull/319) (v1.37.13): `AGENTS.md` priority-label policy. The issue is closed as completed. | None for the policy. Labeling individual bugs remains a triage task. | Policy document only. |
| Device health: root filesystem, pressure and expiry signals | [#342](https://github.com/StealthCat/MrPatchy/issues/342) | Partial | [PR #348](https://github.com/StealthCat/MrPatchy/pull/348) (v1.37.12): root filesystem byte and inode telemetry. [PR #391](https://github.com/StealthCat/MrPatchy/pull/391) (v1.59.2): CPU/memory pressure (PSI) and memory availability telemetry. | Time sync, certificate expiry, history, alerts, UI and patch preflight remain. | Telemetry only. Unit tests only. |
| Incident review state versus deferred security plans | [#103](https://github.com/StealthCat/MrPatchy/issues/103) | Blocked | None. | Reproduced again on 2026-11-10 on SQLite and MySQL: a deferred manual plan completes and can be approved after its incident closes. A maintainer must choose whether to allow retrospective plans or bind the plan to incident state. | Reproduced on disposable synthetic data. This is a policy decision, not a defect fix. |

## Improvement issues #334–#347

Every issue in this set now has a merged or open first slice. None is complete;
each issue stays open for its remaining acceptance.

| Issue | Capability | Status | Delivered or in review |
| --- | --- | --- | --- |
| [#334](https://github.com/StealthCat/MrPatchy/issues/334) | Asset groups, policy inheritance and scoped administration | Partial | [PR #495](https://github.com/StealthCat/MrPatchy/pull/495) (v1.59.6): pure asset metadata, static/rule group membership and effective-policy preview contract with conflict reporting (unwired). Persistence, group-scoped authorization, queued-work revalidation, UI and audit remain. |
| [#335](https://github.com/StealthCat/MrPatchy/issues/335) | Read-only security posture and configuration compliance | Partial | [PR #386](https://github.com/StealthCat/MrPatchy/pull/386) (v1.59.1): pure versioned SSH daemon posture rule evaluator (unwired; global `sshd -T` settings only). Other rule families, `Match` blocks, collection, storage, exceptions and UI remain. |
| [#336](https://github.com/StealthCat/MrPatchy/issues/336) | Container and application dependency inventory with workload attribution | Partial | [PR #394](https://github.com/StealthCat/MrPatchy/pull/394) (v1.59.3): pure Docker/Podman workload inventory contract with image-digest identity, explicit gaps and change comparison (unwired). Collection, application dependencies, SBOM, advisory matching and fleet search remain. |
| [#337](https://github.com/StealthCat/MrPatchy/issues/337) | Scoped service credentials and reliable external integrations | Partial | [PR #494](https://github.com/StealthCat/MrPatchy/pull/494) (v1.59.5): pure idempotency-key contract binding identity, action, targets and payload, with replay/conflict decisions (unwired). Scoped service identities, API surface, durable records and ticket/SIEM mappings remain. |
| [#338](https://github.com/StealthCat/MrPatchy/issues/338) | Application-aware health gates for patch and reboot workflows | Partial | [PR #382](https://github.com/StealthCat/MrPatchy/pull/382) (v1.57.0): reviewed loopback HTTP/TCP probes that gate rollout patch stages. Replication/workload adapters, dependency groups, non-rollout patches and a probe editor UI remain. |
| [#339](https://github.com/StealthCat/MrPatchy/issues/339) | Rollout rings, soak gates and service availability limits | Partial | [PR #392](https://github.com/StealthCat/MrPatchy/pull/392) (v1.57.2): pure rollout-ring planner with soak, failure and service/site availability limits (unwired). Runtime ring execution, soak enforcement and drain/rejoin remain. |
| [#340](https://github.com/StealthCat/MrPatchy/issues/340) | Change freezes, holiday calendars and expiring patch exceptions | Partial | [PR #352](https://github.com/StealthCat/MrPatchy/pull/352) (v1.59.0): audited administrator-managed fleet-wide change freezes (API only) that block scheduled, manual and urgent patch, repair and release-upgrade dispatch. Per-host/group scope, holiday calendars, package deferrals, emergency exceptions and UI remain. |
| [#341](https://github.com/StealthCat/MrPatchy/issues/341) | Verified OS support lifecycle and migration planning queue | Partial | [PR #393](https://github.com/StealthCat/MrPatchy/pull/393) (v1.54.0): vendor-sourced lifecycle status on the server Overview. Migration queue, plans, fleet reports and alerts remain. |
| [#343](https://github.com/StealthCat/MrPatchy/issues/343) | Incident case ownership, investigation notes and scoped exceptions | Partial | [PR #363](https://github.com/StealthCat/MrPatchy/pull/363) (v1.56.1): ownership and notes API. Severity/SLA, links, scoped exceptions, UI and notifications remain. |
| [#344](https://github.com/StealthCat/MrPatchy/issues/344) | Saved fleet queries and evidence-backed patch compliance reports | Partial | [PR #377](https://github.com/StealthCat/MrPatchy/pull/377) (v1.53.0): saved fleet queries API. Further filters, reports, exports and UI remain. |
| [#345](https://github.com/StealthCat/MrPatchy/issues/345) | Recovery readiness dashboard and verifiable restore evidence | Partial | [PR #355](https://github.com/StealthCat/MrPatchy/pull/355) (v1.56.0): drill-receipt readiness API. UI, adapter examples and scheduled verification remain. |
| [#346](https://github.com/StealthCat/MrPatchy/issues/346) | External secret custody and recoverable encryption-key rotation | Partial | [PR #364](https://github.com/StealthCat/MrPatchy/pull/364) (v1.56.4): secret custody inventory and key-rotation migration contract (design only). The provider interface, versioned envelopes, rotation, retirement and backup key-id manifests remain. |
| [#347](https://github.com/StealthCat/MrPatchy/issues/347) | This matrix | Partial | Delivered by the PR that adds this file. Coordinator-checklist maintenance remains. |

Later roadmap issues (for example #359–#362, #396–#402, #405, #444–#454 and #512 onward) are not yet indexed here. Adding them remains part of #347.

## Maintenance

- Update the matrix in the same handoff as the PR that changes a row. A worker
  proposes the row change in the PR body. The coordinator applies it with the
  README and changelog notes.
- Change a status to **Delivered** only after the PR is merged and listed in
  `CHANGELOG.md`. Link the PR. Do not rewrite historical checkpoint text.
- The remaining open-PR rows go stale quickly. When a PR merges, move its
  contribution into the *Delivered* column and shorten *Remaining acceptance*.
