## 1.59.69 — 2026-11-12

1. [PR #736](https://github.com/StealthCat/MrPatchy/pull/736): In daily-cap modes, a saved model that the bundled price catalog cannot price, or a catalog that is not valid, is now reported in advance instead of surfacing as a stream of generic blocked retries. A new pure `ai_pricing.model_status()` performs the same alias-aware check that `reservation()` applies, using the same fixed reason. While AI is enabled with a cap mode and a saved model, `GET /api/settings/ai-control-status` adds an indefinite `pricing` blocker with fixed text that omits the model ID, so `can_start_now` is false and there is no next start. Administrators also get an in-app notification while that blocker lasts, resolved once pricing is possible again. Closes #735.
2. Compatibility and limits: an additive status blocker and notification, with no change to admission, pricing data or schema. `ok` never promises admission, because tier, tools, output bound and context size are still checked per call. Disabled AI reports only the existing disabled gate. This source update does not publish a Docker image.

## 1.59.68 — 2026-11-12

1. [PR #757](https://github.com/StealthCat/MrPatchy/pull/757): Fix workers and the embedded scheduler without `MRPATCHY_WORKER_ID` registering under a new random ID on every start, which produced duplicate registrations and false missing or stale entries after restarts and upgrades. Each runtime now generates an identity once and keeps it in a per-role slot under `DATA_DIR/worker-identities/`. The existing cross-process identity lock decides slot ownership, so replicas sharing a data volume get distinct identities and a restarted process reclaims a free slot. An explicit `MRPATCHY_WORKER_ID` still takes precedence. Unreadable, invalid or exhausted slots, and unavailable storage, fall back to a boot-only identity with a warning. Fixes #754.
2. Compatibility and limits: no schema, API or UI change. On its first post-upgrade start, each unconfigured runtime registers once more under its new persistent ID. Earlier random-ID registrations, and those from scaled-down slots, remain as stale history and are not removed automatically (#755). Workers on other machines with their own data directories get their own identities. This source update does not publish a Docker image.

## 1.59.67 — 2026-11-12

1. [PR #734](https://github.com/StealthCat/MrPatchy/pull/734): Administrators get one in-app notification, linking to Investigations, while process investigations are blocked by a non-transient AI provider failure under the current model and key. Examples are a rejected key, unavailable quota and an unsupported model. Alert collection uses the same blocked predicate as the AI status, so items blocked under an earlier configuration are not counted. Revisions are bound to a re-hashed configuration digest, not counts, so a newly rejected configuration resurfaces as unread. The payload is fixed text with no provider message, key or evidence. The event resolves when nothing remains blocked and reopens on recurrence. Closes #733.
2. Compatibility and limits: a read-only producer that never retries, unblocks, reserves spend or changes authorization, and adds no SMTP/webhook alert or schema change. This source update does not publish a Docker image.

## 1.59.66 — 2026-11-12

1. [PR #732](https://github.com/StealthCat/MrPatchy/pull/732): A failed operator-initiated patch, repository change, signing-key change, package repair, OS release upgrade or agent update now raises an operator-visible, medium-severity in-app notification linking to the job in Activity. Previously it appeared only in Activity. There is one event per server and action. A repeat failure adds an unread revision linking the newest job, and a later successful run of the same action resolves it. Scheduled patch runs and `recovery_required` jobs, which existing alerts already cover, publish nothing, and neither do cancelled jobs, read-only actions or jobs for deleted servers. Reasons use fixed wording, so job output never enters the payload. Publishing runs in the transaction that records the final job state, and a notification error is contained in a savepoint without changing the outcome. Closes #731.
2. Compatibility and limits: an additive notification producer with no schema, API or role change. It retries, acknowledges and authorizes nothing. This source update does not publish a Docker image.

## 1.59.65 — 2026-11-12

1. [PR #730](https://github.com/StealthCat/MrPatchy/pull/730): When one account has several Mr Patchy tabs open, each new high or critical notification revision shows its toast in only one tab.
   - Tabs claim admitted revisions in `localStorage`, bound to the signed-in user. The check-and-claim is atomic across tabs where the Web Locks API is available and best-effort otherwise.
   - A tab fails open and shows its own toasts if storage or locks fail.
   - Claims are bounded to 500 entries kept for 24 hours, hold no notification text, source or link, and are removed at logout.
   - A higher revision can still toast once, and burst summaries count only the tab's own claims.
   - Closes #729.
2. Compatibility and limits: a client-only change to toast admission, with no API or schema change. Without Web Locks, simultaneous claims across tabs are best-effort. This source update does not publish a Docker image.

## 1.59.64 — 2026-11-12

1. [PR #728](https://github.com/StealthCat/MrPatchy/pull/728): The administrator Investigations page shows a **Shared AI start gates** card below the AI worker status, read from the existing `GET /api/settings/ai-control-status`.
   - When the gates are open, it says so with the snapshot's limitations and never promises that a particular call will start.
   - When blocked, it lists each blocker with its next eligible time, a reset recheck boundary marked as not a promised start, or a statement that an administrator must act. It also shows the overall next eligible start, or that there is none while an indefinite hold applies.
   - An unavailable snapshot shows a retryable notice and is never shown as permission to start.
   - Closes #727.
2. Compatibility and limits: a client-only, administrator-only card using an existing API, with no API, schema or admission change. This source update does not publish a Docker image.

## 1.59.63 — 2026-11-12

1. [PR #726](https://github.com/StealthCat/MrPatchy/pull/726): Add a pure CVE-exploitation containment eligibility contract (`app/cve_containment.py`). It decides whether one exploitation detection may automatically quarantine the artifact and/or terminate the process under a per-CVE policy, with modes `disabled`, `monitor_only` and `enforce`, bounded thresholds and exclusions.
   - `confirmed_exploitation` requires all of:
     - an authenticated, fresh rule that names the CVE and matched the exact artifact hash at sufficient confidence;
     - a fresh, server-bound applicability assessment of `affected` (or `uncertain` only with opt-in);
     - distinct supporting evidence kinds bound to the same server, evidence revision and artifact.
   - A vulnerable version, advisory or CVSS score is never exploitation evidence on its own. AI enrichment is ignored, and AI availability cannot affect the decision.
   - Quarantine and termination reuse the malware-containment identity checks from #683.
   - Malformed input fails closed.
   - Closes #725.
2. Compatibility and limits: an unwired contract only. No detector, policy storage, executor, API, UI or schema change, and no response action is authorized at runtime. This source update does not publish a Docker image.

## 1.59.62 — 2026-11-12

1. [PR #724](https://github.com/StealthCat/MrPatchy/pull/724): Add a pure startup mechanism catalog and coverage contract (`app/startup_catalog.py`). It catalogs 26 mechanisms, each with a stable ID, label, trigger, scope, parse level and per-family locations:
   - cron, anacron and at;
   - systemd system, generated, transient and user units, generators and hooks;
   - SysV and rc.local;
   - shell startup files, XDG autostart, SSH rc hooks and `authorized_keys` commands;
   - PAM, MOTD and X session hooks;
   - network, logrotate and package-manager hooks;
   - udev, ld.so preload and search paths, and module loading.

   Only the cron mechanisms claim entry-level parsing, matching the parsers on main. Every result carries a `catalog_not_exhaustive` gap, and an administrator-configurable additional scope is supported. Closes #723.
2. Compatibility and limits: an unwired contract for a later collection and view slice. No collection, schema, API or UI change. This source update does not publish a Docker image.

## 1.59.61 — 2026-11-12

1. [PR #742](https://github.com/StealthCat/MrPatchy/pull/742): Fix capped-AI tests depending on the wall clock being inside the bundled price catalog's validity window. CI on main and on every PR would otherwise have started failing at 2026-11-26 00:00 UTC, when the catalog expires. An autouse test fixture now pins a catalog window that covers both the bundled reviewed window and the current clock. Tests marked `bundled_pricing_catalog` opt out. A regression guard confirms that the source constants are unchanged and that a genuinely expired catalog still refuses capped admission without a ledger row. Fixes #741.
2. Compatibility and limits: test-suite change only. Runtime behaviour is unchanged, and the bundled catalog's expiry still fails closed in production. This source update does not publish a Docker image.

## 1.59.60 — 2026-11-12

1. [PR #722](https://github.com/StealthCat/MrPatchy/pull/722): Add a pure startup-entry provenance contract (`app/startup_provenance.py`). It classifies one startup file and its entries (crontab, anacrontab, systemd unit, drop-in or override, SysV script or `rc.local`) as `verified_default`, `modified`, `unverifiable`, `custom` or `unknown`. Each result carries its basis, verification strength, explicit gaps, a separate baseline field and `safety: not_assessed`. Package ownership or a match against the target's own package database alone is never `verified_default`. Evidence for another package or version is recorded as a gap. Entries in a modified file are classified individually, and default entries whose execution context is unverified or changed are reported as modified. Closes #720.
2. Compatibility and limits: an unwired contract only. It feeds later wiring of the startup parsers, which still report provenance as `not_assessed`. No collection, schema, API or UI change, and provenance is not a safety verdict. This source update does not publish a Docker image.

## 1.59.59 — 2026-11-12

1. [PR #718](https://github.com/StealthCat/MrPatchy/pull/718): Add a pure, I/O-free SysV contract (`app/sysv_init.py`) that turns captured SysV boot material into typed, bounded records.
   - `parse_init_script()` reports the interpreter, execute bit, full-text SHA-256 and size, and the LSB `INIT INFO` fields, never the script body.
   - `parse_rc_links()` resolves start and stop links, with their order numbers, from captured runlevel directories.
   - `effective_services()` reports enabled runlevels, start orders, orphan links, and observations (not verdicts) such as start and stop links in one runlevel, links that differ from LSB defaults, and start links to non-executable scripts.
   - `parse_rc_local()` returns bounded logical commands with digests, background flags, and the top-level `exit` with the commands after it flagged. An `exit` inside a conditional, loop or function is not treated as top-level, and invalid text becomes a gap instead of an error.
   - Closes #717.
2. Compatibility and limits: an unwired contract only. No collection, schema, API or UI change. Native collection, inventory wiring and provenance remain open in roadmap F. This source update does not publish a Docker image.

## 1.59.58 — 2026-11-12

1. [PR #721](https://github.com/StealthCat/MrPatchy/pull/721): The notification bell panel shows a live-update status line and the last synchronization time.
   - The live-update state is connecting, live, reconnecting, unavailable (polling only after a refused stream), polling only, or delayed after a failed refresh.
   - A refused stream is retried only after a successful refresh, with a doubling backoff from 30 seconds to 10 minutes.
   - The sync time advances only on successful list and count refreshes, with the ISO time in a tooltip. Before the first success it shows "Not yet synchronized".
   - The line states that it reflects notification delivery only, not collector, agent or AI health.
   - Closes #719.
2. Compatibility and limits: a client-only change, with no API or schema change. This source update does not publish a Docker image.

## 1.59.57 — 2026-11-12

1. [PR #716](https://github.com/StealthCat/MrPatchy/pull/716): A **Mark shown read** button in the bell panel and notification center marks every notification currently shown as read in one action. It is backed by `POST /api/notifications/read-batch`, which accepts 1–100 displayed `{id, revision}` pairs. Each pair follows the single-item revision rule, so an event that escalated or reopened after the page loaded stays unread at its newer revision. Missing or role-hidden events are skipped without a write or disclosure. Malformed, duplicate, empty, oversized or future-revision batches are rejected before any write. One `read notifications` audit row is written per changing batch, and dismiss state is untouched. Closes #715.
2. Compatibility and limits: an additive per-user endpoint and UI action, with no schema change. Read state remains per-user UI state and never acknowledges an alert, resolves an incident or authorizes a response. This source update does not publish a Docker image.

## 1.59.56 — 2026-11-12

1. [PR #712](https://github.com/StealthCat/MrPatchy/pull/712): Add a pure, I/O-free anacrontab and at-queue parsing contract (`app/scheduled_jobs.py`). `parse_anacrontab()` turns captured anacrontab text into typed, bounded job records: period, delay, identifier, a bounded command with a full-text SHA-256, and any directories named by `run-parts`. Only ASCII digits are accepted in numeric fields, so other numeric characters such as superscripts become coverage gaps instead of errors. Duplicate identifiers are flagged. Environment values are withheld (only names are returned), while `START_HOURS_RANGE` and `RANDOM_DELAY` are validated and disclosed. At spool job files are parsed into bounded records in the same way, and malformed or over-limit data is reported as coverage gaps. Closes #711.
2. Compatibility and limits: an unwired contract only. No schema, API, UI, agent or response change. Native collection, inventory wiring, provenance and classification remain open in roadmap F, along with two documented non-ASCII parser fidelity edges. This source update does not publish a Docker image.

## 1.59.55 — 2026-11-12

1. [PR #714](https://github.com/StealthCat/MrPatchy/pull/714): Fleet AI logs gain an administrator-only **Fleet known-good cache** panel, loaded on demand from the existing `GET /api/ai/known-good/summary`. It shows active and revoked candidates, retained reuse assessments and reuse assessments on revoked candidates. When reuse is linked to revoked candidates, a review note explains that the original results are unchanged and how to request Re-triage. The panel states that these are record counts only: they do not verify context, count misses or estimate savings, and reuse grants no approval. Malformed counts render as "Unavailable", a failed request shows a fixed retryable message, and stale responses after navigation are discarded. Closes #713.
2. Compatibility and limits: a client-only addition using an existing administrator API, with no API or schema change. Viewers never request the endpoint. This source update does not publish a Docker image.

## 1.59.54 — 2026-11-12

1. [PR #707](https://github.com/StealthCat/MrPatchy/pull/707): Administrators are notified when an AI-proposed security-incident or startup-change response plan awaits review. A leader-only periodic reconciler publishes one administrator-only, medium-severity notification per reviewable draft (younger than 24 hours, on an active server). It links to the server tab where the plan is reviewed: Security for incident plans and File integrity for startup-change plans. Approval, supersession, the 24-hour expiry, plan deletion and server deletion or deactivation each resolve the notification exactly once. The plan's own severity and text never reach the payload, and unchanged passes add no revisions. Closes #706.
2. Compatibility and limits: an additive notification producer that writes only notification rows. It changes no plan, incident, approval or response-authorization state. Each pass reads at most 500 rows per query, and a still-reviewable draft beyond that bound stays active rather than being falsely resolved. This source update does not publish a Docker image.

## 1.59.53 — 2026-11-12

1. [PR #705](https://github.com/StealthCat/MrPatchy/pull/705): Startup-change (persistence) incidents now publish administrator-only in-app notifications that link to the server's File integrity tab, so they appear in the bell, notification center, SSE stream and arrivals cursor. A new incident publishes one medium-severity active event. Repeat detections of an open incident add nothing, while a repeat detection of a closed incident reopens it. Administrator closure resolves the event, reopening a closed incident re-activates it, and deleting a server resolves its active events while keeping the incidents. Reasons are fixed text stating that a change is not a malware verdict; no endpoint paths, hashes or link targets reach the payload. Publishing shares the incident transaction. Closes #704.
2. Compatibility and limits: an additive notification producer, with no schema, API, incident-lifecycle or response-authorization change. Notifications acknowledge and authorize nothing. This source update does not publish a Docker image.

## 1.59.52 — 2026-11-12

1. [PR #703](https://github.com/StealthCat/MrPatchy/pull/703): Add a pure systemd effective-unit contract (`app/systemd_units.py`). It turns captured read-only observations of systemd system-unit search directories into effective-unit records, trigger relationships, explicit coverage gaps and a deterministic digest.
   - It follows the system manager's search-path precedence and records shadowed fragments.
   - It resolves masking, and applies unit, template, dash-prefix and type-level `.conf` drop-ins in order, with empty-assignment list resets. Drop-ins are read for the canonical name and every effective alias.
   - It separates enablement links (`.wants`, `.requires`, `.upholds` in `/etc`, `/run`, generator and transient directories) from vendor static dependencies, and reports dangling or foreign links as gaps.
   - It resolves aliases, linked units and template instances, and maps timer, socket and path units to their targets.
   - Refs #702.
2. Compatibility and limits: an unwired contract only. No collection, agent, storage, API or UI change. User units, generated and transient runtime state, and live wiring into the startup inventory remain open in #702. This source update does not publish a Docker image.

## 1.59.51 — 2026-11-12

1. [PR #701](https://github.com/StealthCat/MrPatchy/pull/701): Scanner-created security incidents now reach the in-app bell and notification center. A new malware detection publishes a high-severity, administrator-only event that matches the incident API and links to the server's Security tab. The reason is fixed text: endpoint paths, rule names and engine output never appear in it. A repeat match on a closed incident reopens the event, and an administrator reopening a closed incident does the same. Repeat matches on an open incident add nothing. Administrator closure (resolved or false positive) or deleting the server resolves the event. Acknowledgement leaves it unchanged. Closes #700.
2. Compatibility and limits: an additive notification producer in the existing incident transaction, with no schema, API, incident lifecycle or response-authorization change. Notifications acknowledge and authorize nothing. This source update does not publish a Docker image.

## 1.59.50 — 2026-11-12

1. [PR #699](https://github.com/StealthCat/MrPatchy/pull/699): Expected workers (`MRPATCHY_EXPECTED_WORKER_IDS`) that need attention now raise an administrator-only in-app notification linking to **Activity → Workers**. `missing`, `stale` and `stopped` are high severity, and `unknown` and `version_mismatch` are medium, using fixed text with only the validated worker ID and state. An unchanged state adds no revision. Reporting or intentional draining resolves the event, and removal from the expected list resolves it with an explanation. An invalid expected-worker configuration raises one separate controller-wide event and leaves existing worker events unchanged. New attention is suppressed for one 120-second freshness window after process start, so co-started workers can register. Closes #698.
2. Compatibility and limits: an additive notification producer run from the existing leader loop, with no schema, API, drain or worker-control change. Unconfigured workers are not monitored. This source update does not publish a Docker image.

## 1.59.49 — 2026-11-12

1. [PR #697](https://github.com/StealthCat/MrPatchy/pull/697): Administrators get an in-app notification linking to AI Settings when the shared AI provider backoff floor needs attention. A floor set from a capped Retry-After over 24 hours raises a high-severity event asking for review, which points to the reviewed Clear action. At least five consecutive transient failures within the existing failure-reset window raise a medium-severity event. The event resolves automatically when the floor clears or AI is disabled. Alert collection evaluates it each pass, an unchanged state adds no revision, and the text is fixed. Closes #696.
2. Compatibility and limits: an additive, administrator-only notification, with no change to backoff behaviour, admission, provider calls, SMTP/webhook alerts or schema. It clears nothing automatically. This source update does not publish a Docker image.

## 1.59.48 — 2026-11-12

1. [PR #695](https://github.com/StealthCat/MrPatchy/pull/695): When the shared daily AI spend cap is exhausted, administrators get an in-app notification linking to AI Settings. It explains that new paid AI work is deferred, not discarded, until the reset or a cap or mode change. Alert collection evaluates the same conservative counted total that admission uses, and the notification's revision is bound to the budget window rather than to amounts, so further reservations in the same window add no revisions. Once the cap no longer blocks, a resolved revision is published. Closes #694.
2. Compatibility and limits: an additive, administrator-only notification. It reserves, releases and authorizes nothing, adds no SMTP/webhook alert and changes no schema. Near-exhaustion warnings are not included. This source update does not publish a Docker image.

## 1.59.47 — 2026-11-12

1. [PR #692](https://github.com/StealthCat/MrPatchy/pull/692): Medium- and high-risk AI process triage verdicts now reach the bell and notification center. Events are advisory: they use fixed text, carry the server and verdict severity, are visible to viewers (matching the Investigations page), and link to the server's Investigations tab. Executable paths and model output never enter the payload. An unchanged risk adds no revision, and a risk change resurfaces as unread. A later `low` verdict (from the provider or exact known-good reuse) or an administrator approval resolves the event, while revoking approval of a still-significant verdict reopens it. `unknown` verdicts and rolled-back or rejected saves announce nothing. Closes #691.
2. Compatibility and limits: an additive notification producer in the existing verdict and approval transactions, with no schema, API, UI, provider, approval-semantics or response-authorization change. Notifications grant nothing. This source update does not publish a Docker image.

## 1.59.46 — 2026-11-12

1. [PR #690](https://github.com/StealthCat/MrPatchy/pull/690): Server conditions that need an administrator now also appear in the in-app bell and notification center, not only in the SMTP/webhook alert outbox. Alert collection publishes an allowlisted set of alert kinds as durable, administrator-only notification events in the same transaction:
   - recovery-required operations, file, process, publication and service holds, and disabled-server recovery;
   - failed scheduled patching, response integrity and verification, service health and coverage, execution-scan coverage, agent health and startup baseline.

   Each event has a stable kind, explicit severity, a controller-composed message and a same-origin deep link to the server tab. Unchanged conditions add no revision. A changed message resurfaces as unread, a cleared condition (or a disabled or deleted server) resolves the event, and a recurrence reopens it. Closes #689.
2. Compatibility and limits: kinds that could carry raw endpoint text stay outbox-only, never reaching notification reasons: stale, raw integrity JSON, repository errors, overdue and server disabled. Alert acknowledgement and notification read/dismiss stay independent, and SMTP/webhook delivery is unchanged. A rejected notification payload is logged and skipped without blocking alert collection. This source update does not publish a Docker image.

## 1.59.45 — 2026-11-12

1. [PR #688](https://github.com/StealthCat/MrPatchy/pull/688): Notification arrival records no longer grow without bound. The leader's hourly cleanup prunes arrivals older than the existing `history_days` retention, in separately committed batches of at most 5,000. It deletes only the oldest contiguous sequenced prefix, stopping at the first arrival still inside the window, and leaves the durable head untouched. `GET /api/notifications/arrivals` now reads its head from the durable head row, so pruning never moves live cursors backwards. A cursor older than the oldest retained arrival gets a fresh baseline with `reset: true, reset_reason: "pruned"`, so clients resynchronize instead of silently skipping pruned revisions. A cursor beyond the head reports `reset_reason: "ahead"`. A pruning failure is logged and does not block the rest of the cleanup. Closes #687.
2. Compatibility and limits: no schema change. The response adds an optional `reset_reason`, and the live toast client already re-baselines on `reset`. Retention follows `history_days`. This source update does not publish a Docker image.

## 1.59.44 — 2026-11-12

1. [PR #683](https://github.com/StealthCat/MrPatchy/pull/683): Add a pure malware automatic-containment eligibility contract (`app/malware_response.py`). It decides whether a malware detection may trigger automatic file quarantine and/or verified process termination under an administrator policy.
   - **Known malware** qualifies only with an authenticated ClamAV, YARA or hash-indicator signature that is fresh, not future-dated and hash-matched.
   - **Unknown malware** qualifies only when the policy allows it, AI is available, and a bound `malicious` verdict meets the confidence threshold with at least two distinct corroborating evidence kinds from the same evidence revision and artifact. A bare model verdict never authorizes an action.
   - Quarantine and termination are decided independently against complete file and process identities. Protected pseudo-filesystems and excluded paths are refused, including for process-only detections.
   - Modes are `disabled` (the default), `monitor_only` and `enforce`. Malformed input fails closed with no action.
   - A stable `binding_digest` and a `still_bound()` pre-execution recheck reject PID reuse, reboot and file replacement.
   - Includes the review fixes from #684: fail-closed process exclusions and artifact-bound AI corroboration. Refs #682.
2. Compatibility and limits: an unwired contract only. No detector, policy storage, executor, API, UI, schema or configuration change, and no response action is authorized at runtime. This is a partial #682 increment. This source update does not publish a Docker image.

## 1.59.43 — 2026-11-12

1. [PR #681](https://github.com/StealthCat/MrPatchy/pull/681): Controller web instances now register themselves in the shared database. Administrators see them in a new **Controllers** section on **Activity → Workers**, backed by the admin-only, paginated `GET /api/operations/controllers`.
   - Each controller self-reports its identity, boot, version, reported deployment type, embedded or disabled scheduler, start time and uptime, refreshing its heartbeat every 15 seconds. A failed refresh shows as stale and never stops the web process.
   - States are reporting, stale, stopped, version mismatch and unknown. Future, invalid or mismatched records are never shown as healthy.
   - The optional `MRPATCHY_EXPECTED_CONTROLLER_IDS` lists controllers that never registered as missing. `MRPATCHY_CONTROLLER_ID` sets a stable identity, and a duplicate live identity is refused.
   - Registration and graceful stop are audited, and records older than 7 days are pruned at controller start. Closes #680.
2. Compatibility and limits: no schema change, since records use the existing settings table, and the two environment variables are optional. A controller record reports database reachability only. It is not readiness, load-balancer membership, serving-role or failover evidence and authorizes nothing. As with workers, an invalid `MRPATCHY_CONTROLLER_ID` or `MRPATCHY_DEPLOYMENT_TYPE` stops the web process at startup. This source update does not publish a Docker image.

## 1.59.42 — 2026-11-12

1. [PR #679](https://github.com/StealthCat/MrPatchy/pull/679): The AI worker status card shows the eligible, unclaimed triage backlog from the existing administrator status fields: an **eligible, unclaimed** count, and the oldest eligible unclaimed observation's first-seen time with an approximate age. The card explains that this is observation age, not time since the item became eligible, and that shared rate, budget and provider admission and available worker capacity may still delay dispatch. Closes #678.
2. Compatibility and limits: a client-only status card addition, with no API, schema or admission change. This source update does not publish a Docker image.

## 1.59.41 — 2026-11-12

1. [PR #677](https://github.com/StealthCat/MrPatchy/pull/677): Add fixed `compose.controller.yaml` and `compose.worker.yaml` files for same-Docker-host split deployments. The controller file runs the app and Caddy by extending `compose.yaml`. The worker file runs scalable workers (`--scale worker=N`) as a separate Compose project on the controller's existing data volume, named by the required `MRPATCHY_CONTROLLER_DATA_VOLUME`. Workers keep the hardening, health check and drain grace period from `compose.yaml`, and each replica gets a unique boot identity. `docs/COMPOSE_CONFIGURATION.md` covers migration from `compose.yaml` with `--remove-orphans`, and CI validates both files. Refs #676.
2. Compatibility and limits: additive deployment files; `compose.yaml` is unchanged. Only the same-Docker-host topology is supported. Multi-host MySQL deployment, drain, failure and recovery acceptance, and live start and scale validation of these files remain open in #676. This source update does not publish a Docker image.

## 1.59.40 — 2026-11-12

1. [PR #686](https://github.com/StealthCat/MrPatchy/pull/686): Fix the investigations queue notice, which showed the legacy hourly limit to administrators even in rate, daily-cap and unthrottled admission modes. The notice now names the control that actually gates new AI work: shared starts per hour (plus the daily spend cap in combined mode), the daily spend cap, unthrottled, or the legacy attempts limit in legacy mode. The AI worker status card uses the same helper. Fixes #685.
2. Compatibility and limits: a client-only display fix, with no API, schema, admission or authorization change. Legacy mode output is unchanged, and the notice stays administrator-only. This source update does not publish a Docker image.

## 1.59.39 — 2026-11-12

1. [PR #675](https://github.com/StealthCat/MrPatchy/pull/675): `tools/benchmark_ai.py` accepts `--follow-up-runs` (0 to the run count), so serial and parallel AI triage benchmarks can compare matched workloads with no, sparse or universal follow-up evidence requests. Explicit counts are distributed deterministically across the fixture subjects, and omitting the option keeps the existing alternating workload. The benchmark verifies provider requests, SSH requests and persisted call counts against the selected workload. A stage with no observations reports `count: 0` and null percentiles, which `tools/compare_ai_benchmarks.py` accepts and reports as unobserved instead of failing. Fixes #674.
2. Compatibility and limits: development tooling only, with no application, schema or API change. Results remain fixture-only measurements, not production performance. This source update does not publish a Docker image.

## 1.59.38 — 2026-11-12

1. [PR #673](https://github.com/StealthCat/MrPatchy/pull/673): Add a pure CVE applicability and exposure-window contract (`app/cve_exposure.py`).
   - `classify()` reads only the OSV entries for the exact distribution release and source package. It applies OSV ecosystem ranges and explicit version lists through an injected comparator (native `dpkg --compare-versions` in production), and reports `affected`, `fixed`, `unaffected` or `uncertain`.
   - A fixed version is named only when the complete matching data classifies it as fixed or unaffected.
   - Another release's or upstream data, GIT/SEMVER-only or `limit` ranges, malformed or oversized data, an unknown installed version and comparator failures all give `uncertain`, never `unaffected`.
   - `exposure_window()` computes explicit exposure intervals. Exposure starts at the first applicability observation only when monitoring covered the whole period since publication, and at publication otherwise.
   - Only a verified install closes a window. A required restart or reboot keeps it pending until activation, and reintroduction, or re-reported applicability while pending or closed, reopens it. Coverage gaps are clipped, and future-dated or malformed clocks are rejected.
2. Compatibility and limits: an unwired contract only. No advisory feed, storage, detector, UI, scheduler or containment action is added, and no response action is authorized. This is a partial #672 increment. This source update does not publish a Docker image.

## 1.59.37 — 2026-11-12

1. [PR #665](https://github.com/StealthCat/MrPatchy/pull/665): **Startup files** now lists individual cron jobs parsed by updated target agents from the crontab-format files already in scope: `/etc/crontab`, `/etc/cron.d/*` and the user spool crontabs. Each job shows its line, schedule, account and a bounded command, parsed from exactly the bytes that were hashed. Credentials in commands are redacted on the target: URL user:password, Bearer and Authorization headers, secret-named options and query parameters, `-u`/`--user` values, and `sshpass`/MySQL `-p`. Standard input after cron's first unescaped `%` is flagged but not stored, and control characters are shown escaped. Environment assignments are counted but not exported, and malformed lines are counted rather than guessed. The controller strictly validates the optional job data (at most 64 jobs per file and 256 in total). Refs #664.
2. Compatibility and limits: older agents keep reporting metadata only, and the controller asks for jobs explicitly. Persistence comparisons, incidents and AI evidence remain metadata-only. Redaction is best-effort and pattern-based, so unusual credential forms can remain; reviewers noted custom Authorization schemes and backslash-escaped header values as follow-ups. Run-parts scripts, anacron and at queues, referenced scripts, cron.d naming rules and PATH/SHELL evaluation are not covered. This is a partial #664 increment. Target agents must be updated to report jobs. This source update does not publish a Docker image.

## 1.59.36 — 2026-11-12

1. [PR #662](https://github.com/StealthCat/MrPatchy/pull/662): When a new or escalated unread high or critical notification arrives for the signed-in account, the authenticated shell shows a short, non-modal toast on any page or dialog. Toasts are admitted from the durable `GET /api/notifications/arrivals` cursor, so an urgent event behind many newer unread events still toasts. The first refresh after sign-in, reload or reconnect takes a baseline, so existing notifications never toast. At most three toasts appear, and a summary toast points to the notification center for overflow. Toasts never take focus and announce through a polite live region. They pause on hover or focus, and hiding a toast leaves the notification unread and undismissed. Logout or account change clears toasts and the baseline. Closes #661.
2. Compatibility and limits: a client-only change using the existing arrivals API, with no schema or API change. Toasts cover only high and critical severities; toasts for lower severities (#660) remain open. Read and dismiss stay per-user UI state and never acknowledge or remediate anything. This source update does not publish a Docker image.

## 1.59.35 — 2026-11-12

1. [PR #583](https://github.com/StealthCat/MrPatchy/pull/583): The strict exact-known-good lookup batches its eligible policy candidates into set reads of at most 100. It reads active entries, their originating assessments and their observations in one query each, instead of three point reads per candidate. Caller order is preserved, and only the first candidate that passes every existing check is returned. Those checks cover the active entry, retained assessment, result, canonical contract and isolated observation. Ineligible evidence performs no registry read. Fixes #582.
2. Compatibility and limits: a read-path optimisation with no schema, API, eligibility or reuse-policy change. Reuse still requires every existing provenance and re-evaluation check. This source update does not publish a Docker image.

## 1.59.34 — 2026-11-11

1. [PR #574](https://github.com/StealthCat/MrPatchy/pull/574): Scoped outbound AI provider calls read server pause policies in bounded batches. Five scoring-sized server IDs, including one without a policy row, now use one policy SELECT, at most 200 servers per query, plus one global enablement lookup, instead of a full status read per server. Pause still takes precedence over global disablement. A corrupt stored policy is treated as paused, failing closed, and an empty scope skips the checks as before. Fixes #573.
2. Compatibility and limits: a read-path optimisation with no schema, API or authorization change. Scoped provider and lease locks are unchanged. This source update does not publish a Docker image.

## 1.59.33 — 2026-11-11

1. [PR #571](https://github.com/StealthCat/MrPatchy/pull/571): The server activity guard reads lifecycle state in bounded batches. After acquiring the ordered per-server locks, it fetches only IDs, enabled flags, deletion timestamps and lifecycle revisions, in one query per 200 distinct servers, instead of loading each server row separately. A five-server scoring batch now uses one SELECT. Disabled and deleted servers are still refused with the acquired locks released, and absent bootstrap records still contribute no revision. Fixes #569.
2. Compatibility and limits: a read-path optimisation with no schema, API, authorization or lifecycle-semantics change. On MySQL, a server ID not matched by the batched query falls back to an exact-equality lookup, which preserves collation behaviour. This source update does not publish a Docker image.

## 1.59.32 — 2026-11-11

1. [PR #563](https://github.com/StealthCat/MrPatchy/pull/563): Viewer and operator requests to `GET /api/investigation-status` no longer run the administrator-only status aggregates. They return the same three fields (`pending`, `oldest` and `enabled`) from one SQL aggregate. It uses the same approval and host-lifecycle predicate as the administrator dashboard, which now shares that predicate. Fixes #562.
2. Compatibility and limits: the response shape for each role is unchanged, with no schema or authorization change. This reduces database work for non-administrator dashboards. This source update does not publish a Docker image.

## 1.59.31 — 2026-11-11

1. [PR #559](https://github.com/StealthCat/MrPatchy/pull/559): The server AI policy panel shows how many live AI investigation leases the server holds and the earliest lease expiry if no renewal arrives. It states that this snapshot does not guarantee global capacity, and that lowering the concurrency limit leaves active leases in place. The administrator server AI policy read and save responses add `active_lease_count` and `earliest_lease_expires_at`, counting only unexpired leases for that server. Fixes #558.
2. Compatibility and limits: additive administrator response fields and panel text, with no schema, admission or role change. Occupancy is a point-in-time snapshot. This source update does not publish a Docker image.

## 1.59.30 — 2026-11-11

1. [PR #555](https://github.com/StealthCat/MrPatchy/pull/555): Administrators can filter fleet and server AI activity by run state: running, complete, failed, deferred or interrupted. The state filter combines with the purpose and server filters, and changing either filter resets the page. Returning from a run restores both filters and the page for that scope. An empty filtered result says that no runs match. `GET /api/ai/runs` accepts an optional, validated `state`, applied in SQL before pagination. Fixes #553.
2. Compatibility and limits: an optional query parameter and a filter control, with no schema change. Existing calls and the response shape are unchanged, and direct, shared and legacy server associations stay in scope. This source update does not publish a Docker image.

## 1.59.29 — 2026-11-11

1. [PR #548](https://github.com/StealthCat/MrPatchy/pull/548): Add the administrator-only `GET /api/settings/ai-control-status`. It returns one redacted, read-only snapshot of every current global shared-AI blocker: disabled or incomplete configuration, provider backoff, a smooth-rate wait and an exhausted daily cap. It reports the latest finite gate as `next_start_at`, and any indefinite hold suppresses a claimed start time. The budget status adds `next_reset_authoritative`. When a retained prior window outlives the configured reset after a timezone change, that reset is reported only as a recheck boundary. Fixes #546.
2. Compatibility and limits: an additive API and status field, with no schema, admission, reservation, UI or role change. The snapshot contains no key, model, prompt, evidence, call or run ID, or ledger row. `can_start_now` means only that the global gates are open: call-specific pricing, provider policy, concurrency, server pause and lifecycle checks still apply. In legacy mode, the snapshot adds a limitation noting that the per-purpose hourly limits are enforced separately and not reflected. The Settings and Investigations UI are not changed. This source update does not publish a Docker image.

## 1.59.28 — 2026-11-11

1. [PR #550](https://github.com/StealthCat/MrPatchy/pull/550): The administrator AI worker status breaks deferred advisory plans down by purpose: release, incident and startup. Each purpose reports deferred and queue-ready counts and its earliest recorded future retry time, in a new `plan_deferred_by_action` field. The AI worker status card shows them under **Deferred plans by purpose**. It explains that queue-ready means due with server AI active, that shared controls can still delay a start, and that recorded retry times may belong to paused servers. Fixes #549.
2. Compatibility and limits: an additive administrator status field and card section, with no schema change. The existing aggregate plan fields come from the same grouped query, which returns at most three groups and no job payloads or host identifiers. The viewer response and admission are unchanged. This source update does not publish a Docker image.

## 1.59.27 — 2026-11-11

1. [PR #545](https://github.com/StealthCat/MrPatchy/pull/545): In capped modes, AI Settings shows how many counted transmitted AI calls await reconciliation and the oldest retained reservation time among them. The current-budget summary adds `unreconciled_call_count` and `oldest_unreconciled_reservation_at`, aggregated in the existing grouped SQL read. Sent and uncertain calls are counted, including those from still-counted prior windows after a timezone change. Settled, reserved, released and unknown-status calls are excluded. With no qualifying calls the API returns zero and null, and Settings shows an empty state. Fixes #544.
2. Compatibility and limits: an additive response field pair and Settings text, with no schema change. Budget membership, dollar totals, admission, roles and retention are unchanged, and no call identifiers, prompts or evidence are returned. The time shown is the reservation time, because the ledger keeps no separate transmission timestamp. This source update does not publish a Docker image.

## 1.59.26 — 2026-11-11

1. [PR #538](https://github.com/StealthCat/MrPatchy/pull/538): Add the administrator-only `GET /api/ai/known-good/summary`. It reports active and revoked published known-good entries, retained cache-reuse assessments and the subset linked to a revoked entry. A provider assessment linked at publication is not counted as reuse, historical reuse stays visible after revocation, and empty counts are zero. One aggregate statement returns only the four counters, without loading evidence, payloads or host identifiers. Fixes #537.
2. Compatibility and limits: an additive read-only API, with no schema, provider, scheduling, authorization-policy or UI change. The counts describe retained cache records. They do not quantify misses, current context validity, provider savings, billing or speed, and dashboard presentation remains open. This source update does not publish a Docker image.

## 1.59.25 — 2026-11-11

1. [PR #521](https://github.com/StealthCat/MrPatchy/pull/521): Add a pure agent spool capacity-admission contract (`app/spool_admission.py`). It accounts logical and physical (journal, WAL and temporary) usage separately, keeps a free-space reserve and reports pressure at 70% and 90%. Admission is by priority. At critical pressure, including the projected pressure after the append with journal overhead, only `security` records are admitted. Refusals are explicit and counted, never silent eviction. An epoch-tagged cumulative loss ledger keeps reason and priority counters monotonic within an epoch, saturating at 2^53 with a flag instead of resetting.
2. Compatibility and limits: an unwired contract only. No agent, controller, target, schema or API change. This is a partial #107 increment: the durable journal, crash-point tests, replay and idempotency, retry with jittered backoff, wiring and persistence of the ledger, and exposure through #108 remain open. This source update does not publish a Docker image.

## 1.59.24 — 2026-11-11

1. [PR #710](https://github.com/StealthCat/MrPatchy/pull/710): Fix partial `PUT /api/settings/ai` saves silently resetting omitted fields to defaults. A model-only save previously restored legacy admission, a $10 daily cap and UTC, and re-enabled paid update scoring. Omitted fields now keep their stored values (Fixes #708). AI admission and spend controls are also revision-checked (Closes #709). Settings and both save responses return an opaque `ai_controls_revision`. `PUT /api/settings/ai` and `PUT /api/settings` accept `expected_ai_controls_revision`, and a stale revision gets 409, writing no settings or audit entry. The Settings AI form sends its loaded revision and keeps the entered values on conflict.
2. Compatibility and limits: an additive response field and an optional request field, with no schema change. Omitting the revision keeps the previous behaviour. API clients that relied on partial `PUT /api/settings/ai` bodies resetting omitted fields now keep the stored values. The revision covers only AI admission and spend controls; the API key, patching and history sections are not revision-checked, and the legacy all-in-one form does not send it. This source update does not publish a Docker image.

## 1.59.23 — 2026-11-11

1. [PR #507](https://github.com/StealthCat/MrPatchy/pull/507): Add a pure firmware policy contract (`app/firmware_policy.py`). `resolve_effective_policy()` merges layered scopes, with narrower scopes winning, sources recorded and sticky exclusions. Conflicts and malformed values, including a non-boolean exclusion, an invalid deferral time or malformed approved channels, are reported as blocking conflicts rather than silently resolved or dropped. `evaluate_device()` reports unrecognized versions as unknown, never compliant, and never treats a policy without requirements, or with conflicts, as compliant. Exceptions must carry a finite expiry and lapse, and deferrals lapse. `authorize_unattended()` decides whether an explicit, expiring unattended opt-in, bounded by device, action and release, covers an exact operation. The opt-in is read only from the narrowest layer and is never inherited from a broader one. Overlong, malformed or over-cap scope IDs disable it instead of being truncated, so a long ID can never authorize a different ID that shares its prefix. More than 16 policy layers is a blocking `too_many_layers` conflict that disables unattended work while every supplied exclusion still applies. A positive result is necessary but never sufficient, and never substitutes a release.
2. Compatibility and limits: an unwired contract only. No database, API, UI, scheduler or runtime change, and no response action is authorized. This is a partial #400 increment: campaigns, UI, scheduling and reporting remain open. This source update does not publish a Docker image.

## 1.59.22 — 2026-11-11

1. [PR #520](https://github.com/StealthCat/MrPatchy/pull/520): Add the administrator-only `GET /api/settings/ai-connections`. It reports the saved OpenAI connection and the model each current AI feature inherits, and distinguishes host features, connection tests and model discovery. Saved-settings completeness is reported separately from the enable switches. The read uses only the saved key record's name: it neither decrypts credentials nor contacts a provider, and a malformed legacy model is withheld.
2. Compatibility and limits: an additive read-only API using the existing OpenAI configuration, with no schema migration. Host policy, request admission, pricing and audit still govern execution. This is a partial #290 increment: named connections, additional adapters, route writes, frozen dispatch and accounting integration, and the Settings UI remain open. This source update does not publish a Docker image.

## 1.59.21 — 2026-11-11

1. [PR #518](https://github.com/StealthCat/MrPatchy/pull/518): Add a labelled **Find a setting** search to the Settings hub. As you type, the section cards are filtered. Every typed term must match a section name, description or keyword list, such as API key, repository checks, certificate, MySQL or retention. Results are announced through a polite live region, and an empty result suggests example terms.
2. Compatibility and limits: routes, section navigation, `#settings/<section>` deep links, saves and role checks are unchanged, and there are no API changes. This is the first slice of #513: section splits, save-feedback consistency and visual review remain open. This source update does not publish a Docker image.

## 1.59.20 — 2026-11-11

1. [PR #508](https://github.com/StealthCat/MrPatchy/pull/508): Add a pure controller membership and serving-role admission contract (`app/controller_membership.py`). It validates member records and heartbeat freshness; future or stale heartbeats are not healthy. Registration rejects identity collisions and stale boot generations, and it reports a shared failure domain. It checks protocol and schema compatibility and standby readiness. A member whose desired role is draining is never promoted, even while it reports a ready standby. The single-serving-controller decision is keep, promote or hold. Split brain and missing evidence hold, and stale or incompatible serving claimants are quarantined. The decision is kept separate from scheduler leadership. Expected but missing members are reported.
2. Compatibility and limits: an unwired contract only. No database, clock, network, API, UI or deployment change, and no role change, failover or target action is authorized. This is a partial #451 increment: registry persistence, role transitions, deployment files and the dashboard remain open. This source update does not publish a Docker image.

## 1.59.19 — 2026-11-11

1. [PR #506](https://github.com/StealthCat/MrPatchy/pull/506): Add a pure firmware operation contract (`app/firmware_operation.py`). `bind_operation()` derives an operation id from the host and enrollment, device, action, exact payload and policy digest, so any change invalidates approval. Requests use a strict schema: unknown fields and overlong values are rejected rather than ignored or truncated, permitted flags are normalized and bound into the operation id, and force/ignore flags are rejected rather than stripped. `preflight_blockers()` treats unknown facts as blockers. The operation state model allows only legal transitions, and cancellation is limited to queued, preflight or staged work. `classify_outcome()` never treats an exit code or a staged image as completion, never verifies an overlong version by prefix, and requires reconciliation for uncertain writes.
2. Compatibility and limits: an unwired contract only. No execution, persistence, transport, UI or authorization change. This is a partial #399 increment: execution, receipts, locks and API/UI remain open. This source update does not publish a Docker image.

## 1.59.18 — 2026-11-11

1. [PR #517](https://github.com/StealthCat/MrPatchy/pull/517): Add a fleet-wide **Available patches** view (`#updates`) to the navigation. The Overview **Updates available** card now opens it for all active servers with no filter. The read-only `GET /api/fleet/updates` (viewer) pages server-side, up to 200 rows per page with no per-host or first-page cap. It searches by package and filters by server, priority, status and scope. Each row shows the server (linked to its Packages view), package and native architecture, installed and candidate versions, priority, policy deadline, and a status of available, queued, held or not installable. Rows also show priority deferral, repository-check freshness and contact staleness. The same package on two servers stays two rows. The unfiltered active total uses the same scope and candidate rule as the Overview count. `scope=inactive` lists retained candidates on disabled servers separately; deleted servers never appear. Status filters follow the row-status precedence. Queued and available membership comes from a database-side relation of open patch-job package specs, so queries stay bounded as the queue grows and a returned row never contradicts its requested status.
2. Compatibility and limits: additive API and UI, with no schema migration and no change to roles or response authorization. Installation is still approved per server. The queued and available filters use SQLite JSON1 (bundled) or MySQL 8 `JSON_TABLE`, matching the supported MySQL 8+ requirement. Access is role-level (viewer); there are no per-server viewer permissions. This fixes #512. This source update does not publish a Docker image.

## 1.59.17 — 2026-11-11

1. [PR #510](https://github.com/StealthCat/MrPatchy/pull/510): Add a pure AI feature-route resolution contract (`app/ai_routing.py`). It defines the routable feature inventory: triage first and follow-up stages, update scoring, incident and startup plans, release configuration, connection test and model discovery. `resolve_route()` applies item override, then feature route, then default precedence. It validates the connection, model and structured-output capability before anything would be sent, and never falls back to another provider. Blocked results carry an actionable code. `route_digest()` binds the feature, provider, connection, model and revision, so cache or reuse identity never crosses providers. `revalidate()` keeps queued work on its frozen route after settings edits and reports drift. It blocks when the frozen route is no longer valid, the feature is disabled, the connection now points at a different provider or the frozen record was altered. Malformed or overlong (more than 128 characters) configuration fails closed instead of being truncated.
2. Compatibility and limits: an unwired contract only. There are no provider adapters, migration, API, UI, network traffic or changes to the existing AI client. This is a partial #290 increment: the provider registry and adapters, migration, API/UI, per-item overrides and accounting remain open. This source update does not publish a Docker image.

## 1.59.16 — 2026-11-11

1. [PR #505](https://github.com/StealthCat/MrPatchy/pull/505): Add a pure database-failover safety contract (`app/db_failover.py`). `classify_outcome()` separates a statement that was provably never sent from an uncertain commit, where the statement or COMMIT was sent but no reply came. An unsent statement may be replayed only after the connection pool is invalidated. An uncertain commit is always reconciled by its durable operation id, never replayed, and refused when there is no id. `resume_gate()` treats a reconnect as no proof of ownership. Resuming requires a verified single writer, an unchanged deployment epoch, an unchanged ownership epoch with this controller still the owner, and no held session (`GET_LOCK`) locks. Malformed input fails closed.
2. Compatibility and limits: an unwired contract only. It opens no connection and authorizes no failover, restore or reconfiguration; there is no runtime change. This is a partial #453 increment: runtime wiring and the remaining #453 acceptance stay open. This source update does not publish a Docker image.

## 1.59.15 — 2026-11-11

1. [PR #504](https://github.com/StealthCat/MrPatchy/pull/504): Add a pure, read-only Raspberry Pi boot-EEPROM status contract (`app/rpi_eeprom.py`). It parses bounded, captured `rpi-eeprom-update` output and classifies it as verified current, update available, pending reboot, unsupported model, missing tool, collection failed or stale/unknown. Only verified current is healthy. A missing tool, empty or unrecognized output, a bad exit status, a timeout, a stale observation or an unsupported board is never healthy. Non-default release streams are flagged for review and never chosen implicitly. The auto-update service state is reported, never changed. The provider declares no stage, execute, recovery or settings capability.
2. Compatibility and limits: an unwired contract only. There is no collection, I/O, database, API or UI change. Fixtures are modelled on documented tool output; it is not yet tested on real Raspberry Pi hardware. This is a partial #402 increment: agent collection, persistence/API/UI, exact-image staging with post-reboot verification, package-managed firmware attribution and a support matrix remain open. This source update does not publish a Docker image.

## 1.59.14 — 2026-11-11

1. [PR #503](https://github.com/StealthCat/MrPatchy/pull/503): Add a pure BIOS/UEFI settings contract (`app/firmware_bios_settings.py`). `redact()` strips the values of sensitive settings such as passwords, tokens and recovery keys without mutating its input. `validate_value()` checks the native type, allowed enumeration values and integer ranges. `drift()` compares settings with an approved baseline as ok, drifted or unknown. A missing setting is never ok, pending reboots are flagged and sensitive values are never echoed. `preview()` blocks locked or read-only, unprivileged, sensitive (manual-only), invalid and no-op changes, and otherwise binds the exact setting state and proposed value. A ready result is eligibility evidence, never authorization. `recheck()` requires re-review when the setting, its lock or the caller's privileges changed since the preview.
2. Compatibility and limits: an unwired contract only. No database, route, dispatch, UI or runtime-authorization change; nothing imports it yet. This is a partial #401 increment: security-attribute collection, advisory integration, fwupd collection, baseline storage and exceptions, approval/apply/re-read, UI and audit remain open. This source update does not publish a Docker image.

## 1.59.13 — 2026-11-11

1. [PR #502](https://github.com/StealthCat/MrPatchy/pull/502): Add a pure, versioned request/receipt envelope contract for future cloud-native agent transport (`app/transport_envelope.py`). `build_request()` binds the host, immutable provider resource id, enrollment generation, agent version, action, canonical payload digest, job id, expiry (at most one hour) and nonce into a binding digest. `check_replay()` refuses nonce reuse per resource within the caller-supplied seen set. `verify_receipt()` treats provider acceptance as no proof of execution. It accepts only a receipt that echoes the exact binding with an execution time no later than the expiry, and its reasons are fixed strings that never echo receipt content. `route_allowed()` blocks unlisted transport/action pairs before dispatch. `classify_submission()` keeps an unknown mutation outcome recovery-required, so it is never replayed or moved to another transport.
2. Compatibility and limits: an unwired contract only. No storage, route, provider call, credential, UI or runtime-action change. The binding is a digest, not a signature: authenticating receipts is left to the future transport. This is a partial #359 increment: the call-site and capability inventory, provider adapters (#360–#362), spool/telemetry, persistence and UI remain open. This source update does not publish a Docker image.

## 1.59.12 — 2026-11-11

1. [PR #501](https://github.com/StealthCat/MrPatchy/pull/501): Add a pure ingress routing contract (`app/ingress_routing.py`) that keeps process liveness, dependency readiness and role eligibility separate, so a responding `/healthz` never makes a standby, fenced or incompatible controller routable. `eligibility()` serves a node only when it is live, ready, not standby, fenced or incompatible, and its role matches the deployment mode. `route_decision()` never routes admin traffic publicly and marks only reads replay-safe, so a failed mutation surfaces uncertainty instead of being retried by the proxy. `pool()` returns usable members. It refuses an active/standby pool with more than one live active claim (split-brain), and an empty, malformed or duplicate inventory serves nothing.
2. Compatibility and limits: an unwired contract only. There is no endpoint, proxy, TLS, deployment or runtime change, standalone and SQLite behavior is untouched, and no failover or response action is authorized. This is a partial #450 increment: the reference deployment, cluster-wide TLS revisions, ACME custody, proxy identity validation and failure tests remain open. This source update does not publish a Docker image.

## 1.59.11 — 2026-11-11

1. [PR #500](https://github.com/StealthCat/MrPatchy/pull/500): Add a pure migration-ownership and version-coexistence contract (`app/migration_compat.py`). `join_decision()` admits a node only when its protocol matches and the deployment schema is within its declared range. `receipt_writable()` stops an older node from overwriting a deployment receipt written by a newer release. `resume_decision()` never races a live migration owner. After the owner is lost, only the additive expand phase restarts; an interrupted destructive phase blocks for an operator. `contract_gate()` blocks the destructive contract step while any replica still declares support for an older schema, when the replica inventory is empty or malformed, or without explicit approval. `rollback_possible()` refuses rollback once a destructive phase has started. Malformed input is always a refusal.
2. Compatibility and limits: an unwired contract only. No database, lock, network or runtime change, and no migration, drain, rollback or contract step is authorized. This is a partial #449 increment: runtime wiring and the remaining #449 acceptance stay open. This source update does not publish a Docker image.

## 1.59.10 — 2026-11-11

1. [PR #499](https://github.com/StealthCat/MrPatchy/pull/499): Add a pure ownership-epoch fencing and adoption contract for HA controller ownership (`app/ha_ownership.py`). Each ownership scope keeps a monotonic epoch. `acquire()` increments it on every takeover, including the same member after expiry; it refuses a live lease held by another member and renews the current owner without changing the epoch. `check()`, `renew()` and `revoke()` let only the exact owner-and-epoch token on an unexpired, unrevoked record act. Superseded, expired, revoked and malformed input fail closed, and an expired token cannot be renewed. `outcome()` classifies an operation as never submitted, accepted, completed or uncertain from durable facts and an authenticated receipt; a submission without a receipt is uncertain, never assumed lost. `adoption()` never replays: uncertain work and targets that do not enforce the fence are held, and only fence-enforced accepted work is resumed by observation.
2. Compatibility and limits: an unwired contract only. No database, lock, clock, network, host, role, audit or response-authorization change, and no dispatch, failover or takeover is authorized. This is a partial #448 increment: scheduler, host-mutation, AI and outbox wiring, target-side journals and two-process failover tests remain open. This source update does not publish a Docker image.

## 1.59.9 — 2026-11-11

1. [PR #498](https://github.com/StealthCat/MrPatchy/pull/498): Add a pure firmware artifact staging and trust contract (`app/firmware_artifact_trust.py`). `evaluate()` decides whether a staged artifact may appear installable. Each of these makes it not installable, with an explicit reason: an untrusted, unknown or (unless enabled) testing source; unverified, stale or future-dated metadata; a partial download; an unverified signature (unless policy allows unsigned); an invalid, uncomputed or mismatched digest; an incompatible device; a blocked release; an unapproved checksum; or a non-allowlisted source. A positive result is eligibility evidence, never authorization. `binding()` binds the artifact to the exact device, release, version, source, trust revision and digest. `recheck()` re-verifies at use and returns replan on any drift.
2. Compatibility and limits: an unwired contract only. No database, network, route, dispatch, UI or runtime-authorization change; nothing imports it yet. This is a partial #398 increment: catalog inventory, artifact cache/transfer, offline bundle import, provider enforcement, settings/API/UI and audit remain open. This source update does not publish a Docker image.

## 1.59.8 — 2026-11-11

1. [PR #497](https://github.com/StealthCat/MrPatchy/pull/497): Add a pure deployment co-location and failure-domain contract (`app/deployment_topology.py`). `classify()` normalizes component placement observations. Placement counts as proven only when it comes from an authenticated source (registration, agent inventory or provider) at verified confidence and is fresh. Configuration, declared or name-matched, stale, future-dated or missing placement stays unverified, stale or unknown. A manual correction never overrides a fresh, conflicting proven observation; that case is flagged as a conflict. A manual correction replaces stale evidence only as unverified. `failure_domains()` groups proven components by host and merges hosts that share storage. `redundancy()` gives an explainable independent or co-located verdict per component kind, and unproven components are listed but never counted as independent.
2. Compatibility and limits: an unwired contract only. No database, route, dispatch, UI or runtime-authorization change; nothing imports it yet. This is a partial #444 increment: registration correlation, the impact planner, admission, drain/failover adapters and UI remain open. This source update does not publish a Docker image.

## 1.59.7 — 2026-11-11

1. [PR #496](https://github.com/StealthCat/MrPatchy/pull/496): Add a pure inventory of controller durable files and a shared-backend capability assessment for HA planning (`app/ha_artifacts.py`). The inventory classifies each consumer under the data and TLS directories as authoritative, cache or coordination, with the storage capabilities it needs. It covers the instance key, SSH keys and rotation journals, database profiles, the evidence archive, vendor and YARA bundles, TLS material, rebuildable apt/rpm working directories and flock coordination files. `assess()` reports which consumers a declared shared backend cannot satisfy. Only a boolean `True` counts as a declared capability, so an unknown or malformed declaration is never ready. Lock-only gaps are reported separately from authoritative state.
2. Compatibility and limits: an unwired planning contract only. Nothing imports it, so there is no behavior change; standalone and SQLite deployments are unaffected, and no migration, failover or response action is authorized. The database itself is outside this file inventory. Multi-controller HA is not yet supported. This is a partial #447 increment: a shared backend, migration, distributed locks and cross-host tests remain open. This source update does not publish a Docker image.

## 1.59.6 — 2026-11-11

1. [PR #495](https://github.com/StealthCat/MrPatchy/pull/495): Add a pure asset-group contract (`app/asset_groups.py`). `normalize_asset()` validates tags, site, owner, environment and criticality, and rejects unknown fields. `validate_group()` accepts static groups (host ids) and rule groups (all/any conditions over asset metadata, with `eq`, `in`, `has` and minimum-criticality operators), with optional parents. Unknown parents, parent cycles and nesting deeper than eight levels are rejected. `membership()` and `membership_diff()` give a deterministic membership preview and what a change would add or remove. `effective_policy()` previews one host's effective policy: a child group overrides its parent, the higher priority wins across groups, and equal-priority disagreements are reported as conflicts with the key left unset. Each resolved key names its source group.
2. Compatibility and limits: an unwired contract only. No schema, migration, route, authorization, scheduling or runtime-action change. This is a partial #334 increment: persistence, group-scoped authorization, queued-work revalidation, UI and audit remain open. This source update does not publish a Docker image.

## 1.59.5 — 2026-11-11

1. [PR #494](https://github.com/StealthCat/MrPatchy/pull/494): Add a pure idempotency-key contract for service-submitted mutations (`app/idempotency.py`). It validates 8–128-character keys without echoing a rejected key, and computes a canonical JSON payload digest. Its request fingerprint binds the identity, action, de-duplicated sorted targets and payload digest. `decide()` classifies a submission against the stored record as new, a replay that returns the original result, in progress, or a conflicting reuse with no result.
2. Compatibility and limits: an unwired contract only. No schema, route, credential, runtime-action, role or response-authorization change; nothing imports it yet. This is a partial #337 increment: scoped service identities, the API surface, durable idempotency records and ticket/SIEM mappings remain open. This source update does not publish a Docker image.

## 1.59.4 — 2026-11-11

1. [PR #490](https://github.com/StealthCat/MrPatchy/pull/490): Add a pure automation-conflict evidence contract (`app/automation_conflicts.py`). `classify()` deterministically classifies scheduled-automation entries against a versioned behavior-rule catalog keyed on effective-configuration behavior tags, not filenames. The result is observed only when evidence links to that exact entry. It is likely when an enabled entry with a conflicting behavior is scheduled inside an upcoming operation window. Otherwise it is insufficient evidence. Overlapping schedules, a lock or an unfamiliar script alone never prove causation. Findings carry the rule id and version, evidence references, affected operations, the entry digest and explicit gaps, and never describe intent. `plan()` proposes, and never executes, an approval-bound, single-entry disable. It keeps prevent-future-starts, stop-active and terminate-process distinct; the latter two need separate scope and response authorization. Temporary suspension needs an approved restore time, and unsupported mechanisms become a manual step. `approval_current()` invalidates an approval when the entry content, state or identity changes.
2. Compatibility and limits: an unwired contract only. There is no discovery, collection, bridge operation, persistence, API, UI, notification, role, audit or response-authorization change. This is a partial #405 increment: discovery, typed disable/restore operations, receipts and UI remain open. This source update does not publish a Docker image.

## 1.59.3 — 2026-11-11

1. [PR #394](https://github.com/StealthCat/MrPatchy/pull/394): Add a pure container workload inventory contract (`app/workload_inventory.py`). It strictly validates a Docker/Podman collector report, identifies workloads by `runtime:container_id` and keys images by immutable `sha256:` digest, treating tags as non-identifying labels. It handles stopped workloads without PIDs, collapses exact duplicates and rejects conflicting observations of one container with an explicit gap. It enforces bounds (512 containers, 16 tags per image, 64 PIDs) and discloses explicit gaps for inaccessible or absent runtimes, skipped malformed records, truncation and unscanned images. `compare()` classifies added, removed, replaced (same runtime and name, unambiguous pairs only) and changed workloads, plus tag movement.
2. Compatibility and limits: an unwired contract only. No runtime is executed and nothing is collected, persisted or exposed through an API or UI. No target, schema or response-authorization behavior changes. This is a partial #336 increment: target-side collection, pip/npm/JAR metadata, SBOM export, advisory matching and fleet search remain open. This source update does not publish a Docker image.

## 1.59.2 — 2026-11-11

1. [PR #391](https://github.com/StealthCat/MrPatchy/pull/391): Add a read-only `resource_pressure` observation to target agent telemetry. It carries CPU and memory pressure-stall (PSI) `some`/`full` averages from `/proc/pressure` and memory total/available from `/proc/meminfo`, with version, collection time, source, units and a collected/unknown state per signal. Missing PSI (older kernels, containers), permission denial and malformed, duplicate or out-of-range data stay unknown with a typed gap (`unsupported`, `permission-denied` or `unavailable-or-malformed`) and never break the collector cycle. Only a missing CPU `full` record is tolerated; available memory is clamped to total, and inputs are size-capped.
2. Compatibility and limits: the `resource_pressure` telemetry key is additive. The `device_health` shape, existing telemetry keys, APIs, roles, schemas, mutation paths and operational/response authorization are unchanged. Targets report the new signal only after the updated agent is deployed through **Finish / verify installation**. The controller stores the signal but does not display or alert on it. Fixtures are synthetic; there is no real-target coverage yet. This is a partial #342 increment: time sync, certificate expiry, history, alerts, UI and patch/reboot preflight remain open. This source update does not publish a Docker image.

## 1.59.1 — 2026-11-11

1. [PR #386](https://github.com/StealthCat/MrPatchy/pull/386): Add a pure, versioned SSH daemon posture rule evaluator (`app/posture.py`). It checks bounded `sshd -T` evidence for PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, PubkeyAuthentication, X11Forwarding and MaxAuthTries. Each rule reports pass, fail, not-applicable or unknown, with the measured and expected values and the rule version; fail results also carry remediation guidance. Missing, failed, stale, future-dated, untimestamped or malformed evidence, and non-string values, are reported unknown, never compliant. Not-applicable requires fresh evidence that reports no settings.
2. Compatibility and limits: an unwired evaluation contract only. No collection, storage, API, UI, exceptions, remediation, target or response-authorization behavior changes. Only the global configuration that plain `sshd -T` reports is evaluated; `Match` blocks are not, so a host can pass while a `Match` block relaxes a setting for some connections. This is a partial #335 increment: other rule families, collection, exceptions and UI remain open. This source update does not publish a Docker image.

## 1.59.0 — 2026-11-11

1. [PR #352](https://github.com/StealthCat/MrPatchy/pull/352): Add audited, administrator-managed fleet-wide change freezes through `GET`/`PUT /api/operations/freezes`. Each interval records an owner, reason and offset-aware start and end, and expires automatically. The response reports active freezes, when the chain of overlapping freezes clears and the precedence rule. Active freezes take precedence over maintenance windows and urgent bypass when starting scheduled or manual patch, repair or release-upgrade jobs; waiting jobs are not cancelled. A malformed saved policy keeps dispatch blocked until an administrator repairs it. Revision checks reject stale edits.
2. Compatibility and limits: existing deployments require no schema migration; the policy is stored in the existing settings table. With no active freeze, existing dispatch rules apply. Scheduled starts can still expire at their approved deadlines. No approval or response authorization is granted or bypassed. Per-host or group scope, holiday calendars, package deferrals, emergency exceptions and UI remain tracked in #340. This source update does not publish a Docker image.

## 1.58.0 — 2026-11-11

1. [PR #669](https://github.com/StealthCat/MrPatchy/pull/669): Add `GET /api/notifications/arrivals` with a durable cursor for newly committed, current-role-visible revisions, independent of producer timestamps and the bounded history list. Sequence numbers are assigned after producer commits so slow or rolled-back writes cannot be skipped or replayed; baselines cover all prior arrivals, with bounded pagination and cursor reset handling. Additive `notification_arrivals` and `notification_arrival_head` tables are created automatically. Existing notification list/count, SSE, read/dismiss, authorization and response behavior remain unchanged. Arrival retention/pruning, client adoption for live toasts (#662/#663) and multi-controller acceptance remain open. This source update does not publish a Docker image.

## 1.57.2 — 2026-11-11

1. [PR #392](https://github.com/StealthCat/MrPatchy/pull/392): Add a pure rollout-ring planner (`app/rollout_rings.py`). It validates reusable ring definitions, computes the exact approved target set with a digest, and makes a deterministic batch-admission decision under parallelism, soak-time, failure-threshold and per-service or per-site availability limits. Availability membership for the bounded fleet is bound into the plan digest, so unavailable hosts outside the rollout's target set still consume a shared service or site budget. Missing membership for a limited scope, observed hosts outside the inventory, unknown fields, newline names and non-finite soak or current times all fail closed.
2. Compatibility and limits: an unwired planning contract only. No scheduler, database, API, UI, target or response-authorization behavior changes, and the decision is advisory and never overrides approvals or holds. This is a partial #339 increment: runtime ring execution, soak enforcement and service drain/rejoin remain open. This source update does not publish a Docker image.

## 1.57.1 — 2026-11-11

1. [PR #671](https://github.com/StealthCat/MrPatchy/pull/671): Make the baseline-history browser regression wait for the policy-backed execution-scan form before reading its panel, and delay the mocked policy response so the loading race is exercised on every run. Test-only; no runtime, API, schema, authorization or compatibility change.

## 1.57.0 — 2026-11-11

1. [PR #382](https://github.com/StealthCat/MrPatchy/pull/382): Add administrator-reviewed loopback HTTP/TCP application probes that gate rollout patch stages. `GET /api/operations/{host_id}/probes` (viewer) and the audited `PUT` (administrator) store up to 16 bounded definitions per server, each with a name, port, optional path and expected status, timeout, required flag and reason. Probes are data, never commands. The target bridge's fixed `app-probe` adapter connects only to `127.0.0.1`, follows no redirects, reads no response body and reports only `ok` and a short status. For patch jobs that belong to a rollout, the worker collects a probe baseline before any package change and compares it afterwards. A missing, duplicated, malformed or non-boolean baseline stops the job before mutation. A required probe that was healthy and now fails stops the rollout. Probes that were already failing are reported as pre-existing.
2. Compatibility and limits: servers without probes behave as before, and definitions are stored in the existing settings table with no schema migration. Targets need the updated helper (**Finish / verify installation**) before probes are configured; with an older helper the baseline fails before any package change. A failing probe never starts a rollback or reboot. Single-server on-demand patches outside a rollout are not gated, and there is no probe editor UI yet. This is a partial #338 increment: replication/workload adapters, service dependency groups and non-rollout patches remain open. This source update does not publish a Docker image.

## 1.56.5 — 2026-11-11

1. [PR #541](https://github.com/StealthCat/MrPatchy/pull/541): Let administrators filter retained AI spend windows by the exact recorded IANA budget timezone in AI Settings. The optional API filter runs before grouping and the result limit; clearing restores all timezones, and unsaved budget settings remain unchanged. Existing calls and response shape are unchanged; there is no schema or accounting-policy change. This completes the bounded timezone-history acceptance in #540; production faster-AI performance and provider-invoice reconciliation remain open. This source update does not publish a Docker image.

## 1.56.4 — 2026-11-10

1. [PR #364](https://github.com/StealthCat/MrPatchy/pull/364): Add `docs/SECRET_CUSTODY.md`, the design inventory and migration contract for external secret custody and recoverable encryption-key rotation. It inventories every consumer of `secret.key`, including Fernet-sealed settings, MFA secrets, release plans, database profile files, the worker preflight key canary and backup bundles, plus the one HKDF-derived subkey. It proposes a provider interface with fail-closed rules, a read-compatible `mp1:<key_id>:` envelope, a resumable rotation, retirement and backup/restore contract, a test matrix and a delivery sequence. At integration the coordinator corrected the inventory to include the worker preflight canary (a fourth independent Fernet construction that workers verify before admitting work) and the legacy `scripts/backup.py` key copy.
2. Compatibility and limits: design documentation only. No runtime, key-semantics, schema or response-authorization change, and no provider is contacted. This is a partial #346 increment: the provider interface, envelopes, rotation job and an external provider adapter remain unimplemented. This source update does not publish a Docker image.

## 1.56.3 — 2026-11-10

1. [PR #667](https://github.com/StealthCat/MrPatchy/pull/667): Raise the MySQL test-shard job timeout from 20 to 30 minutes so slow but passing shards are no longer cancelled mid-run, and print the 25 slowest tests in each MySQL shard log. A regression test pins the bounded timeout, the unchanged four-shard matrix, the 5-minute apt setup bound and the unfiltered pytest command. Fixes #666.
2. Compatibility and limits: CI only, with no runtime, schema, API, UI, role or response-authorization change, and no test is skipped or deselected. A hung shard can now use up to 10 more minutes of runner time before cancellation. Shards are still balanced by test count rather than measured duration. This source update does not publish a Docker image.

## 1.56.2 — 2026-11-10

1. [PR #349](https://github.com/StealthCat/MrPatchy/pull/349): Add `docs/CAPABILITY_MATRIX.md`, a current capability and delivery-status index that links each tracked capability to its merged PRs, open PRs and remaining acceptance. It separates open issues, unmerged PRs and synthetic validation from delivered, real-target-verified behavior. At integration the coordinator reconciled the rows, written against v1.37.10, to current main: #202 and #318 are delivered, and merged slices for #96/#305, #108, #189, #190, #201, #341, #342, #343, #344 and #345 are listed. Issues #334–#347 now show their merged or in-review first slices instead of appearing unclaimed.
2. Compatibility and limits: documentation only, with no code, API, schema, role or response-authorization change. The matrix indexes the reconciled set and #334–#347 only; later roadmap issues are not yet indexed. Rows go stale unless updated with each integration. This is a partial #347 increment: coordinator-checklist maintenance remains open. This source update does not publish a Docker image.

## 1.56.1 — 2026-11-10

1. [PR #363](https://github.com/StealthCat/MrPatchy/pull/363): Add administrator-only incident case ownership and investigator notes for scanner incidents. `GET /api/hosts/{host_id}/security/incidents/{incident_id}/case` returns the current owner and ownership revision. `PUT …/owner` assigns or clears an enabled administrator owner and requires the expected revision and a 10–4000 character reason; stale revisions return HTTP 409. `POST …/notes` appends a note of up to 4000 characters. Both are host-scoped, audited and recorded as `assign`/`note` events on the incident timeline.
2. Compatibility and limits: additive API with no schema migration; ownership is derived from the existing append-only incident timeline. Assignment and notes never change incident state, evidence, plans or `updated`, and never authorize a response action. They take the server's configuration lock, so they return HTTP 409 while that server has an active operation. No UI yet. This is a partial #343 increment: severity/SLA deadlines, ticket/recovery links, scoped exceptions, UI and notifications remain open. This source update does not publish a Docker image.

## 1.56.0 — 2026-11-10

1. [PR #355](https://github.com/StealthCat/MrPatchy/pull/355): Add administrator-only, read-only recovery readiness derived from operator-recorded drill receipts. `POST /api/recovery/receipts` validates and audits one version-2 receipt per stage (backup, archive verification, isolated restore, optional boot recovery, application recovery). Each receipt is bound to one backup ID, archive SHA-256, environment/adapter, database/trust identity, non-secret key fingerprint, and records a key-verification time; each later stage names its exact parent receipt. `GET /api/recovery/readiness` reports per-stage missing, failed, stale, mismatched, unbound or unknown states and blockers. Readiness requires a current, matched backup → archive-verification → isolated-restore → application-recovery chain, a restore that covers the declared backup scope, externally held key custody and a recent key verification. An archive checksum alone is never sufficient. Receipt appends are serialized by the shared recovery-receipts lock, retain the newest 100 receipts and reject unknown fields, so key material cannot be stored.
2. Compatibility and limits: new admin-only routes; receipts are stored in the existing settings table with no schema migration, and no existing route, role or response-authorization behavior changes. Readiness reports matched operator attestations, not independently executed drills or proof that a deployment is recoverable. Recording a receipt never starts a backup, restore, stop or activation. This is a partial #345 increment: UI, adapter examples and scheduled verification remain open. This source update does not publish a Docker image.

## 1.55.11 — 2026-11-10

1. [PR #659](https://github.com/StealthCat/MrPatchy/pull/659): Stabilize the Settings browser test after clearing reviewed provider backoff by waiting for the post-clear reload to detach the old control. Test-only; no runtime, API, schema, permission, or configuration change. This source update does not publish a Docker image.

## 1.55.10 — 2026-11-10

1. [PR #657](https://github.com/StealthCat/MrPatchy/pull/657): Fix server AI capacity and Pause/Resume saves so a still-current dialog closes and shows the persisted policy even when a background refresh replaces the panel and its older policy read completes afterward. Preserve navigation and dialog revision guards, role/CSRF checks, required reason, and existing conflict behavior. No API, schema, permission, or configuration change. This source update does not publish a Docker image.

## 1.55.9 — 2026-11-10

1. [PR #287](https://github.com/StealthCat/MrPatchy/pull/287): Move the digest-pinned container runtime and backend CI to Python 3.15, regenerate the hash-locked runtime dependency target, and add a separate hash-pinned build-input lock for sdist-only zstandard. Networked build steps fetch verified bytes only; compilation and installation run offline in a compiler-only stage, and build tools are removed from the final image. Add the test compatibility shim for Python 3.13+ PGPy imports. Container rebuild required; image builds require BuildKit. No schema, API or application configuration change. This closes the Python 3.13+ test/runtime CI gap tracked in #445. This source update does not publish a Docker image.

## 1.55.8 — 2026-11-10

1. [PR #655](https://github.com/StealthCat/MrPatchy/pull/655): Add an opt-in same-server layout to the disposable AI investigation benchmark, report fixture topology, supported slots and observed peak provider overlap, and reject comparisons with mismatched layout or slot limits while retaining legacy report interpretation. No application API, schema or runtime configuration change. The CLI measures synthetic SQLite fixtures and does not establish production or MySQL throughput. This source update does not publish a Docker image.

## 1.55.7 — 2026-11-10

1. [PR #653](https://github.com/StealthCat/MrPatchy/pull/653): Release raw host inventory after preparing bounded update-scoring batches, retaining only scoring context and indexed RPM versions while preserving score identities, candidate order, outbound evidence, and fresh-inventory persistence checks. No schema, API or configuration migration. Compact per-host state still scales with the eligible fleet; synthetic allocation results do not establish production throughput or complete #436. This source update does not publish a Docker image.

# Changelog

## 1.55.6 — 2026-11-10

1. [PR #652](https://github.com/StealthCat/MrPatchy/pull/652): Preserve warm update-scoring memo entries at the 256-server cap while evaluating overflow with a bounded pass-local memo. Reclaim slots only after a complete pass confirms retained servers are no longer eligible; early exits preserve unvisited entries. Keep candidate order, score identities, RPM evidence invalidation, provider payloads and pause/lifecycle filters unchanged. No schema, API or settings migration. The selector still walks eligible candidates, and this fixture-based optimization does not establish production throughput or complete the broader #436 performance work. This source update does not publish a Docker image.

## 1.55.5 — 2026-11-10

1. [PR #554](https://github.com/StealthCat/MrPatchy/pull/554): Add a reviewed administrator reset for an active fleet-wide provider Retry-After/transient-failure cooldown in Settings. Show the sanitized reason, failure count, recorded time and next eligibility; require the reviewed-state revision, a meaningful reason and exact confirmation, with a locked recheck that rejects stale or expired state. Clearing sends no provider or target request and releases only the shared provider floor and provider-only waits; local retries, rate/budget, pause, lifecycle, concurrency and authorization controls remain in force. Compatibility: the administrator-only clear endpoint now requires JSON fields `expected_revision`, `reason` and `confirmation`; bodyless calls are rejected, and active status adds `updated_at` and `revision`. No schema or helper upgrade. Does not diagnose provider health, reconcile uncertain billing or complete the broader faster-AI program. This source update does not publish a Docker image.

## 1.55.4 — 2026-11-10

1. [PR #651](https://github.com/StealthCat/MrPatchy/pull/651): Reuse the process-local update-scoring memo when repository-file text, raw APT status, collection time or unrelated OS fields change without changing scoring evidence. Installed RPM records, scoring distribution and package manager still invalidate the memo; exact retained score keys and provider payloads are preserved. No schema or API change. The bounded memo still holds at most 256 hosts, scans eligible candidates and fingerprints the RPM inventory; fleet-capacity handling and production throughput remain open. No roles, provider-call policy or response-authorization changes. This source update does not publish a Docker image.

## 1.55.3 — 2026-11-10

1. [PR #650](https://github.com/StealthCat/MrPatchy/pull/650): Add an idempotently installed purpose/start covering index for administrator AI status and legacy triage and update-scoring counts on SQLite and MySQL. Preserve existing rows and indexes, strict one-hour cutoff, purpose separation, retry times and admission limits. Existing databases create the index at startup, and writes incur index-maintenance cost; fixture measurements do not establish production throughput. No run lifecycle, provider-call, API or authorization behavior change. Broader Roadmap A acceptance remains open. This source update does not publish a Docker image.

## 1.55.2 — 2026-11-10

1. [PR #535](https://github.com/StealthCat/MrPatchy/pull/535): Add the earliest non-expired process-investigation lease expiry to administrator AI status and explain that expiry only permits fenced recovery if renewal stops; it does not prove a provider request stopped or was not billed. The API field is additive, null when no lease is live, and hidden from non-admin status. No schema, admission, scheduling, provider-call or authorization behavior changes. Multi-controller failover and production recovery timing remain unverified. This source update does not publish a Docker image.

## 1.55.1 — 2026-11-10

1. [PR #648](https://github.com/StealthCat/MrPatchy/pull/648): Add the `ix_behaviors_attempted` covering timestamp index for administrator recent-attempt status and legacy hourly admission reads, and install it idempotently on existing SQLite/MySQL databases without rewriting retained rows. Preserve the strict one-hour cutoff, count, retry time and admission denial; API, policy, provider, UI and authorization behavior do not change. Index maintenance adds timestamp-write cost, and fixture measurements do not establish production throughput. This source update does not publish a Docker image.

## 1.55.0 — 2026-11-10

1. [PR #389](https://github.com/StealthCat/MrPatchy/pull/389): Distribute newly admitted process-triage work across eligible servers by live claim count, durable least-recently-admitted turns, then oldest eligible observation; commit a turn only with a successful claim. Add the `ai_triage_host_turns` table at normal startup and preserve it through offline SQLite/MySQL migration and copy. No API, role, audit, provider-payload, target-helper or response-authorization change. Same-server overlap remains available when no less-occupied eligible server waits, and existing lifecycle, capacity, retry and spend fences remain. Indexed election avoids a retained-history scan in SQLite; a dense MySQL fixture showed a higher query median despite indexed access. Production throughput and complete multi-controller failover remain unverified. This source update does not publish a Docker image.

## 1.54.16 — 2026-11-10

1. [PR #529](https://github.com/StealthCat/MrPatchy/pull/529): Add administrator investigation-status fields for the count and oldest observation age of retry-eligible, unclaimed process-triage work. The same aggregate snapshot counts only active, unpaused observations, excludes blocked, delayed and live-leased work, and leaves expired-lease work visible; empty timestamps are null. This is additive and keeps existing viewer/operator fields and authorization unchanged, with no schema migration, provider call, scheduler or UI change. Shared admission and available worker capacity can still delay dispatch; matched production throughput and broader dashboard work remain open. This source update does not publish a Docker image.

## 1.54.15 — 2026-11-10

1. [PR #646](https://github.com/StealthCat/MrPatchy/pull/646): In AI follow-up, let the newest validated authenticated vendor receipt for the exact executable path govern provenance. A mismatched hash, observed difference or incomplete verification keeps the package-authentication gap and prevents fallback to older matching proof; invalid receipts and unrelated paths remain skippable. No schema, configuration, API or authorization changes; the existing bounded receipt search remains. This is a partial provenance milestone and does not complete fleet-wide known-good reuse. This source update does not publish a Docker image.

## 1.54.14 — 2026-11-10

1. [PR #608](https://github.com/StealthCat/MrPatchy/pull/608): Add composite indexes for retained AI assessment exact-state Re-triage preservation and subject/host history, with idempotent startup reconciliation and SQLite/MySQL query-plan coverage. Existing rows, retention, newest-first ordering, query/API behavior, roles, provider behavior and response authorization remain unchanged. Existing databases incur ordinary index-build locking, time and disk costs; this is a bounded persistence/query-performance increment, not a production throughput or full faster-AI completion claim. This source update does not publish a Docker image.

## 1.54.13 — 2026-11-10

1. [PR #644](https://github.com/StealthCat/MrPatchy/pull/644): Reduce repeated authenticated file-receipt validation during single-executable triage and cross-server byte-trust rechecks while preserving exact case-sensitive path matching, newest mismatch precedence, full validation of selected receipts and complete inventory maps. No schema, public API, trust-policy or authorization changes. Misses may still scan retained history; database-driver buffering and native runtime latency are outside this fixture-validated increment, and broader known-good-cache/production performance work remains open. This source update does not publish a Docker image.

## 1.54.12 — 2026-11-10

1. [PR #604](https://github.com/StealthCat/MrPatchy/pull/604): Add the idempotent `ix_update_scores_host_name_state_candidate` index for exact package score history and deferred AI scoring lookups on new and existing SQLite/MySQL databases. Retained scores and existing indexes remain intact; existing databases incur ordinary index-build locking and disk use. Query results, ordering, APIs, roles, provider behavior and response authorization are unchanged. This is a partial scoring-performance increment; repeated idle hashing and production throughput remain open. This source update does not publish a Docker image.

## 1.54.11 — 2026-11-10

1. [PR #642](https://github.com/StealthCat/MrPatchy/pull/642): Add a bounded `--retained-history-rows` control (0–50,000) to the disposable SQLite AI-triage benchmark, report the seeded count, and require matched history sizes when comparing serial and parallel runs; older reports default to zero. This is benchmark tooling only and does not change application runtime, schema, provider behavior or response authorization. Synthetic SQLite measurements do not establish MySQL, endpoint or production throughput. PR version checks now resolve the target branch tip when they run, avoiding stale base snapshots after integration preparation; this does not change runtime behavior. This source update does not publish a Docker image.

## 1.54.10 — 2026-11-10

1. [PR #600](https://github.com/StealthCat/MrPatchy/pull/600): Add the composite `ix_behaviors_admission (approved, verdict, first_seen, id)` index to accelerate pending/error process-triage admission over retained behavior history. Existing SQLite and MySQL databases add the index idempotently, preserving rows and oldest-eligible selection across both verdict ranges. Existing databases incur ordinary index-build locking and disk use; this is a partial performance milestone, not a production-throughput or full faster-AI completion claim. No API, schema-column or response-authorization changes. This source update does not publish a Docker image.

## 1.54.9 — 2026-11-10

1. [PR #631](https://github.com/StealthCat/MrPatchy/pull/631): Update SQLAlchemy from 2.1.6 to 2.1.8 in the runtime requirements and hash-pinned lock. No application code, configuration, schema or public API changes are included, with no compatibility impact expected. This source update does not publish a Docker image.

## 1.54.8 — 2026-11-10

1. [PR #630](https://github.com/StealthCat/MrPatchy/pull/630): Upgrade the hash-pinned Authlib runtime dependency from 1.9.1 to 1.9.4, including upstream OAuth ID-JAG scope and issuer/subject user-resolution fixes. Application OAuth configuration, schema and public API remain unchanged; existing integrations gain these upstream fixes where ID-JAG is used, with no expected compatibility impact. This source update does not publish a Docker image.

## 1.54.7 — 2026-11-09

1. [PR #629](https://github.com/StealthCat/MrPatchy/pull/629): Update python-multipart from 0.0.32 to 0.0.33 in the runtime requirements and hash-pinned lock for upstream parser, upload and decoding fixes. Upstream drops Python 3.10; the application image uses Python 3.12, so its supported runtime is unaffected. Target-agent Python requirements are unchanged. Upstream URL-encoded field caps are opt-in and this update does not enable them. No application code, configuration, schema or public API changes. This source update does not publish a Docker image.

## 1.54.6 — 2026-11-09

1. [PR #576](https://github.com/StealthCat/MrPatchy/pull/576): Reduce database reads during investigation lease validation by rejecting lost, replaced and expired claims before fetching behavior evidence, then selecting only the host lifecycle fields (`enabled` and `deleted_at`) needed for valid leases. Preserve the evidence, owner, configuration, expiry, heartbeat, disabled/deleted-host and mutation fences. Compatibility and limits: no schema, public API, locking, lease lifetime, provider policy or response-authorization change; production throughput remains unverified. This source bump does not publish a Docker image.

## 1.54.5 — 2026-11-09

1. [PR #581](https://github.com/StealthCat/MrPatchy/pull/581): Join expired AI lease claims to their retained run rows in one bounded read, followed by the existing bounded orphan scan. Preserve live leases, completed runs, interruption events, provider receipts, idempotent recovery and the admission lock. Compatibility and limits: no schema, API, queue-policy, retry or response-authorization change; production throughput remains unverified. This source bump does not publish a Docker image.

## 1.54.4 — 2026-11-09

1. [PR #591](https://github.com/StealthCat/MrPatchy/pull/591): Read the newest running triage stage and newest triage/worker diagnostic through one bounded UNION ALL query and one database snapshot, projecting only the fields used by the existing status response. Compatibility and limits: no schema, API, UI, provider, admission, pause, scoring, operational policy or response-authorization change. This reduces a polling round trip but does not establish production throughput or complete the broader faster-AI milestones. This source bump does not publish a Docker image.

## 1.54.3 — 2026-11-09

1. [PR #587](https://github.com/StealthCat/MrPatchy/pull/587): Batch the rolling triage-run count/oldest timestamp and deferred update-score count/next eligibility into one aggregate query each, reducing empty AI-status reads from 20 to 18 SQL statements and keeping each pair on one database snapshot. Compatibility and limits: no schema, API, UI, status, pause, admission, budget, provider-backoff, authorization or response behavior change; SQLite and MySQL remain supported. This is a partial database-read optimization; production throughput, threaded investigations, fair scheduling, shared accounting and the remaining failover/reset milestones are not established. This source bump does not publish a Docker image.

## 1.54.2 — 2026-11-09

1. [PR #593](https://github.com/StealthCat/MrPatchy/pull/593): Batch candidate-host and queued/running advisory-plan occupancy eligibility into one bounded query for up to 100 incidents, preserving database host collation in SQL and canonical-host deduplication within each tick. Compatibility and limits: no schema, API, UI, provider-call, role, spend-control, plan-content or response-authorization change; candidate order and the ten-plan allowance remain unchanged. The 12-host fixture falls from 151 to 132 SELECTs, but production throughput is unverified; earlier pause/quarantine reads and smooth shared admission remain unfinished. This source bump does not publish a Docker image.

## 1.54.1 — 2026-11-09

1. [PR #579](https://github.com/StealthCat/MrPatchy/pull/579): Read live process-triage claim counts and saved per-server concurrency policy together under the existing admission lock, preserving expiry, candidate selection, defaults and the minimum fallback. No schema, public API, role or response-authorization change.
2. This reduces database reads; production throughput impact remains unverified.

## 1.54.0 — 2026-11-09

1. [PR #393](https://github.com/StealthCat/MrPatchy/pull/393): Show conservative vendor-sourced operating-system lifecycle status (standard, extended, ended and unknown) on each server Overview, failing closed for derivatives, stale or future-dated inventory, unverified extended-support architectures and unobserved Ubuntu Pro entitlement.
2. Compatibility and limits: the existing viewer-scoped summary API gains bounded read-only lifecycle metadata; no schema, mutation, role, AI, patching or response-authorization behavior changes. The catalog is static/versioned and displays its review date; Ubuntu Pro entitlement is not observed. This is a partial #341 increment: migration queue/plans, target correlation, fleet filters/reports, alerts, RPM/vendor coverage, entitlement discovery, automated catalog refresh and real-target upgrade acceptance remain out of scope. A source bump does not publish a Docker image.

## 1.53.4 — 2026-11-09

1. [PR #640](https://github.com/StealthCat/MrPatchy/pull/640): Memoize host RPM version indexes and candidate identities across idle scoring passes while inventory and package fields are unchanged, including timestamp-only refreshes. Real scoring-relevant inventory and package changes still invalidate identities and preserve existing rescoring behavior.
2. Compatibility and limits: no API, schema, settings, provider-evidence, scoring-result or response-authorization behavior changes. The process-local FIFO retains 256 hosts and up to 20,000 identities per host; larger or frequently cycling host sets can rebuild indexes, and the host inventory fingerprint is still computed per pass. SQLite/MySQL fixture timings are not production benchmarks. This is a partial fix for #436; broader performance scope remains open. This source update does not publish a Docker image.

## 1.53.3 — 2026-11-09

1. [PR #598](https://github.com/StealthCat/MrPatchy/pull/598): Add an ordered `(purpose, state, started)` index for active AI run status and recovery lookups, and create it idempotently on existing databases while retaining run history and diagnostics. SQLite and MySQL query-plan tests verify the active index is selected without a temporary sort/filesort.
2. Compatibility and limits: additive startup index creation may require normal database DDL time and disk space. No query-result, API, role, lease, recovery, provider or response-authorization behavior changes. This is a bounded database optimization; production throughput and end-to-end parallel triage acceptance remain open. This source update does not publish a Docker image.

## 1.53.2 — 2026-11-09

1. [PR #585](https://github.com/StealthCat/MrPatchy/pull/585): Reuse the initial settings and encrypted key snapshot during triage preflight, including rate and budget checks and retry-signature construction. Preserve gate order, while refreshing capped eligibility after the queue lock and retaining the authoritative provider reservation.
2. Compatibility and limits: no public API, schema or settings migration. No provider, budget, pause or response-authorization behavior changes. The change reduces repeated settings reads; production throughput remains unverified. This source update does not publish a Docker image.

## 1.53.1 — 2026-11-09

1. [PR #618](https://github.com/StealthCat/MrPatchy/pull/618): Skip the shared AI rate lock for legacy, daily-cap-only and unthrottled provider starts after a fresh mode read; paced starts keep atomic admission and reread the current mode/rate under lock. This removes one shared lock acquisition per start in modes that do not use shared pacing, while preserving same-work continuation behavior.
2. Compatibility and limits: no schema, API, settings migration, provider, budget, pause, or authorization changes. Paced starts add one settings read. This is a bounded lock-contention reduction, not a production throughput claim; broader shared-control acceptance remains open. This source update does not publish a Docker image.

## 1.53.0 — 2026-11-09

1. [PR #377](https://github.com/StealthCat/MrPatchy/pull/377): Add administrator-managed, versioned saved fleet queries over OS, package, state, enabled and overdue-update filters. Viewers can retrieve bounded, paginated host and matching-package evidence with evaluation time, query version and freshness; stale or incomplete observations are flagged, not counted as fresh.
2. Compatibility and limits: additive viewer/admin API and one `saved_fleet_queries` table created by normal schema initialization; no existing API or response-authorization behavior changes. This is the API-only first slice of #344; CVE/hash filters, group/owner/site dimensions, reports/exports, UI and large-fleet MySQL scale verification remain open. This source update does not publish a Docker image.

## 1.52.2 — 2026-11-09

1. [PR #620](https://github.com/StealthCat/MrPatchy/pull/620): Retain the monotonic distributed `claim_lock` wait separately from aggregate admission and queue-age timings for successful process-triage claims.
2. Compatibility and limits: diagnostic-only; no schema, API, setting, role, lease, lock, evidence or response-authorization changes. Older retained runs lack this sample; failed lock acquisitions and termination before timing flush may leave coverage incomplete. Production contention baselines and broader faster-AI acceptance remain open. This source update does not publish a Docker image.

## 1.52.1 — 2026-11-09

1. [PR #602](https://github.com/StealthCat/MrPatchy/pull/602): Skip the rolling-hour security/startup plan-history count when automatic planning uses rate, daily-cap, combined or unthrottled shared admission. Preserve the combined hourly allowance in legacy mode; the per-tick queue maximum and downstream shared admission remain unchanged.
2. Compatibility and limits: no schema, API, setting, default or scheduling changes. The legacy combined allowance remains until explicit migration; broader shared-control migration and end-to-end throughput acceptance remain open. This source update does not publish a Docker image.

# Changelog

## 1.52.0 — 2026-11-09

1. [PR #637](https://github.com/StealthCat/MrPatchy/pull/637): Add durable automatic file trust for matches backed by authenticated repository evidence and exact active known-good context. Trust records carry host/path/SHA-256 provenance and audit history; exact-path lookups remain collation-independent, concurrent duplicate observations resolve safely, and after a newer authenticated mismatch, only a subsequent authenticated matching inspection restores trust.
2. Compatibility and limits: adds an indexed `file_trust_observations` table through normal schema initialization, with no API, role, manual approval or response-authorization changes. Trust concerns file identity and does not approve behavior or suppress incidents and response safeguards. Existing records are learned on later ingestion/inspection/investigation; signing-key revocation and automatic repository retrieval remain separate work. This source update does not publish a Docker image.

## 1.51.1 — 2026-11-09

1. [PR #616](https://github.com/StealthCat/MrPatchy/pull/616): Skip the fleet-wide daily spend lock and spend quote when AI budget admission starts in legacy, rate-only or unthrottled mode. Capped requests reread settings after waiting for the lock; a removed cap skips the quote and ledger write, while an active cap is quoted and reserved atomically.
2. Compatibility and limits: no schema, API, setting or default changes; capped requests add a settings read and compute the bounded quote while holding the lock. Rate, provider and policy controls remain independent. This removes one lock acquisition for uncapped budget admission; broader shared-controls and production throughput acceptance remain open. This source update does not publish a Docker image.

## 1.51.0 — 2026-11-08

1. [PR #639](https://github.com/StealthCat/MrPatchy/pull/639): Add a menu-driven Python Compose configurator for app-and-worker, app-only and worker-only layouts with 1–16 containers per selected role. Customize normal/GCP builds or an existing image, project and shared data volume, database requirements, ports/subnet, worker concurrency and IDs, and memory limits. Preview generated YAML before saving; explicit replacement preserves a backup. The generator inherits maintained service restrictions, health checks and worker drain settings, orders initial app startup and removes local app/TLS dependencies from worker-only output. Fixes #638.
2. Compatibility and limits: generated YAML is standalone and defaults to a separate project; existing deployments and runtime dependencies are unchanged. Worker-only layouts require matching controller state on the same Docker host. Multiple apps share local state and a DNS endpoint; they do not establish load-balancing, migration fencing, cross-host storage or production HA guarantees. The host-side tool requires PyYAML. This source update does not publish a Docker image.

## 1.50.0 — 2026-11-09

1. [PR #635](https://github.com/StealthCat/MrPatchy/pull/635): Add an administrator-only **Test connection** action to Settings → Database (`POST /api/settings/database/test`) that checks the entered MySQL values, including unsaved edits, before a migration destination is staged. The probe verifies TLS and the host name when enabled, authenticates to the selected database and runs only `SELECT 1` in a disposable subprocess with a five-second overall deadline, at most two concurrent probes per controller process, sanitized result categories and an audit record of the category only. The button keeps keyboard focus, ignores duplicate activation, announces results through a live status and clears stale results after edits or Save. Fixes #634.
2. Compatibility: this is an additive administrator endpoint and UI with the existing administrator and CSRF guards; there is no schema or deployment migration, and saving, staging and offline migration behavior are unchanged. Material limits: results describe only the serving controller, the concurrency limit is per process, and a success does not verify migration privileges, schema compatibility or HA readiness. This source update does not publish a Docker image.

## 1.49.8 — 2026-11-08

1. [PR #612](https://github.com/StealthCat/MrPatchy/pull/612): Add an administrator-only Process triage timings panel to Fleet AI logs, backed by the bounded summary API delivered in PR #523. The panel lazily loads per-stage sample/error counts and p50/p95 milliseconds, preserves measured zero versus missing values, reports missing, malformed and truncated coverage, retries independently of run history, and discards stale responses after navigation. Compatibility: this is a presentation-only addition with no schema, provider traffic, target access, identity/evidence exposure, scheduling, role, admission, authorization or response-action change; per-server logs and non-administrator views are unchanged. Material limits: retained diagnostics can be incomplete or pruned, stages overlap, and the panel does not establish matched production serial/parallel performance, so #611 remains open. This source update does not publish a Docker image.

## 1.49.7 — 2026-11-08

1. [PR #523](https://github.com/StealthCat/MrPatchy/pull/523): Add an administrator-only `GET /api/ai/triage/timings` endpoint that summarizes a bounded sample of retained completed or failed process-triage timing events with per-stage sample/error counts and nearest-rank p50/p95 milliseconds. The response discloses missing-run coverage, malformed-event discards and event truncation while omitting event text, run/host identities, credentials and evidence. Compatibility: this is an additive read-only API with no schema migration, provider traffic, scheduling, admission, role, audit, authorization or response-action change. Material limits: the summary samples at most 100 runs and 2,048 events, stages may overlap, retained history can be incomplete or pruned, and it does not provide matched production serial/parallel measurements or the separately tracked dashboard presentation in #611/#612. This source update does not publish a Docker image.

## 1.49.6 — 2026-11-08

1. [PR #493](https://github.com/StealthCat/MrPatchy/pull/493): Add a regression guard requiring the GCP Compose override to extend only base services and inherit, rather than replace, production capability, privilege, identity, namespace, read-only-root, temporary-filesystem, process and memory hardening. The guard also pins writable Google Cloud CLI state to the persistent `/data/gcloud` location. Compatibility: this is test-only and does not alter existing Compose output, application behavior, deployment settings, API, schema, role, audit, authorization or response handling. Material limits: the regression verifies the repository configuration structure but does not inspect a live deployment or complete the remaining GitHub security-alert inventory tracked by #201, which stays open. This source update does not publish a Docker image.

## 1.49.5 — 2026-11-08

1. [PR #614](https://github.com/StealthCat/MrPatchy/pull/614): Add a bounded `--persistence-delay-ms` control to the disposable AI triage benchmark so receipt creation and usage reconciliation can each be measured under the same selected synthetic latency. Machine-readable output now includes the configured delay and completed/approved subject counts, focused acceptance proves equivalent serial and parallel work, and a reproducible 12-subject fixture artifact records the bounded comparison. Compatibility: the control defaults to zero, preserving existing benchmark execution, and the additional report fields are additive; v1.49.4 comparisons normalize older reports without the delay field to the same zero-delay contract. There is no application runtime, deployment setting, production provider, target access, database schema, API, UI, role, authorization or response change. Material limits: the fixture does not emulate database lock contention, network latency, failover, MySQL behavior or production/TLS/database performance, and it does not complete the wider faster-AI program. This source update does not publish a Docker image.

## 1.49.4 — 2026-11-08

1. [PR #551](https://github.com/StealthCat/MrPatchy/pull/551): Require fixture-only AI benchmark comparisons to use matching synthetic persistence-delay controls before emitting performance deltas. Reported `persistence_delay_ms` values are validated from 0 through 1,000 milliseconds, older reports without the field retain their documented zero-delay behavior, and accepted output records both the normalized value and whether it came from the report or the legacy default. Compatibility: existing pre-field benchmark reports remain mutually comparable at zero delay, while unequal or malformed delay controls that were previously accepted are now refused. There is no application runtime, production provider, target access, database schema, API, UI, role, authorization or response change. Material limits: this comparison guard does not add the benchmark producer control, establish production persistence performance or complete the wider faster-AI program. This source update does not publish a Docker image.

## 1.49.3 — 2026-11-08

1. [PR #543](https://github.com/StealthCat/MrPatchy/pull/543): Add a bounded `--queue-age-seconds` control to the disposable AI triage benchmark so fixture reports can measure fresh or delayed synthetic observations without waiting in real time. The selected age is applied to every fixture observation and reported through synchronized `queue_age_seconds` and `initial_fixture_queue_age_seconds` fields; negative values and values above 86,400 seconds are rejected before fixture startup. Compatibility: existing invocations retain the historical two-second default, and the additional report field is additive; there is no production provider call, SSH target, schema, runtime, API, UI, model, evidence, admission, authorization, pause, budget, retry or response change. Material limits: queue age remains synthetic and does not reproduce scheduler contention, production deferral or load, establish a production speedup, or complete the wider faster-AI program. This source update does not publish a Docker image.

## 1.49.2 — 2026-11-08

1. [PR #539](https://github.com/StealthCat/MrPatchy/pull/539): Bind fixture-only AI benchmark comparisons to the versioned SHA-256 fingerprint of the observed synthetic provider and SSH workload, refusing missing, malformed, unsupported or mismatched fingerprints before emitting deltas; seeded fixture queue age is also validated as a capability control, including bounded stage overhead at the maximum accepted seed. Accepted output retains only the verified fingerprint and bounded queue-age metadata, not raw requests. Compatibility: reports produced before workload fingerprinting must be regenerated, while legacy queue-age metadata defaults to the historical two-second seed and conflicting or unequal seeds are refused. There is no production provider call, target access, schema, runtime, API, UI, authorization, admission, pause, model, evidence-quality or response change. Material limits: this secures synthetic fixture comparison identity only and does not establish production performance, repeated-run statistics, dashboard presentation or complete the faster-AI roadmap. This source update does not publish a Docker image.

## 1.49.1 — 2026-11-08

1. [PR #533](https://github.com/StealthCat/MrPatchy/pull/533): Validate fixture-only AI benchmark timing consistency before reporting performance deltas by reconciling run count with independently three-decimal-rounded elapsed time and throughput through exact decimal intervals. Valid rounding boundaries and the retained historical fixture pair remain accepted, while inconsistent baseline or candidate reports fail with field-specific diagnostics. Compatibility: existing valid benchmark reports remain comparable; malformed or arithmetically inconsistent reports that were previously accepted are now refused. There is no production provider call, target access, schema, configuration, API, UI, role, admission or response-authorization change. Material limits: this validates synthetic fixture report arithmetic only; workload fingerprints, repeated production measurements, dashboard presentation and the broader faster-AI acceptance milestone remain separate, so #532 stays open. This source update does not publish a Docker image.

## 1.49.0 — 2026-11-08

1. [PR #622](https://github.com/StealthCat/MrPatchy/pull/622): Add administrator-only global defaults for automatic agent upgrade and repair, with one effective-policy resolver shared by APIs and background execution, explicit per-server `true`/`false` overrides, inheritance reset through omitted or `null` values, and response metadata identifying global values and inherited versus overridden sources. Concurrent global saves serialize across workers and reject stale or contended updates with HTTP 409; missing defaults remain disabled and legacy per-server rows remain explicit overrides. Compatibility: the per-server policy response keeps its effective `policy` shape and adds `global` and `sources`; omitted per-server fields now restore inheritance instead of writing `false`. No database schema migration or target-agent update is required. Material limits: this is the backend/API slice of #621; Settings and server UI controls, responsive UI acceptance and remaining documentation milestones are not delivered, so #621 remains open. Existing manual confirmation, role and runtime response safeguards remain in force. This source update does not publish a Docker image.

## 1.48.6 — 2026-11-08

1. [PR #632](https://github.com/StealthCat/MrPatchy/pull/632): Update the pinned CodeQL analysis action from v3.39.1 to v4.39.3 and reconcile its inline release comment, completing alignment with the initialization action integrated by PR #633. Compatibility: this is a CI-only workflow dependency change with no application runtime, API, schema, configuration, UI, installation, admission or response-authorization impact. Material limits: the change governs repository security-analysis execution only, does not alter the configured security-extended query suite, and cannot prevent transient external bundle-download or GitHub Actions infrastructure failures. This source update does not publish a Docker image.

## 1.48.5 — 2026-11-08

1. [PR #633](https://github.com/StealthCat/MrPatchy/pull/633): Update the pinned CodeQL initialization action from v3.39.1 to v4.39.3 and reconcile its inline release comment so pull-request security analysis uses the current action major and CodeQL 2.27.4 bundle line. Compatibility: this is a CI-only workflow dependency change with no application runtime, API, schema, configuration, UI, installation, admission or response-authorization impact. Material limits: the separately pinned CodeQL analysis step remains on v3.39.1 until paired PR #632 is integrated, and transient bundle-download failures remain external infrastructure conditions. This source update does not publish a Docker image.

## 1.48.4 — 2026-11-08

1. [PR #525](https://github.com/StealthCat/MrPatchy/pull/525): Add a bounded `--ssh-delay-ms` option to the disposable AI triage benchmark, preserving the historical 10 ms default while recording both synthetic provider and SSH delays in JSON and testing that the selected delay retains the expected one-stage/two-stage workload, provider calls and evidence follow-up. Compatibility: this adds an optional benchmark-only CLI input and additive JSON field with no application runtime, external provider, live target, API, schema, configuration, UI, admission or response-authorization change. Material limits: results remain loopback fixture measurements, do not establish production throughput or TLS latency, and do not complete the broader faster-triage acceptance program. This source update does not publish a Docker image.

## 1.48.3 — 2026-11-08

1. [PR #531](https://github.com/StealthCat/MrPatchy/pull/531): Add a versioned deterministic SHA-256 workload fingerprint to disposable AI benchmark reports, computed from the observed multiset of complete synthetic provider requests and allowlisted SSH evidence requests while retaining duplicates, model, policy, schema, limits and evidence. Canonicalization ignores dispatch order, the synthetic follow-up collection timestamp and ordering within set-valued SSH checks, and reports expose only the fingerprint version and digest rather than raw requests. Compatibility: this is an additive benchmark JSON field with no application runtime, live provider or target call, API, schema, configuration, UI, admission or response-authorization change. Material limits: the digest establishes fixture-workload identity only; enforcing it during comparison remains a downstream increment, and this does not supply production measurements or complete faster-AI acceptance. This source update does not publish a Docker image.

## 1.48.2 — 2026-11-08

1. [PR #527](https://github.com/StealthCat/MrPatchy/pull/527): Add a bounded, fixture-only AI benchmark comparator that emits strict fixed-shape JSON for elapsed time, throughput and allowlisted stage-latency deltas only after confirming equivalent run counts, provider and SSH fixture delays, workload shape, calls, tokens and required stage samples. Reports containing errors, malformed, non-finite or out-of-contract values, unchanged execution configurations or more than 1,000,000 bytes are refused before interpretation, with reads capped at the limit plus one byte; unavailable synthetic cost remains unavailable and zero baselines receive an explicit unavailable percentage. Compatibility: application runtime, APIs, schema, provider calls, target access, UI, configuration and response authorization are unchanged; existing benchmark reports without an SSH-delay field retain the documented legacy 10 ms fixture default. Material limits: results describe only disposable loopback fixtures and do not establish production performance, add live-provider telemetry or a dashboard, or complete faster-AI acceptance. This source update does not publish a Docker image.

## 1.48.1 — 2026-11-08

1. [PR #509](https://github.com/StealthCat/MrPatchy/pull/509): Add a pure, read-only config-revision freshness contract that marks cached security or configuration decisions usable only when cached and authoritative non-negative integer revisions match and the authoritative value was confirmed within the configured positive age bound. Behind revisions and old confirmations receive explicit stale verdicts; ahead, missing, malformed, non-finite or future-dated values fail closed as unknown, and a strict helper raises unless freshness is established. Compatibility: no API, schema, database, UI, cache, authorization, provider, scheduler or runtime behavior changes because this contract is not yet wired into decision paths. Material limits: this is only a foundation slice and does not deliver cache invalidation, durable request deduplication, cross-node identity/session consistency, active/active controllers or complete issue #452. This source update does not publish a Docker image.

## 1.48.0 — 2026-11-08

1. [PR #519](https://github.com/StealthCat/MrPatchy/pull/519): Add an administrator-only, CSRF-protected per-server setting for the serialized agent observation-batch ceiling, accepting strict integer values from 16 KiB through 1 MiB while retaining the 256 KiB default. The root-owned target configuration applies to normal and eBPF observations, is persisted atomically, reports its effective value through existing spool telemetry, rolls back failed collector restarts, and reconciles lost or malformed SSH replies with one serialized read-only status check before saving confirmed state. Compatibility: no database migration is required, existing targets retain 256 KiB until configured, and targets need the existing Finish/verify installation workflow to receive the updated bridge and collector. Material limits: this bounded slice does not deliver adaptive or scheduled flushing, compression, durable-capacity expansion, graceful-shutdown/replay guarantees, or complete issues #106, #107, or #108. This source update does not publish a Docker image.

## 1.47.1 — 2026-11-08

1. [PR #557](https://github.com/StealthCat/MrPatchy/pull/557): Route administrator model discovery through the existing bounded process-local AI HTTP pool instead of opening a one-off connection. Discovery still performs one non-billable GET with its own credentials, no cookies or body, redirect refusal, a 20-second timeout, the existing 2,000,000-byte and 10,000-model response limits, controlled errors and no automatic retry. Compatibility: API responses, UI, schema, provider POST payloads, billable request admission, roles and runtime response authorization are unchanged. Material limits: connection reuse does not guarantee provider availability or throughput, raise AI task concurrency or complete the broader faster-AI program. This source update does not publish a Docker image.

## 1.47.0 — 2026-11-08

1. [PR #561](https://github.com/StealthCat/MrPatchy/pull/561): Add the optional startup-only `MRPATCHY_AI_HTTP_CONNECTIONS` setting (integer 1–64, default 16) to bound each controller or worker process's reusable AI provider HTTP connections, applying the same limit to total and keepalive capacity. Complete Compose deployments pass the setting to both app and worker services, and worker registration, API and Activity → Workers display the effective `ai_http_capacity` as a transport ceiling. Invalid values fail closed before provider-client creation or worker registration. Compatibility: the default remains 16, no database or target migration is required, and existing task concurrency, shared admission, provider limits, pause/lifecycle checks and runtime response authorization are unchanged. Material limits: increasing the setting does not raise task concurrency, override provider limits, guarantee sockets or throughput, or complete the broader faster-AI program. This source update does not publish a Docker image.

## 1.46.3 — 2026-11-07

1. [PR #516](https://github.com/StealthCat/MrPatchy/pull/516): Expand the free-use license to legally recognized nonprofits and local government bodies operating their own systems, including use by their employees and volunteers, while keeping contractors, managed service providers, commercial service use, for-profit schools, and state or national government deployments outside that grant unless separately licensed. Synchronize License v1.1 across the bundled terms, commercial-use guide, contribution summary, in-app license page, container metadata and licensing tests. Compatibility impact is limited to the expanded licensing terms; runtime code, APIs, schema, roles, configuration and response authorization are unchanged, and existing agreements and earlier grants retain their stated treatment. The separately staged companion website rollout remains pending. This source version does not publish a Docker image.

## 1.46.2 — 2026-11-07

1. [PR #403](https://github.com/StealthCat/MrPatchy/pull/403): Validate the target boot identity before a reboot-requiring RPM transaction begins, then write the reboot marker from that prevalidated value only after DNF commits. A malformed or unavailable boot ID now refuses a reboot-requiring patch before any package change, while patches that do not require a reboot do not read the boot identity. This is a partial resolution of issue #190; the other duplicated or unvalidated target reads remain open. Package selection, API and schema contracts, roles and runtime response authorization are unchanged. This source update does not publish a Docker image.

## 1.46.1 — 2026-11-07

1. [PR #480](https://github.com/StealthCat/MrPatchy/pull/480): Require target `/usr/bin/python3` 3.8 or newer before enrollment or helper deployment. The installer and current bridge reject older interpreters with a clear message, while deployments through bridges installed before this release use the existing compile-before-write step to refuse the new helper payload before replacing any managed file; the controller translates that refusal into the same actionable requirement. Python 3.8-or-newer targets are unchanged. Hosts such as EL8 with the default Python 3.6 must install a supported interpreter before finishing enrollment. This update does not install or upgrade Python, add legacy EL8 runtime support, alter forced-command or response authorization boundaries, or publish a Docker image.

## 1.46.0 — 2026-11-07

1. [PR #628](https://github.com/StealthCat/MrPatchy/pull/628): Complete ordered file-provenance review for startup baselines and explicitly requested startup advisory plans. Baseline review now checks retained authenticated artifact hashes before conservative strict known-good eligibility, keeps metadata-only or mismatched files unresolved, and displays the assessment before manual approval. Browser approvals bind the displayed provenance digest so a changed review must be refreshed. Startup AI receives bounded, digest-bound assessments for current and approved inventories, and provenance changes invalidate in-flight results. Existing API clients may omit the additive review digest and retain the inventory-bound approval contract. No schema or target-collector migration is required. Coverage remains limited to retained operator-managed artifacts and recorded inventories; authenticated bytes do not establish safe behavior, approve a baseline, or authorize response actions. This source update does not publish a Docker image.

## 1.45.1 — 2026-11-07

1. [PR #477](https://github.com/StealthCat/MrPatchy/pull/477): Preserve accurate read-only quarantine evidence status when the original file's parent disappears. A retained vault record now reports `uncertain` / `parent_changed` and still verifies the held file instead of reporting `not_found` / `missing`, including when removal races the parent open. This changes the reported audit state for that case without mutating the target, restoring a file or changing response authorization. This source update does not publish a Docker image.

## 1.45.0 — 2026-11-07

1. [PR #627](https://github.com/StealthCat/MrPatchy/pull/627): Check stored, authenticated Debian/RPM artifact manifests and exact file hashes before consulting the strict known-good cache and using AI for unresolved process behavior. A hash mismatch bypasses cache reuse. Administrators can review recorded file hashes, sources, assessment history, baseline comparison, freshness and coverage gaps from fleet and server File status views. The views use stored evidence, and existing manual baseline approval and response authorization still apply. No schema migration is required. Coverage is limited to recorded observations and retained artifact evidence. Signature verification does not establish safe behavior or current signing-key revocation status. This source update does not publish a Docker image.

## 1.44.9 — 2026-11-07

1. [PR #395](https://github.com/StealthCat/MrPatchy/pull/395): Use the bridge’s shared RPM/Debian backend detection for read-only target security inspection. The package database selection and inspection report format stay the same. This covers only security inspection; other duplicated target helpers remain tracked in issue #190. This source update does not publish a Docker image.

## 1.44.8 — 2026-11-07

1. [PR #625](https://github.com/StealthCat/MrPatchy/pull/625): Add responsive Mr Patchy browser pages for forbidden access, missing pages, redirects and server failures, with eight themed transparent mascot illustrations. Failed application views and sign-in errors also use the new artwork. Preserve actual status codes, redirect destinations, cookies, Retry-After, security headers, API/download contracts and bodyless 304 responses; generic public messages do not disclose exception details. Pages work without JavaScript or database startup. External proxy-generated failures require that proxy's own handler; reusable static pages are included. No schema, role or runtime response-authorization changes. This source update does not publish a Docker image.
2. Allow 45 minutes for the complete SQLite/container/HTTPS CI job after a 30-minute run passed all 2,297 Python tests but was cancelled at the end of its final TLS smoke check. All validation steps remain enabled.

## 1.44.7 — 2026-11-07

1. [PR #482](https://github.com/StealthCat/MrPatchy/pull/482): Reject a still-queued evidence copy when its linked `evidence-preserve` job fails before execution, clearing the approval expiry so a fresh preservation can be prepared instead of leaving the copy permanently stuck in `queued`. Compatibility: controller bookkeeping and the retry path change only for failed, unstarted preservation jobs; API shape, database schema, roles and runtime response authorization are unchanged. Material limits: copies that reached `uncertain` or any later state, copies for another host and target-side evidence remain untouched; operators must explicitly prepare and approve a new preservation. This source update does not publish a Docker image.

## 1.44.6 — 2026-11-07

1. [PR #470](https://github.com/StealthCat/MrPatchy/pull/470): Preserve structured bridge health results when the collector service is inactive, failed, activating or unknown by accepting documented `systemctl is-active` status codes and reporting `collector_active=false`; pre-patch, rollback and health-comparison callers can now produce their designed diagnostics instead of receiving a bare command error. Compatibility: the bridge health response schema, roles and runtime response authorization are unchanged, but non-active collector states now return a successful structured health response rather than raising. Material limits: command execution, timeout, failed-unit ambiguity checks and all operation fail-closed gates remain enforced; this does not restart or repair an inactive collector. This source update does not publish a Docker image.

## 1.44.5 — 2026-11-07

1. [PR #483](https://github.com/StealthCat/MrPatchy/pull/483): Export every retained RPM package version, including older install-only kernels, and emit Debian/RPM package URLs with validated vendor namespaces and distribution qualifiers, bare component names, and nonzero RPM epochs in the `epoch` qualifier. Compatibility: SBOM component names, RPM version fields and package-URL identities change to the ecosystem form expected by vulnerability scanners; consumers that keyed records by the previous `name:arch` or epoch-in-version representation must reconcile those identifiers. Material limits: vendor/distribution metadata is emitted only when usable `ID` and `VERSION_ID` values are present in the saved OS inventory; the export remains a read-only snapshot and does not establish scanner coverage. Roles, schema and runtime response authorization are unchanged. This source update does not publish a Docker image.

## 1.44.4 — 2026-11-07

1. [PR #474](https://github.com/StealthCat/MrPatchy/pull/474): Keep the security-signature and oversized-tar test fixtures runnable on Python 3.13 and newer by supplying the removed `imghdr` interface only to PGPy's test-only photo-ID probe and by streaming zero bytes for the declared oversized archive member so the application budget check is exercised. Compatibility: production code, runtime dependencies, APIs, schema, roles and runtime response authorization are unchanged. Material limits: CI is still pinned independently of the production image and PGPy remains in the test fixtures, so #445 stays open and the Python 3.15 image bump must not merge until those gaps are resolved. This source update does not publish a Docker image.

## 1.44.3 — 2026-11-07

1. [PR #567](https://github.com/StealthCat/MrPatchy/pull/567): Fetch only the six retained score fields used to match exact assessments and check deferral eligibility during periodic AI update scoring. Preserve oldest-first selection, stale-deferred cleanup and full assessment details in the existing detail and completion paths. The database schema, API, provider inputs and runtime response authorization are unchanged. Repeated candidate hashing and measured production throughput remain open under #436.

## 1.44.2 — 2026-11-07

1. [PR #566](https://github.com/StealthCat/MrPatchy/pull/566): Narrow periodic AI update-score candidate discovery to the server ID and saved inventory actually used for scoring, leaving telemetry, baselines and other unrelated server fields out of the bounded candidate queries while preserving candidate order and exact APT/RPM evidence and score identities. Compatibility: scoring inputs, provider payloads, completed-score reuse, pause/lifecycle eligibility, APIs, schema, roles and runtime response authorization are unchanged. Material limits: every candidate is still hashed on each pass, measured production throughput remains unverified and the remaining CPU work stays tracked under #436, which remains open. This source update does not publish a Docker image.

## 1.44.1 — 2026-11-07

1. [PR #487](https://github.com/StealthCat/MrPatchy/pull/487): Correct the operator recovery documentation with the Python application prerequisites, concrete Compose named-volume discovery and restoration steps, and replace the stale administrator password-reset one-liner with the supported locked, audited helper and its explicit MFA/account-enable options. The README now states the implemented default of four AI worker tasks rather than one. Compatibility: documentation only; application behavior, APIs, schema, roles and runtime response authorization are unchanged. Material limits: these instructions do not automate infrastructure recovery, credential restoration or password-reset authorization, and operators still need trusted host access and separately protected recovery material. Completes #410. This source update does not publish a Docker image.

## 1.44.0 — 2026-11-07

1. [PR #304](https://github.com/StealthCat/MrPatchy/pull/304): Report distribution-upgrade availability from saved inventory through a shared `os_upgrade` status in the hosts and host-summary APIs, and show an accessible badge beside eligible Debian server names plus a report-only Overview notice. Malformed, stale, offline, disabled and unsupported inventories fail closed without disrupting other fleet responses, including legacy timestamps outside the supported numeric range. Compatibility: the API change is additive; inventory ingestion stores a bounded derived summary and startup backfills existing hosts. No upgrade is contacted or started by detection. Material limits: this slice reports fresh online Debian 11→12 and 12→13 paths only; Ubuntu offer verification, RPM-family detection, remaining server references and fleet notification remain under #96 and #305, which stay open. Existing roles and runtime response authorization remain unchanged. This source update does not publish a Docker image.

## 1.43.4 — 2026-11-07

1. [PR #595](https://github.com/StealthCat/MrPatchy/pull/595): Batch AI update-scoring row reads when linking a diagnostic run and persisting complete, superseded, deferred or failed outcomes for the existing five-item scoring batch, while retaining separate transaction boundaries and current package/server evidence rechecks. Compatibility: no schema, API, scoring model, provider, authorization, pause or rate/spend-control behavior changes. Material limits: this reduces ID-filtered score-row reads from twelve to four in the five-item fixture but does not address idle candidate hashing, measured production throughput or broader parallel scoring tracked under #436. Completes #594. This source update does not publish a Docker image.

## 1.43.3 — 2026-11-07

1. [PR #623](https://github.com/StealthCat/MrPatchy/pull/623): Reduce client-side validation failures to bounded field-labelled messages without reflecting rejected input or validation context, and accept whitespace-grouped six-digit authenticator codes during sign-in, reauthentication and MFA confirmation. Compatibility: ordinary six-digit codes remain unchanged; 7–16-character malformed codes now reach the existing authentication refusal path instead of failing request validation with HTTP 422. Material limits: optional client-side login `pattern` and `maxlength` constraints remain tracked under #419, which stays open. Existing roles, audit history and runtime response authorization remain unchanged. This source update does not publish a Docker image.

## 1.43.2 — 2026-11-07

1. [PR #283](https://github.com/StealthCat/MrPatchy/pull/283): Use one shared processing-tier multiplier table for AI cost estimates and pre-call spend reservations, and remove the unused `ai_runs.event(call=)` argument. Compatibility: verified estimate and reservation outputs, provider calls, accounting, APIs, roles, audit history and runtime response authorization remain unchanged. Material limits: this consolidates only the tier table and dead event flag; the duplicated advisory-plan generator, response failure/latest-record helpers, original-file stub and gpgv validation remain tracked under #189. This source update does not publish a Docker image.

## 1.43.1 — 2026-11-07

1. [PR #484](https://github.com/StealthCat/MrPatchy/pull/484): Build one installed-RPM-version index per host during each AI update-scoring pass instead of rescanning the host's full RPM inventory for every candidate, while preserving byte-for-byte score identities and the existing APT fallback. Compatibility: scoring inputs, completed-score reuse, provider requests, APIs, schema, roles and runtime response authorization are unchanged. Material limits: each candidate is still hashed on every pass and full host rows remain loaded, so #436 stays open for those remaining CPU and memory costs; the recorded performance comparison is a disposable single-sample fixture rather than a fleet throughput guarantee. This source update does not publish a Docker image.

## 1.43.0 — 2026-11-07

1. [PR #488](https://github.com/StealthCat/MrPatchy/pull/488): Add administrator recovery for another user's lost authenticator with administrator reauthentication, MFA-state clearing and session revocation, plus administrator APIs to list and remove SSO bindings. SSO replacement now requires an expected current username, serializes replacement with removal and records bounded subject digests and previous accounts in audit history. Compatibility: `PUT /api/operations/sso-binding` now returns HTTP 409 when an existing binding is changed without a matching `replace_username`; callers that reassign bindings must first read the current binding or remove it. Material limits: the bundled UI exposes MFA reset but does not yet provide SSO binding list/removal controls, self-MFA reset remains under Account, and these recovery operations require an administrator session and reauthentication where applicable. Existing roles and runtime response authorization boundaries remain unchanged. This source update does not publish a Docker image. Completes #418.

## 1.42.54 — 2026-11-07

1. [PR #476](https://github.com/StealthCat/MrPatchy/pull/476): Return bounded, field-labelled validation messages without reflecting rejected values, validation context, dynamic dictionary keys or forbidden extra-field names; invalid sign-in payloads now receive the generic `Invalid credentials` detail. Compatibility: HTTP 422 remains unchanged, but its `detail` value changes from a Pydantic error array to a string, and sign-in validation intentionally omits field-specific diagnostics. Material limits: this server-side slice does not add client-side fallback sanitization, normalize spaces in OTP input or add optional login input constraints, so #419 remains open for those items. Existing authorization and runtime response boundaries remain unchanged. This source update does not publish a Docker image.

## 1.42.53 — 2026-11-07

1. [PR #281](https://github.com/StealthCat/MrPatchy/pull/281): Make the native Debian package fixture independent of restrictive process umasks by assigning explicit package-tree permissions, and harden the HTTPS signed-repository fixture with HTTP/1.1 plus an explicit zero-length authenticated-mirror rejection. Compatibility: this changes test fixtures only; product runtime, APIs, TLS verification, authorization and response behavior are unchanged. Material limits: the Debian failure was reproduced and corrected, but the reported HTTPS EOF failure has not been revalidated on apt 3.0.x with OpenSSL 3.5.x, so #279 remains open for that evidence. This source update does not publish a Docker image.

## 1.42.52 — 2026-11-07

1. [PR #268](https://github.com/StealthCat/MrPatchy/pull/268): Detect distributed password guessing when failures against one account arrive from five or more distinct addresses within five minutes, recording one credential-free `login suspicious` audit entry per account and window. Compatibility: authentication responses and admission remain unchanged; detection does not lock accounts or block a legitimate sign-in. Detector state retains at most five recent addresses per tracked account and at most the existing login-bucket account limit, with expiry cleanup. Material limits: this adds audit detection rather than automatic throttling, alert delivery or response action, and new accounts are not tracked while the bounded account table is full. Existing authorization and runtime response boundaries remain unchanged. This source update does not publish a Docker image. Completes #199.

## 1.42.51 — 2026-11-06

1. [PR #244](https://github.com/StealthCat/MrPatchy/pull/244): Consume completed host-poll and notification futures so failures outside their operation handlers are logged instead of silently discarded, including during worker shutdown. Alert delivery failures now retain a bounded exception class plus an HTTP status or SMTP reply code without storing response text, URLs, credentials or tokens. Compatibility: `alert.error` may become more informative, for example `HTTPStatusError (HTTP 503)`, while APIs and schema remain unchanged. Material limits: these diagnostics do not retry failed delivery or expose remote response bodies. Roles, audit history and runtime response authorization are unchanged. This source update does not publish a Docker image. Completes #169.

## 1.42.50 — 2026-11-06

1. [PR #234](https://github.com/StealthCat/MrPatchy/pull/234): Resolve `scans:<id>` advisory-plan citations against scans included in portable scanner-record exports, and report valid `executions:<id>` and `inspections:<id>` citations as explicitly out of scope instead of missing. Malformed empty-suffix references remain missing so exports do not overstate completeness, and offline integrity verification continues to cover the hashed record. Compatibility: exports gain the additive `scope.out_of_scope_evidence_references` field while retaining format version 1. Material limits: execution and inspection evidence remains outside this export rather than being embedded. Roles, audit history and runtime response authorization are unchanged. This source update does not publish a Docker image. Completes #164.

## 1.42.49 — 2026-11-06

1. [PR #258](https://github.com/StealthCat/MrPatchy/pull/258): Apply shared scan-directory validation to manual ClamAV and YARA requests and to recurring and execution-triggered scan policies. Compatibility: noncanonical paths, control characters and excluded directories now return HTTP 400 before a job is queued or a policy is saved. Execution-triggered policies still disallow root and overlapping directories. Material limits: validation does not check whether a directory exists on the remote host or migrate previously saved policies. Existing authorization and audit controls remain in place. This source update does not publish a Docker image. Completes #158.

## 1.42.48 — 2026-11-06

1. [PR #252](https://github.com/StealthCat/MrPatchy/pull/252): Keep the Server Security and File integrity tabs usable when an independent panel fails. Load independent panels concurrently and show panel-local errors and Retry controls. A delayed failure cannot replace a newer successful refresh. Compatibility: browser requests for independent panels can overlap, while APIs, roles, audit records and runtime response authorization are unchanged. Material limits: retries use the existing backend operations and do not make failed operations idempotent. This source update does not publish a Docker image. Completes #155.

## 1.42.47 — 2026-11-06

1. [PR #610](https://github.com/StealthCat/MrPatchy/pull/610): Skip the shared AI provider-backoff lock and database writes when a successful or non-transient response has no eligible backoff to clear. Eligible resets still take the existing lock and recheck current state in a fresh transaction, preserving newer failures and their Retry-After floor. Compatibility is unchanged for APIs, schema, settings and response authorization. Already-clear rows retain their timestamps. The improvement removes unnecessary locking and writes on these paths. Fleet throughput and full multi-controller performance remain unverified. This source update does not publish a Docker image. Completes #609.

## 1.42.46 — 2026-11-06

1. [PR #606](https://github.com/StealthCat/MrPatchy/pull/606): Keep confirmed local HTTP connection-pool contention out of the fleet-wide AI provider backoff. The affected advisory or scoring request gets a five-second local delay, process investigations retain their bounded per-item retry schedule, and the matching unsent spend reservation is released. Compatibility: genuine provider failures and ambiguous network timeouts still create shared cooldowns and retain conservative spend; rate admission, evidence, API, schema, settings and response authorization are unchanged. Material limits: this distinguishes only the HTTP client's confirmed pool timeout and does not add automatic provider replay or complete broader AI failover and throughput work. This source update does not publish a Docker image. Completes #605.

## 1.42.45 — 2026-11-06

1. [PR #572](https://github.com/StealthCat/MrPatchy/pull/572): Reject invalid or oversized OpenAI Responses API requests locally with a fixed, redacted diagnostic. The shared request path validates strict UTF-8 JSON against a 2,000,000-byte encoded ceiling before provider backoff, budget or rate admission, then sends the validated bytes. Compatibility: valid requests keep their existing wire format and structured pricing inputs. The response limit, API, schema and runtime response authorization remain unchanged. The ceiling applies to the shared Responses API request body. This source update does not publish a Docker image. Completes #568.

## 1.42.44 — 2026-11-06

1. [PR #565](https://github.com/StealthCat/MrPatchy/pull/565): Cap pooled OpenAI Responses API replies at 2,000,000 decoded bytes with bounded streaming for identity and gzip. Oversized declared bodies are refused before reading, and oversized or invalid replies are closed without accepting partial results. Compatibility: provider POSTs advertise gzip and also accept identity. Unsupported or malformed encodings are rejected. Calls with unavailable usage remain conservatively counted when sent, and requests are never replayed automatically. Schema, API and response authorization are unchanged. The limit applies to pooled Responses API POST replies. This source update does not publish a Docker image. Completes #564.

## 1.42.43 — 2026-11-06

1. [PR #589](https://github.com/StealthCat/MrPatchy/pull/589): Restore daily AI budget capacity when the local HTTP connection pool times out before sending a provider request. Only the matching reservation is released, with a redacted ledger reason. Compatibility: no schema, settings or response-authorization changes. Rate consumption, transient backoff and conservative charges for potentially sent requests still apply. Material limits: earlier uncertain charges are retained, and this change does not add automatic retries or complete broader AI failover and throughput work. Completes #588. This source update does not publish a Docker image.

## 1.42.42 — 2026-11-06

1. [PR #596](https://github.com/StealthCat/MrPatchy/pull/596): Keep MySQL fleet and per-server Activity history on the existing ordered indexes with an order-only hint, avoiding retained-history filesorts for paginated requests while preserving stable newest-first ordering. Compatibility: there is no schema, settings, API, SQLite, authorization, redaction or runtime response-authorization change; existing installations already receive the named indexes through the idempotent startup migration. Material limits: the optimization depends on those existing MySQL indexes, does not add job retention or change other job-query plans, and this source update does not publish a Docker image. Completes #130.

## 1.42.41 — 2026-11-05

1. [PR #251](https://github.com/StealthCat/MrPatchy/pull/251): Add composite indexes for the retained jobs table's host/state, host/action/created, host-history, fleet-history and state/created query shapes, including idempotent startup creation for existing databases, so scheduler admission, queue checks, latest refreshes and Activity history avoid full-table scans and temporary ordering. Compatibility: this is an additive schema change with no API, ordering, recovery or runtime response-authorization change; the first start after upgrade creates the missing indexes and may take time on a large history table. Material limits: indexes consume database storage and add normal write-maintenance cost, and the change does not add job retention or rewrite other queries. This source update does not publish a Docker image. Completes #130.

## 1.42.40 — 2026-11-05

1. [PR #261](https://github.com/StealthCat/MrPatchy/pull/261): Compute AI investigation-status triage counts, retry minima, recent attempts and deferred-plan summaries with bounded SQL aggregates, and count recent automatic security/startup plans without loading full pending behavior or job rows. Related triage counts now share one database statement so a concurrent insert cannot make the paused count negative, while the status response shape and existing eligibility rules remain unchanged. Compatibility: no API, schema, configuration or runtime response-authorization change. Material limits: the queries still inspect the matching database rows and do not change AI admission, provider calls or retry policy; this source update does not publish a Docker image. Completes #184.

## 1.42.39 — 2026-11-05

1. [PR #514](https://github.com/StealthCat/MrPatchy/pull/514): Add a Host identity & recovery card to each server's Connection settings, showing the pinned SSH fingerprint or an Unpinned state and letting administrators pin or explicitly confirm an audited replacement from a trusted-console value, download or rerun the personalized installer, and finish or verify installation beside the existing Direct SSH and Google Cloud IAP controls. Compatibility: API clients replacing a different existing fingerprint must now send `replace_existing: true` or receive HTTP 409; first pins and idempotent re-pins remain compatible, host verification stays enforced, and no key is silently trusted from the connection being repaired. Material limits: this flow reuses the existing installer and verification operations rather than diagnosing the underlying route, authentication or bridge failure; the pre-existing enrollment Finish form keeps its separate browser-pattern behavior and server-side validation. Completes #511. This source update does not publish a Docker image.

## 1.42.38 — 2026-11-05

1. [PR #472](https://github.com/StealthCat/MrPatchy/pull/472): Report SSH deadline timeouts after a remote command starts as an unknown remote outcome with instructions to verify target state, instead of replacing the timeout with a misleading address, port or firewall hint. Compatibility: no API, configuration or runtime response-authorization change; connection, DNS and routing failures before command start retain the existing transport guidance. Material limits: the controller cannot determine whether the timed-out remote action completed, so operators must reconcile target state before retrying, and this change does not alter the configured deadline or add automatic retry. Completes #430. This source update does not publish a Docker image.

## 1.42.37 — 2026-11-05

1. [PR #384](https://github.com/StealthCat/MrPatchy/pull/384): Let administrators configure each server to occupy one to four concurrent AI process-investigation slots in its revisioned, audited AI policy. Legacy or absent settings keep the previous default of two, malformed stored values fail closed to one, and lowering the limit preserves live leases while blocking later admission until occupancy falls below the new bound. Compatibility: there is no schema migration or API removal, and existing clients may omit `concurrency_limit` to retain the current effective value; global capacity, pause, lifecycle, rate, spend and provider controls remain authoritative. Material limits: this does not add cross-purpose priority or aging, provider-specific quotas, native complete-context collection or complete multi-controller failover. Partially delivers #383, which remains open. This source update does not publish a Docker image.

## 1.42.36 — 2026-11-05

1. [PR #478](https://github.com/StealthCat/MrPatchy/pull/478): Require administrators to review and confirm a manual agent upgrade or repair, and keep both Agent health action buttons disabled while a check or upgrade request is pending so double submission cannot produce conflicting queue feedback. Compatibility: APIs, backend authorization, configuration and automatic maintenance are unchanged; the manual browser upgrade flow now has one additional confirmation step. Material limits: the browser guard is scoped to the currently loaded Agent health view, does not make requests idempotent, and the backend one-agent-job rule remains authoritative. Completes #441. This source update does not publish a Docker image.

## 1.42.35 — 2026-11-05

1. [PR #475](https://github.com/StealthCat/MrPatchy/pull/475): Resolve every requested server ID before taking configuration-change or rollout locks, so authenticated requests naming nonexistent servers return HTTP 404 without leaving permanent coordination files or in-memory lock entries. Compatibility: existing-server workflows, API schemas, configuration and runtime response authorization are unchanged; invalid rollout requests now fail before locking any listed server. Material limits: locks for persisted valid server IDs retain their existing lifetime, and disabled or deleted retained records continue through the normal lifecycle-state rejection path. Completes #437. This source update does not publish a Docker image.

## 1.42.34 — 2026-11-05

1. [PR #473](https://github.com/StealthCat/MrPatchy/pull/473): Clear stale sign-in errors after a successful login and explicit sign-out, and explain when password changes, session revocation, MFA enrollment or an expired established session require signing in again. Compatibility: login APIs, authentication policy, configuration and runtime response authorization are unchanged; this is browser feedback only. Material limits: an explicit sign-out intentionally shows no forced-sign-out reason, failed login attempts and the initial session probe do not claim that a prior session expired, and the sign-out form still resets the username field. Completes #439. This source update does not publish a Docker image.

## 1.42.33 — 2026-11-05

1. [PR #492](https://github.com/StealthCat/MrPatchy/pull/492): Add the first, pure read-only firmware inventory contract for normalizing bounded fwupd device and release data, advertising provider capabilities, classifying explicit non-healthy states, redacting serials by default and reconciling disconnected identities without transferring approval. Compatibility: no API, persistence, collection, UI, installation or runtime response-authorization change; this module is a foundation for later firmware delivery slices. Material limits: agent/bridge collection, migrations, fleet API/UI, execution and a tested platform matrix remain unresolved under #397; malformed provider data and failed collection status are conservatively non-healthy. This source update does not publish a Docker image.

## 1.42.32 — 2026-11-05

1. [PR #486](https://github.com/StealthCat/MrPatchy/pull/486): Include the per-server lifecycle control-lock wait in each SSH call's existing deadline and give the transport only the remaining budget, so calls blocked behind long-running work fail busy without starting a remote command instead of waiting up to an additional hour or indefinitely. Compatibility: no API, configuration or runtime response-authorization change; callers can now receive the existing busy/timeout failure within their requested deadline when a server lock remains occupied. Material limits: once a remote mutation has started, existing receipt and reconciliation safeguards still apply, and this does not shorten the duration of the operation holding the lock. Completes #431. This source update does not publish a Docker image.

## 1.42.31 — 2026-11-05

1. [PR #491](https://github.com/StealthCat/MrPatchy/pull/491): Refuse an approved release plan that expires in the queue before submitting it to the target, re-read the target receipt after a lost no-reboot rollback reply, and perform one final receipt read when a worker resumes after the four-hour observation window so completed upgrades and rollbacks are reported accurately. Compatibility: no API, configuration or runtime response-authorization change; expired plans now fail plainly and require a newly created and approved plan. Material limits: an unfinished release after the observation window still requires manual inspection, and no verify, rollback or start action is attempted after that window. Completes #426. This source update does not publish a Docker image.

## 1.42.30 — 2026-11-05

1. [PR #489](https://github.com/StealthCat/MrPatchy/pull/489): Bind behavior approval and revocation to the exact assessment revision shown to the administrator, expose that revision in the investigations listing, reject stale decisions with HTTP 409 and refresh the web view before another decision. Compatibility: API clients calling `PUT /api/investigations/{id}` must now send the 64-character `expected_revision` returned by `GET /api/investigations`; omitting or malforming it returns HTTP 422. Runtime response authorization is unchanged. Material limits: the revision fence applies to behavior approval and revocation only; AI assessments remain advisory, and this change does not alter triage admission, evidence validation or known-good scope. Completes #413. This source update does not publish a Docker image.

## 1.42.29 — 2026-11-05

1. [PR #485](https://github.com/StealthCat/MrPatchy/pull/485): Give every package-priority selector and repository-source editor a specific accessible name, and replace nested installer-download buttons with valid styled download links across enrollment and server management. Compatibility: no API, configuration, permission, runtime response-authorization or workflow change; existing installer URLs and download behavior are preserved. Material limits: this fixes the reported naming and nested-control defects only and does not constitute a complete accessibility audit. Completes #442. This source update does not publish a Docker image.

## 1.42.28 — 2026-11-05

1. [PR #479](https://github.com/StealthCat/MrPatchy/pull/479): Preserve a reviewed package-update selection across search edits, the Updates only filter and package-priority saves, count selections hidden by the current filter, and submit the selected packages with their reviewed candidate versions. Compatibility: no API, configuration or runtime response-authorization change; changing hosts, clearing the selection or successfully queuing the installation resets the client-side selection. Material limits: a package that disappears while Updates only is active can remain counted as hidden until an unfiltered reload, and the server rejects it if its candidate is missing or changed; selections remain capped at 500 packages. Completes #440. This source update does not publish a Docker image.

## 1.42.27 — 2026-11-05

1. [PR #481](https://github.com/StealthCat/MrPatchy/pull/481): Require recovery backups to acquire the database maintenance lock exclusively before reading deployment state, refusing while any app or worker replica is live, and replace the automatic post-backup full-pack read with a structural `restic check` while retaining `--read-data` for the explicit check action. The recovery guide now distinguishes routine and periodic full verification and provides an operator-run retention example. Compatibility: `--app-stopped` remains required, and backups attempted while replicas hold the shared lock now fail instead of trusting the assertion; there is no API or runtime response-authorization change. Material limits: the script never deletes snapshots, off-host transports remain operator-configured, and full data checks and retention must be scheduled separately. Completes #409. This source update does not publish a Docker image.

## 1.42.26 — 2026-11-05

1. [PR #459](https://github.com/StealthCat/MrPatchy/pull/459): Keep add-server step 1 editable and retryable after a definite client-side rejection, show the possible-created-server warning only when a network, server, timeout or rate-limit outcome is uncertain, and apply the server address character rule in the browser before submission. Compatibility: no API, configuration or runtime response-authorization change; uncertain submission outcomes deliberately keep Continue disabled until the operator reviews the server list. Completes #438. This source update does not publish a Docker image.

## 1.42.25 — 2026-11-05

1. [PR #457](https://github.com/StealthCat/MrPatchy/pull/457): Create APT and RPM repository-key directories with an explicit `0755` mode despite the bridge's restrictive umask, and repair existing bridge-owned `0700` key directories before saving a key so `_apt` and package tooling can traverse them. Compatibility: no API, configuration or runtime response-authorization change; symlink destinations and directories not owned by the bridge user remain refused. Completes #421. This source update does not publish a Docker image.

## 1.42.24 — 2026-11-05

1. [PR #462](https://github.com/StealthCat/MrPatchy/pull/462): Report clean target-side release start, status and rollback refusals with their actual message, and fail a refused start without placing the server in `recovery_required` when a follow-up status confirms that no receipt or target mutation exists. Compatibility: no API, configuration or runtime response-authorization change; transport failures and any submitted or uncertain release still retain the existing observation and reconciliation safeguards. Material limits: central plan-expiry validation, an unchanged-boot status re-read during rollback recovery and a final status read before the four-hour observation timeout remain unresolved under #426. This source update does not publish a Docker image.

## 1.42.23 — 2026-11-05

1. [PR #456](https://github.com/StealthCat/MrPatchy/pull/456): Preserve each RPM update candidate's repository severity while a manual package-priority override is active, so resetting that package to auto restores the repository classification instead of applying the APT origin rule; candidate installation clears the cached classification, and APT continues deriving auto priority from the current candidate. Compatibility: startup adds the nullable-default `packages.repository_priority` column to existing databases; old RPM rows without a stored classification retain their current priority and force a repository refresh on auto reset, while packages without an outstanding candidate reset to normal. No runtime response-authorization change. Completes #433. This source update does not publish a Docker image.

## 1.42.22 — 2026-11-05

1. [PR #461](https://github.com/StealthCat/MrPatchy/pull/461): Fail a protected patch normally when its read-only configuration inspection or helper-version validation fails before `protected-patch` is sent, instead of marking the job `recovery_required` and holding the server when no target mutation began. Compatibility: no API, configuration, recovery-policy or runtime response-authorization change; failures after the protected mutation is submitted retain the existing reconciliation hold. Completes #427. This source update does not publish a Docker image.

## 1.42.21 — 2026-11-04

1. [PR #458](https://github.com/StealthCat/MrPatchy/pull/458): Keep the eBPF execution collector running when one bpftrace line or decoded event is malformed, retain valid sibling events from the same read, preserve non-UTF-8 paths through surrogate escaping, and record skipped input in the eBPF diagnostic. Compatibility: no API, configuration or runtime response-authorization change; malformed lines and failing individual events are skipped rather than restarting the collector, while the existing oversized-line limit still stops and restarts that collector run. Completes #422. This source update does not publish a Docker image.

## 1.42.20 — 2026-11-04

1. [PR #467](https://github.com/StealthCat/MrPatchy/pull/467): Keep an in-flight AI behavior-triage lease valid when the same behavior re-spawns under a new process identity, while preserving the latest observed identity through follow-up evidence collection so a validated provider verdict is not discarded or overwritten by stale observation state. Compatibility: no API, configuration, approval, retry or runtime response-authorization change; only the observation-only `process_identity` is excluded from the live lease revision, while evidence, approval, attempt and AI-configuration changes still fence late results, and remote evidence remains bound to the originally verified identity. Completes #412. This source update does not publish a Docker image.

## 1.42.19 — 2026-11-04

1. [PR #465](https://github.com/StealthCat/MrPatchy/pull/465): Make encrypted off-host recovery backups follow an activated SQLite migration profile by rebasing its container `/data/...` database path onto the host `--data` directory, while refusing the `/data` directory itself, traversal escapes and paths outside that container data root. Compatibility: default deployments and non-SQLite profiles are unchanged; recovery backup now rejects active SQLite profiles outside `/data`, and a source-path symlink remains subject to the host filesystem's normal resolution behavior. No API or runtime response-authorization change. Completes #408. This source update does not publish a Docker image.

## 1.42.18 — 2026-11-04

1. [PR #466](https://github.com/StealthCat/MrPatchy/pull/466): Keep queued release-planning jobs dormant while AI is disabled globally or paused for their server, extending the existing scheduler guard shared by security and startup plans so the job is not reclaimed every tick, does not repeat SSH inspection or deferred-audit work, and no longer blocks later jobs for that server. Compatibility: no API, configuration, plan-state or response-authorization change; paused work remains queued with its existing administrator-controlled resume behavior, and ordinary non-plan jobs are unaffected. Completes #411. This source update does not publish a Docker image.

## 1.42.17 — 2026-11-04

1. [PR #464](https://github.com/StealthCat/MrPatchy/pull/464): Bound pending SSO login states to ten per requesting source and, at the 1,000-state global cap, evict the oldest state instead of refusing every new login; admission is serialized across processes so concurrent requests cannot bypass the bounds. Compatibility: no API or configured-provider change; one abusive source receives HTTP 429 after its own allowance, while other sources retain sign-in availability and an evicted stale flow must restart. No runtime response-authorization expansion. Completes #416. This source update does not publish a Docker image.

## 1.42.16 — 2026-11-04

1. [PR #463](https://github.com/StealthCat/MrPatchy/pull/463): Allow an interrupted SSH key rotation to resume through the agent-health gate only when an unfinished rotation journal exists and every recorded drift issue is the managed `authorized_keys` path; unavailable agents, missing journals and any other drift remain blocked. Compatibility: no API, configuration or response-shape change; the exception is limited to completing the already-authorized, journaled key transition and does not broaden other remote-operation authorization. Completes #429. This source update does not publish a Docker image.

## 1.42.15 — 2026-11-04

1. [PR #468](https://github.com/StealthCat/MrPatchy/pull/468): Persist the Google Cloud compose-file chain, project and zone in `.env` during `install-gcp.sh`, so later plain `docker compose` upgrade, migration and TLS commands keep the gcloud runtime, Workload Identity Federation mount and IAP connectivity. Compatibility: new installs receive the settings automatically; existing Google Cloud deployments must re-run `install-gcp.sh` once or continue using `./gcp-compose.sh` until `.env` is updated. The installer upsert is idempotent, preserves other keys and keeps `.env` mode 0600. No runtime response-authorization change. Completes #407. This source update does not publish a Docker image.

## 1.42.14 — 2026-11-04

1. [PR #469](https://github.com/StealthCat/MrPatchy/pull/469): Aggregate schedule-calendar runs in SQL, count target hosts without loading full host rows and remove the 10,000-run cap that silently omitted in-range results; active runs still reflect their linked job state and non-regular runs remain individually addressable. Compatibility: the calendar API response shape and scheduling behavior are unchanged; query count is bounded by schedules rather than runs, while result size remains bounded by distinct schedule/due/state groups plus individual non-regular triggers. No runtime response-authorization change. Completes #434. This source update does not publish a Docker image.

## 1.42.13 — 2026-11-04

1. [PR #471](https://github.com/StealthCat/MrPatchy/pull/471): Refuse Add-user requests for an existing or case-only variant username with HTTP 409 instead of silently replacing that account, and apply bootstrap-administrator and self-lockout guards to the stored username so case-insensitive MySQL lookups cannot bypass them. Compatibility: `PUT /api/users` accepts an optional `create` boolean; omitting it preserves the existing upsert behavior for API clients, while the web Add-user dialog now sends `create: true`. No runtime response-authorization expansion. Completes #417. This source update does not publish a Docker image.

## 1.42.12 — 2026-11-04

1. [PR #455](https://github.com/StealthCat/MrPatchy/pull/455): Keep fleet-wide scheduling, queued-job dispatch and alert collection running when one server's 50-operation queue prevents a periodic refresh from being enqueued; the skipped refresh is logged and retried on a later scheduler tick. Compatibility: no API, configuration or runtime response-authorization change; the affected server remains subject to its existing queue limit and does not receive that refresh until capacity becomes available. Completes #428. This source update does not publish a Docker image.

## 1.42.11 — 2026-11-04

1. [PR #420](https://github.com/StealthCat/MrPatchy/pull/420): Give the Compose worker an 8100-second stop grace period so in-flight patch, rollback and release work can drain instead of being SIGKILLed after Docker's 10-second default; the GCP override inherits the same setting. Compatibility: worker stop, restart and upgrade can now wait up to 2h15m, and `docker compose stop -t <seconds> worker` can shorten an explicit stop; work that exceeds the finite grace may still be interrupted. No runtime response authorization changes. Completes #406. This source update does not publish a Docker image.

## 1.42.10 — 2026-11-04

1. [PR #460](https://github.com/StealthCat/MrPatchy/pull/460): Return the same `Invalid credentials or MFA code` response for every login and account step-up failure so an MFA-protected account no longer reveals whether its password was correct. Compatibility: clients matching the former `Invalid credentials` or `Invalid MFA code` strings must update; login and step-up keep their existing 401 and 403 statuses, and roles, CSRF enforcement, throttling and factor verification are unchanged. Detailed login failure reasons remain in the audit log. This source update does not publish a Docker image.

## 1.42.9 — 2026-11-04

1. [PR #242](https://github.com/StealthCat/MrPatchy/pull/242): Remove retired TLS state directories after a confirmed Caddy activation, keeping the current and rollback generations and every recovery-required directory. Unconfirmed bootstrap renders and failed applies do not trigger pruning. Compatibility: no API or response-authorization change; retired profile, certificate, private-key and EAB files are overwritten in bounded chunks before best-effort removal, without a forensic-erasure guarantee on SSD or copy-on-write storage. This source update does not publish a Docker image.

## 1.42.8 — 2026-11-04

1. [PR #443](https://github.com/StealthCat/MrPatchy/pull/443): Bind logout completion and errors to the initiating session so authentication expiry or an obsolete response cannot display feedback after sign-out. Start the browser sign-out control with any prior toast hidden, while retaining the stronger eBPF CollectorClock isolation already delivered by #274. Compatibility: UI feedback and regression controls only; authentication, CSRF and response authorization are unchanged. Completes #404. This source update does not publish a Docker image.

## 1.42.7 — 2026-11-04

1. [PR #248](https://github.com/StealthCat/MrPatchy/pull/248): Check shared AI eligibility and exact candidate reservation ceilings before creating triage attempts, and reserve durable staggered rate-wake slots after the existing deferred tail. Preserve provider-only absolute floors from #390 without rate staggering; final atomic request admission remains authoritative. Compatibility: insufficient or unpriced budget candidates remain queued without consuming investigation attempts. This source update does not publish a Docker image.

## 1.42.6 — 2026-11-04

1. [PR #390](https://github.com/StealthCat/MrPatchy/pull/390): Cap provider-sent Retry-After at 24 hours and add an administrator-only audited clear of shared AI provider backoff. Keep local exponential retry gates separate, preserve longer local delays on clear, and release provider-only durable waits including admission races using their exact absolute provider floor. Compatibility: local-only backoff no longer blocks manual retry; provider calls still recheck shared rate, budget, pause and lifecycle admission. Includes the original [PR #229](https://github.com/StealthCat/MrPatchy/pull/229) history. This source update does not publish a Docker image.

## 1.42.5 — 2026-11-04

1. [PR #274](https://github.com/StealthCat/MrPatchy/pull/274): Keep transactional running byte/count totals for the target agent event spool, measuring legacy queues once and decrementing only successful acknowledgement deletes. Reuse a bounded executable hash cache with unchanged inode/metadata rechecks and throttle active eBPF status persistence to about once per second. Fix the eBPF test clock so collector sleeps cannot replace Python process-wide sleep or miscount background-thread sleeps. Fixes #186; batching/configuration work remains separately tracked in #106/#107. Compatibility: additive spool counter rows, unchanged observation/acknowledgement protocol and response authorization. This source update does not publish a Docker image.

## 1.42.4 — 2026-11-04

1. [PR #245](https://github.com/StealthCat/MrPatchy/pull/245): Restore into existing empty recovery destinations, including mounted TLS and Caddy volumes, without removing their roots. Validate all four destination roots and write-probe every destination before importing the database or writing secrets; reject symlinks, dangling links and non-directory roots before any recovery data is written. Fixes #151. Compatibility: preserves the existing empty-destination requirement and recovery authorization; no API, schema or response-authority change. This source update does not publish a Docker image.

## 1.42.3 — 2026-11-04

1. [PR #387](https://github.com/StealthCat/MrPatchy/pull/387): Add a CI drift guard requiring the target agent and bridge to retain the same managed-file list and requiring the observability systemd drop-in path to agree across the target and controller modules that verify, repair or install it. Compatibility: test/CI enforcement only, with no runtime, API, schema, role, audit or response-authorization change. Material limits: the duplicated constants remain in place, and the wider #190 hash-loop, ancestor-walker and import consolidation remains unfinished. This source update does not publish a Docker image.

## 1.42.2 — 2026-11-04

1. [PR #385](https://github.com/StealthCat/MrPatchy/pull/385): Run the production Compose `app`, `worker` and `caddy` services with read-only root filesystems, retaining only the existing named-volume state and an explicit private `/tmp` tmpfs as writable paths, with regression coverage requiring every production service to preserve both controls. Compatibility: no API, schema, UI, role, audit or response-authorization change; custom Compose overrides that write outside `app`/`worker` `/data`, app `/tls`, Caddy `/data` or `/config`, and each service's `/tmp` must mount an appropriate volume or tmpfs. This is a partial #201 hardening increment only: GCP override hardening and live alert inventory remain unfinished. This source update does not publish a Docker image.

## 1.42.1 — 2026-11-04

1. [PR #249](https://github.com/StealthCat/MrPatchy/pull/249): Keep the 30-second Fleet Overview and Servers background refresh from replacing the view with a loading placeholder or dropping the reader's scroll position and keyboard focus; unchanged results restore the original DOM nodes, while an open details panel defers the refresh. Compatibility: no API, schema, role, audit or response-authorization change; manual refresh, navigation and Retry retain their existing loading behavior, and changed results restore focus by stable element attributes when possible. This source update does not publish a Docker image.

## 1.42.0 — 2026-11-04

1. [PR #380](https://github.com/StealthCat/MrPatchy/pull/380): Allow two independently leased process investigations for one server to perform provider work concurrently while retaining exclusive subject claims, the fleet-wide AI executor limit, bounded third/fourth admission, pause and lifecycle fencing, post-wait lifecycle revalidation, evidence/configuration ownership checks, and explicit worker-status/UI disclosure. Compatibility: no schema, provider contract, role, approval, audit or response-authorization change; non-triage AI purposes retain their exclusive per-server provider gate, and higher overlap can consume configured rate and spend capacity sooner. Administrator-configurable per-server occupancy, broader cross-purpose fairness, native complete-context collection and complete multi-controller failover acceptance remain unfinished. This source update does not publish a Docker image.

## 1.41.1 — 2026-11-04

1. [PR #381](https://github.com/StealthCat/MrPatchy/pull/381): Bound the production Compose `app`, `worker` and `caddy` services to 2 GiB, 4 GiB and 512 MiB of memory by default, with per-service `MRPATCHY_*_MEM_LIMIT` overrides and regression coverage requiring every production service to retain a finite overridable limit. Compatibility: no API, schema, UI, role, audit or response-authorization change; large fleets or concurrent scan and AI workloads may need to raise the worker limit, and reaching a limit can OOM-kill and restart the affected container. This is a partial #201 hardening increment only: read-only root filesystems, GCP override hardening and live alert inventory remain unfinished. This source update does not publish a Docker image.

## 1.41.0 — 2026-11-04

1. [PR #375](https://github.com/StealthCat/MrPatchy/pull/375): Add authenticated same-origin notification Server-Sent Events with durable digest-cursor catch-up, session/account/role revalidation, bounded per-controller connections, heartbeats and polling fallback; refresh the bell, recent panel and open notification center from the existing permission-filtered APIs without replacing filters, losing unrelated form state or stealing focus. Compatibility: this is an additive stream endpoint and shell behavior with no schema migration, public API removal, global acknowledgement, SMTP/webhook producer, remediation or response-authorization change; frames contain no notification text, credentials or raw evidence. Production Caddy flushing/timeout measurement, slow-client and connection-exhaustion drills, pruned-cursor gap handling, live toasts, multi-controller failover and complete two-browser SQLite/MySQL acceptance remain unfinished. This source update does not publish a Docker image.

## 1.40.6 — 2026-11-04

1. [PR #378](https://github.com/StealthCat/MrPatchy/pull/378): Bound the production Compose `app`, `worker` and `caddy` services to 1024 processes each, with regression coverage requiring every service to retain a finite process limit. Compatibility: no API, schema, UI, role, audit or response-authorization change; custom deployments that legitimately require more than 1024 simultaneous processes in one container must raise `pids_limit` explicitly. This is a partial #201 hardening increment only: memory limits, read-only root filesystems, GCP override hardening and live alert inventory remain unfinished. This source update does not publish a Docker image.

## 1.40.5 — 2026-11-04

1. [PR #376](https://github.com/StealthCat/MrPatchy/pull/376): Add a liveness-based Docker Compose healthcheck for the worker service, refreshed only after a successful registry heartbeat and failed by missing, stale or implausibly future liveness timestamps. Compatibility: no API, schema, UI, role, audit or response-authorization change; the worker container now reports unhealthy when registry heartbeats stop, but Docker Compose does not restart unhealthy containers automatically. This is a partial #201 hardening increment only: read-only root filesystems, PID/memory limits, GCP override hardening and live alert inventory remain unfinished. This source update does not publish a Docker image.

## 1.40.4 — 2026-11-04

1. [PR #373](https://github.com/StealthCat/MrPatchy/pull/373): Add administrator-only retained AI spend history for trailing 1–90 day ranges, grouped by each ledger entry's persisted reset time and IANA timezone, with exact SQL aggregates for settled estimates and conservative unreleased ceilings plus bounded 7-, 30- and 90-day Settings views. Compatibility: this is an additive read-only API and UI change with no schema, admission, provider-call, pause, ledger-retention or response-authorization change; released unsent attempts remain excluded, estimates are not provider invoices, and output is capped at four reset/timezone groups per requested day with explicit truncation. Provider-invoice reconciliation, automated or signed catalog lifecycle and complete multi-controller failover/reset acceptance remain outside this increment. This source update does not publish a Docker image.

## 1.40.3 — 2026-11-04

1. [PR #371](https://github.com/StealthCat/MrPatchy/pull/371): Warn administrators through the durable operational outbox and retained in-app notification history during the final seven days of the reviewed AI public-price catalog window; deduplicate unchanged warnings, escalate and reopen delivery when the catalog expires, and resolve the lifecycle event after a verified refresh or applicable cap-mode disablement. Compatibility: no schema, target-agent, provider-call, deployment or response-authorization change; the alert applies only to enabled daily-cap modes and contains bounded catalog version/status/expiry metadata. Automated or signed catalog updates, provider-invoice reconciliation, live provider billing truth and complete multi-controller/reset acceptance remain outside this increment. This source update does not publish a Docker image.

## 1.40.2 — 2026-11-04

1. [PR #368](https://github.com/StealthCat/MrPatchy/pull/368): Drop every Linux capability from the production Compose `app`, `worker` and `caddy` services, then add back only `CHOWN`, `SETUID` and `SETGID` for the application entrypoints and `NET_BIND_SERVICE` and `DAC_READ_SEARCH` for Caddy; run the Compose acceptance proxy as the unprivileged `mrpatchy` user and pin the exact service sets with regression coverage. Compatibility: APIs, schemas, roles and runtime response authorization are unchanged, while custom Compose overrides that relied on Docker's default capability set must explicitly add their required capabilities. This is a partial #201 hardening increment only: read-only root filesystems, PID/memory limits, GCP override hardening, worker health checks and live alert inventory remain unfinished. This source update does not publish a Docker image.

## 1.40.1 — 2026-11-04

1. [PR #369](https://github.com/StealthCat/MrPatchy/pull/369): Add a CI dependency-vulnerability gate that runs `pip-audit` against the hash-locked Python runtime requirements and enforces reviewed exceptions with an advisory ID, owner, reason and expiry of at most 90 days; expired, malformed and unused exceptions fail closed. Compatibility: runtime APIs, schemas, roles, deployment and response authorization are unchanged, while pull-request validation now requires access to the PyPI advisory service. This is a partial #201 hardening increment only: npm tooling, base-image packages, live GitHub alert inventory, read-only filesystems, resource limits and worker health checks remain outside this gate. This source update does not publish a Docker image.

## 1.40.0 — 2026-11-04

1. [PR #367](https://github.com/StealthCat/MrPatchy/pull/367): Make multi-stage distribution-release configuration review resumable: each accepted AI review is durably sealed before the next provider call, controlled rate/spend/backoff/pause waits keep the plan queued and non-approvable, and an exact evidence/model/policy/vendor/news match reuses completed stages without paying to repeat them; changed evidence conservatively re-reviews the affected plan, and deferred release plans now appear in shared AI queue status. Compatibility: no schema, target-agent, role, approval, audit, deployment or response-authorization change; interrupted calls without an accepted structured result are not replayed automatically, and provider-invoice plus multi-controller failover/reset acceptance remain unfinished. This source update does not publish a Docker image.

## 1.39.3 — 2026-11-04

1. [PR #365](https://github.com/StealthCat/MrPatchy/pull/365): Align the release runner, RPM inventory and advisory ecosystem os-release parsers so they consistently ignore indented comments, trim keys and whitespace, and accept either single- or double-quoted values; this prevents valid single-quoted distribution metadata from losing its advisory ecosystem mapping. Compatibility: no API, schema, role, deployment, target action or response-authorization change; parser output changes only for previously inconsistent comments, whitespace and quote forms. This is a partial #190 consolidation only: shared hash loops, ancestor walkers and import cleanup remain unfinished. This source update does not publish a Docker image.

## 1.39.2 — 2026-11-04

1. [PR #358](https://github.com/StealthCat/MrPatchy/pull/358): Give the bundled AI public-price catalog exact reviewed-at and expiry metadata, expose its bounded freshness state in administrator settings, and make daily-cap and combined-cap admission fail closed at the expiry boundary before consuming smooth-rate capacity or contacting the provider. Compatibility: no schema, migration, target-agent, credential, provider-payload or response-authorization change; rate-only and unthrottled operation are unchanged, while capped installations require a reviewed catalog update before 2026-11-26 00:00 UTC or capped calls deliberately stop. Automated or signed catalog updates, lifecycle alerting, provider-invoice reconciliation, long-horizon reporting and broader failover acceptance remain unfinished. This source update does not publish a Docker image.

## 1.39.1 — 2026-11-04

1. [PR #356](https://github.com/StealthCat/MrPatchy/pull/356): Validate the target boot identity through one bounded lowercase-UUID parser and reuse it for recovery-status reads, rejecting missing, malformed, uppercase or oversized `/proc` values instead of propagating an untrusted identity. Compatibility: no API shape, schema, role, deployment, target action or response-authorization change; a malformed boot identity now fails closed. This is a partial #190 increment only: shared hash loops, ancestor walkers, OS-release parsing, RPM detection and import cleanup remain unfinished. This source update does not publish a Docker image.

## 1.39.0 — 2026-11-03

1. [PR #354](https://github.com/StealthCat/MrPatchy/pull/354): Add a first-class, deep-linkable notification center with bounded retained-history pagination; permission-filtered unread, dismissed, severity, source and server filters; current-revision lifecycle, time and escaped reason details; defensively revalidated same-origin subject links; and exact-revision per-user read/dismiss controls that remain separate from operational acknowledgement, resolution, approval and remediation. Compatibility: additive workspace UI and optional API query parameters only; no schema, provider, role, deployment, SMTP/webhook, target-agent or response-authorization change. Producers and retention, authenticated push/replay, cross-controller and multi-tab synchronization, live toasts, slow-client/backpressure/failover coverage and complete two-browser acceptance remain unfinished. This source update does not publish a Docker image.

## 1.38.3 — 2026-11-03

1. [PR #333](https://github.com/StealthCat/MrPatchy/pull/333): Add a read-only permission-filtered fleet spool-health API and Overview card with exhaustive enabled-server counts for pressure, stale and unavailable telemetry, cumulative loss totals, and a bounded ten-server urgent list; the route projects exactly the five required Host columns in one query without lazy-loading fleet blobs, and UI/API failures remain explicit rather than healthy. Compatibility: additive viewer API and UI only; no schema, target-agent, remote-call, deployment or operational/response-authorization change. This is a partial #108 increment: oldest-observation age, ingest/flush rates, retries, delivery latency, counter continuity, alert producers/deduplication/hysteresis and durable loss history remain unfinished. This source update does not publish a Docker image.

## 1.38.2 — 2026-11-03

1. [PR #332](https://github.com/StealthCat/MrPatchy/pull/332): Add a read-only Agent event spool card to each server's Overview summary, showing stored queue pressure and utilization, pending batches, queued/capacity bytes, telemetry freshness and cumulative loss with per-reason detail; stale, unavailable and request-failure states remain explicit and warning/critical pressure links to Agent health. Compatibility: no API, schema, role, target-contact, deployment or operational/response-authorization change; the card consumes the existing permission-scoped spool-health API and performs no remote work. This is a partial #108 UI increment only: fleet-wide projection, oldest-observation age, rates, retries, delivery latency, alert producers/deduplication, counter continuity and durable loss history remain unfinished. This source update does not publish a Docker image.

## 1.38.1 — 2026-11-03

1. [PR #289](https://github.com/StealthCat/MrPatchy/pull/289): Raise the development and CI pytest requirement from version 8 or newer to version 9.2.0 or newer while retaining the existing upper bound below 10. Compatibility: production dependencies and application behavior, APIs, roles, schemas and operational/response authorization are unchanged; local development and CI environments must use pytest 9.2.0–9.x and therefore inherit pytest 9 command, configuration and plugin compatibility requirements. This source update does not publish a Docker image.

## 1.38.0 — 2026-11-03

1. [PR #351](https://github.com/StealthCat/MrPatchy/pull/351): Add a persistent responsive notification bell and bounded eight-item recent panel to the authenticated shell, with permission-filtered unread severity, escaped payload text, defensively validated same-origin review links, exact-revision per-user read/dismiss controls, 30-second/visibility catch-up that preserves page and dialog state, session-reset race isolation and browser coverage across desktop, tablet and mobile layouts. Compatibility: no schema, API, role, deployment, provider, SMTP/webhook or operational/response-authorization change; read/dismiss does not acknowledge or remediate the underlying subject. Event producers and retention, authenticated push/replay and cross-controller/multi-tab delivery, live toasts, the dedicated filtered notification center, retained-history navigation and full two-browser/SQLite/MySQL/failover acceptance remain planned. This source update does not publish a Docker image.

## 1.37.13 — 2026-11-03

1. [PR #319](https://github.com/StealthCat/MrPatchy/pull/319): Require development triage to assign exactly one actual `P1`, `P2` or `P3` GitHub label to every bug and to correct missing or conflicting priority labels before concluding that no P1 bug exists or selecting feature work. Compatibility: contributor/coordinator policy only; application behavior, APIs, roles and operational/response authorization remain unchanged. This delivery does not bulk reclassify existing issues; missing labels or label permissions must be handled and reported separately. This source update does not publish a Docker image.

## 1.37.12 — 2026-11-03

1. [PR #348](https://github.com/StealthCat/MrPatchy/pull/348): Add bounded, versioned root-filesystem byte and inode capacity observations to agent telemetry, with collection time, source, scope, units, independent collected/unknown states, clamped values, redacted typed gaps and controller-persistence coverage. Compatibility: the `device_health` telemetry object is additive; existing telemetry keys, APIs, roles, schemas, mutation paths and operational/response authorization remain unchanged. This is the first partial #342 increment only; CPU/memory pressure, time sync, certificate expiry, history/hysteresis, alerts, UI and patch/reboot preflight remain unfinished. This source update does not publish a Docker image.

## 1.37.11 — 2026-11-03

1. [PR #288](https://github.com/StealthCat/MrPatchy/pull/288): Update the pinned CI static-analysis tool Ruff from 0.16.9 to 0.17.3. Compatibility: development/CI tooling only; production dependencies, application behavior, APIs, roles and operational/response authorization remain unchanged. This source update does not publish a Docker image.

## 1.37.10 — 2026-11-03

1. [PR #265](https://github.com/StealthCat/MrPatchy/pull/265): Render baseline review history as a readable list of actor, date and reason with Previous/Next paging, escaped text, stale-response protection and an explicit empty state. Format execution-triggered scan counts as readable state totals or “No triggers recorded” instead of raw JSON. Compatibility: UI-only fix; existing APIs, roles, audit history and operational/response authorization remain unchanged. Completes #178.

## 1.37.9 — 2026-11-03

1. [PR #291](https://github.com/StealthCat/MrPatchy/pull/291): Reuse worker patch validation in the patch route for repository freshness and held, broken or missing-candidate packages, resolving configuration once per request batch. Compatibility: API status codes, candidate-version review, recovery-policy review and execution-time validation remain unchanged; stale-repository errors now use the shared worker wording. No role, audit or response-authorization change. This delivers only the patch-validation portion of #188; the broader issue remains open.

## 1.37.8 — 2026-11-03

1. [PR #286](https://github.com/StealthCat/MrPatchy/pull/286): Refuse existing symlink destinations for target-agent status and telemetry writes, fsync the parent directory after atomic replacement, and obtain managed-file hashes and ownership/mode metadata from the same descriptor to prevent split hash/stat observations. Compatibility: managed metadata retains its uid/gid/mode shape; no role or response-authorization change. Deploy the updated target agent through the existing reviewed maintenance workflow to receive the target-side behavior. Shared-helper consolidation and other duplication under #190 remain unfinished, so #190 stays open.

## 1.37.7 — 2026-11-03

1. [PR #236](https://github.com/StealthCat/MrPatchy/pull/236): Wrap long unbroken server names, including FQDNs, inside page headings so phone-width screens do not scroll horizontally. Cover long headings at 320, 768 and 1440 pixels in the browser regression suite. Compatibility: layout-only fix; no API, role, audit or response-authorization change. Completes #176.

## 1.37.6 — 2026-11-03

1. [PR #264](https://github.com/StealthCat/MrPatchy/pull/264): Catch unhandled route errors passing through the request guard, log them server-side and return a generic JSON 500 with the standard security headers and applicable no-store policy; authenticated mutations also retain their request-audit status. Compatibility: these route errors now use a generic JSON body without internal exception details. Errors in the guard's own post-response audit write remain outside this catch; enrollment-link reuse and throttling are not implemented by this change, so #202 remains partial/open.

## 1.37.5 — 2026-11-03

1. [PR #331](https://github.com/StealthCat/MrPatchy/pull/331): Batch maintenance-window, recovery-policy, security-hold, active-job and existing-run lookups during patch-schedule ticks, reducing the open-window 40-host regression fixture from 844 to 57 SQL statements. Share newly queued work across schedules within each tick so two schedules cannot queue duplicate refresh or patch work for one host. Compatibility: no schema or scheduling-policy change; existing approval, lifecycle, maintenance-window, recovery and executor safeguards remain in force. Statement counts describe the regression fixture, not a fleet-wide latency guarantee. Completes #330.

## 1.37.4 — 2026-11-03

1. [PR #329](https://github.com/StealthCat/MrPatchy/pull/329): Pin the scheduler query-count test to noon UTC outside its seeded maintenance window, preventing daily 02:00–04:00 UTC failures while preserving its query limits. Compatibility: test-fixture change only; production scheduling behavior is unchanged. The separate in-window scheduler query cost remains open under #330. Completes #328.

## 1.37.3 — 2026-11-03

1. [PR #327](https://github.com/StealthCat/MrPatchy/pull/327): Reduce overview API memory and decoding work by projecting the three displayed host metadata fields in SQL, deferring inventory/telemetry/baseline blobs, and counting packages, updates and overdue updates in SQL instead of materializing every Package row. Preserve explicit JSON nulls separately from missing-key defaults, existing response shapes, role and deleted/disabled-host filtering, deadline comparisons and integrity counts. Compatibility: no schema, API contract, UI, configuration or runtime-response authorization change. Database work still scans eligible rows and the dashboard retains the Host fields needed for its counts; this is not a constant-time or fleet-latency guarantee. Continues and preserves #253's implementation history, corrects its nullable-metadata boundary, and completes #147.

## 1.37.2 — 2026-11-03

1. [PR #270](https://github.com/StealthCat/MrPatchy/pull/270): Store passwords in a versioned scrypt format with stronger bounded-cost parameters, continue verifying legacy hashes and upgrade them after a successful sign-in, cap concurrent KDF work, reject unsupported or malformed stored parameters before hashing, cache the Fernet key until its file changes, and derive the short-lived OIDC flow-cookie secret with purpose-bound HKDF instead of reusing Fernet signing material. Compatibility: existing credentials continue to work, but older releases cannot verify hashes upgraded by this release and in-flight OIDC sign-ins must be restarted once after upgrade. The default four concurrent current-cost hashes can consume roughly 512 MiB in aggregate; `secret.key` still shares the data volume with the database, so encryption does not protect against compromise of that volume. Completes #200.

## 1.37.1 — 2026-11-03

1. [PR #326](https://github.com/StealthCat/MrPatchy/pull/326): Add a read-only per-server agent spool-health API that derives freshness, lifecycle, queue pressure and cumulative loss by reason from already stored telemetry, rejects malformed or fractional counters without exposing payloads or unknown keys, and preserves viewer/deleted-server access boundaries. Compatibility: additive authenticated API only; no schema, target-agent, remote-call or runtime-response authorization change. The endpoint cannot report metrics the agent does not collect, including oldest-observation age, rates, retries and delivery latency; UI, alerts, additional agent metrics and durable loss history remain unfinished under partial #108.

## 1.37.0 — 2026-11-02

1. [PR #325](https://github.com/StealthCat/MrPatchy/pull/325): Add authenticated, current-role-filtered notification list and unread-count APIs plus CSRF-protected, revision-bound per-user read and dismiss mutations. Responses expose only retained safe summaries, hide higher-role events, audit state changes and remain independent of global alert acknowledgement, incident state, AI approval and response authorization; a second exact 60-second enrollment-window fixture is also made deterministic across SQLite/MySQL timestamp round trips without changing runtime admission behavior. Compatibility: additive authenticated APIs and test/CI stabilization only; existing schema, alert delivery/lifecycle and runtime behavior remain compatible. Notification producers, retention/pruning, live cross-controller delivery/replay, shell/center UI and full end-to-end acceptance remain future work. Completes #324.

## 1.36.1 — 2026-11-02

1. [PR #323](https://github.com/StealthCat/MrPatchy/pull/323): Make the enrollment-download capacity/expiry boundary regression deterministic across SQLite and MySQL timestamp round trips by freezing its clock at an exactly representable whole second. Preserve the exact 60-second Retry-After assertion and all active-quota, finite-source-capacity, eviction, expiry and recovery checks. Compatibility: test and CI behavior only; production admission code, quotas, persisted state, APIs, roles and runtime-response authorization are unchanged. Completes #322 and unblocks dependent PR validation without weakening the boundary.

## 1.36.0 — 2026-11-02

1. [PR #321](https://github.com/StealthCat/MrPatchy/pull/321): Add the durable backend foundation for in-app notifications with stable source/kind/subject/host identities, retained safe revisions, exact-observation deduplication, resolution/reopening history, current-role filtering and independent revision-aware read/dismiss state per enabled user. Register three additive tables and audit user state changes without acknowledging operational alerts, changing incidents, approving AI output or authorizing response. Compatibility: existing APIs, UI, alert delivery/lifecycle and runtime behavior are unchanged; this increment exposes no notification endpoint or UI. Transactional producer integration, concurrent publication recovery, retention/pruning, broader alert lifecycle integration, live transport/replay, notification-center UI and multi-controller SQLite/MySQL acceptance remain future work. Completes the bounded foundation in #320, not the wider notification roadmap.

## 1.35.105 — 2026-11-02

1. [PR #317](https://github.com/StealthCat/MrPatchy/pull/317): Expose only explicitly controlled, bounded diagnostics from repository health and AI connection/model-discovery failures. Give APT and RPM repository validators dedicated controlled exception types, retain actionable intentional validation messages, and replace arbitrary plain, subclass or library exception text with fixed public fallbacks; persist only the explicit AIError diagnostic. Compatibility: API shapes and successful behavior are unchanged, while unexpected failure details are intentionally less specific. No schema, role, provider request, package action or runtime-response authorization change. Completes #309's reported exception-text exposure; successful changed-code scanning does not establish complete repository-wide live-alert closure.

## 1.35.104 — 2026-11-02

1. [PR #315](https://github.com/StealthCat/MrPatchy/pull/315): Build the central APT patch-preview configuration path from the persisted server identity rather than request-path text, so case-insensitive Host and Package lookups use the repository configuration that refresh actually saved. Add regressions for missing configuration, the exact simulation command, unknown servers and differently cased request/stored identities. Compatibility: matching-case requests are unchanged; differently cased requests now use the canonical stored directory. No schema, API, role, package-selection, target command or runtime-response authorization change. Completes #310's reported path construction defect; successful changed-code scanning does not establish complete repository-wide live-alert closure.

## 1.35.103 — 2026-11-02

1. [PR #312](https://github.com/StealthCat/MrPatchy/pull/312): Set an explicit TLS 1.2 minimum on the SNI integration client and native RPM HTTPS fixture, retaining certificate verification, hostname handling and fixture behavior while removing reliance on constructor defaults. Compatibility: test and CI policy only; production TLS configuration, schema, APIs, roles and runtime-response authorization are unchanged. Completes #307's reported test-context remediation; successful changed-code scanning does not establish a complete repository-wide live-alert inventory or closure.

## 1.35.102 — 2026-11-02

1. [PR #314](https://github.com/StealthCat/MrPatchy/pull/314): Validate signing-key filename stems and response service-unit names without ambiguous regular expressions, retaining the existing accepted character/suffix languages and service-unit bounds. Bound key filenames to 255 characters at request validation. Compatibility: longer key names now return HTTP 422 before host work; valid names and service-health approval behavior remain unchanged. No schema, role, command or runtime-response authorization change. Completes #308's reported validator remediation; PR CodeQL results do not establish a complete repository-wide live-alert inventory or closure.

## 1.35.101 — 2026-11-02

1. [PR #316](https://github.com/StealthCat/MrPatchy/pull/316): Create central APT auth.conf and recovery MySQL option files with owner-only 0600 permissions from the initial exclusive, no-follow open, replacing the existing final directory entry instead of following a symlink. Validate remote MySQL CA configuration before writing credential content, and retain creation-mode/symlink/failure regressions without altering os.open test semantics. Compatibility: required plaintext formats, locations and final modes remain unchanged; destination symlinks are now replaced rather than written through. No encryption, schema, API, role or runtime-response authorization change is introduced. Completes #311; fresh PR CodeQL evidence does not establish complete repository-wide live-alert closure.

## 1.35.100 — 2026-11-02

1. [PR #313](https://github.com/StealthCat/MrPatchy/pull/313): Bound public enrollment-installer preparation with a shared persistent ten-attempt sliding sixty-second quota per ASGI client address, finite retained source state and nonblocking admission contention; audit first/retry preparations without bearer tokens and recheck link expiry/revocation under the canonical stored-host lifecycle fence. Compatibility: links remain reusable for one hour, but excess requests now return 429/Retry-After and admission-lock contention returns 503/Retry-After:1; shared-NAT clients share an address quota and trusted ASGI proxy configuration still applies. Installer content, schema, roles and runtime-response approvals are unchanged. Preparation is not proof of delivery/execution; this is partial #202, whose independent route-exception-header item remains open in #264.

## 1.35.99 — 2026-11-02

1. [PR #306](https://github.com/StealthCat/MrPatchy/pull/306): Hash-lock the complete 31-package Python 3.12 production dependency graph with 607 published-artifact SHA-256 hashes and enforce pip --require-hashes in controller image builds, preserving the delivered Python/Caddy image pins and unchanged direct runtime versions. Add lock/install regression coverage and document reviewed regeneration. Compatibility: transitive runtime versions are now explicit and dependency changes require regenerating/reviewing the lock; no schema, API, UI, role or runtime-response authorization change. This does not establish native ARM execution, independent signing, vulnerability-free dependencies or fully reproducible apt/GCP/source-build inputs. Partial #201 remains open for the remaining supply-chain and sandbox work.

## 1.35.98 — 2026-11-02

1. [PR #303](https://github.com/StealthCat/MrPatchy/pull/303): Pin the production Python 3.12 and Caddy 2.10 multi-platform image indexes by immutable digest while retaining readable tags, keep deployed Caddy and its adapter fixture aligned, and validate both default and GCP-override Compose configurations before startup. Document coordinated tag/digest refresh and remaining build-input limits. Compatibility: no runtime version-family, schema, API, role or response-authorization change; pinning fixes selected base/proxy bytes but does not establish native acceptance on every platform, independent signing, vulnerability-free images or a fully reproducible apt/pip/GCP build. Partial #201 remains open.

## 1.35.97 — 2026-11-02

1. [PR #275](https://github.com/StealthCat/MrPatchy/pull/275): Batch scheduled candidate-package reads and selected fleet alert hold/run/recovery lookups, and preload existing packages during repository refresh, with query-count regressions that also prevent deferred Host attributes from adding per-host SELECTs. Preserve alert, scheduling, lifecycle, hold and executor authorization semantics. Compatibility: no schema, API, configuration, role or runtime-response authorization change; scheduler readiness still loads required inventory, while telemetry/baseline remain deferred, and separate per-host assessments continue to query. Completes #181.

## 1.35.96 — 2026-11-02

1. [PR #240](https://github.com/StealthCat/MrPatchy/pull/240): Keep unreleased AI spend counted while its original admission window remains open, as well as within the current reset-timezone day, so changing the reset timezone cannot silently regrant that spend. Preserve bounded exact-money status aggregation, conservative unknown/transmitted charges and atomic admission. Compatibility: no schema, API, provider-routing, role or runtime-response authorization change; timezone switches may retain counted spend until its applicable window expires. Completes #162.

## 1.35.95 — 2026-11-02

1. [PR #302](https://github.com/StealthCat/MrPatchy/pull/302): Add a least-privilege, SHA-pinned CodeQL workflow that analyzes Python with the security-extended query suite on pull requests targeting `main`, pushes to `main` and a bounded weekly schedule, with regression coverage for its triggers, action pins, timeout and upload permissions. Compatibility: CI, tests and documentation only; no application schema, persisted data, API, UI, deployment behavior, role, audit, target action or runtime-response authorization change. Findings remain advisory repository evidence rather than runtime remediation; future scheduled/default-branch execution and absence of findings are not established by this delivery, and base-image digests, hash-pinned Python installs, dependency-vulnerability scanning policy and additional Compose/container sandboxing remain open under partial #201.

## 1.35.94 — 2026-11-02

1. [PR #301](https://github.com/StealthCat/MrPatchy/pull/301): Share one tracked request, strict structured-validation, evidence-bound persistence and durable AI-error deferral pipeline across scanner-incident and startup-change advisory plans, while preserving each domain's exact prompts, models, evidence and reference gates, secret timing, rechecks, transactions, audit/events and manual-only approval boundary. Compatibility: no schema, persisted-data, API, UI, configuration, provider-routing, role, target-action or runtime-response authorization change. This is partial #189; pricing consolidation in unmerged #283 and other duplicated logic remain open, and #103's closed-incident plan policy decision is unchanged.

## 1.35.93 — 2026-11-02

1. [PR #292](https://github.com/StealthCat/MrPatchy/pull/292): Pin every third-party action reference in the validation workflow to a full commit SHA with a readable major-version comment, add regression coverage that rejects unpinned workflow actions, and update the security checkpoint to distinguish these pins from unfinished supply-chain work. Compatibility: CI, tests and documentation only; no application schema, persisted data, API, UI, deployment behavior, role, audit, target action or runtime-response authorization change. Dependabot continues to propose GitHub Actions updates; base-image digests, hash-pinned Python installs, code scanning and additional Compose sandboxing remain open under partial #201.

## 1.35.92 — 2026-11-02

1. [PR #300](https://github.com/StealthCat/MrPatchy/pull/300): Share the controller-local failed response-observation transition across file and process handlers and worker backstops while preserving every caller's host, row, started/status and duplicate-event guards, actor and job attribution, uncertainty hold, receipt clearing, clock and event writer, and caller-owned transaction boundaries. Compatibility: no schema, persisted-data, API, UI, configuration, audit, role, actor-attribution, target-action or runtime-response authorization change. This is partial #189; shared advisory-plan generation, unmerged pricing consolidation and other undelivered rows remain open.

## 1.35.91 — 2026-11-02

1. [PR #299](https://github.com/StealthCat/MrPatchy/pull/299): Share one pending-response-work query across the general file-response guard and trusted-repair preparation, staging and publication paths, while preserving each caller's host/hold scope, check precedence, exact conflict message and audit-action inclusion or exclusion. Compatibility: no schema, persisted-data, API, UI, configuration, role, audit, lifecycle, target-action or runtime-response authorization change. This is partial #188; patch-validation consolidation and other duplicated route logic remain open.

## 1.35.90 — 2026-11-02

1. [PR #298](https://github.com/StealthCat/MrPatchy/pull/298): Replace the duplicate staging and publication readiness `Original` carrier classes with the standard-library `SimpleNamespace`, preserving the original quarantine identity, exact plan and manifest references, receipt validation, state gates and runtime-response authorization boundaries. Compatibility: no schema, persisted-data, API, UI, configuration, audit, actor-attribution, target-action or deployment change. This is partial #189; advisory-plan generation, failed-status handling, unmerged pricing consolidation and other undelivered rows remain open.

## 1.35.89 — 2026-11-02

1. [PR #297](https://github.com/StealthCat/MrPatchy/pull/297): Share one newest-record query helper across process observations, service-health observations and repair publications, while preserving each caller's host and publication-state filters, newest-created/ascending-ID tie-break, empty-input behavior and result mapping. Compatibility: no schema, API, UI, configuration, deployment, role, audit, target-action or runtime-response authorization change. This is partial #189; shared advisory-plan generation, failed-status handling, the duplicated `Original` stub and other undelivered rows remain open.

## 1.35.88 — 2026-11-02

1. [PR #296](https://github.com/StealthCat/MrPatchy/pull/296): Share the controller-local transition that rejects an unstarted response job across file quarantine and process-response paths, while preserving each path's actor attribution, host/state guards, hold clearing and transactional rollback behavior. Compatibility: no schema, API, UI, configuration, target-action or runtime-response authorization change; this is partial #189, whose remaining advisory-plan, response/status/query and duplicate-stub consolidation stays open.

## 1.35.87 — 2026-11-02

1. [PR #295](https://github.com/StealthCat/MrPatchy/pull/295): Bound daily AI spend accounting to at most five exact-money status totals regardless of distinct receipt amounts, retaining conservative unknown, sent and uncertain charges, released-row exclusion, durable ledger evidence and atomic cap admission. Compatibility: no schema, API, provider-call, UI, role or runtime-response authorization change; SQLite retains its existing nine-place NUMERIC read precision and MySQL uses native DECIMAL summation. Eligible ledger rows are still scanned in SQL, so database work remains O(N); later #240 integration must preserve both its timezone-membership predicate and this aggregation. Completes #133.

## 1.35.86 — 2026-11-01

1. [PR #294](https://github.com/StealthCat/MrPatchy/pull/294): Share one bounded, strong-digest gpgv verification boundary across Debian vendor-package and YARA-bundle authentication, preserving signer fingerprints and the existing SHA-224/256/384/512 acceptance set while normalizing command, timeout, output-limit and status failures to a redacted `ValueError` subtype. Compatibility: failed YARA gpgv commands now use the shared failure type instead of exposing a `RuntimeError`; no schema, API, target helper, UI, role, audit or runtime-response authorization change. This is partial #189; advisory-plan, response/status/query and duplicate-stub consolidation remain open.

## 1.35.85 — 2026-11-01

1. [PR #293](https://github.com/StealthCat/MrPatchy/pull/293): Complete native-browser regression coverage for delayed patch success and conflict responses after navigation or sign-out, retaining one-shot submission, same-session global feedback, destination/login state and obsolete-session suppression. Compatibility: test-only completion of the already-delivered #241/#238 lifecycle guards; no production source, API, schema, role, audit, target action, data-sharing or runtime-response authorization change. Completes #126.

## 1.35.84 — 2026-11-01

1. [PR #259](https://github.com/StealthCat/MrPatchy/pull/259): Batch descriptor-safe ClamAV scans into local engine processes of at most 32 files / 128 MiB, while preserving exact per-file result mapping, descriptor/path/metadata identity checks, signature provenance, scan budgets and cleanup on every exit. Ambiguous output or engine failure conservatively retries through the existing single-file path. Compatibility: no schema, role, target-action, daemon or runtime-response authorization change; batches may run for up to 120 seconds within the existing four-minute overall budget, and fallback invocations retain their 30-second per-file timeout.

## 1.35.83 — 2026-11-01

1. [PR #262](https://github.com/StealthCat/MrPatchy/pull/262): Initially open the patch calendar in hourly day view at widths of 700px or narrower and keep weekday headers visible while scrolling the month grid. Retain the wider-screen month default and manual view selection.
2. Compatibility: presentation-only defaults; no schedule execution, API, schema or authorization change. The initial choice is not reset on resize, and explicitly selected month/tablet grids can still scroll horizontally.

## 1.35.82 — 2026-11-01

1. [PR #238](https://github.com/StealthCat/MrPatchy/pull/238): Keep late manual-response-plan approval and patch-confirmation results from closing or annotating a newer dialog. Patch success/error feedback uses the shared same-session global notification contract and suppresses obsolete-session effects.
2. Compatibility: no API, schema, role or runtime-response authorization change; manual-plan approval still executes no target action. Fixes #156; #126 remains open for broader acceptance, including patch-specific navigation/sign-out browser variants not added here.

## 1.35.81 — 2026-11-01

1. [PR #255](https://github.com/StealthCat/MrPatchy/pull/255): Place Security scan forms inside cards, space the targeted Security and File integrity pager/evidence actions consistently, and move Browse startup files below the baseline heading.
2. Compatibility: markup-only presentation change; existing element identities and handlers are retained. No API, schema, role, audit or runtime-response authorization change.

## 1.35.80 — 2026-11-01

1. [PR #256](https://github.com/StealthCat/MrPatchy/pull/256): Reflow server Overview summary cards by available content width, keep the decorative mascot clear of guide text and actions, and render multi-line link buttons with complete borders on Overview and Patching pages.
2. Compatibility: CSS-only presentation change; no API, schema, role or runtime-response authorization change. The separately tracked long server-heading overflow (#176) is not changed by this delivery.

## 1.35.79 — 2026-11-01

1. [PR #233](https://github.com/StealthCat/MrPatchy/pull/233): Show readable HTTP-status errors for non-JSON or empty API error bodies instead of JSON parser failures. Preserve valid JSON values, including null, accept empty successful responses, and retain sign-in reset and stale-session response guards.
2. Compatibility: no backend API, schema, role or runtime-response authorization change. Unexpected non-JSON successful responses produce a readable error; existing structured API detail messages are retained.

## 1.35.78 — 2026-11-01

1. [PR #284](https://github.com/StealthCat/MrPatchy/pull/284): Configure weekly Dependabot update PRs for pip, npm, GitHub Actions and Docker, covering the root, deploy and test-fixture Dockerfile locations. Add tracked-manifest coverage regressions.
2. Compatibility: no runtime or API change. Configuration does not establish a successful live update-generation run, dependency vulnerability scanning, code scanning, digest/hash/Actions-SHA pinning or additional Compose sandboxing. Partial #201 remains open for those requirements.

## 1.35.77 — 2026-11-01

1. [PR #285](https://github.com/StealthCat/MrPatchy/pull/285): Stage rollout jobs through the shared worker queue helper, recording one `queue patch` audit entry per server job alongside the existing batch audit. Share the per-server 50-operation queue-capacity check with ordinary queueing.
2. Compatibility: retain single-transaction submission, canary dependencies, actor, reviewed recovery policy and host lifecycle revision. A full server queue still rejects the entire submission with HTTP 429; its error text now comes from the shared helper. No schema, role or runtime-response authorization change. Partial #188: patch-validation reuse and response-idle deduplication remain unfinished.

## 1.35.76 — 2026-11-01

1. [PR #263](https://github.com/StealthCat/MrPatchy/pull/263): Render the destination once after enrollment completion or server deletion, and reuse the loaded identity when displaying Activity controls. Show navigation success feedback only after its matching destination render succeeds, including unchanged-hash navigation.
2. Drop pending feedback on failed renders, logout or superseding navigation; add native UI regressions for request counts, delayed destinations, failed-render retry, session changes and fresh same-hash success.
3. Compatibility: no schema/API/role or runtime-response authorization change. Cached identity affects presentation only; backend authorization remains authoritative. Shared escaping, pager behavior and release-review polling are retained.

## 1.35.75 — 2026-11-01

1. [PR #282](https://github.com/StealthCat/MrPatchy/pull/282): Remove the unused frontend configuration cache and unreferenced confirmation-free deploy-action branch. Share the existing HTML escape routine through PatchyUI, and reuse common page slicing, labels, buttons and pager bindings for Overview and Servers.
2. Compatibility: no schema/API/configuration/role or runtime-response authorization change. Existing enrollment confirmation, refresh actions, filter/reset behavior, 12/24-item page sizes, scrolling and escaping for current consumers are retained. This is preventive maintenance of existing UI behavior; the release-review polling improvements remain intact.

## 1.35.74 — 2026-11-01

1. [PR #266](https://github.com/StealthCat/MrPatchy/pull/266): Update release-upgrade review status and progress in place during unchanged-state background polls, retaining open package/configuration details, scroll position and dialog messages. Reapply expanded-detail flags when a plan state transition rebuilds the review; add a browser regression covering polling and completion.
2. Synchronize the eBPF diagnostic test fixture with recorded collector recovery before emitting its late warning, and cover delayed event processing while retaining every original diagnostic assertion. Runtime collector behavior is unchanged.
3. Compatibility: no schema/API/role or runtime-response authorization change. Plan state transitions and explicit manual refresh can still rebuild the dialog; request/modal/session stale-response guards and the separately reviewed GO workflow remain intact.

## 1.35.73 — 2026-11-01

1. [PR #278](https://github.com/StealthCat/MrPatchy/pull/278): Share one pure, action-specific response-hold scope resolver between worker admission and execution, and derive the dispatch hold-cache key from that scope. Add table-driven coverage for response, process, read-only, staging, publication, local-observation and service exemptions.
2. Compatibility: no schema/API/configuration/role or runtime-response authorization change. Execution still checks current holds independently before claiming work; strict service-watch distinctions, separate hold IDs, per-host serialization, approvals and existing dispatch-cache boundaries are retained.

## 1.35.72 — 2026-11-01

1. [PR #280](https://github.com/StealthCat/MrPatchy/pull/280): Count sign-in attempts against the exact client address instead of a text prefix. Attempts from a different IPv6 address sharing that prefix no longer exhaust another address's sign-in window; same-address limits and audit-once behavior remain covered by regression tests. This coordinator integration preserves the implementation and history from PR #277.
2. Compatibility: no schema/API/configuration/role or runtime-response authorization change. Existing bucket format, per-account limits, expiry/eviction, IPv4 protection, password/MFA and session checks are retained. This does not complete the separate login-spray retention or aggregate password-hashing resource/concurrency work.

## 1.35.71 — 2026-11-01

1. [PR #273](https://github.com/StealthCat/MrPatchy/pull/273): Compute daily AI budget totals from SQL groups by status and exact amount instead of loading every ledger entry as an ORM object. Reuse those totals for status displays, exclude released reservations, and retain conservative cap accounting for unrecognized unreleased states.
2. Compatibility: no schema/API/configuration/role or runtime-response authorization change; durable ledger evidence, Decimal money, release/uncertain semantics, timezone windows and atomic admission are retained. This is partial progress on #133: distinct receipt amounts can still produce one group per row under the shared lock. Bounded aggregation or a reconciled summary and SQLite/MySQL concurrency/lock-duration evidence remain open.

## 1.35.70 — 2026-11-01

1. [PR #272](https://github.com/StealthCat/MrPatchy/pull/272): Add pinned Ruff Pyflakes-rule checks to CI for undefined names, redefinitions and unused imports across controller/target/scripts/tools, plus undefined-name checks for tests. Remove redundant imports and one unused local while retaining model-registration side effects and intentionally test-facing module imports.
2. Compatibility: no schema/API/role/runtime-response behavior change. The lint dependency is development-only; code rejected by the new static gate must be corrected before merge. This does not broaden runtime authorization or claim completion of unrelated SBOM work.

## 1.35.69 — 2026-11-01

1. [PR #271](https://github.com/StealthCat/MrPatchy/pull/271): Share the automatic package-priority rule between repository refresh and the manual reset-to-auto action. A security-origin package is high only when it has a newer candidate; no-candidate packages remain normal instead of temporarily becoming high.
2. Compatibility: no schema/API/configuration/role or runtime-approval change; explicit manual priorities remain unchanged. This delivers only the auto-priority drift fix from #188. Patch-validation reuse, rollout queue/audit consolidation and response-idle dedup remain open and are not claimed complete.

## 1.35.68 — 2026-11-01

1. [PR #269](https://github.com/StealthCat/MrPatchy/pull/269): Check newly busy servers before dispatch evaluation and reuse exact response-hold scopes and ordinary patch-window results within each worker iteration. Skip later ordinary patch work after a closed window while retaining scheduled and non-patch paths, reducing repeated per-job database queries.
2. Compatibility: no schema/API/configuration/role or runtime-response authority change. Cache state is local to one dispatch iteration; execution-time hold/window checks remain mandatory. This is not cross-worker shared authorization or an exactly-once guarantee. The separate shared-scope refactor in #134 remains open.

## 1.35.67 — 2026-11-01

1. [PR #267](https://github.com/StealthCat/MrPatchy/pull/267): Avoid ingesting the first event batch twice per poll by reusing its committed IDs for acknowledgement, reducing redundant policy and observation lookups. Remove the unused worker `ai_cycle` helper and update its tests; the strict newest-changelog-section check already present on main is retained.
2. Compatibility: no schema/API or runtime-response authorization change. Commit-before-acknowledgement, replay deduplication, later batches and finite drain budgets remain intact; a lost acknowledgement can still cause a safe replay. No cross-worker exactly-once or lossless-capture guarantee is added.

## 1.35.66 — 2026-11-01

1. [PR #257](https://github.com/StealthCat/MrPatchy/pull/257): Return HTTP 409 consistently for disabled/deleted-server and busy-state conflicts, and HTTP 429 for the existing 50-operation server-queue limit, using dedicated centrally handled exceptions.
2. Compatibility: API consumers that expected HTTP 400 for these conflicts or capacity refusals must handle 409/429. Ordinary invalid input remains 400; queue capacity, lifecycle checks, roles and runtime response approvals are unchanged. No schema change.

## 1.35.65 — 2026-11-01

1. [PR #260](https://github.com/StealthCat/MrPatchy/pull/260): A validated helper `not_started` process-response receipt restores the matching approval's prior state and process hold, resolving a stuck hold after a lost reply. Retain the receipt and `observed_not_started` audit event; a new suspension still requires fresh typed approval.
2. Compatibility: no schema, helper protocol or role change. Uncertain/suspended responses, invalid verification and missing or mismatched approvals retain conservative holds; prior holds and the independent file-response hold remain intact. Receipt validation does not establish trust in a compromised target.

## 1.35.64 — 2026-11-01

1. [PR #254](https://github.com/StealthCat/MrPatchy/pull/254): Load schedule recovery policies with one batched Setting lookup instead of one lookup per server. Preserve missing/partial flag defaults, the existing per-server recovery-policy helper, host lifecycle filtering and the schedules response contract.
2. Compatibility: no API/schema, role, audit or runtime-approval change. Fewer policy-query round trips do not make the complete schedules response constant-time; host/policy rows and payload still scale with fleet size.

## 1.35.63 — 2026-11-01

1. [PR #232](https://github.com/StealthCat/MrPatchy/pull/232): Close the staged-rollout review dialog before displaying its queued-server confirmation so the message is visible. Disable approval while the request is in flight and reenable the captured button on error to reduce duplicate submissions.
2. Compatibility: UI-only; backend rollout authorization, roles, audit and recovery rules are unchanged. This focused confirmation fix does not complete the separately tracked stale-dialog/session isolation work in #126/#156, which remains open.

## 1.35.62 — 2026-11-01

1. [PR #250](https://github.com/StealthCat/MrPatchy/pull/250): Bulk-load advisory update-scoring candidates and exact/deferred score state in ordered 200-package chunks instead of two per-package score queries. Retain oldest-first/id ordering, stale deferred supersession, due-work eligibility, the five-item provider batch and final exact-evidence checks.
2. Compatibility: no API/schema, model-quality, role or response-authorization change. Existing scoring ownership, lifecycle/AI pause, admission and spend gates remain required. Reduced local database round trips are not a guarantee of provider or end-to-end throughput.

## 1.35.61 — 2026-11-01

1. [PR #243](https://github.com/StealthCat/MrPatchy/pull/243): Page fleet Investigations in batches of 50 with Previous/Next controls so behaviors beyond the former first-500 limit remain reachable. Remember each fleet/server view's offset across refresh and navigation; clear it on session reset. Keep host scoping, role restrictions, advisory assessments and explicit approvals unchanged.
2. Compatibility: frontend-only paging uses the existing API offset/limit contract; no schema or API change. Page state belongs to the current signed-in session, and existing response authorization remains required.

## 1.35.60 — 2026-11-01

1. [PR #247](https://github.com/StealthCat/MrPatchy/pull/247): Verify missing/disabled account attempts against a dummy password hash, move password verification outside the global login lock, and evict oldest throttle buckets at the 10,000-bucket cap instead of rejecting every sign-in. Recheck current identity/password and consume MFA under the lock before creating a session; retain failure/audit responses and existing per-bucket/address limits.
2. Compatibility: no API schema change. This reduces account-existence timing differences and concurrent sign-in blocking; it does not add cross-process MFA guarantees or account-wide distributed throttling. Wider throttling and hash-format policy remain separate work.

## 1.35.59 — 2026-11-01

1. [PR #246](https://github.com/StealthCat/MrPatchy/pull/246): Fail lifecycle activity closed when its lock cannot be acquired; interactive SSH requests use nonblocking admission and report HTTP 409 when busy. Background operations retain blocking exclusion. Lifecycle admission/release errors preserve whether a remote command started, so pre-transport repair, repository and key failures release the host without losing uncertain-outcome safeguards after remote start.
2. Compatibility: internal SSH calls gain an optional admission flag; external API schemas and operational approvals are unchanged. Busy interactive requests must be retried after active work finishes; no operation is replayed automatically.

## 1.35.58 — 2026-11-01

1. [PR #230](https://github.com/StealthCat/MrPatchy/pull/230): Restrict investigation-status AI budget, spend, admission, provider-backoff, error and capacity telemetry to administrators. Non-admins receive only pending count, oldest pending time and enabled state; the fleet Investigations page retains its safe queue summary and shows triage diagnostics and hourly limits only to admins.
2. Compatibility: viewer/operator clients of `/api/investigation-status` must use the reduced response. Administrator telemetry and existing roles, approvals, response authorization and recent dialog guards remain unchanged.

## 1.35.57 — 2026-10-31

1. [PR #235](https://github.com/StealthCat/MrPatchy/pull/235): create a fresh urgent high/critical attempt when a previous run was skipped after its window expired without ever queuing a patch job. Reconsider it only after host telemetry, health and the approved maintenance-window/bypass rules allow.
2. Retain deterministic attempt identities and previous run history. Existing active, failed or patch-queued attempts stop the reissue chain, preserving no-replay behavior and one patch batch per eligible attempt. Preserve the dispatcher-first expiry reporting delivered in PR #231.
3. Compatibility: urgent work previously stranded after an unstarted expired window can become eligible again. Current repository revalidation, policy, host locks, recovery and response authorization remain required; no schema or target-helper change, major remains 1.

## 1.35.56 — 2026-10-31

1. [PR #231](https://github.com/StealthCat/MrPatchy/pull/231): record an otherwise-authorized scheduled patch whose start window expired as a skipped run even when the job dispatcher notices before the schedule tick. Retain the expiry reason so history and scheduled-patching alerts report the missed window.
2. Keep authorization revocation separate: disabled or revised schedules, missing runs and mismatched host scope retain cancellation behavior. Expired queued jobs are cancelled before execution; running work is not replayed.
3. Compatibility: expired runs previously shown as cancelled now show skipped and participate in existing missed-window alerting. No schema, roles, target-helper or response-authority change; major remains 1.

## 1.35.55 — 2026-10-31

1. [PR #241](https://github.com/StealthCat/MrPatchy/pull/241): bind repository source/key/access, investigation trust and schedule save/delete submissions to their originating dialog and session. Disable covered submissions while pending to prevent duplicate requests.
2. Preserve newer dialogs when earlier requests finish; report stale same-session results globally and suppress obsolete feedback after sign-out. Keep the existing queued-response cancellation browser coverage alongside the new dialog-race coverage.
3. Compatibility: UI lifecycle only; submitted operations are not cancelled by closing a dialog or signing out. No API, schema, role or response-authority change; major remains 1. Related #126 stays open pending the separately owned patch-confirm/manual-response work and complete combined acceptance.

## 1.35.54 — 2026-10-31

1. [PR #237](https://github.com/StealthCat/MrPatchy/pull/237): let administrators cancel genuinely unstarted file/process response and related queued security jobs despite retained response holds. Keep the host mutex and use an atomic queued-only transition with linked-record cleanup in one transaction.
2. Reuse reject-unstarted approval, publication, staging, preparation and evidence semantics; mark only the cancelled execution-scan job's queued triggers skipped. Preserve prior/unrelated/uncertain holds, audit history, running/recovery job refusal and existing lifecycle/release-plan cancellation.
3. Compatibility: cancellation remains controller-local bookkeeping, reflected in Activity, and does not undo target work or release an uncertain response. No schema, target-helper or runtime response-authority change; major remains 1.

## 1.35.53 — 2026-10-31

1. [PR #239](https://github.com/StealthCat/MrPatchy/pull/239): explain retained file-response, process-response, replacement-publication and service-monitoring review holds in package installation forecasts. Queued and scheduled work show a waiting state without a concrete start estimate while a hold remains.
2. Reuse the authoritative local hold predicate in one request-local snapshot, reevaluate on the next request after separately authorized release, and preserve already-running installation status and host isolation.
3. Compatibility: existing forecast fields and rendering are retained; held work now reports an unknown start instead of a misleading timestamp. Forecasts remain advisory and do not contact targets, release holds or change execution/response authorization. No schema change; major remains 1.

## 1.35.52 — 2026-10-31

1. [PR #228](https://github.com/StealthCat/MrPatchy/pull/228): render IPv6 server endpoints as [address]:port through one shared presentation helper in the server directory, enrollment verification, management dialog, workspace heading and system facts.
2. Preserve hostname/IPv4 formatting and existing HTML escaping. Connection settings, request payloads, roles, audit and response authorization are unchanged; this is a display correction.
3. Add a browser regression asserting a long IPv6 address with port 2222 renders with brackets in the server directory. Major remains 1.

## 1.35.51 — 2026-10-31

1. [PR #225](https://github.com/StealthCat/MrPatchy/pull/225): reject explicit public-URL port 0, empty ports and out-of-range ports with a clear error before creating .env. Use HTTPS port 443 only when no port is supplied, avoiding silent fallback or a Python traceback.
2. Warn on stderr when an existing .env is retained and a supplied --public-url is ignored. Existing configuration remains unchanged; no cloud resource or credential behavior changes.
3. Cover default 443, invalid/empty IPv4-hostname and bracketed-IPv6 port cases, and ignored-URL warnings. Valid installation inputs and trust checks retain their behavior; major remains 1.

## 1.35.50 — 2026-10-31

1. [PR #223](https://github.com/StealthCat/MrPatchy/pull/223): make legacy bridge verify a thin alias of agent-status. Missing managed files return status entries instead of failing the entire request, and the existing descriptor-based probes avoid following unchecked links or splitting stat/hash identity.
2. Update the native SSH integration caller to use canonical agent-status and retain alias dispatch regression coverage. Command allowlists and trust boundaries are unchanged.
3. Compatibility: verify now returns the agent-status response shape and service probes; file entries may report missing:true or unsafe:true. No controller runtime caller used legacy verify. Deploy the updated bridge through the reviewed maintenance workflow; major remains 1.

## 1.35.49 — 2026-10-31

1. [PR #220](https://github.com/StealthCat/MrPatchy/pull/220): return verified cached artifact hashes after the shared collection deadline instead of marking later processes unverified solely because their hashes are already cached.
2. Apply the initial time-budget guard inside the cache-miss branch before any data read, including empty files; retain per-chunk budgets and device/inode/mtime/ctime/size identity checks. Cover expired cached hits and empty/nonempty uncached misses with zero-read assertions.
3. Deploy the updated target agent through the existing reviewed helper-maintenance workflow. No receipt-format, role, schema or response-authority change; major remains 1.

## 1.35.48 — 2026-10-31

1. [PR #210](https://github.com/StealthCat/MrPatchy/pull/210): exclude soft-deleted server records from the Prometheus mrpatchy_hosts gauge by filtering deleted_at==0 in SQL.
2. Preserve disabled-server counting, retained administrator history, other metrics and viewer access to the metrics endpoint. A regression verifies the count drops from two to one after soft deletion.
3. Compatibility: consumers may see a lower host count reflecting deleted records; no database records are removed. No schema, audit or response-authority change; major remains 1.

## 1.35.47 — 2026-10-31

1. [PR #216](https://github.com/StealthCat/MrPatchy/pull/216): record old-to-new role and enabled state plus password-set yes/no in manage-user audit entries. Newly created users are identified as new; passwords and hashes are never included in the detail.
2. Add an authenticated API regression covering account creation, role escalation, disabling and password-presence markers while asserting the supplied password is absent from audit history.
3. Preserve administrator/self-access checks, session-generation invalidation and audit retention. No schema or response-authority change; major remains 1.

## 1.35.46 — 2026-10-31

1. [PR #218](https://github.com/StealthCat/MrPatchy/pull/218): prevent older ineligible incidents from permanently hiding eligible automatic ClamAV advisory plans. Filter quarantined hosts before selecting candidates and page past YARA incidents instead of using a fixed oldest-100 window.
2. Preserve YARA's automatic-plan exclusion, per-host pending checks, host lifecycle/pause gates and existing remaining-capacity limits. Advisory planning does not authorize runtime response actions.
3. Add the 100-older-YARA-plus-newer-ClamAV regression. No schema, target-helper or permission change; major remains 1.

## 1.35.45 — 2026-10-31

1. [PR #213](https://github.com/StealthCat/MrPatchy/pull/213): parse standard DNF4 versionlock exclude records without failing RPM inventory and patch evidence. Strip one optional exclusion marker, then an optional epoch prefix, before extracting the package name; treat excludes conservatively as held packages.
2. Cover DNF4 add/exclude and yum epoch-first add/exclude layouts. Keep unsupported expressions rejected, including repeated exclusion markers; coordinator review tightened the candidate's unrestricted leading-marker stripping.
3. Preserve package-manager trust and response authorization. No schema or controller API change; update target helpers through the existing reviewed deployment workflow. Major remains 1.

## 1.35.44 — 2026-10-31

1. [PR #211](https://github.com/StealthCat/MrPatchy/pull/211): merge only client-supplied fields in legacy PUT /api/settings under the shared settings-config lock. Preserve omitted retention, AI model/enabled state, admission mode, limits and legacy migration requirements.
2. Capture supplied fields before request normalization so trimming an omitted model cannot turn its default into an explicit reset. Audit changed fields and admission/cap/reset-timezone transitions; align the legacy input's admission default with section settings.
3. Compatibility: partial legacy API saves now retain stored settings instead of silently applying defaults; explicit settings remain validated. No role, history-retention policy or runtime response-authority change; major remains 1.

## 1.35.43 — 2026-10-31

1. [PR #224](https://github.com/StealthCat/MrPatchy/pull/224): retain recovery holds after unknown repair, repository-configuration and signing-key mutation outcomes, matching ordinary-patch safeguards. Lost/unverified replies or a failed post-mutation inventory block later host changes without automatic replay.
2. Retain available completion receipts in existing bounded operation output, audit the action and operation ID, and explain the package/configuration/trust state an administrator must inspect before the existing explicit reconciliation workflow releases the queue.
3. Compatibility: uncertain non-patch mutations now pause later changes for target review. Known-unstarted, structured target failures, successful outcomes and journaled patch/release recovery retain their existing behavior. A structured failure is not proof that no partial changes occurred; inventory is a bounded observation. No schema, target-helper or response-authority change; major remains 1.

## 1.35.42 — 2026-10-31

1. [PR #226](https://github.com/StealthCat/MrPatchy/pull/226): deliver the original commits from [PR #206](https://github.com/StealthCat/MrPatchy/pull/206) through an upstream integration branch. Declare viewer/operator/admin/self-service roles on each route and reject undeclared, conflicting or incorrectly public routes during startup.
2. Preserve session generation, CSRF, audit and host lifecycle/deleted-server read safeguards. Give refresh its own operator route while keeping other host actions administrator-only; concrete identifiers can no longer gain permissions by matching a path suffix.
3. Pin the complete route-to-role inventory and exercise anonymous, viewer and operator access across routes. Existing intended permissions are retained; the separately tracked investigation-status telemetry permission issue #157 remains open. Major remains 1.
4. Unblock exact-head validation after a confirmed 30-minute Ubuntu Azure-mirror prerequisite stall (#227). Share the primary-archive setup across apt-consuming runner jobs, bound network waits/retries and limit prerequisite installation steps to five minutes while retaining signature checks and unrelated package sources. Application checks remain required.

## 1.35.41 — 2026-10-31

1. [PR #214](https://github.com/StealthCat/MrPatchy/pull/214): isolate each periodic leader producer so a failed schedule, scanner, monitoring or AI-plan tick cannot stop other producers, polling, queued-job dispatch, cleanup or notifications.
2. Log named failures and retry independently at 30/60/120/240 seconds, capped at 300 seconds; successful producers retain a 30-second cadence. Module-loading failures share the same isolation, while worker identity loss still stops admission.
3. Preserve election, drain, leases, host locks, audit and response authorization. Retry deadlines are process-local; no schema, target-helper or UI changes. Major remains 1.

## 1.35.40 — 2026-10-31

1. [PR #209](https://github.com/StealthCat/MrPatchy/pull/209): report flushed offline migration progress, stage/role/table context, sanitized error categories and safe driver/OS codes with actionable next checks. Add bounded, redacted cause-chain and stack-location details with `--verbose`.
2. Preserve JSON-only stdout and report progress and completion on stderr. Identify destination write/commit state honestly, including a failed fresh connection after commit; preserve offline locking, read-only source checks, verification and explicit activation.
3. Compatibility: scripts reading the former trailing completion notice from stdout must read stderr. The reported Apollo deployment cause remains unverified; diagnostics now identify the failing phase. Major remains 1.

## 1.35.39 — 2026-10-31

1. [PR #221](https://github.com/StealthCat/MrPatchy/pull/221): allow two independent implementation streams with isolated issue ownership and explicit ready handoffs to a single integration/version/merge coordinator.
2. Reserve all README.md and CHANGELOG.md notes and updates for the coordinator. Workers leave those files and APP_VERSION unchanged, proposing documentation and change notes in PR descriptions. Remove the current-version field and synchronization requirement from README; runtime metadata still derives from APP_VERSION.
3. Separate development validation from strict integration readiness. Unversioned worker checks reject README/changelog changes; the new integration-version CI job requires a newer major-1 version and the exact PR's changelog link, preserving historical entries. Cover worker handoffs, malformed/decreasing versions, PR binding and history preservation with real Git-history tests.
4. Reconcile repository guidance and all four development-task prompts, retaining their roadmap requirements, schedules and enabled states. Add the copyable coordinator prompt and legacy-PR transition procedure. Compatibility: worker commits/PR titles no longer require version prefixes, and unversioned PRs intentionally await coordinator preparation at the new integration-version check. Existing versioned PRs are retained for handoff. No runtime authorization changes, Docker publication or Git tags.

## 1.35.37 — 2026-10-31

- Parse successful rollback-adapter JSON exclusively from stdout, keeping stderr warnings separate so snapshot and rollback side effects are not misreported as failures (issue #150).
- Reject adapter stdout larger than 20 KB before JSON parsing. Invalid or non-object responses still fail closed; the adapter trust, operation and identifier checks are unchanged. No compatibility impact for conforming adapters; major version stays 1.

## 1.35.35 — Log and audit rejected SSO callbacks

- Fix #170: the SSO callback no longer discards every validation failure silently. The server logs the exception class and a fixed-vocabulary sanitized reason (discovery/endpoint, issuer or subject mismatch, unbound subject, missing ID token, token exchange) and writes an `SSO login failed` audit entry with issuer, truncated hashed subject and reason.
- Audit entries are rate-limited to one per reason/subject per five minutes (bounded table) so unauthenticated callers cannot flood the audit log. The user-facing 400 message is unchanged, so there is no enumeration signal; raw provider error text and subjects are never recorded.
- Add regressions for misconfigured discovery, unassigned subject and rate limiting. No schema changes; major remains 1.

## 1.35.30 — 2026-10-31

- Hold the server with `recovery_required` when an ordinary patch (reboot and rollback off) may have changed packages without a trustworthy outcome: a lost, truncated or invalid completion reply, a bridge exit without its own failure receipt, or a failed post-patch inventory read (#119). Later queued work waits for **Review interrupted operation**, and the patch is never replayed.
- Keep `failed` without a hold for known-unstarted failures (pre-send validation, inactive server, SSH unreachable before the remote command starts) and for failures the target bridge reports in its own JSON receipt. `ssh.call` now records whether the remote command started, and structured bridge errors raise `ssh.RemoteFailure` (still a `RuntimeError`).
- Preserve the target's patch receipt in the operation output whenever a later step fails, and audit uncertain outcomes as `uncertain patch` with the operation ID.
- Compatibility: an ordinary patch that loses its SSH reply now pauses the server until an administrator reviews it, instead of releasing the queue. Major version stays 1.

## 1.35.29 — Enforce deleted-server read boundaries

- Resolve host authorization for query-scoped investigations, jobs and package history and job-ID output reads. Viewers/operators receive the existing administrator-only refusal for deleted-server records.
- Filter deleted-server jobs and package events in SQL before pagination; keep administrator retention access and disabled-server read policy unchanged.
- Add API regressions for both non-admin roles, indirect/query/global reads, pagination, missing/mismatched scope, administrator retention, disabled servers and hostless jobs. No schema or target-helper changes; major remains 1.

## 1.35.27 — 2026-10-31

1. Fix complete recovery omitting controller evidence archives, vendor packages/trusted keys, YARA rules/trusted keys and local GCP credential state (#120). Format-2 manifests record exact file coverage and hashes; backup, restore and activation validate this state. Verified archive records require their content and receipt files.
2. Restore durable directories/files with private permissions and service ownership; reject links and special files. Continue accepting format-1 bundles with an explicit missing-coverage warning. Report absent directories and external infrastructure/credential dependencies honestly.
3. Add SQLite evidence verification, signed vendor/YARA authentication, tamper/link/legacy regressions and native encrypted SQLite/MySQL recovery drills. Install native restic/MySQL clients in MySQL CI.
4. Compatibility: older script versions cannot read format-2 bundles; update the recovery script before restoring. Unsafe linked/special filesystem state or missing verified evidence now blocks publication/activation. Major stays 1. No Docker image publication or Git tag.

## 1.35.25 — 2026-10-31

- Style `.inline-check` like `label.check` so the response-monitoring, response-watch and service-watch checkboxes render inline with their labels (issue #175). A regression test requires every `check`/`inline-check` label in the UI to have a matching stylesheet rule. No compatibility impact; major version stays 1.

## 1.35.24 — 2026-10-31

- Stop pushes to `main` cancelling each other's CI runs. The shared concurrency group had cancelled the main runs for v1.35.16–v1.35.20 before they finished. Only superseded pull request runs are cancelled now, and pull requests are grouped by number so a fork branch named `main` cannot collide with `main`.
- Fix the shell syntax check: `bash -n a b c` checks only its first operand, so six of the seven scripts had never been checked. Every tracked `*.sh`, JavaScript and browser-test file is now checked, and `scripts/`, `tools/` and `tests/` are byte-compiled.
- Pin all CI runners to `ubuntu-24.04` ahead of the `ubuntu-latest` move to Ubuntu 26 (#197).
- Shorten the critical path. The ~21-minute MySQL suite is split by test file across four isolated jobs (`MRPATCHY_TEST_SHARD`), and fast static checks run in their own job instead of after the full SQLite suite.
- Remove duplicated work. The recovery job, which re-ran one test file to get restic coverage, is folded into `tests`. Target-independent native RPM unit tests run once instead of in every RPM leg. Pip and npm downloads are cached.
- Compatibility: the CI check names change (`static` is added, `mysql (1)`–`mysql (4)` replace `mysql`, `recovery` is removed). Update any branch-protection required checks. No application behaviour changes. Major version stays 1.

## 1.35.21 — 2026-10-31

- Fix full recovery backups of a valid zero-server deployment, which failed with `FileNotFoundError` because `ssh/` is created only when the first server is added. The bundle now carries an explicit empty owner-only SSH directory that activation restores.
- Distinguish that optional absence from damaged key state: backup and activation require a non-empty, non-linked private key for every server that is not deleted, checked against the database snapshot. They fail before restic runs or any destination changes. The manifest lists the required server identifiers. Bundles from earlier versions remain accepted.
- Compatibility: a deployment that has a non-deleted server without its private key, which previously backed up silently, now fails until the key is restored or the server is deleted. Major version stays 1.

## 1.35.20 — 2026-10-31

- Emit native eBPF execution UIDs as canonical non-negative integers and validate the collector record before durable spooling.
- Normalize legacy decimal-string UIDs at controller intake so stored verified observations still create scoped execution-scan triggers.
- Count malformed verified eBPF observations as explicit coverage loss, with a producer-shaped spool-to-queue regression for issue #117.

## 1.35.19 — 2026-10-31

- Skip identical Debian version comparisons during refresh and inventory reconciliation; reuse up to 512 native comparison results per inventory.
- Bound each remaining dpkg comparison to ten seconds and fail closed on native errors, preserving Debian epochs, revisions and tilde ordering.
- Cover native version edge cases, inventory process counts, candidate/hold/architecture semantics and comparison cache limits.

## 1.35.18 — 2026-10-31

- Preserve significant integral zeros in every AI budget amount, so a configured $10 cap and remaining budget display as $10.
- Validate and normalize omitted daily-cap defaults consistently in both settings APIs, with Decimal, API and visible settings regressions.

## 1.35.17 — 2026-10-31

- Fix populated SBOM exports by retaining the resolved host for Debian/RPM package URL selection (#121).
- Cover populated, empty and missing-host exports, package identity/version/architecture, host isolation and existing role/lifecycle access boundaries.

## 1.35.16 — 2026-10-31

- Integrate PR #116 enrollment temporary-file hardening, PR #137 failed-login auditing and PR #115 CI runtime maintenance against current main, preserving the v1.35.11 eBPF diagnostic lifecycle fix and all original commit histories.

## 1.35.14 — 2026-10-31

- Move every CI job from the deprecated Node.js 20 action runtime to Node 24 by upgrading `actions/checkout` (v4 to v7), `actions/setup-python` (v5 to v7) and `actions/setup-node` (v4 to v7), removing the `Node.js 20 is deprecated` warnings (#98).
- Run the Playwright browser checks on Node.js 26, the current LTS line, instead of Node.js 22. Used inputs are unchanged, and no `registry-url`, `always-auth` or `packageManager` setting is affected by the new action majors' breaking changes.
- Workflow-only update: application behaviour, schema and target helpers are unchanged.

## 1.35.13 — 2026-10-31

- Harden the generated enrollment command: the installer is downloaded to an unpredictable owner-only `mktemp` file and removed afterwards, instead of a fixed `/tmp/mrpatchy-enroll.sh` path that root then executes. Compatibility: operators copying a previously issued command keep working; new commands use the temporary file. No schema, helper, token-lifetime or authorization change.

## 1.35.11 — 2026-10-31

- Give eBPF collector diagnostics an explicit current/historical lifecycle: each bpftrace run is tagged with a run identifier and the collector status records its last state-transition time.
- Retire (keep as history, with reason and time) a warning when the collector recovers on its first delivered event, is intentionally disabled or restarts, so a superseded warning no longer keeps a host in attention indefinitely.
- Raise the `eBPF diagnostics` finding only for a warning from the current run that is not superseded by its recovery; warnings after recovery, malformed diagnostics and older untagged collectors still fail closed. Retained diagnostics remain visible in host telemetry.

## 1.35.7 — 2026-10-31

- Audit failed sign-ins: each rejected password login now records `login failed` with the submitted username, source address and a coarse reason (unknown or disabled account, bad password, bad MFA code). Submitted passwords and one-time codes are never recorded.
- Audit sign-in lockouts: a rate-limit rejection records one `login throttled` entry per limit and five-minute window (account, address or global), so rejected requests cannot flood the audit history.
- Compatibility: HTTP status codes and response bodies are unchanged, so account existence is still not revealed to the client. No schema, role, session or throttling-threshold change.

## 1.35.6 — 2026-10-31

- Detect orphaned running incident/startup advisory-plan jobs under the elected scheduler and each server's distributed worker lock, while leaving live workers untouched.
- Surface interrupted paid work as an explicit recovery hold without automatically replaying a provider request, preserving AI run, call-usage and spend-reservation records for review.
- Require an administrator to review retained AI/spend records before releasing the server queue, without performing an unrelated target SSH status query.
- Isolate advisory recovery failures from other scheduler work and verify crash recovery before and after provider transmission without duplicating a paid call.

## 1.35.4 — 2026-10-31

- Enable concurrent agent development coordinated through issue claims, linked draft PRs, explicit ownership/checkpoints, review and handoff records.
- Require overlap checks, isolated branches and serialized version/integration checks while preserving existing operational authorization boundaries.

## 1.35.3 — 2026-10-31

- Project a sanitized `ai_deferred` Boolean from operation APIs so Activity list/detail views show timed eligibility and administrator-resume waits without exposing internal job payloads.
- Prefer eligible advisory work over another plan's future backoff in AI worker status, with an explicit eligible-plan count alongside deferred/next-time data.
- Reclassify active incident/startup plan runs blocked by an untimed administrator pause as deferred instead of recording a false terminal error.

## 1.35.2 — 2026-10-31

- Split large normal process-observation snapshots into durable 256 KiB batches instead of dropping the entire snapshot at the former 2 MB ceiling.
- Preserve individually oversized-record and 48 MB capacity loss as explicit, reasoned cumulative batch/observation counters with queued-byte and limit telemetry.
- Raise an active event-spool integrity finding only when the cumulative counter increases, retaining historical evidence without leaving recovered agents permanently in attention state.

## 1.35.1 — 2026-10-31

- Accept Linux's valid zero process start tick when binding collector, controller, follow-up and reference identities, fixing fleet-wide PID 1 `Process identity unverified` findings without weakening the remaining identity fields.
- Replace raw exception-class-only collector output with bounded, evidence-safe identity diagnostic codes and retain fail-closed rejection of negative or malformed identities.
- Track distribution/major-version upgrade availability cards and server-reference badges as planned read-only work; detection and UI delivery are not implemented in this patch.

## 1.35.0 — 2026-10-31

- Retain incident-response and startup-change advisory AI plan jobs across shared rate, daily-spend, provider-backoff and administrator-pause refusals instead of marking them terminally failed.
- Persist exact timed eligibility or an explicit resume wait, refuse early execution, and recheck lifecycle, pause, evidence and every shared control before a later scheduler attempt.
- Preserve sent-call receipts and spend outcomes without immediate HTTP replay; pre-send refusals create no provider call, rate start or budget charge.
- Expose deferred plan count and next eligibility in AI worker status and Activity, with regression coverage for zero-transport refusal, pause, resume, pooled-schema upgrade and successful completion; multi-stage release planning remains deliberately excluded until per-stage persistence exists.

## 1.34.0 — 2026-10-31

- Retain update-scoring work refused by shared rate, spend or provider-backoff controls as a durable deferral with its exact next eligibility instead of a generic one-hour error delay.
- Resume eligible scoring through the full current pause, lifecycle, admission, budget and provider checks without charging a pre-send refusal or automatically replaying a transmitted request.
- Supersede deferred identities when package evidence changes, exclude removed or changed packages from queue status, and expose the retained state and next time in Packages and AI worker status.
- Add regression coverage for pre-send rate refusal, transmitted Retry-After failure, exact resume and stale-evidence invalidation; durable jobs for manual plan and connection-test paths remain planned.

## 1.33.0 — 2026-10-31

- Add one durable fleet-wide provider backoff boundary before rate and budget admission for every current billable AI request path.
- Honor valid provider Retry-After floors and use bounded exponential full-jitter delays for transient responses, timeouts and connection failures without automatically replaying a potentially billable request.
- Preserve process-investigation queue eligibility and attempt counts while shared backoff is active, prevent manual retry bypass, and expose sanitized failure count/next eligibility in Settings and AI worker status.
- Clear stale escalation after a successful or non-transient provider response without allowing an older parallel success to erase a newer failure; already in-flight calls and complete durable queuing for every manual/plan path remain documented limitations.

## 1.32.0 — 2026-10-31

- Add daily-cap and rate-plus-cap AI modes with an administrator-set USD/day amount and explicit IANA reset timezone.
- Atomically reserve a conservative per-call ceiling across workers before provider transmission; unknown model, tier, tool, output or long-context pricing fails closed instead of becoming zero cost.
- Reconcile valid usage to retained public-price estimates, release unsent failures and keep full uncertain reservations after transmitted timeouts, missing receipts or restarts.
- Retain the budget ledger independently of diagnostic-history pruning, canonicalize its fixed-precision amounts during offline database verification, and show settled, reserved, uncertain, remaining and next-reset values in Settings and AI worker status; provider invoice reconciliation and complete durable deferral remain planned.

## 1.31.0 — 2026-10-31

- Add one durable fleet-wide admission boundary to every current billable AI path, with smooth no-burst logical-work pacing and an explained next-start time.
- Preserve legacy investigation/scoring/incident-plan allowances until an administrator explicitly saves an audited conservative migration; fresh installs default to shared rate mode.
- Add a bounded unthrottled mode that removes only Mr Patchy's pacing while retaining provider, pause, role, lifecycle, data-sharing and finite-concurrency controls.
- Serialize SQLite/MySQL admission before provider transport or call receipts, preserve admitted multi-stage follow-ups, and defer triage without consuming an attempt; daily USD reservations and complete durable deferral remain planned.

## 1.30.0 — 2026-10-31

- Automatically invalidate an active fleet safe candidate when a retained final non-low provider assessment contradicts the identical verified context, model and policy.
- Ignore partial follow-up requests, failures and contextual/model/policy misses; invalidation changes reuse eligibility only and never authorizes a response.
- Retain and audit the contradictory assessment identity while preserving every earlier result and marking all linked source/reuse assessments for review.
- Add an escaped deep link from responsive Assessment history to the contradictory advisory result; native complete evidence and shared rate/spend controls remain planned.

## 1.29.0 — 2026-10-31

- Add administrator-confirmed, reasoned fleet invalidation for exact known-good entries, serialized with AI-state mutations and protected by existing role and CSRF controls.
- Block future reuse immediately while retaining original source and reuse assessments, observations and provenance without rewriting historical results.
- Mark every linked Assessment detail for review with escaped actor/time/reason context and retain explicit Re-triage as the current-policy refresh path.
- Validate stale versions, duplicate revocation, active investigation locks, role isolation, responsive confirmation and untrusted-text rendering; native complete evidence and automatic contradiction invalidation remain planned.

## 1.28.0 — 2026-10-31

- Revalidate active fleet safe candidates against exact complete context, model, policy, original retained AI assessment and isolated observation before reuse.
- Complete exact cross-server matches with zero provider calls while retaining a new cache-sourced per-host assessment, observation and redacted audit record.
- Make administrator Re-triage bypass reuse and follow the normal provider path; changed, incomplete, revoked, orphaned or mismatched candidates remain misses.
- Explain reused provenance in responsive Assessment history without implying approval, response authorization, clean-host status or deterministic-protection suppression.
- Keep current incomplete runtime evidence ineligible; fleet revocation, contradiction review, native complete-context collection and shared pacing/spend controls remain planned.

## 1.27.0 — 2026-10-31

- Publish only fully validated low-risk exact-match candidates into a durable fingerprint-keyed registry.
- Atomically deduplicate concurrent identical candidates while retaining every assessment/server observation in an isolated linked row.
- Preserve model, policy, canonical-contract and AI-classification provenance independently of diagnostic pruning; conflicting stored identity fails closed and inactive entries are not reactivated.
- Show durable publication status in Assessment detail without adding lookup, provider-call bypass, approval, response authorization or detector suppression; current incomplete runtime evidence remains ineligible.
- Register and preserve the two new tables across current-schema offline database migration; start the current controller first to initialize them.

## 1.26.0 — 2026-10-31

- Canonically bind complete authenticated v2 follow-up receipts into versioned requirements and evidence digests.
- Include requested checks, privilege context, artifact identities, context hashes, optional results and declared coverage while excluding only process/namespace instance observations.
- Keep cross-server identical receipts stable and make changed security context or requirements a hard miss; malformed/partial receipts preserve every declared gap.
- Leave configuration, effective behavior and complete coverage ineligible, so no cache lookup, provider-call bypass, approval or response authorization is introduced.

## 1.25.0 — 2026-10-31

- Retain controller-authenticated signed-package manifests with exact target artifact verification.
- Bind an exact recorded-process executable path and SHA-256 to versioned artifact/provenance components while keeping server, PID, inspection and authentication-time observations local.
- Revalidate persisted Debian/RPM manifests, signature provenance and target receipts; changed bytes, incomplete verification and malformed/tampered evidence remain hard cache misses.
- Remove only the package-authentication gap and keep configuration, behavior, follow-up and coverage incomplete, so no fingerprint, cache hit, approval or provider-call bypass is introduced.

## 1.24.0 — 2026-10-31

- Define a strict versioned canonical fingerprint contract for future fleet-wide exact known-good reuse.
- Bind verified artifact bytes, authenticated provenance, configuration, effective behavior, required follow-up evidence, coverage, model and assessment policy while excluding isolated host/PID/time/ephemeral-port observations.
- Fail closed with explicit cache-miss reasons for incomplete, unverified, malformed or host-contaminated evidence; current partial receipts remain ineligible.
- Show candidate readiness on retained assessment detail without publishing/looking up cache entries, granting approval, suppressing protection or avoiding provider calls.

## 1.23.1 — 2026-10-31

- Explain database-migration schema refusals with bounded, escaped lists of missing tables, unexpected tables and unexpected views.
- Preserve strict source validation, read-only dry runs and unknown-object refusal; no database object is ignored, removed or automatically accepted.
- Verify that current startup initialization repairs a missing current table before migration and that standalone current-schema copy remains complete.

## 1.23.0 — 2026-10-30

- Retain boot/PID/start/proc identities for new process observations without changing behavior deduplication keys.
- Require follow-up evidence to match the exact recorded process before and after optional package/service reads; never substitute an equivalent executable.
- Keep legacy observations on the existing conservative current-match path and keep every other fleet-cache coverage gap intact.
- Explain recorded versus sampled process scope in Assessment history and add PID-reuse/restart, collector, persistence, native SSH and responsive acceptance.
- Rebuild controller/workers and upgrade the reviewed target helper/collector together; no schema change or fleet cache hit is introduced.

## 1.22.0 — 2026-10-30

- Run process investigations concurrently across servers with configurable 1–8 AI slots (default 4, serial at 1).
- Add renewable durable subject/worker/boot claims, atomic existing hourly admission and fenced evidence/result writes; retain full model and follow-up capability.
- Bind follow-up input and claim revisions to the database round-trip representation, retaining strict equality after native JSON numeric normalization.
- Recover expired claims without interrupting live investigations; preserve uncertain call receipts, retry limits, approvals and pause/drain boundaries.
- Show active investigations, queued work, reported capacity and actual worker AI task counts. Add threaded/process races, full one/two-stage acceptance and a reproducible serial/parallel benchmark.
- Drain old workers, initialize the new claims table with the upgraded controller, then start matching workers. Same-server parallelism, fleet reuse and shared spend/pacing controls remain planned.

## 1.21.0 — 2026-10-30

- Bind read-only AI follow-up artifact/privilege context to a pinned, rechecked process directory.
- Recheck executable, script and mapped-file identities after package/service queries; refuse mixed or unavailable context.
- Retain explicit coverage gaps without exporting raw arguments/environment/maps or claiming fleet-cache eligibility.
- Add controlled race/limit and live Linux SSH acceptance; reviewed target helper/collector upgrade is required for new context. Model/response safeguards remain unchanged.

## 1.20.1 — 2026-10-30

- Fix standalone offline database migration refusing a current schema because its separate model list omitted AI retry and assessment/refresh tables.
- Share the startup model registry and validate fresh-process dry-run/copy preservation without relaxing unknown-table, offline or destination safeguards.

## 1.20.0 — 2026-10-30

- Retain completed process assessments, exact supplied evidence, requested model and policy provenance independently of diagnostic pruning.
- Add audited, revision-checked Re-triage for completed observations with explicit approval withdrawal and preserved prior results.
- Add paginated fleet/server assessment history and detail pages with role, scope, Back/reload and responsive UI acceptance.
- New assessment/refresh tables require controller-first startup before matched workers. Fleet exact-match reuse, threaded scheduling and shared spending controls remain planned.

## 1.19.0 — 2026-10-30

- Queue durable, bounded process-triage retries using classified transient errors, exponential jitter and provider Retry-After floors.
- Block authentication/billing/configuration failures until correction or explicit retry; preserve AI pause, receipts and existing admission limits.
- Explain retry eligibility, review blockers and paused work in the existing glass investigations/AI status surfaces.
- Add a retry-state table; upgrade controller before matched workers. Shared rate/spend controls and parallel/cache milestones remain planned.

## 1.18.1 — 2026-10-30

- Fix repeated initialization after SQLite schema changes on warmed pooled connections.
- Keep schema reflection and existing upgrades on one connection; retain single migration-owner requirements.
- Add before/after pooled-schema regression cases and remove the timing-test pool-disposal workaround.

## 1.18.0 — 2026-10-30

- Reuse bounded, lifecycle-managed HTTP connections for billable AI calls without reusing credentials/cookies or adding automatic retries.
- Record redacted stage timings and expose readable timing events in AI run timelines.
- Add a disposable serial one-/two-stage benchmark, capability checks and connection/concurrency/shutdown regressions; retain the wider faster-triage program as unfinished.

## 1.17.0 — 2026-10-30

1. Set the major version to 1, retaining the current minor/patch numbers, and keep it fixed until explicitly changed by the user.
2. Preserve existing minor/patch, metadata, commit/PR and skipped-Git-tag rules in the repository and scheduled development task.
3. Enforce the major-version pin in the version checker with regression coverage for other majors, minor/patch advances, legacy adoption and unchanged/decreasing versions.
4. Plan an authenticated-shell notification icon, per-user unread center and asynchronous in-app alerts for human attention and significant triage findings.
5. Define durable event identity, server push/replay, authorization and finite notification UI/end-to-end acceptance. Notification runtime implementation remains planned.

## 0.17.0 — 2026-10-30

- Separate paginated audit review from operations and add linked audit/operation detail pages.
- Preserve fleet/server list position and verify server scope on operation detail reads; retain existing cancellation/recovery confirmations.

## 0.16.1 — 2026-10-30

1. Plan faster AI triage with unchanged investigation capability, configurable threaded parallel execution, fair scheduling, safe connection/evidence reuse and classified retry handling.
2. Plan a fleet-wide exact-match known-good cache with source provenance, context-aware fingerprints, revocation and an explicit Re-triage action.
3. Plan shared rate throttling, an optional daily USD spend cap and unthrottled operation, including concurrent reservations, all billable AI paths and queue/spend diagnostics.
4. Record finite performance, capability-equivalence and concurrency/budget acceptance milestones. This update changes the roadmap and development task; runtime triage and limits await implementation.

## 0.16.0 — 2026-10-30

- Add linked server inventory/process snapshot list and detail pages, replacing the history inspection dialog.
- Preserve scoped pagination, role restrictions, retained history and explicit snapshot/retention limits.

## 0.15.0 — 2026-10-30

- Migrate fleet Overview into route-linked Summary, Server attention and Monitoring pages.
- Add bounded server review cards, filter/page context and explicit missing, expired, future and disabled contact states.
- Retain the glass palette and mascot, with responsive reading surfaces and collection/health limitations.

## 0.14.0 — 2026-10-30

- Check strict-worker receipt protocol and required tables, columns and primary keys before database initialization or job admission.
- Upgrade valid legacy controller receipts with a deterministic requirements digest; refuse malformed or unknown protocol metadata.
- Display schema-structure startup results separately from key verification and readiness; document remaining type/constraint/shared-state limits.

## 0.13.0 — 2026-10-30

- Add a controller encryption canary/version receipt and opt-in fail-closed worker startup verification before worker database initialization or job admission.
- Enable the limited gate in complete Compose and show verified-at-startup/disabled/unreported states in Workers without claiming full readiness.
- Document upgrade/recovery limits and add missing/mismatched/private-key, incompatible receipt and native worker refusal coverage.
- Fix the descendant-test procfs disappearance race found by MySQL CI; retain timeout, zombie/absent success conditions and the surviving-child failure assertion; use namespace-correct kernel exit checks when host procfs is exposed.

## 0.12.0 — 2026-10-30

- Add a bounded controller-configured expected-worker inventory, including never-registered identities, independent of registration pagination.
- Explain missing/stale/stopped/version/drain observations and invalid configuration in Activity → Workers, with responsive cards and preserved read-only/administrator boundaries.
- Add expected-inventory acceptance and document remaining all-component health/deployment work.

## 0.11.0 — 2026-10-30

1. Move stored startup metadata review into dedicated server Files/Coverage pages with deep links, responsive glass surfaces and the established mascot.
2. Retain scoped search/page/revision context, support explicit refresh after receipt changes and allow read-only retained review for inactive servers.
3. Add browser/backend acceptance for paging, Back/reload, history/roles, untrusted text and collection limits. Comprehensive startup discovery/provenance/classification and the broader roadmap remain unfinished.

## 0.10.0 — 2026-10-30

1. Migrate fleet/server AI run inspections from long dialogs to Summary, Cost and Timeline pages with deep links, Back/Forward and responsive glass/mascot surfaces.
2. Preserve scoped list purpose/page context during navigation and refresh; fix the malformed Process triage filter option.
3. Verify server membership for scoped run details, retain shared-batch cost uncertainty, roles and read-only history; add backend/browser acceptance. The wider UI/security/deployment roadmap remains unfinished.

## 0.9.0 — 2026-10-30

1. Add administrator boot/revision-checked cooperative worker drain/resume, persisted requests, observed states and audit events; stop new admission while assigned work finishes and coordinator leadership transfers.
2. Configure bounded startup job/poll concurrency in the actual executors and admission limits, preserving defaults, serialized AI and per-host/recovery safeguards.
3. Put worker controls beside identities, explain request/acknowledgement and queued-poll/notification state, and use a validated identity body to preserve dot/case IDs. Validate process, race, permission and responsive workflows. Remote deployment/readiness/migration acceptance remains planned.
4. Preserve exact related-evidence snapshot boundaries across MySQL JSON persistence using scope v2 text metadata; retain strict evidence-digest approval checks, legacy history and malformed/tampered-boundary rejection.

## 0.8.0 — 2026-10-30

1. Register worker runtime identities, boot IDs, source versions, bounded scheduler heartbeats and actual pool/activity snapshots; reject duplicate configured identities and stop scheduling after identity-lock loss.
2. Add administrator-only Activity → Workers with explicit liveness, clock/version uncertainty and readiness/coverage limits.
3. Add worker-role container startup that skips controller TLS bootstrap, with process/startup/permission/browser validation. Remote deployment, shared-state preflight, drain and the full component dashboard remain planned.

## 0.7.0 — 2026-10-29

1. Migrate the Servers directory to searchable, filtered glass cards with 24-server pagination, retained view context and existing lifecycle controls.
2. Split server Overview into deep-linked Summary, System & collector and Patching status pages, preserving selected context across server switching.
3. Improve phone action wrapping, card-title readability, keyboard navigation and honest telemetry/recovery messaging; retain the mascot and operational safeguards.
4. Add directory/Overview browser coverage and reviewed responsive renders; update the finite screen-migration checkpoint. The full application redesign and broader security/deployment roadmap remain unfinished.

## 0.6.0 — 2026-10-29

1. Start the planned UI rework with a compact server workbench, four primary routes and a reusable mascot-supported grouped section disclosure, above policy content.
2. Retain package filters per server/fleet view during navigation and refresh, with fresh installation selections and account-session reset.
3. Escape server names and reported architecture in workspace headers; cover malicious markup as literal text.
4. Establish the finite screen-migration inventory and navigation map; add keyboard, permissions, route-context and mobile/tablet/desktop checks. The full UI rework and broader security/deployment roadmap remain unfinished.

## 0.5.1 — 2026-10-29

1. Add the planned complete UI rework with the established palette, extensive mascot/graphics use and a polished glass-like appearance.
2. Align the roadmap and UI design guide on focused pages, tabs and menus, shared components, readability/accessibility, responsive workflows and finite completion criteria. This documents planned work; the UI is not redesigned by this update.

## 0.5.0 — 2026-10-29

1. Open the correct server Overview after backend-confirmed installation verification, retaining success status on refresh.
2. Restore tab/account-scoped installation progress after reload; keep pending/failed/interrupted work actionable and recover lost submissions through read-only job lookup without automatic replay.
3. Add desktop/mobile enrollment regression coverage for correct operation identity, failure/retry, reload and lost-response recovery.

## 0.4.2 — 2026-10-29

1. Plan complete/controller-only/worker-only deployment modes with remote-worker state, health, scaling, drain, installation and failure/recovery acceptance.
2. Plan a unified deployment-component health dashboard and dedicated GCP integration Docker node with scoped transport, credentials, installation and migration requirements.
3. Plan navigation to the specific server's Overview page after backend-confirmed successful installation/verification. These entries add roadmap requirements; deployment and enrollment behavior remain unchanged until implementation.

## 0.4.1 — 2026-10-29

1. Make server deletion discoverable in a dedicated per-server Settings tab and in the Manage dialog, with a shared administrator-only management section.
2. Keep exact-name/reason confirmation, active-work/recovery safeguards and retained history unchanged; provide read-only settings for deleted servers and responsive destructive-action styling.

## 0.4.0 — 2026-10-29

1. Add an administrator-only searchable startup-file review workspace with deterministic paging, receipt/baseline revision guards and baseline-change labels.
2. Show mechanism counts, explicit discovery gaps and unassessed provenance without claiming individual job discovery or package-default verification. Preserve stored history and AI-independent access.

## 0.3.0 — 2026-10-29

1. Add opt-in, bounded cross-source historical evidence to manual scanner AI response plans, with host/source binding, retained review snapshots and stale-evidence rejection. Existing automatic plans remain scanner-only.
2. Add a responsive sharing review and inspectable evidence scope while preserving the established raccoon theme.
3. Establish one authoritative source version in `app/main.py`, synchronized README, UI/API metadata and CI consistency validation. Prior development used API metadata 0.2.0 without a numbered changelog; older milestones are documented in the security checkpoint rather than retroactively versioned. Git tags are omitted by user instruction.
