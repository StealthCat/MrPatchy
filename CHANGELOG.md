# Changelog

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
