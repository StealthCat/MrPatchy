# Changelog

## 1.35.21 — 2026-10-31

- Declare the required role on every route (`viewer`, `operator`, `admin`, self-service or an allow-listed public route) instead of deciding roles from path substrings in `auth()`; a route that declares no role now stops the application from starting rather than defaulting to viewer-readable (#198).
- Add a route inventory test that fails for any route missing from the expected-role table, and viewer/operator tests for every admin-only and operator route. Role assignments, CSRF, audit, host lifecycle and self-service behaviour are unchanged. Compatibility: a refused request names the required tier ("Administrator access required" or "This role cannot perform that operation") instead of the old path-dependent wording; status codes are unchanged. Major version stays 1.

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
