# Changelog

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
