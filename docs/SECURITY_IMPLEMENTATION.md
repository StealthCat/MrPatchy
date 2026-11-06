Warning: truncated output (original token count: 114156)
Total output lines: 6049

# Security implementation checkpoint

## Development and integration policy

User instructions (2026-10-30 and 2026-10-31): keep the application major at **1**;
allow independent concurrent implementation with one coordinator responsible for
final version allocation, integration, merging and verified issue closure. Start
with at most two active implementation streams. Existing schedules are unchanged.

Workers use isolated issue-owned branches and leave APP_VERSION, README.md and
CHANGELOG.md unchanged. They document reproduction, delivered behavior, compatibility impacts
and validation in the PR, then explicitly hand the exact ready commit to the
coordinator. Development commits/PRs need no version prefix. The coordinator owns
all README/changelog notes and updates based on the PR description, and adds
the final version, a numbered PR-linked changelog entry and versioned integration/
merge subjects only when integrating that PR. README no longer tracks a source
version. Runtime UI/API/health/identity still derive from APP_VERSION. Preserve
historical commits/changelog entries and skip Git tags. A source bump does not
publish a Docker image.

Development metadata checks permit unchanged release metadata against main. The
separate `integration-version` gate requires a newer version and this PR's link in
the newest changelog entry; all applicable checks must pass on the exact final
integrated commit before merge. Reconcile/retest when main or the head changes.
Only the coordinator merges and verifies fully delivered issues close. Read
[AGENTS.md](../AGENTS.md) and [the coordinator guide](DEVELOPMENT_COORDINATOR.md)
for ownership, handoff, transition and the copyable coordinator prompt. Historical
delivery records below describe the policy in force when they were written.

## Dependency vulnerability gate (partial #201)

The CI `static` job runs `pip-audit` (pinned in `requirements-audit.txt`) against the
hash-locked `requirements.lock` and then `tools/dependency_policy.py`, which fails the
job for any finding without an active exception. Policy: fix by upgrading the
dependency where a fixed version exists. If no fix is available, record an entry in
`docs/dependency-exceptions.json` with `id` (the advisory id or alias), `owner`,
`reason` and an ISO `expires` date at most 90 days ahead. Expired, malformed or
unused exceptions also fail, so exceptions cannot linger silently. The gate covers
Python runtime dependencies only; npm dev tooling, base-image packages and live
GitHub alert state are not covered, and a successful scan is not evidence of the
latter. The scan needs network access to the PyPI advisory service.

## Dependency update coverage (partial #201)

PR #284 configures weekly Dependabot updates for pip, npm, GitHub Actions and
Docker at the root, deploy and test-fixture manifest locations. Tracked Dockerfile
location coverage has regression tests; live Dependabot update generation has not
been exercised as part of this delivery. This is update configuration, not code
or dependency vulnerability scanning. PR #292 pins the CI workflow's
`actions/checkout`, `actions/setup-python` and `actions/setup-node` references to
full commit SHAs with version comments, covered by a regression test. Base images
remain tag-based and Python requirements lack install hashes. Image digest and
hash pinning, code scanning and additional Compose sandboxing remain unfinished
under #201; no runtime response authority or deployment sandbox boundary is
changed.

This checkpoint supersedes the code-scanning status immediately above: a
separate least-privilege CodeQL workflow analyzes Python on pull requests
targeting `main`, pushes to `main` and a bounded weekly schedule. Checkout and both
CodeQL actions are pinned to full commit SHAs with readable version comments, and
regression coverage keeps the triggers, Python/security-extended query suite,
action pins, timeout and upload permission explicit. Results are repository
security-analysis findings; they do not authorize runtime remediation. Base-image
digests, hash-pinned Python
installs, dependency-vulnerability scanning and additional Compose sandboxing
remain unfinished under #201.

## Scheduled development completion gate

Before each scheduled development cycle, assess the current roadmap against current
`main`, the latest merged PR's actual changes and recorded validation, the
implementation checkpoint and any unfinished related PR. This is a read-only
assessment before any implementation, UI polishing, versioning or repository write.

- After issue-first triage, if the requested roadmap is feature complete and neither actionable issue fixes nor unfinished in-scope implementation remains, stop that cycle without working on the code. Do not invent additional features, refactor, polish the UI or begin speculative bug hunts to fill the cycle.
- A completed cycle with no work must not change source, tests, documentation or the checkpoint; it must not bump a version or create commits, tags or PRs merely to record that nothing needs doing.
- Report briefly that no development is needed, citing this roadmap and the latest merged PR/commit used for the assessment. Keep the development schedule enabled; later cycles may resume when a new roadmap requirement or unfinished in-scope milestone is present.
- Proceed when the assessment identifies an actionable issue fix, a concrete outstanding roadmap requirement or unfinished related implementation. State the remaining work before starting it. Workers own implementation/testing/checkpoints; the coordinator owns final versioning, integration and merge checks.
- Missing, contradictory or blocked evidence is not proof of completion. Report the uncertainty or blocker and stop without speculative code changes; retain honest outstanding requirements and limitations.

This gate takes precedence over instructions to always continue development or
produce another PR. Judge completion from the current repository and latest merged
work rather than stale milestone numbers or repeated historical requests.

### Runtime Python dependency hash lock — partial #201 checkpoint

This source checkpoint supersedes every older #201 status statement in this
historical document, including entries located later in the file, that production
Python installs remain unhashed. A generated Python 3.12 lock pins the complete
production dependency graph and records SHA-256 hashes for the available
distributions. Container builds now install that lock with pip's
`--require-hashes` enforcement; focused tests require exact direct pins, hashed
transitive entries and the enforced Docker install path. The development/test
dependency range remains outside this production-runtime slice. Base-image digest
pinning, code scanning and the other #201 controls remain independently tracked;
this checkpoint does not add vulnerability scanning or alter runtime response
authority.

## Development-cycle work budget

When the completion gate identifies remaining work, select a coherent batch of
actionable roadmap items aimed at about **40–50 minutes of productive work within
the allocated hour**, including implementation, relevant UI work, review,
validation and PR completion. A large milestone may fill the batch; combine
several small related items when appropriate.

- State the selected items and intended outcome before implementation, respecting dependency order and unfinished work from earlier runs.
- Reserve roughly the final 10–15 minutes for review, applicable tests/checks, the PR ready handoff and the checkpoint. Final version/changelog preparation and merging belong to the coordinator.
- If a small item finishes early and roadmap work remains, take the next coherent item only when it can reasonably be completed and validated within the remaining budget. Do not stop merely because one small milestone is finished.
- Preserve reviewable scope and applicable checks on the exact worker commit. Independent development may overlap within the two-stream limit; overlapping ownership and concurrent final integration are prohibited. Avoid risky late additions and leave a precise checkpoint when a safe handoff is not possible.
- This is a sizing target, not a mandatory minimum. Stop early for roadmap completion or a genuine blocker. Do not invent work, wait, repeat successful checks or change completed code simply to fill time.

The completion gate takes priority, and the development schedule is unchanged.

## Current implementation status

### Enrollment installer downloads (partial #202)

Enrollment links retain their one-hour expiry and support repeated downloads for
partial-download retries. Public download requests, including invalid tokens,
share a ten-attempt sliding sixty-second window per ASGI client address across
controllers using the existing SQLite/shared-filesystem or MySQL coordination.
Admission is persisted in one settings row with at most 1,024 active source hashes
and ten timestamps per source. Active sources are never evicted to admit new ones;
when capacity is full, new sources receive HTTP 429 until a slot expires. Requests
over quota return 429 with Retry-After before installer generation; lock contention
returns 503 with a one-second retry. The limiter does not authorize enrollment or
alter the installer or managed-target actions. Proxy trust remains the deployment's
ASGI configuration; the route does not consume raw forwarding headers.

Every successfully prepared valid installer records its first/retry use number,
host ID, non-bearer link identifier and hashed client address in the audit history.
Preparation is not proof of full delivery or execution. Expired/revoked links,
inactive hosts, generation failures and throttled requests do not record a prepared
installer. Tokens and installer content are not included in these audit records.
The independent route-exception-header item remains in PR #264, and #202 stays
open pending both deliveries. No new schema, runtime response authority or source
version is introduced by this worker slice.

### Bounded budget aggregation follow-up (#133)

The follow-up to partial #273 replaces grouping by distinct receipt amount with
at most five status buckets, including a conservative bucket for every unknown
unreleased status. MySQL uses native DECIMAL summation. SQLite uses a registered
bounded-memory integer nano-dollar aggregate, normalizing each value at the same
nine-place precision as the previous SQLAlchemy Numeric reader and returning text
to avoid an additional floating-point sum. This does not change SQLite's existing
NUMERIC storage precision, ledger retention, admission locks or timezone membership.

On disposable 10,000-receipt fixtures, exact-head SQLite and MySQL checks reduced
aggregation results from 10,000 rows to one. The recorded locked aggregation times
were 0.0295 to 0.0176 seconds on SQLite and 0.0487 to 0.0107 seconds on MySQL.
Separately, five actual reserve() calls on SQLite measured median held-lock time of
0.1497 versus 0.0493 seconds and peak traced allocation of 3,335,400 versus 157,231
bytes. These are single fixture measurements without a timing guarantee or fleet
throughput claim. Exact-head SQLite/MySQL, precision and concurrent near-cap tests
retain exact money totals and atomic admission.

PR #240 separately owns timezone-window membership; its later integration must
preserve both its predicate correction and this aggregate. Eligible ledger scanning
remains O(N), and the wider faster-triage program and its end-to-end acceptance gate
remain unfinished.

Current response milestone: approved target preservation and separately approved
controller acquisition are implemented. Reviewed quarantine and original-file
restoration now support protected files under `/srv` and `/opt`. Retained-response
monitoring, manual process-reference observations and separately approved suspension/
recovery of selected root-owned executable processes are available. Authenticated
replacement preparation is read-only. Separately approved private replacement staging
is available, along with separately approved no-overwrite live-file publication,
independent publication pauses and verification of the published file plus retained
original. Service restart/rollback, broader repair and cloud isolation remain future work.
Read-only service-health observations and explicit baseline comparisons are available
to support the separate review of affected services.
Opt-in recurring service watches now provide coverage alerts and independently
reviewed service pauses. Service orchestration remains future work.
Portable metadata-only response records and per-server scanner records with offline
integrity verification are available for independent retention. External immutable storage and automatic
retention remain future work.
Broader typed remediation and process/cloud containment remain unfinished. The sections below retain the scope and limitations
of each earlier milestone; later sections describe the features added since then.

Opt-in execution-triggered scoped ClamAV scans now complement recurring scanning.
They use verified event metadata as scheduling hints and retain explicit coverage
limits. Fleet scanner coverage and read-only cross-source incident evidence pivots
are also available; see the latest milestones below.

The endpoint protection expansion remains incomplete. It must not be represented as complete malware protection or unrestricted automated incident response.

Implemented: administrator-only, on-demand and interval-scheduled read-only ClamAV scan jobs; a server Security tab with scan policy, coverage, paginated scan history, incidents and response plans. Scan receipts are stored in dedicated tables and are never overwritten by a later scan. Repeated path/hash detections on the same host update an incident while retaining each scan receipt. Historical reports from the first draft remain readable as a legacy latest report; new scans use durable history.

Administrators can request an AI response plan for an incident. Generation uses the saved AI settings, caps requests at ten per hour across the fleet, validates allowed advisory action types and evidence IDs, and records the model run and usage through existing AI activity logging. Evidence changes during generation reject the result. Scanner failures do not require a working AI provider.

Plans are advisory manual tasks. Approval never executes shell commands, quarantines files, isolates hosts, or marks an incident remediated. A plan must match the current incident evidence and be reviewed within 24 hours. Approved reviews expire after one hour. Repeat detections supersede prior approvals. The UI identifies expired approvals. No user-facing claim of automated remediation is made.

New tables are included in the offline SQLite/MySQL migration metadata. Security records currently have no automatic deletion policy; size storage accordingly. Engine installation and external evidence storage remain unfinished. Signature age assessment is described below. Automatic proposal generation is available as described below.

Prerequisites: install ClamAV and current signatures on the managed target and redeploy the Mr Patchy collector/bridge using the existing reviewed installation workflow. No scanner installation or signature updates are performed automatically. Engine version is captured with the scan report.

Limits: 16 explicit root directories, 2,000 examined files, 32 MiB per file and a four-minute overall work budget. ClamAV groups at most 32 already-open file descriptors and 128 MiB of source bytes into one local `clamscan` process with a 120-second batch timeout. An engine failure or output that cannot be mapped exactly back to every descriptor falls back to the prior 30-second per-file invocation while the overall deadline remains. This does not enable or connect to a ClamAV daemon. Symlinks are not followed during traversal. Virtual filesystem directories and the reserved quarantine directory are excluded. Exclusions and failures are reported as incomplete coverage. Scanning uses opened file and parent-directory descriptors and checks metadata before accepting each result. A compromised root/kernel remains outside this trust boundary. Reports never claim the server is clean.

Remaining major work before the requested system is complete (later sections define
the bounded features already implemented):

- Complete application-wide UI rework retaining the current color scheme and mascot, with extensive graphics, polished glass styling and readable, uncluttered page/tab/menu navigation; see the planned milestone below.
- Persistent in-app notification icon/center and asynchronous alerts for human attention and significant triage results; see the planned milestone below.
- Faster AI triage without capability loss, true threaded parallel investigations and shared rate-throttle/daily-spend/unthrottled controls; see the planned milestone below.
- Comprehensive startup and scheduled-task awareness, package-default versus custom provenance, and explained AI triage of custom/modified entries; see the planned milestone below.
- Separate complete/controller-only/worker-only deployments with supported remote-worker state, health, scaling, drain and recovery; see the planned milestone below.
- Unified deployment health/status dashboard for controllers, workers, agents and integration nodes, plus a dedicated GCP integration Docker node; see the planned milestone below.
- General malware protection: known-malware detection, AI-enabled triage of previously unknown malware, and automatic file quarantine plus malicious-process termination; see the planned milestone below.
- CVE exposure-window exploitation monitoring with automatic quarantine or termination of detected malicious artifacts/processes; see the planned milestone below.
- Configurable evidence retention, external immutable storage and independent audit retention. Bounded per-server scanner record exports now complement file-response exports; automatic deletion and external storage are not implemented.
- Broader behavioral/threat-intelligence correlation and cross-source AI investigation evidence. Read-only exact file identity pivots now connect scanner, execution and integrity receipts; Opt-in manual scanner plans now bind a bounded related-evidence snapshot; broader signature-free AI investigations remain unfinished.
- File-write triggers and coverage beyond fresh verified eBPF executions; unsupported kernels, transient/unverified processes and broader runtime mechanisms still have gaps.
- Reviewed engine/signature installation and maintenance; existing scanners/rules require separately prepared trusted prerequisites.
- Separately approved service restart/rollback and broader typed remediation, credential-rotation tasks, rebuild escalation and cloud isolation with validated recovery paths.
- Real-VM/eBPF/ClamAV/YARA acceptance, performance tests, platform expansion and failure-injection response drills beyond the existing bounded CI fixtures.

Only the explicitly reviewed, bounded response operations described below are enabled.
No detector or AI plan automatically authorizes destructive response.


## Incident review and fleet hash correlation

Server Security cards now provide **Review incident**, **Incident timeline**, and **Find hash across fleet**. Administrators can acknowledge, reopen, mark a false positive, or record manual resolution with a reason of 10–4,000 characters. Resolution records the administrator's assessment; it does not certify a clean host or execute remediation. A new detection reopens the incident, including a previously resolved or false-positive record. False-positive review is not an allowlist.

Reviews use the displayed update timestamp to reject stale decisions and share the host operation lock with scan workers. Any status change supersedes draft and approved plans. Scans and their evidence remain unchanged. Timelines record new detections, previous state, plan generation, plan approval, and manual reviews with actors and timestamps. Timeline capture starts with this version; earlier events are not fabricated.

Hash correlation searches exact SHA-256 values among stored incident detections across the fleet, with pagination and administrator-only access. It does not initiate a fleet scan, establish that matching files are malware, or prove absence on hosts with no stored detection. Scan and timeline models are included automatically in database migration metadata.


## Optional automatic AI plans

Each server's scan policy can enable automatic AI response proposals. It is off by default and sends scanner evidence through the existing configured AI integration. The leader checks for unplanned open incidents, with at most ten queued plan requests per hour across the fleet (including manual requests) and one outstanding plan per host. Each incident/scan revision receives at most one automatic attempt; failures require manual retry or a later detection. Disabling the option prevents queued automatic jobs from making a new provider call. A changed or reviewed incident is checked again at execution. No plan is automatically approved or executed, and detection continues without AI.


## Scanner traversal and signature provenance

Version 2 scan receipts assess the **advertised daily database build date** from `clamscan --version`, with the subprocess locale set to C and timezone to UTC. The fixed age limit is seven days; dates more than five minutes in the future are flagged for clock review. Missing/unparseable dates, stale or future dates, failed final health checks, and a version change across a scan keep its coverage state **incomplete**. The scanner still retains detections from available signatures. The Security tab shows freshness and build time; older receipts explicitly show that freshness was not recorded.

This is a local age assessment, not verification that the database is the newest vendor release, that all signature files are authentic, or that a compromised root/kernel reported truthfully. No outbound update check or automatic signature installation occurs. Only the advertised daily database version/date is compared before and after a scan; changes to custom signatures or database replacement with identical advertised metadata are not detected. See [ClamAV version reporting](https://github.com/Cisco-Talos/clamav/blob/main/common/misc.c) and [engine/database maintenance](https://www.clamav.net/downloads).

Traversal opens each root ancestor with `O_DIRECTORY|O_NOFOLLOW`, then descends using directory-relative opens. Symlinked roots/ancestors are rejected, including common aliases such as `/var/run`; select the intended real directory when appropriate. Virtual filesystem and quarantine exclusions also apply to roots, not just children. The traversal is bounded to 10,000 entries and 32 nested directory levels in addition to the existing file/time/size limits. Directory and file descriptors close on early exits. File identity, parent directory identity and file metadata are rechecked before accepting a result; replacements become coverage gaps. This does not provide a filesystem snapshot, detect every transient change, or prevent a privileged attacker from changing mounts or kernel behavior.

New incident evidence includes a bounded scan coverage summary (engine, freshness, counts, timestamps and up to 20 shortened gap messages). AI proposals see these limitations, and the existing evidence digest binds them into plan generation and review. Full immutable receipts remain available in scan history. Historical incidents/approvals are not silently rewritten; their signature context remains unknown until a new scan supplies it. Plans still require review and remain advisory only.

After updating the controller, use the existing **Finish / verify installation** workflow to redeploy the updated collector to managed targets. Old collectors continue producing legacy receipts without freshness metadata. Automated tests simulate bounded multi-file ClamAV invocations, mixed clean/detection mapping, ambiguous-output fallback, engine output, signature drift, path replacement, parent symlink races, finding-limit descriptor cleanup, empty-directory budgets and AI evidence binding.

A disposable supported-target ClamAV 1.5.3 run used the complete cryptographically verified production set: `main.cvd` version 63 (3,287,027 signatures), `daily.cvd` version 28171 (355,841 signatures, built 2026-11-01) and `bytecode.cvd` version 339. Loading that set and scanning one benign file took 8.070–8.640 seconds across three launches with about 987,312 KiB peak child RSS. Scanning the same 20 benign files separately took 173.018 seconds / 20 launches; one bounded batch took 9.382 seconds / one launch (18.4x elapsed improvement). Both modes scanned 20/20 files with no gaps or detections and the same 987,460 KiB peak child RSS. An end-to-end `security_scan()` run also used one descriptor batch, scanned 20/20 files in 9.625 seconds, reported recent signatures and no coverage gaps, and retained the before/after engine-version checks.

## Read-only package and persistence inspection

The administrator-only **File integrity** tab on each server queues a separate `security-inspect` job. Select up to 16 installed package names and/or a metadata-only inventory of common system startup locations. Completed receipts are immutable, scoped to the server, paginated, and included in SQLite/MySQL migration metadata. A job can complete with an **incomplete** inspection receipt; review its gaps.

Package checks use `dpkg --verify-format=rpm --verify` or `rpm --verify --noscripts --nodeps` against the **target's local package database**. RPM verification scripts are explicitly disabled. Package identity is queried before and after verification; changes, diagnostics, timeouts, unknown output and absent packages are coverage gaps. Reports distinguish missing paths, configuration-file markers and the native verification flags. At most 200 file discrepancies are retained across the inspection. Commands have 30-second individual deadlines and 512 KB output limits, within a three-minute job budget. There are no package repairs, network repository downloads, maintainer-script execution or automatic AI uploads.

This is not the independent trusted-vendor verification milestone. Dpkg's local checksum coverage is limited to metadata it has recorded; local databases, binaries and a compromised root/kernel are not independently trusted. A discrepancy may be a legitimate administrative change, and no reported differences is not a clean-host verdict. Exact installed-version artifacts authenticated through repository signatures, approved custom baselines, and broader RPM-native platform validation remain required.

The optional startup inventory covers `/etc/systemd/system`, system cron directories and `/var/spool/cron`, `/etc/init.d`, `/etc/profile.d`, `/etc/crontab`, `/etc/rc.local` and `/etc/ld.so.preload`. It retains paths, ownership, permissions, modification time, symlink targets, and SHA-256 for regular files up to 1 MiB. It does not collect file contents, follow symlinks, or execute startup entries. It uses the descriptor-based traversal and identity checks from the scanner, with a 15-second budget and at most 256 recorded entries. Missing roots are explicit; inaccessible paths, special files, races and limits are gaps. This is an inventory, not a detector that declares startup entries malicious. User home startup files, transient units, kernel mechanisms, runtime injection and other persistence locations remain outside its scope. History permits manual comparison; automatic persistence-change alerts and incident linkage are not yet implemented.

Redeploy the collector and bridge with **Finish / verify installation** before using this feature. Older helpers reject the new action rather than returning a fabricated successful report. Unit tests cover native output parsing, safe argument selection, RPM script suppression, deadlines/limits, symlink handling, report immutability, roles and host scoping. A native read-only dpkg check is exercised where available; RPM behavior also requires validation on a real RPM target.

Package verifier references: [dpkg verification format and limitations](https://dyn.manpages.debian.org/trixie/dpkg/dpkg.1.en.html), [RPM verification flags and script suppression](https://rpm.org/docs/4.20.x/man/rpm.8).

## Native security validation

The SSH integration matrix exercises `security-inspect` through the deployed,
restricted bridge on Ubuntu 24.04, Debian Bookworm, Fedora 44 and AlmaLinux 9.
Disposable packages provide known checksums so tests can assert unchanged,
modified, missing and restored content without assuming the runner's own system
files are unchanged or readable. An RPM verification script writes a sentinel;
the test asserts that inspection never executes it. An absent package must report
incomplete coverage, and a startup inventory fixture must return its hash without
its contents. These containers stub systemd and are not full VM or runtime-malware
validation. No quarantine or remediation execution is introduced.

The controller's native dpkg test uses an isolated database and filesystem. This
avoids depending on GitHub's mutable host `base-files` package. SSH key-rotation
checks assert the wrapped authentication exception and its underlying cause, so
unrelated connection errors cannot count as successful key revocation. Both SSH
matrix entries run even if one fails. CI supports manual dispatch and bounds each
job to at most 30 minutes (see "CI pipeline review (v1.35.24)" for current limits);
PR and main-push triggers remain enabled.

## Managed-agent health and maintenance

The controller now classifies enrolled helper versions and unexpected managed-file
or service drift, with independent bridge receipts and opt-in bounded upgrades or
repairs. See [Agent maintenance](AGENT_MAINTENANCE.md) for the trust boundary,
blocked access-path changes, verification and retry limits. This maintains the
Mr Patchy installation; it is not arbitrary malware remediation or independent
attestation of a compromised root/kernel.

## Startup inventory comparison

**File integrity → Compare startup inventory** compares immutable observations on
the same server. It requires two complete, valid inventories with matching scope;
package-only reports are skipped, while intervening incomplete inventories are not.
Content, ownership, mode, type, size and link-target differences are displayed with
before/after metadata. Timestamp-only changes are ignored. Historical malformed
receipts, coverage gaps or scope changes produce an unavailable comparison, never
an inferred deletion. This advances persistence history review; approved baselines,
automatic change alerts and incident linkage remain unfinished. See
[the October 27 code review](CODE_REVIEW_2026-10-27.md) for findings and limits.

## Administrator-reviewed startup baselines

The File integrity tab now offers **Review latest as baseline**. Administrators
review the full inventory, scope and missing roots, and provide a reason. Only the
latest persistence receipt on that server can be approved; it must be valid,
complete and received within 24 hours. The request binds the receipt digest and
previous active baseline ID, and shares the host operation lock with inspections.
A newer receipt, concurrent approval, incomplete coverage or expired observation
rejects the review. Approving a replacement can acknowledge legitimate changes;
it never repairs files or establishes that they are malware-free.

Approvals are append-only records containing actor, reason, receipt, digest and
time. The active selection is separate; old approvals and inspection receipts
remain available. The new `persistence_baselines` table is created at startup and
included in the existing verified offline SQLite/MySQL migration metadata. Start
this version to initialize its schema before an offline migration.

Subsequent observations are compared against the approved receipt. State is
`matches`, `drifted`, `unavailable`, or `stale`; without approval it is
`not_configured`. A mismatch opens a startup-baseline alert in the existing alert
system. Incomplete observations, incompatible scope, missing evidence or evidence
older than 24 hours cannot resolve as matches. The age is measured from controller
receipt time, not a trusted target clock. Package-only inspections do not refresh
startup coverage. Queue inspections regularly: approving a baseline does not
schedule new inspections. Alert delivery follows the existing notification policy.

This milestone covers the existing bounded startup inventory, not arbitrary
custom file paths. Automatic incident linkage, scheduled persistence inspection,
trusted-vendor verification and typed remediation remain future work. It requires
no additional target helper changes beyond the security-inspection protocol.

## Scheduled startup inspection and linked incidents

File integrity now has two independent opt-in settings: recurring startup
inspection (1–168 hours, default 12) and startup-change incident recording. Both
are disabled by default. The scheduler shares the manual inspection queue lock,
allows at most one outstanding inspection, defers when any host job is queued,
running or requires recovery, and observes the interval after failed attempts as
well as successful/manual inspections. Enrollment and missing host pins prevent
scheduling. These read-only jobs do not install packages. A changed or disabled
policy is rechecked before a scheduled job accesses the target; already-started
inspections are not remotely cancelled. Approval of a baseline still does not
automatically enable either setting.

With incident recording enabled, a complete new persistence receipt that differs
from the approved baseline creates a startup-change incident. Its identity binds
the host, approved baseline and normalized change set; timestamp-only differences
are excluded. Repeat detections reuse that incident, reopen it, and retain a link
to every immutable inspection receipt. Missing baselines, stale observations,
incomplete inventories and scope mismatch do not create inferred changes.
There is no retrospective backfill when the option is enabled.

The File integrity tab lists incidents, before/after evidence, linked inspection
IDs and review history with pagination. Administrators can acknowledge, reopen,
mark a false positive or record manual resolution with a reason. Reviews require
the displayed incident revision and the host operation lock. They never alter a
baseline, suppress future detections, repair a file or certify a clean host.
Changing a baseline or observing a later matching inventory does not silently
resolve existing incidents. Incomplete observations cannot resolve them either.
The existing baseline alert remains an independent coverage/drift signal.

Startup-change incidents are separate from scanner malware detections and are
not automatically sent to AI. Existing scanner AI proposals continue to use
scanner evidence. New persistence incident, detection-link and review tables are
included in startup schema initialization and verified offline migration metadata.
No new target protocol is required. Remaining work includes AI correlation of
these evidence types, arbitrary custom baselines, trusted-vendor verification,
authenticated YARA delivery and approved typed remediation/quarantine.

## Advisory AI plans for startup changes

File integrity startup incidents now offer **Request startup AI plan**. A separate
confirmation explains that bounded paths, hashes, metadata, symlink targets,
baseline references and coverage will be sent to the configured AI provider and
may incur API charges. This is explicit per-request authorization: enabling
startup monitoring or incident recording does not enable AI uploads.

The evidence packet binds the incident revision and full evidence digest, approved
baseline receipt/digest, linked detection receipt and current observation digest.
The original change set and current comparison are distinct. At most 20 changes
from each are supplied, with omission counts and bounded strings; packets over
64 KB are refused. Current scope, missing roots, freshness/coverage state and
bounded gaps remain visible. No raw file contents are collected or uploaded.
Baseline changes, missing evidence and closed incidents prevent requests. Changed
incidents at execution prevent provider calls; changed evidence during generation
rejects the response. Responses must use the existing allowed advisory step types
and reference supplied evidence IDs only.

Startup and scanner plans share the ten-per-hour fleet queue limit and one
outstanding incident-plan job per host. Calls use the existing AI Activity usage,
cost and diagnostic tracking under `security_plan`. Startup plans are not
scheduled automatically. Generation is metadata-only and performs no remote
commands. The existing AI enable/model/key settings are checked at execution.

Plans appear alongside the startup incident. Administrators can record manual
review only while the plan's evidence digest still matches, the incident remains
open/acknowledged, and the draft is at most 24 hours old. Approval expires after
one hour. New detections, incident reviews, changed baseline or current coverage
make older plans stale. Approval never runs commands, changes files, quarantines
content, isolates hosts or declares them clean. Plans are retained in the existing
plan table and offline migration metadata; no additional schema is introduced.

This adds bounded AI review across baseline/detection/current-observation evidence.
Trusted-vendor verification, authenticated rule distribution, arbitrary custom
file baselines and approved typed remediation with race-resistant quarantine and
restore remain unfinished.

## Offline authenticated Debian artifact comparisons

File integrity now offers **Queue vendor verification** using an administrator-provisioned
bundle ID. The worker authenticates the bundle on the controller before contacting
the target. A separate operator-managed OpenPGP keyring verifies `Release.gpg` over
`Release`; SHA-256 and byte counts bind the selected `Packages` index and exact
`package.deb`. Package control metadata must agree with the authenticated index.
The signed Release must be no more than seven days old, no more than five minutes
in the future, and within `Valid-Until` when supplied. This follows the archive
trust chain described in [APT authentication](https://manpages.debian.org/testing/apt/apt-secure.8.en.html).
It authenticates an archive publisher, not the safety of its software.

Provision these files under the controller's shared `DATA_DIR` (normally `/data`):

```
vendor-packages/trustedkeys.gpg
vendor-packages/example/Release
vendor-packages/example/Release.gpg
vendor-packages/example/Packages
vendor-packages/example/index-path
vendor-packages/example/package.deb
```

`example` is the bundle ID. `index-path` contains the exact relative index path
listed in Release's SHA256 section, for example `main/binary-amd64/Packages`.
Supply the uncompressed index and detached signed Release from the same repository
snapshot and the exact installed-version artifact. Obtain/verify archive signing
keys independently through the vendor's documented channel; never copy a target's
keyring or accept a bundle-supplied key as trust. The keyring must be an exported
OpenPGP public-key file, not a GnuPG keybox. Limit it to approved publishers.
Bundle files are regular files, final symlinks are rejected, and bundle directories
must not be symlink aliases. Restrict their write access to trusted administrators;
app and workers need read access. Provision atomically and do not edit bundles while
jobs are running. No network retrieval, trust-key import, repository mutation,
package installation or maintainer script is performed.

Preview authentication inside the controller before queueing:

```bash
python -m app.vendor example
```

Use the same files/read permissions on every worker. The Docker image already
includes GnuPG. Redeploy app/workers and use **Finish / verify installation** to
install the updated target bridge and collector. Old helpers reject this action.
Authentication is repeated when the queued job executes; failures appear in the
job log and prevent SSH. Bundle IDs do not imply authentication success.

Target comparison requires an exact installed Debian package version and
architecture before and after inspection, using dpkg only for identity. Expected
SHA-256 values come from regular file bytes in the authenticated artifact, never
the target's checksum database. File opens reject symlinked ancestors/final paths
and special files; file/parent identity and change metadata are rechecked around
hashing. Missing and differing regular files are findings. Races, unsupported paths,
limits and identity mismatches are incomplete coverage. Legitimate configuration
changes, diversions and usr-merge aliases can require review or cause gaps.

Limits: one artifact per job, 64 MiB compressed artifact/index, 200 regular files,
32 MiB per file, 128 MiB unpacked/read bytes, 2,048 archive members, 20-second tar
iteration checks, 15-second signature subprocess, and two-minute target work budget.
Gzip/xz/bzip2/uncompressed tar payloads are supported by Python; zstd payloads
currently fail closed. Symlinks/hardlinks/special archive entries are counted and
excluded; permissions, ownership, generated files, extra installed files and
runtime behavior are outside scope. Tar files are streamed without extraction.
Controller clocks, controller storage/keyring and the target kernel/root remain
trust assumptions. Byte matches never establish a clean host.

Immutable inspection receipts retain controller-recorded signing fingerprints,
keyring/Release/index/artifact digests, publisher/suite/codename, exclusions and
comparison results. They use the existing inspection history and offline database
migration support. Bundle bytes and trust keys require separate operator backup;
receipts alone cannot replay authentication. Comparisons do not automatically
create malware incidents, send AI evidence or repair files. RPM authentication,
automatic trusted artifact retrieval, arbitrary custom baselines, YARA and typed
quarantine/restoration remain future milestones.

## Offline authenticated RPM artifact comparisons

The same File integrity vendor-verification form now also accepts RPM bundles.
Provision `vendor-packages/<bundle-id>/package.rpm` and the separate operator-managed
`vendor-packages/rpm-trustedkeys.asc` under the shared controller `DATA_DIR`.
The key file is an ASCII-armored export of independently verified publisher public
keys. It is outside the individual bundles; target keys and the controller's normal
RPM key database are never used. A bundle containing both `package.deb` and
`package.rpm` is rejected. Existing Debian bundle provisioning remains supported.
`python -m app.vendor <bundle-id>` previews either format without contacting a host.

The controller copies bounded artifact/key snapshots into a private temporary
workspace. Native `rpmkeys` imports approved keys into a new isolated database,
then checks the package. Explicit strong header signature success plus SHA-256
header and compressed-payload digest success are required. A successful process
exit alone is insufficient: unsigned RPMs can otherwise pass digest checks.
Unknown/weak signature output fails closed. The initial supported native output
is RPM 4.x verbose verification (as supplied by the controller Docker image);
newer package/signature formats unsupported by that runtime require a controller
upgrade and validation, not verification bypasses. See [RPM verification](https://rpm.org/docs/4.20.x/man/rpmkeys.8)
and [signed header/file digests](https://rpm.org/docs/4.20.x/manual/signatures_digests.html).

After authentication, a bounded native RPM query returns selected XML-escaped
metadata. Expected file SHA-256 values come from the authenticated package header,
never installed target checksums. File digest algorithm 8 (SHA-256) is mandatory;
missing or weaker file digests are rejected. Regular hardlinked paths with valid
hashes can be compared separately. Directories, symlinks, special files and ghost
files are excluded; exclusions are recorded. No payload extraction, installation,
RPM plugins or package scripts (including `%verifyscript`) execute. The isolated
database is deleted after the operation; the normal controller database is untouched.

The target's read-only RPM identity query requires the exact name, numeric epoch,
version-release and architecture before and after descriptor-based hashing.
An absent epoch is normalized to zero by RPM. Ambiguous multiple installed versions
produce incomplete coverage; this initial workflow does not resolve install-only
kernel package selections. File-read races, aliases, missing files and differences
use the existing comparison semantics and coverage reporting. This compares bytes,
not permissions, ownership, generated files or runtime behavior; discrepancies
still require review and matches are not a clean-host verdict.

Limits: 64 MiB artifact, 4 MiB trusted key export, three native subprocesses with
30-second deadlines and 1 MiB combined output caps each, at most 2,048 file metadata
entries and 200 comparable regular files, 32 MiB per regular file and 128 MiB total
expected bytes. Target hashing retains its two-minute/128 MiB work limits.
Unsafe/duplicate paths, malformed metadata, mismatched arrays and limits fail closed.

Controller-recorded immutable receipts distinguish RPM from Debian trust, retain
artifact/keyring SHA-256, verified signature **key IDs** (not full fingerprints),
excluded-entry counts, exact package identity and comparison results. Receipt
validation rejects mismatched trust formats. Targets cannot originate trusted
controller provenance. Existing history and database migration support apply.
The artifact and key files require separate operator backups. Offline signatures
do not prove current repository membership, support status, or up-to-date key
revocation information. No repository freshness claim is made for RPM bundles.

Rebuild app/workers and redeploy helpers through **Finish / verify installation**.
The controller Docker image already includes native RPM tools. RPM integration CI
exercises signed Fedora/AlmaLinux fixture packages through controller authentication
and the restricted SSH bridge, including changed/missing files, epoch mismatch,
unsigned and tampered artifacts, invalid trust, and a sentinel proving the package
verification script did not run. Systemd remains stubbed in these container tests.
Automatic trusted artifact retrieval, custom baselines, YARA delivery and typed
quarantine/restoration remain subsequent milestones.

## Reviewed custom integrity scope

File integrity now accepts up to 16 additional canonical absolute file or directory
paths in manual inspections and the recurring monitoring policy. They are combined
with the built-in startup scope and use its existing approval, comparison, alert,
incident, review and explicitly requested advisory AI workflows. This is one active
combined baseline per server, not independent baselines per path. Saving a policy
does not collect evidence or approve a baseline; status describes the latest stored
observation, with its existing 24-hour age limit. Keep manual and scheduled scope
consistent so a built-in-only inspection does not replace custom coverage.

Directories are traversed without following symlinks; explicitly selected regular
files are hashed, and selected symlink leaves retain link metadata only. Symlinked
ancestors, special files, read failures and directory replacement races are coverage
gaps. A genuinely absent selected path is listed under missing roots. No file
contents are stored. Directory metadata itself, access-control lists, extended
attributes and runtime behavior are outside the file inventory. A local approved
baseline is administrator evidence, not independent vendor authenticity.

Custom paths may not overlap each other or built-in startup scope. Root `/`, virtual
filesystem paths (`/proc`, `/sys`, `/dev`, `/run`) and the reserved quarantine tree
are rejected. Traversal exclusions also apply below selected directories; excluded
descendants make coverage incomplete. Scope shares the existing 15-second budget,
256-entry receipt, 10,000 examined-entry/32-level traversal limits and 1 MiB regular
file hash limit. Adding paths does not increase those budgets. Over-limit or
incomplete observations cannot be approved or used to infer removals.

To use: update app/workers and redeploy helpers through **Finish / verify
installation**, enter additional paths, queue an inspection, review its full scope
and coverage, then approve the complete latest inventory. Configure the same paths
in recurring monitoring and opt in to scheduling/incident recording as needed.
A scope change makes comparison with the previous baseline unavailable after the
new observation; collect and explicitly review a new complete baseline. Old
approvals, receipts and incidents remain retained. Scope edits cancel queued
scheduled work through the existing policy revision check; already-running jobs
are not cancelled. Custom-path requests use a separate bridge action so older
helpers reject them, and the controller verifies returned scope before storing a
receipt. Missing custom scope can never count as a successful inspection.

Custom-path changes remain ordinary reviewed change incidents, not automatic malware
verdicts. They retain the startup workflow's historical labels. AI metadata upload
still requires its separate confirmation; evidence includes the combined scope and
coverage, is bounded, and uses existing stale-plan and manual-only approval checks.
No automatic file repair, quarantine, AI upload or baseline acceptance is enabled.
Future work includes authenticated YARA rules, automatic trusted artifact retrieval,
and approved typed quarantine/restoration and containment workflows.

## Authenticated offline YARA source scans

Security now offers a separate **Queue YARA scan** form, with explicit directories
and an offline bundle ID. This is manual read-only scanning, independently of
ClamAV scheduling. Provision the target's `yara` CLI (YARA 4.x), update app/workers,
and redeploy helpers through **Finish / verify installation**. Engine installation
and automatic rule retrieval remain operator tasks.

Under controller `DATA_DIR` provision `yara-rules/trustedkeys.gpg` as an exported
OpenPGP public keyring from independently verified rule publishers. Each bundle
is `yara-rules/<id>/` containing `rules.yar`, `manifest.json` and detached
`manifest.json.sig`. Trust keys are separate from bundles and never taken from
managed targets. Use regular files and real directories, with writes limited to
trusted administrators and read access for workers. Provision bundles atomically.

Manifest JSON has exactly four keys: `version` (1), `sha256` (lowercase SHA-256 of
exact UTF-8 source bytes), `issued` and `expires` (Unix timestamps). Sign the exact
manifest bytes with a trusted publisher key, for example:

```bash
gpg --detach-sign --output manifest.json.sig manifest.json
python -m app.yara_rules bundle-id
```

The preview authenticates without target access. Workers repeat authentication
before SSH, require a strong signature and matching source hash, reject future
issue times beyond five minutes and expired bundles, and limit validity to 30 days.
Keys and bundle bytes need separate backups; database receipts retain provenance,
not replayable rule source. Offline checks do not establish newest rules or latest
key revocations. Controller/target clock skew can prevent scans.

Only bounded source text is accepted, never compiled rule blobs. Include/import
words are rejected conservatively even inside comments/strings, preventing external
includes and modules; simplify such rules rather than bypassing validation. The
CLI is never given `-C`, module data, process IDs, recursive traversal or string/meta
printing options. Authenticated rules still require publisher review and can produce
false positives. See [YARA source and compiled-rule handling](https://yara.readthedocs.io/en/latest/commandline.html).

The target compiles against an empty descriptor before traversal so invalid rules
cannot report successful empty coverage. Each file is scanned through an opened
regular-file descriptor; file and parent identity/change metadata are checked as
in ClamAV scanning. Rules remain in a temporary descriptor for this job only and
are not installed persistently. Source is capped at 128 KiB, each native invocation
at 15 seconds, 64 KB output and 512 MiB address space, with YARA's ten-second scan
timeout. Existing 16-root, 2,000-file, 32 MiB/file, 10,000-entry, depth and four-minute
traversal limits apply. Per-file compilation is deliberate in this initial version;
large/expensive bundles may hit coverage limits. No filesystem snapshot or root/kernel
attestation is provided.

Missing engines, compilation diagnostics, timeouts, unsafe paths, replaced files,
rule expiry during scanning, and budget limits produce incomplete coverage. Match
receipts retain rule identifiers and file hashes without matched strings or file
contents. Immutable scan history and incidents reuse existing reviews, hash search,
manual AI plans, usage tracking and offline database migration support. Controller
provenance binds manifest/rule/keyring hashes and verified fingerprints into incident
coverage. Target-supplied controller provenance is rejected. Rule validity is shown
separately from ClamAV database freshness.

YARA requests share the pending scan guard with ClamAV. YARA findings do not trigger
automatic AI proposals, even when ClamAV automatic proposals are enabled. Explicit
AI requests still require manual plan approval and execute no response actions.
Native YARA integration runs on disposable Debian/Ubuntu targets; other targets
require a compatible engine and platform validation. Quarantine/restoration,
containment, behavioral detection and automatic trusted rule delivery remain future
milestones. Matches do not establish malicious intent; no matches is not a clean-host
verdict.

## Approved evidence-preservation vault

Security scanner incidents now offer **Prepare evidence copy**. This queues a
read-only target check against the detection's path, SHA-256 and device/inode.
It captures fresh size, ownership, full mode, link count, modification/change times
and parent identity. Old receipts lacking device/inode require a new scan. Only
regular files up to 32 MiB qualify. Virtual filesystems, symlinked ancestors/leaves
and the quarantine/evidence stores are excluded. No contents return over SSH.

Completed preparations appear in **Evidence preservation vault**. Review the full
snapshot, provide a reason and type `PRESERVE` in the separate approval dialog.
Preparation expires after 15 minutes; execution approval after five minutes and is
checked by both controller and target. A changed/resolved incident, stale snapshot,
changed bytes/identity or mismatched host/digest rejects execution. AI plan approval
never authorizes this action; it uses a separate explicit preservation approval.

The target copies descriptor-read bytes to
`/var/lib/mrpatchy-evidence/<operation-id>/content`. All vault ancestors must be
root-owned and not group/world writable; vault/operation directories are 0700,
content/receipts are root-owned 0600. Root directories cannot be symlink aliases.
The source is never renamed, unlinked, chmodded or repaired. Reads may update its
access time. This is **evidence preservation**, not quarantine or containment:
original bytes can remain executable and running processes are not stopped.

Hash/identity checks surround bounded reads and are repeated immediately before
and after copying. The copy is fsynced, independently rehashed, and bound to a
protected, fsynced operation receipt. An operation ID is bound to one snapshot;
retries return its receipt rather than making another copy. Metadata/partial files
are retained on interrupted copies and are never automatically overwritten or
promoted to verified evidence. There is no automatic cleanup or retention policy;
plan storage for approved copies. Source/copy phases each have 30-second and 32 MiB
limits; SSH execution has a three-minute deadline. These are bounded observations,
not a filesystem snapshot, remote-root attestation, trusted timestamp or immutable
external evidence archive.

A controller marks an operation uncertain before requesting the copy. Lost replies
or restarts therefore do not imply success or re-execute copying automatically.
**Verify vault status** queues read-only reconciliation, validates protected receipts
and rehashes complete vault content. Incomplete or missing evidence remains explicit.
Target-console review is required for partial files; no arbitrary file download,
execution, deletion or restore endpoint is exposed. Controller metadata retains
approval actor/reason, snapshot digest and latest observed receipt, with audit events.
Repeated read-only status observations update this latest observation; target
content and its original completed receipt are retained. Incidents are not silently
resolved, and no clean-host verdict is recorded.

The `security_evidence_copies` table is initialized at startup and included in
verified offline database migration metadata. Initialize the current schema before
migrating. Vault bytes live on targets and require separate protected backups;
controller database backups alone do not retain them. Rebuild app/workers and
redeploy target helpers through **Finish / verify installation** before use.

Native integration tests exercise guarded vault creation, unchanged source bytes,
copy verification, permissions and idempotent status/retry on Debian, Ubuntu,
Fedora and AlmaLinux containers. Service managers remain stubbed. Quarantine moves,
restore approval, durable destructive-action recovery, process/cloud containment
and trusted remediation executors remain subsequent milestones. No automatic
security response is enabled by this preservation feature.

## Separately approved controller evidence acquisition

After a target copy is preserved, **Security → Evidence preservation vault → Review
controller acquisition** offers a separate reason-and-`ACQUIRE` approval. This
explicitly authorizes transfer of the preserved **file contents**, which can contain
malware and sensitive information. Preservation and AI-plan approvals do not
authorize transfer. Acquisitions never send contents to AI or serve them through
the browser. A completed incident review does not prevent retaining previously
preserved evidence. Each approval creates a new independently retained acquisition;
there is one pending acquisition/verification job per host, with no automatic retry.

Approval binds the server's pinned SSH fingerprint, copy ID and complete snapshot
and expires after five minutes. The worker rechecks these before access. The target
also checks expiry and exports only the approved completed vault operation, never
an arbitrary path. It locks the operation, rehashes and checks protected content and
receipts around export. The original source is not read or modified during export.
Transfer uses the existing pinned SSH route, including GCP IAP where configured.
Old helpers reject the action: redeploy through **Finish / verify installation**.

The controller verifies the exact identity, decoded byte count and SHA-256 before
writing. Files reside at `/data/evidence-archive/<acquisition-id>/` (or the configured
`DATA_DIR`). Directories must be owned by the service UID and mode 0700; files are
0600 with one hard link. The data directory must belong to that UID and have no
group/world write permissions. Ancestors and files are opened without following
symlinks. Intent is durable before transfer; content is fsynced before completion
metadata, then independently rehashed through reopened storage. Nothing is executed,
extracted, automatically deleted or overwritten by a repeated job.

The existing 32 MiB per-file bound applies. Transfer uses one bounded base64 JSON
response under the SSH protocol's 64 MiB ceiling, not streaming; budget roughly
256 MiB of transient worker memory for a maximum-size acquisition and allow for
network overhead. SSH has a 150-second total deadline, target hashing phases and
controller rehashing each have 30-second read budgets. Approval must still be valid
when the controller receives the reply. A slow transfer, full disk, malformed reply,
hash mismatch or interruption leaves uncertainty/partial intent or bytes, never an
inferred successful acquisition. No incomplete acquisition is automatically retried
or promoted. Console review is required for partial-file cleanup; a fresh explicit
approval can acquire another copy without overwriting the earlier attempt.

**Controller evidence archive** shows the last observed state and time, with
**Verify controller copy** and paginated **Acquisition custody history**. Verification
reads only controller storage, so it works with an unavailable or blocked target.
It reports `verified`, `incomplete`, `not_found`, or `unavailable`; an interrupted
database update can be reconciled as verified only if completed receipt and bytes
match the approved acquisition. Append-only application observations retain
approvals, starts, interruptions/rejections and later verification outcomes; a later
failed check does not erase earlier records. They are not cryptographically immutable
or protected from controller administrators. Verified is a bounded observation at
the last check, not a clean-file verdict, continuous monitoring or root attestation.

The new `security_evidence_archives` and
`security_evidence_archive_observations` metadata tables are included in startup
initialization and verified offline SQLite/MySQL migration. **Database migration or
backup does not copy archive bytes.** Back up the private archive directory together
with controller metadata, secrets and audit records using an independently protected
destination. Inspect acquired content only through a controlled forensic workflow.
Automatic retention, encryption beyond the underlying storage, immutable external
storage, archive download/delete/restore endpoints and destructive quarantine remain
future work. Rebuild app/workers and redeploy helpers for this milestone.

Tests cover approval separation, host/role boundaries, expiry/pin/evidence changes,
malformed/corrupted transfers, symlink/hard-link/mode guards, source-independent
export, interrupted publication and local recovery, custody retention and UI
confirmation. Native SSH integration exercises export approval and controller
acquisition on Debian, Ubuntu, Fedora and AlmaLinux containers. These tests still
stub systemd and do not replace real-VM or production-scale response drills.

## Reviewed file quarantine and original-file restoration

The next response stage is available under server **Security**:

1. Preserve a scanner detection and acquire its bytes to the controller using the
   separate approvals above.
2. On a verified acquisition, select **Prepare file quarantine**. This queues
   read-only checks of the retained controller bytes, current source and helper.
3. In **Reviewed file responses**, open **Review quarantine approval**, inspect the
   complete plan, provide a reason and type `QUARANTINE`. Preparation expires after
   15 minutes; execution approval expires after five minutes.
4. Review the resulting file state and affected applications. Other Mr Patchy
   server changes stay paused until verified restoration or a separate review of
   the pause. AI-plan approval never authorizes a move or restoration.

This first executor intentionally supports only canonical files below `/srv/` and
`/opt/`, excluding `/opt/drpatch`. Every source ancestor must be root-owned, have
no group/other write permissions and open without following symlinks. The source
must be a root-owned regular file, have one hard link, no group/other write or
special mode bits, and be at most 32 MiB. File capabilities and file access ACLs
require console response. Extended attributes are hashed (at most 32 names and
64 KiB of values); values are never uploaded. Plan metadata is capped at 48,000 bytes.
These constraints exclude many user-owned uploads, shared temporary directories,
home directories and operating-system paths. Do not change ownership or remove
protections merely to bypass refusal; investigate those cases through a reviewed
console, trusted remediation or rebuild procedure.

Preparation and execution bind the acquired source snapshot, exact scanner
incident evidence, pinned host, source device/inode, size, UID/GID, mode, timestamps,
link count, extended-attribute hashes and protected ancestor identities. The
controller archive is rehashed before a quarantine request. A reviewed agent
installation and fresh independent **current** agent-health assessment are required
before imported helper actions, including state verification. An outdated, changed
or unavailable installation refuses remote response rather than bypassing trust
checks. Redeploy current helpers through **Finish / verify installation** first.

The target uses Linux `renameat2(RENAME_NOREPLACE)` with no overwrite fallback.
The vault and source must be on the same filesystem; cross-filesystem copying and
removal are unsupported. A fresh path/hash/metadata check immediately precedes the
move. The captured inode and bytes are checked again after the move before its mode
is restricted to 0600. The vault is `/var/lib/mrpatchy-quarantine/<response-id>/`,
with root-owned 0700 directories and private, fsynced journals. The held original is
named `held`; evidence-preservation copies remain separate. Virtual scan scopes
exclude this vault, preventing automatic rescanning of retained response material.

Quarantine removes the original pathname and execute permissions; this can break an
application. It **does not** stop processes, revoke existing open descriptors, remove
other persistence, isolate a host or certify successful malware eradication.
Protected namespaces exclude unprivileged replacement races. Concurrent privileged
changes, mounts or kernel compromise remain outside that guarantee; metadata,
parent, inode or content inconsistencies retain uncertainty and require review.
There is no automatic rollback that could overwrite a concurrent deployment.

Approval immediately creates a durable server hold. The worker commits uncertainty
before issuing a mutating RPC. Normal queued jobs, scheduled patching/inspections,
automatic scanner AI plans and agent maintenance defer while held. The matching
response's verification/restoration jobs can run; local controller archive
verification also remains available without target access. A dedicated alert reports
the hold. A rejected preflight releases only the hold introduced by that attempt;
after an RPC may have run, connection loss or invalid replies preserve the hold.
Action jobs with an observed incomplete result fail explicitly. Status jobs can
complete with an uncertain observation; that is not action success.

**Verify file response** is read-only. It checks the immutable intent journals,
captured inode, protected metadata, hash and source-path occupancy. A lost final
journal can be reconciled from positive current filesystem evidence without
repeating the move. An interrupted move before permission restriction can be
eligible for explicitly approved restoration while remaining uncertain. Unknown,
missing, conflicting or changed evidence does not imply successful quarantine or
restoration. An ID is never automatically replayed, and partial journals are retained.
If a worker restart leaves an Activity job marked running, first use the existing
Activity reconciliation workflow; it checks the target mutation lock. That review
does not clear the separate file-response hold. Then verify the file response.

**Review restoration approval** requires fresh (five-minute) readiness evidence and
a separate reason-and-`RESTORE` approval bound to the displayed plan and receipt.
The helper rechecks readiness and expiry, records restoration intent, restores
the original permitted mode and moves the captured inode back using the same atomic
no-overwrite primitive. An occupied destination is never replaced, even if it has
matching bytes. The original inode, hash, ownership, mode, modification time and
attribute hashes must verify at the original path before the hold clears.
Restoration can reintroduce malware: it restores the **original captured file**,
not authenticated vendor content. No file is executed and no incident is resolved.
An interrupted restoration intent is never retried automatically or authorized as
a second restore; uncertain recovery requires console review.

To keep a verified file quarantined, **Review server pause** requires a reason and
typing `KEEP QUARANTINED`. It binds the current receipt and requires verification
within five minutes. The administrator must check service impact before releasing
the pause. `CONSOLE RECOVERED` is a separate explicit manual override after console
review; it can release an uncertain hold and records an administrator's assertion,
not a verified or clean-server verdict. Neither option changes retained bytes,
approvals or incident state. Releasing a pause permits deferred ordinary jobs to
run under their existing scheduling rules; inspect that queue before release.

Plans, immutable typed approvals and append-only observations/reviews are stored
in `security_quarantines`, `security_quarantine_approvals` and
`security_quarantine_events`, with paginated history in Security. Startup schema
initialization and verified offline SQLite/MySQL migration include those tables.
Target journals and held bytes, target preservation copies and controller archive
bytes need separately protected backups; database migration alone does not copy
them. There is no automatic deletion/retention, cryptographic immutability,
arbitrary-path restoration, trusted-vendor repair or cloud/process containment.

Each source/hash phase has a 30-second read budget; preparation SSH has a 90-second
deadline and response/state SSH a five-minute deadline. Filesystem calls blocked
inside the kernel may outlast userspace read budgets. SSH timeout cannot prove a
remote process stopped: verify the mutation lock and journals instead of retrying.
All response approvals are checked again immediately before namespace mutation.
Expiry checks depend on controller and target clock accuracy; keep both clocks
synchronized. Remote timestamps are not independently attested.

Tests cover typed approval separation, host/role binding, strict scope/identity and
permissions, capabilities/attribute policy, changed archives and helper health,
expiry, holds and scheduler deferral, destination conflicts, interrupted move and
restore phases, no-overwrite races and receipt reconciliation. Privileged namespace
fixtures skip on unprivileged runners; a local unmapped-UID fixture may also skip.
Native SSH tests on Debian, Ubuntu, Fedora and AlmaLinux exercise the real controller
worker, independent helper verification, evidence prerequisite, hold, rename,
conflict detection, permissions, original restoration and refusal of a file owned
by an unprivileged user. Systemd remains stubbed; real-VM, SELinux enforcement,
production-scale and broader failure-injection response drills remain necessary.

## Recurring verification of retained responses

Server **Security → Retained response monitoring** adds two separate opt-ins:
automatic verification (off by default) and pausing other server changes when a
check reports a problem (also off by default). The server interval is 5–1,440 minutes,
default 15. Each interval checks **one** retained response, starting with the least
recently attempted. The estimated full rotation therefore scales with the number
of watched responses; this is periodic verification, not continuous detection.
No contents are sent to AI and no paid AI request is triggered.

Retained, uncertain, missing, manually console-reviewed and not-moved responses can
be watched. A verified completed restoration leaves this scope; use File integrity
and an approved baseline to monitor the restored file afterward. A not-moved result
is a monitoring problem because the requested quarantine is not in place, not proof
that the original file is safe. Reviewed responses are included by default when the
server policy is enabled. **Review automatic watch** can retire or re-enable a
watch with a reason and revision-bound review. Retirement acknowledges that watch's
monitoring alerts after review; it does not delete evidence, resolve incidents or
release an existing server hold. Reviews remain in File response history.

The new read-only helper action checks the existing intent journals, protected
ancestors, retained inode/hash/metadata and occupancy of the original path. It
classifies verified retention, an occupied original path, unverifiable held bytes,
changed parents, missing evidence, uncertainty, not-quarantined state or completed
restoration. Source-path occupancy is not a malware verdict: a legitimate deployment
may have recreated it. Missing/unreadable/changed evidence is never reported as
verified. The action creates no directories or journals, moves no files, changes no
permissions and never resumes a quarantine or restore attempt.

The scheduler admits at most one pending response job per host, respects the server
interval after failed/skipped attempts and selects the oldest attempted observation.
Running jobs, recovery-required Activity jobs and normal queued work defer checks;
the response that owns an existing hold can still be checked despite ordinary work
deferred by that hold. Another response's hold defers unrelated checks. Scheduling
shares a distributed queue lock and the worker still claims the host lock. Retired
watches are excluded before the 500-active-response scope limit; reaching that limit
is an explicit coverage alert, never a complete-coverage claim.

Queued jobs bind policy/watch revisions, the prepared plan digest and pinned host.
Disabling/changing policy, retiring a watch, completing recovery or changing the
bound scope prevents stale queued reads. Before importing helper code, every check
requires fresh independent current-agent verification. Cached connection failures
can be rechecked through that independent path. A disabled or retired watch cannot
cancel a read already in progress; its observation may still be retained. Policy,
watch, host and scope are rechecked after the remote round trip, ending MySQL read
snapshots before deciding whether a new hold is authorized. Superseded policy/watch
settings cannot create a new pause, and an observation for changed response scope
cannot overwrite that scope's operational state.

Problem observations open the existing fleet alert **response integrity**. Missing
timely positive verification opens **response verification** when monitoring is
enabled. Coverage uses an estimated full rotation plus one server interval of slack;
unavailable or future-dated observations cannot count as fresh positive coverage.
Busy servers and helper failures can therefore produce coverage alerts. Turning the
server policy off does not silently resolve already-recorded integrity problems.
A newer manual positive file-response verification or verified restoration can
supersede an old problem, while its original failed receipt remains in history.

With the separate pause option enabled, a reported problem can create a durable
server hold, including connection/helper failure or missing evidence. With it off,
monitoring records the problem and alerts without introducing a new hold. Existing
holds remain intact until reviewed through the normal workflow; turning the policy
off or retiring a watch does not unpause work. Successful retained-file verification
does not automatically accept quarantine's service impact. A verified completion of
an already approved restoration can reconcile its hold. No new quarantine,
restoration, process termination or cloud action is automatically authorized.

**Verification check history** provides paginated, append-only receipts in
`security_response_checks`. Compact records bind the plan digest, observed facts,
receipt digest, compact receipt, policy revision and hold decision without duplicating
the entire plan or including contents/exception strings. Skipped jobs are explicitly
recorded and do not refresh positive coverage. Lost workers leave no invented final
receipt: the pending Activity job and overdue coverage remain visible until normal
Activity reconciliation. Receipts and watch reviews are not cryptographically
immutable and have no automatic deletion policy; plan storage and protected backups.
The new table participates in startup schema initialization and verified offline
SQLite/MySQL migration. Retained bytes still require separate backups.

The existing per-file/phase budgets remain; monitoring SSH has a three-minute total
deadline plus the separate independent health check. Kernel-blocked filesystem I/O
may outlast a userspace budget. Clocks must be synchronized; no remote-root, kernel
or trusted-clock attestation is added. Rebuild app/workers and redeploy the current
helpers before enabling monitoring. Container SSH tests cover the scheduled worker,
retained verification, source-path occupancy, independent pause policy and completed
restoration on Debian, Ubuntu, Fedora and AlmaLinux; systemd is stubbed. Real-VM,
SELinux enforcement, performance and broader failure-injection validation remain
future work, along with trusted vendor repair and process/cloud containment.

## Process references to a retained original

**Security → Reviewed file responses → Inspect process references** queues a manual,
read-only observation of processes that still reference the captured inode. Moving
and chmodding a file does not revoke open descriptors or memory mappings. This
observation is the next prerequisite for reviewed process containment; it never
signals, stops or resumes processes, changes a file, releases a server pause,
resolves an incident, or authorizes another response action. No automatic process
checks or AI requests are enabled.

The restricted helper verifies the protected response journals, ancestors, retained
inode, hash and metadata, and refuses restored/missing/unverifiable originals or an
interrupted restoration. The retained inode stays open throughout the observation
to prevent inode reuse. The helper excludes its own process, including that required
verification descriptor, and revalidates held bytes afterward. An occupied original
pathname does not hide references to the separately retained original. A replacement
with identical bytes but a different inode is not considered a reference.

Only kernel procfs at the helper's `/proc` is used. The helper samples each visible
process leader's executable link, numbered descriptor links and `map_files` links,
comparing device/inode metadata without reading linked file bytes, memory, command
lines or environment variables. Receipts retain PID, start ticks, process PID
namespace identity, reference kinds/counts, kernel boot ID and the observer PID and
PID namespace. A second process identity check rejects changed/exited/reused PIDs.
PIDs are relative to the **mounted procfs view**, which can differ from the helper's
own PID namespace. Namespace inode numbers and boot IDs are observations, not
attestation or an authorization to signal the displayed PID.

Work is bounded to 4,096 process leaders, 50,000 directory entries (including procfs
root entries), 128 matched leaders and a 15-second process-observation budget.
Budget exhaustion retains already verified partial matches and an explicit gap.
Each file hash phase keeps its existing 30-second budget; SSH has a 120-second
limit in addition to independent helper verification. Kernel-blocked I/O can outlast
userspace deadlines. Results are `references_found`, `none_observed` or `unavailable`;
permission failures, disappearing links, invalid identities and work limits retain
classified counts, never raw exception bodies. No gaps recorded still does not
establish full coverage. Procfs restrictions (including hidepid), unobservable PID
namespaces, nonleader threads with private descriptors, process churn, references
closed before inspection, copied bytes, anonymous memory and compromised root/kernel
remain outside this bounded inode observation. A memory mapping is not necessarily
executable, and a reference is not proof of malware execution.

Administrators can inspect a retained or uncertain response even while its own
response hold pauses ordinary work. Another response's hold, a running or recovery
required Activity job, and pending response work still prevent access. Queue entries
bind the prepared plan digest and pinned SSH host. The worker performs fresh
independent current-agent verification and ends MySQL snapshots before rechecking
scope immediately before SSH and after the reply. Stale queued work is skipped;
protocol/helper/transport failures are explicitly unavailable. Observations never
update quarantine state, restoration readiness, monitoring coverage or hold status.
A report that became historical during I/O is retained with `scope_current: false`;
that field records scope agreement **at receipt time**, not continuing validity.

**Process reference history** displays paginated append-only application records,
counts, matches, gaps, actors and timestamps. The card shows the latest observation
time; results are always historical samples. The new
`security_response_process_observations` table participates in startup initialization
and verified offline SQLite/MySQL migration. These records require protected backups
and are not cryptographically immutable. No file contents or raw `/proc` documents
are retained. Rebuild app/workers and redeploy current helpers using **Finish /
verify installation** before using the new action; older helpers refuse it.

Tests include exact-inode matching, same-byte replacements, descriptor and mapping
metadata, helper-self exclusion, PID changes, symlinked PID directories, denied or
disappearing references, bounded partial results, unavailable evidence, stale queue
bindings, independent agent checks, scope changes during I/O, roles, holds, receipt
validation and paginated history. Native SSH validation retains a harmless process
descriptor across quarantine and checks the real worker/helper on Debian, Ubuntu,
Fedora and AlmaLinux. Those containers stub systemd; real-VM/SELinux, performance
and broader response drills remain future work. Approved process suspension/recovery,
cloud isolation and authenticated vendor repair remain subsequent milestones.

## Separately approved process suspension and recovery

After a **fresh process reference observation**, an executable match in **Process
reference history** offers **Prepare process suspension**. This is read-only
preparation plus a zero-signal permission/support probe. Descriptor-only and
mapping-only references cannot authorize suspension. The observation must be no
more than five minutes old and bind the same pinned host and quarantined original.
The helper verifies retained bytes and journals, boot identity, the selected process
and its executable before returning a plan. Preparation expires after 15 minutes.

**Reviewed process responses → Review process suspension** requires a reason and
`SUSPEND`. It authorizes one SIGSTOP for the selected root-owned process leader and
its thread group, with a five-minute execution approval. This can interrupt
services, retain locks and leave transactions unfinished. It does not stop children,
other holders, other copies, containers, network access or the host. It is not a
malware-eradication or complete process-containment verdict. AI-plan review, file
quarantine approval and process inspection never authorize this signal.

Scope is deliberately narrow: all four reported process UIDs must be root, its PID
namespace must match the helper's, it must be a thread-group leader with at most 256
observable threads, and its executable must be the verified held original inode.
Init, the helper and its ancestors are excluded. Already stopped/traced, exited,
unobservable, mismatched and unsupported targets require console response. Do not
change credentials or protections to bypass refusal. A process can exec a different
image between inspection and signal; approval identifies the process, and failed
post-signal executable/identity checks retain uncertainty for console recovery.
Concurrent root interference is outside these guarantees.

Linux `pidfd_send_signal` is mandatory. The helper uses the opened `/proc/<pid>`
**directory descriptor**, supported by that syscall as a stable reference to the
selected task. There is no numeric `kill()` fallback. This also avoids confusing
PIDs from a mounted procfs view with the helper's own numeric PID coordinates.
Preparation and execution bind boot ID, namespace, PID, start ticks and the opened
proc-directory device/inode. The extra proc inode binding can conservatively refuse
an evicted/recreated proc entry. A reboot, changed credentials, namespace, executable,
retained bytes or process identity refuses new signals. See the Linux
[pidfd signal interface](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html).
Older kernels/Python runtimes without this interface refuse preparation.

Before signal delivery, protected 0700 directories and 0600 append-only intent
journals are fsynced under `/var/lib/mrpatchy-process-response/<response-id>/`.
An operation ID never sends SIGSTOP twice. Post-action checks require all observed
threads to be stopped (`T`) and revalidate the retained original before reporting
`suspended`. The helper observes for up to eight seconds; blocked/unobservable or
changed threads remain uncertain. A lost completion journal can be reconciled from
its bound intent and positive current evidence without replaying the signal.
Clock-dependent approvals are checked immediately before intent and again before
the syscall. Expiry after durable intent deliberately leaves reviewable uncertainty.

**Verify process response** reads journals, process identity, thread states,
executable and retained original without delivering a signal or changing journals.
It reports `suspended`, `resumed`, `exited`, `identity_changed`, `not_started` or
`uncertain`. Missing or corrupted existing journals do not establish an unstarted
operation. Process exit is an observation, not proof that its children or a service
supervisor did not start another process. No automated resuspension occurs.

**Review process recovery** requires fresh (five-minute) verified suspension and a
separate reason-and-`RESUME` approval. Resumption can continue malicious execution.
The helper rechecks identity, held executable and all stopped threads, durably writes
a separate resume intent, and sends one SIGCONT through the same stable descriptor.
Only a positive current running/sleeping thread-group observation with that intent
reports `resumed`. Interrupted resume intent is never retried by a new approval;
uncertain recovery requires console review. No signal terminates the process, and
no signal authorizes restoration of its file.

Approval creates a separate **process response hold** before queueing. The worker
commits uncertainty before a mutating RPC, rechecks approvals after fresh independent
current-agent verification, and ends MySQL snapshots before final state decisions.
Lost replies, bad receipts and scope changes retain that hold. Preflight refusal
before requesting a signal releases only that attempt's new process hold. Matching
verification/recovery can run through its own process hold and owning file hold;
other response/recovery holds still block it. Ordinary work, agent maintenance,
scans and retained-file monitoring defer. A process hold has its own fleet alert and
cannot be cleared by the file-response review. Local controller archive verification
remains available. After verified resumption only the process hold clears; the
independent file-response hold remains until its separate review or restoration.

**Review process pause** can record `ACCEPT PROCESS EXIT` after fresh observed exit,
or `CONSOLE RECOVERED` following trusted-console recovery and service review. These
are reason-bound administrative reviews, send no signals and never resolve the
incident. Console review can release uncertainty, so inspect deferred jobs before
releasing any pause. Other independent holds continue to block work.

The Security panel retains paginated plans, typed approvals, observations and manual
reviews with actors/timestamps in `security_process_responses`,
`security_process_approvals` and `security_process_events`. Startup initialization
and verified offline SQLite/MySQL migration include all three. Host journals need
separate protected backup; application records are not cryptographically immutable.
No command lines, environment, memory bytes or file contents are collected by this
executor. There are no automatic signals, retries, expiry-driven resumes or paid AI
calls. Rebuild app/workers and redeploy current helpers before using it.

Target/controller tests cover real stable-descriptor stop/resume, identity/boot/
namespace/credential/executable changes, init/ancestor exclusion, thread budgets,
expiry before and after intent, lost completions, interrupted recovery, PID exit,
separate approvals, role/host binding, independent holds, stale evidence, malformed
receipts, read-only recovery, scheduling deferral and database migration. Native SSH
integration repeats full preservation, independent acquisition, executable quarantine,
worker preparation, suspension, verification, separately approved recovery and file
restoration on Debian, Ubuntu, Fedora and AlmaLinux. Privileged fixtures skip on
unprivileged runners; production guards remain enforced. Containers stub systemd;
real-VM/SELinux, supervisor/child-process coverage, performance and broader response
drills remain future work, along with cloud isolation and authenticated vendor repair.

## Authenticated replacement preparation (read-only)

The next trusted-repair prerequisite is available as **Security → Reviewed file
responses → Prepare trusted replacement**. Enter an operator-provisioned offline
vendor bundle ID. **Trusted replacement preparations** retains the authenticated
selected-file metadata and a fresh read-only readiness observation. This feature
**does not publish a replacement, transfer replacement contents to the target,
approve execution, run package scripts, signal a process, release a pause or resolve
an incident**. There is no repair execution endpoint or publication button in this
milestone. Ready describes the observation, not a continuing guarantee or approval.

Provision the existing Debian or RPM offline package bundle and independently
approved controller trust keys as described earlier. In that bundle directory,
place the separately extracted **regular-file bytes** for the quarantined pathname
at the constant leaf `replacement`, e.g.
`/data/vendor-packages/<bundle-id>/replacement`. Protect bundles and replacement
files through the controller's controlled forensic/administrative workflow. They
are not browser uploads and are never sent to AI. The payload can be supplied
separately because its exact byte length and SHA-256 must match the unique regular
file entry in the authenticated package artifact. No new archive extraction or
maintainer-script execution is introduced. The whole Debian signature/index/artifact
chain or native isolated-database RPM signature/digest verification still runs.
Unsigned artifacts, unlisted paths, symlinked payload files, mismatched bytes,
expired Debian metadata and changed trust fail closed.

The controller authenticates the package and hashes the selected payload **before
any helper access**, then performs fresh independent current-agent verification.
The target receives only package/file metadata and the bound quarantine plan; it
receives no replacement bytes. After target I/O the controller authenticates and
hashes the payload again. Artifact, keyring, signers, manifest or payload changes
cannot produce a ready preparation. The stable authentication digest excludes only
the per-call authentication timestamp; the retained report includes provenance.
RPM offline verification does not establish current repository membership or the
latest key revocations. Operators remain responsible for approved publisher keys.

The target checks the protected original-response journals and held inode/hash,
completed quarantine, unchanged protected ancestors and an empty original pathname.
The selected path must be the quarantined regular-file path, use the supported
canonical ASCII path characters, and lie below `/srv/` or `/opt/`, excluding
`/opt/drpatch`. An occupied destination, including a symlink or legitimate new
deployment, is explicitly blocked and never overwritten. Lost/incomplete quarantine,
missing evidence and races cannot imply readiness. Protected evidence is rehashed
and namespace facts rechecked after package queries; no journals or directories are
created by the readiness action.

Exact installed package version/architecture and unique ownership of the selected
pathname are checked before and after the observation. RPM also binds the epoch and
uses `--noplugins`; neither query path invokes package verification scripts. Debian
diversions, multiple owners/providers, diagnostics or changed DB observations block
readiness. These local package DB facts are compatibility observations, not
independent vendor authentication or an attestation of compromised root/kernel.
The publisher/artifact byte authentication occurs independently on the controller.

The initial metadata policy supports original UID/GID 0, no extended attributes,
and only modes 0600, 0640, 0644, 0700, 0750 or 0755 from the previously reviewed
quarantine snapshot. Other ownership, permissions, ACLs/capabilities, labels or
attributes require a different reviewed procedure. **Those original permissions
are not authenticated vendor permissions.** The preparation shows the proposed
policy explicitly. It does not reconstruct package ownership metadata, configuration
semantics, service dependencies, generated files or a complete package installation.
Same-version authenticated bytes can still be vulnerable; readiness is not a
malware-free or service-health verdict.

This manually requested read can run through its owning file hold and process holds
belonging to that same file response. The exemption is limited to this read-only job;
it does not enable other file/process actions. Unrelated response holds, running
work and Activity recovery requirements still block it. Deferred automatic retained
checks cannot deadlock the manual read. All existing file/process holds and their
receipts remain unchanged after ready, blocked or failed observations. No automatic
preparations, paid AI calls or policy changes are enabled.

Each request creates a retained `security_repair_preparations` record containing
actor, pinned host, original plan digest, selected path/bundle, timestamps, package
provenance and classified facts/gaps. Its terminal receipt is never overwritten;
refreshing readiness requires a new request. States are queued, ready, blocked,
unavailable or skipped. Blocked is a completed negative observation, not successful
repair. Authentication/helper/transport/protocol failures retain only classified
stage and exception type, not arbitrary diagnostic bodies or file contents. Scope
changes are checked using fresh MySQL snapshots, and historical target observations
cannot be promoted to ready after their controller scope changes. Records are
paginated in Security and included in startup initialization and verified offline
SQLite/MySQL migration. They are not cryptographically immutable and have no automatic
retention policy. Back up operator bundles/payloads separately from database metadata.

The existing artifact limits remain: 64 MiB package artifact, 32 MiB selected payload,
and bounded archive work. Retained preparation provenance is capped at 32,000 bytes.
Debian zstd sections are decoded incrementally without extraction, with a 128 MiB
window limit, 130 MiB decoded stream limit and 20-second decode budget. Truncated,
concatenated and trailing-data frames are rejected; the existing per-member,
aggregate-content and member-count limits still apply after decoding.
Signature/native RPM command deadlines apply independently; package identity/owner
queries each have ten seconds. Target readiness has a 150-second SSH deadline plus
independent health verification; each retained hash phase keeps its 30-second budget.
Kernel-blocked I/O can exceed userspace deadlines. Rebuild app/workers and redeploy
current helpers with **Finish / verify installation** before using this action.

Tests cover authentic selected bytes, payload/path/trust changes, stale scope,
protocol contradictions, role/host boundaries, immutable history, related/unrelated
holds, exact package/owner checks, metadata policy, retained evidence, occupied paths,
read-time races and read-only filesystem behavior. Native SSH validation uses signed
Debian/RPM packages with an owned `/srv` file on Debian, Ubuntu, Fedora and AlmaLinux,
including positive readiness and a legitimate occupied destination, while preserving
original evidence and holds and checking that no package verification script runs.
Containers still stub systemd; real-VM/SELinux and broader performance drills remain.

Private transfer/staging and separate live-file publication are described below.
No preparation record is an execution token. Broader trusted repair, cloud isolation
and rebuild/credential workflows remain unfinished.

## Separately approved private replacement staging

On a ready **Trusted replacement preparation**, **Review replacement staging**
requires a meaningful reason and `STAGE`. The preparation must be no more than
15 minutes old, bind the current pinned host, quarantine plan and exact displayed
preparation report, and still describe a quarantined original. Each preparation
can authorize only one staging operation. The staging approval expires after five
minutes and is recorded independently from preparation, quarantine and process
approvals. There is no automatic staging policy or paid AI action.

The worker authenticates the offline artifact, selected payload and publisher
trust again before target access, after fresh independent current-helper checking,
before finishing transfer and after the reply. It loads only a SHA-256/size-matching
selected payload, never an arbitrary user-supplied target path. Changes in artifact,
keyring, signers, manifest or bytes cannot become a positive staging completion.
Queued scope, approval expiry and unrelated recovery/response holds are rechecked
with fresh MySQL snapshots between requests and after final I/O.

The target's existing **4,000,000-byte request ceiling is unchanged**. At most
32 MiB is sent in chunks of at most **1 MiB decoded** (about 1.4 MB base64 per
request). Chunks travel through the existing pinned SSH/bridge route, including
IAP where configured; payload contents never enter HTTP/browser uploads, the
database…64156 tokens truncated…ocess and namespace instances with otherwise exact receipts and produce
identical canonical follow-up components.

Configuration and effective-behavior components remain incomplete and the coverage
component retains every disclosed gap. Current assessments therefore still produce no
known-good fingerprint and always contact the provider. There is no cache table,
publication/lookup/hit, implicit approval, response authorization, detector
suppression, schema/helper change, Docker publication, Git tag or schedule change.
APP_VERSION/README/changelog/UI/API synchronize at v1.26.0; major remains 1.

Focused acceptance covers cross-host observation independence, security-context and
requirements sensitivity, invalid-receipt gap preservation, retained assessment
history and provider-input observation redaction. The finite program remains
unfinished: collect complete configuration/behavior/coverage manifests, then add
durable safe-only publication and atomic cross-server zero-call lookup, audited
invalidation/revocation, contradiction-linked review, explicit Re-triage bypass and
SQLite/MySQL race/role acceptance. Shared pacing/spend modes and remaining roadmap
programs follow under the existing priority.


## v1.27.0 — Durable safe-candidate publication

Issue-first reconciliation read current main `bda18815`, repository instructions,
this checkpoint and merged PR #86. The first 100-item open-issue and open-PR pages
were empty, so no actionable GitHub report or unfinished delivery competed with this
roadmap batch. The chat-reported database-migration refusal remains blocked on its
v1.23.1 mismatch category/list or a separately reviewed schema inventory; no object
is ignored or guessed away and no closure is claimed.

This dependency-ordered exact-known-good milestone adds durable publication after a
retained AI Assessment is recorded. Only the existing complete low-risk canonical
contract can publish. A fingerprint-keyed entry retains the contract version, exact
model and policy binding, AI classification provenance, original assessment/server
identity and result. Assessment-keyed observation rows retain host/PID/time fields
separately, so host-specific evidence never enters the canonical contract.

Publication uses a database uniqueness boundary and nested transaction savepoints.
Concurrent exact candidates converge on one entry while retaining each observation;
a fingerprint whose stored canonical/model/policy identity differs fails closed.
Idempotent retries add nothing, and an inactive entry is not reactivated. Audit rows
record only the fingerprint and assessment/server identifiers, not raw evidence.
Assessment detail reports `published` only while an active durable entry exists.

Current runtime receipts still lack complete configuration, effective-behavior and
coverage components, so they remain ineligible and publish nothing. This milestone
does not perform cache lookup, avoid a provider call, approve behavior, authorize a
response or suppress deterministic protection. Explicit Re-triage bypass, audited
revocation/invalidation, contradiction-linked review, role-scoped cache management
and actual zero-call cross-server hits remain planned.

The two new candidate/observation tables require current controller startup before
offline database migration or matched workers use the schema. Standalone migration
acceptance preserves both tables and keeps strict unknown-object refusal. Focused
acceptance covers eligibility, nonpublication, idempotence, cross-host and concurrent
deduplication, contextual misses, inactive entries, retained API state and published
UI text. APP_VERSION/README/changelog/UI/API synchronize at v1.27.0; major remains 1.
No Docker publication, Git tag or schedule change is introduced.

Versioned implementation commit
[`a630d669`](https://github.com/StealthCat/MrPatchy/commit/a630d6698d1a331bce26511974b9f17036cf6e55)
is published in [PR #87](https://github.com/StealthCat/MrPatchy/pull/87), targeting
`main` with label `v1.27.0`. The exact final documentation head, all required workflow
results and actual merge commit are recorded in the completion report; this reference
does not permit merging an earlier or failed head.


## v1.28.0 — Strict exact-match safe-result reuse

Issue-first reconciliation read current main `10b8ca08`, repository instructions,
this checkpoint and merged PR #87. The first 100-item open-issue and open-PR pages
were empty, so no actionable GitHub report or unfinished delivery competed with this
roadmap batch. The chat-reported database-migration refusal remains blocked on its
v1.23.1 categorized mismatch list or a separately reviewed schema inventory; no
database object is ignored or guessed away and no closure is claimed.

This dependency-ordered milestone adds conservative lookup before a process-triage
provider call. The worker derives the exact one- and two-stage policy digests from the
current unchanged investigation policy and checks the complete host-independent
fingerprint for the configured model. An active entry is usable only if its stored
contract and safe result re-evaluate to the same fingerprint and its original retained
AI assessment plus isolated observation still agree with the registry provenance.
Missing, changed, inactive, orphaned or corrupt state fails closed and proceeds through
the normal provider flow.

On a hit, Mr Patchy sends no provider request and records an AI run with zero calls.
It retains a new `known_good`-sourced Assessment, current server observation and
redacted audit link to the original fingerprint/assessment/server. The original
explanation and recommended checks remain visible; source provenance is not
misrepresented as a fresh AI call. The current behavior remains unapproved, no
response is authorized, and signatures, scanners, incident evidence and later changed
observations continue normally.

An existing explicit administrator Re-triage row is a mandatory lookup bypass. The
fresh result retains the request and follows the normal AI pause, lifecycle, model,
data-sharing, retry and admission path. Focused acceptance proves exact cross-server
zero-call reuse, contextual/model/policy/inactive misses, original-provenance
validation and a worker-level Re-triage provider call. Responsive Assessment history
labels reused provenance and preserves escaped text, deep links, Back/reload and role
boundaries.

Current native runtime collection still declares configuration, effective-behavior
and complete-coverage gaps, so it remains ineligible and publishes/hits nothing. This
is a strict runtime boundary plus synthetic complete-contract acceptance, not a claim
that ordinary production evidence is ready. Lookup also remains after the existing
claim, global/server AI enablement/pause, key/model and rolling-hour gate; shared
rate/spend admission is not implemented. Fleet revocation/invalidation UI,
contradiction-linked review, native complete-context collection, concurrent
revocation/MySQL end-to-end acceptance and administrator-origin classifications remain
finite known-good work. Same-server parallelism, fairness and shared throttle/daily-
spend/unthrottled controls remain planned.

APP_VERSION/README/changelog/UI/API synchronize at v1.28.0 with major fixed at 1.
No schema, target-helper/agent update, Docker publication, Git tag or schedule change
is introduced. Versioned commit, PR, exact-final-head checks and merge references are
recorded in the completion report after publication; no earlier or failed head may be
merged.


## v1.29.0 — Audited fleet candidate invalidation and linked review

Issue-first reconciliation read current main `05c46912`, repository instructions,
this checkpoint and merged PR #88. The first 100-item open-issue and open-PR pages
were empty, so no actionable GitHub report or unfinished delivery competed with this
roadmap batch. The chat-reported database-migration refusal remains blocked on its
v1.23.1 categorized mismatch list or a separately reviewed schema inventory; no
database object is ignored or guessed away and no closure is claimed.

This dependency-ordered exact-known-good milestone adds an administrator-only fleet
invalidation mutation to Assessment detail. A meaningful reason and explicit UI
confirmation are required. The API reuses existing CSRF/role enforcement, validates
the fingerprint and expected contract version, and serializes with the distributed
`ai-triage` lock used by worker lookup/result persistence. A successful mutation
stores actor, time and reason, audits only registry identifiers plus that reviewed
reason, and makes every later lookup miss immediately. Stale, duplicate, missing or
concurrently changing entries fail without partially updating registry state.

Revocation never rewrites an Assessment result or its isolated observation. The
source assessment and every exact-reuse assessment remain linked to the inactive
entry and now report `review_required`, linked count and revocation provenance.
Assessment history renders this state with escaped text, preserves the original
source deep link and directs administrators to explicit Re-triage for fresh provider
work. It does not confer or withdraw a host-specific approval, authorize a response,
suppress deterministic protection or claim a host is clean.

Focused SQLite acceptance covers immediate lookup denial, original/reused linked
review, audit provenance, role/CSRF enforcement, stale versions, duplicate requests,
AI-state lock conflict and malformed fingerprints. Browser acceptance covers the
confirmation workflow, 320/768/1440 responsive layouts, escaped actor/reason text and
the post-revocation history state. The local workspace could not download Playwright's
Chromium artifact, so exact-final-head CI browser acceptance remains mandatory before
merge.

Current native runtime collection still declares configuration, effective-behavior
and complete-coverage gaps and therefore publishes/hits nothing. Automatic
contradiction-triggered invalidation, administrator-origin classifications, native
complete-context collection, broader SQLite/MySQL concurrency/revocation acceptance,
same-server fairness and shared throttle/daily-spend/unthrottled controls remain
planned.

APP_VERSION/README/changelog/UI/API synchronize at v1.29.0 with major fixed at 1.
No schema, target-helper/agent update, Docker publication, Git tag or schedule change
is introduced. Versioned commit, PR, exact-final-head checks and merge references are
recorded in the completion report after publication; no earlier or failed head may be
merged.


## v1.30.0 — Exact-context contradiction invalidation and linked review

Issue-first reconciliation read current main `85c4abc8`, repository instructions,
this checkpoint and merged PR #89. The first 100-item open-issue and open-PR pages
were empty, so no actionable GitHub report or unfinished delivery competed with this
roadmap batch. The chat-reported database-migration refusal remains blocked on its
v1.23.1 categorized mismatch list or a separately reviewed schema inventory; no
database object is ignored or guessed away and no closure is claimed.

This dependency-ordered exact-known-good milestone closes the automatic contradiction
boundary. After a normal fresh provider path persists a final medium/high/unknown
assessment, the worker derives the candidate identity using a non-authorizing low-risk
probe and reuses the existing strict lookup validation. Only an active entry with the
identical complete canonical context, requested model and policy digest is locked and
invalidated. Results with outstanding requested checks, provider failures, incomplete
evidence, changed context, model or policy do nothing.

The entry records the retained contradictory assessment identity, timestamp and a
bounded system reason. Audit includes only registry/assessment identifiers, risk and
linked count, never raw evidence. Source and exact-reuse observations remain immutable;
their authenticated detail status revalidates the contradiction against the same
fingerprint before exposing its subject/host/risk and a deep link. Every linked result
is marked review-required, but the new advisory output does not confer or withdraw a
host approval, authorize containment, suppress deterministic protection or invent a
response action.

Focused acceptance first reproduced that a high-risk Re-triage left the old active
entry reusable. It now covers a real worker provider call, retained refresh provenance,
immediate reuse denial, source/reuse review state, identity-checked contradiction links,
redacted audit provenance, partial-result refusal and contextual misses. Browser
acceptance covers the escaped deep link and advisory boundary on existing responsive
Assessment history. SQLite/MySQL and browser jobs remain mandatory on the exact final
commit before merge.

Current native runtime collection still declares configuration, effective-behavior
and complete-coverage gaps and therefore publishes/hits nothing. Administrator-origin
classifications, native complete-context collection, broader SQLite/MySQL concurrency
and revocation acceptance, same-server fairness and shared throttle/daily-spend/
unthrottled controls remain planned.

APP_VERSION/README/changelog/UI/API synchronize at v1.30.0 with major fixed at 1.
No schema, target-helper/agent update, Docker publication, Git tag or schedule change
is introduced. Versioned commit, PR, exact-final-head checks and merge references are
recorded in the completion report after publication; no earlier or failed head may be
merged.


## v1.31.0 — Shared smooth-rate AI provider admission

Issue-first reconciliation read merged v1.30.0 main, repository instructions, this
checkpoint and recent PR #90. The first 100 open-issue and open-PR results were empty,
so no actionable issue or unfinished delivery competed with this roadmap batch. The
chat-reported database-migration refusal remains blocked on its categorized v1.23.1
schema mismatch output or a separately reviewed schema inventory; no unknown object
is ignored and no closure is claimed.

The selected faster-triage milestone replaces separate burst admission after explicit
migration with one durable logical-work boundary. Every existing billable
`ai.request` path—process triage and follow-ups, update scoring, connection tests,
incident/startup plans and release configuration review—now reserves through the same
distributed lock before transport or call-receipt creation. Rate mode advances one
fleet-wide next-start timestamp by `3600 / configured work starts per hour`; idle time
never accumulates a burst. Required follow-ups and multiple reviewed configuration
calls within the same admitted run/job reuse only that bounded scope and still recheck
pause/lifecycle policy. A crash or later retry requires a new reservation. Concurrent
SQLite/MySQL workers can admit only one competing work item.
Invalid local keys/models and policy-paused work fail before a reservation.

Existing installations without a saved mode stay on their former investigation,
scoring and hidden incident/startup-plan hourly allowances. Settings presents the
lower former automatic allowance as the conservative migration preview. Only an
administrator save changes modes, and the old/new mode is retained in audit; fresh
installations default to shared rate. Shared mode disables the former purpose-specific
pre-gates, while the central boundary covers their provider calls. Unthrottled mode
removes only Mr Patchy's pacing and retains finite executor concurrency, provider
limits, global/per-server pause, lifecycle, role and sharing controls.

AI worker status reports the configured mode and durable next eligibility. A triage
rate refusal is retained as a deferred item at that eligibility without consuming a
retry attempt or sending a provider request. The admission row contains only bounded
model metadata, count and timestamps—no key, request body or evidence—and is included
in current-schema initialization and offline migration.

Focused regression first failed because no shared module/provider boundary existed.
Acceptance covers smooth spacing, restart-durable state, eight-thread atomic refusal,
transport-not-called behavior, invalid-local-configuration non-consumption, explicit
migration/status and legacy/unthrottled semantics. Exact-head SQLite, MySQL, browser
and full-suite checks remain mandatory before merge.

This is not the complete shared-controls program. Administrator-set USD/day caps,
timezone/reset semantics, conservative multi-stage reservations, actual-usage
reconciliation, uncertain-charge retention, pricing refusal, spend dashboards and
exact durable defer/resume behavior for every manual/plan path remain planned.
Same-server fairness, native complete context and administrator-origin exact-safe
classifications also remain planned. APP_VERSION/README/changelog/UI/API synchronize
at v1.31.0 with major fixed at 1. Rebuild the controller first to initialize the new
table, then matching workers. No target-helper/agent update, Docker publication, Git
tag or schedule change is included.


## v1.32.0 — Conservative daily AI spend admission and retained ledger

Issue-first reconciliation read merged v1.31.0 main, repository instructions, this
checkpoint and PR #91. The first 100 open-issue and open-PR results were empty, so no
actionable report or unfinished fix competed with this roadmap batch. The separately
reported database-migration refusal remains blocked on its categorized post-v1.23.1
schema mismatch output or a reviewed inventory; no object is guessed or ignored.

This shared-controls milestone adds explicit daily-cap and rate-plus-daily-cap modes.
Before every current billable provider request, a fleet-wide budget lock calculates
and persists a conservative per-call ceiling from the exact catalogued model,
requested processing tier, bounded serialized request bytes and maximum output
tokens. It uses the highest applicable ordinary/cached/cache-write input rate.
Unknown models, snapshots, tiers, tool fees, unbounded output, unsupported cache
settings and unpriced long context fail closed before rate admission or transport;
none becomes a zero-dollar reservation. Combined mode reserves budget before
consuming a smooth-rate start.

The independent `ai_budget_entries` ledger records only run/call identifiers,
bounded model/rate provenance, timestamps, status and amounts—never keys, prompts or
evidence. It is not part of diagnostic-history cleanup. A valid usage receipt
reconciles to the retained public-price estimate. An unsent failure releases its
reservation. Once provider transmission begins, a timeout, restart or unavailable
usage/price retains the full ceiling as uncertain; a later valid receipt may still
settle it. SQLite and MySQL contenders serialize admission with the existing
cross-process lock design.
Offline migration fingerprints encode fixed-precision decimal values with an explicit
type tag so SQLite/MySQL copies compare the ledger without float conversion.

Administrators choose the USD/day cap and an explicit validated IANA reset timezone.
Mode, cap and timezone changes are audited. Settings and worker status expose
settled, reserved, uncertain, counted, remaining and reset values and explain that
estimates are not provider invoices. Unthrottled continues to remove only Mr Patchy
rate/spend controls, not provider limits, finite concurrency, pause, lifecycle, roles
or data-sharing policy.

Regression acceptance first failed because no `ai_budget` module or ledger existed.
Focused coverage includes unknown-pricing refusal before rate/provider work,
eight-thread atomic admission, reset/remaining status, actual reconciliation,
uncertain transmitted failures, unsent release, combined-mode settings and timezone
validation. Exact-head SQLite, MySQL, browser and full-suite checks remain mandatory.

The bundled public-price catalog now carries an exact reviewed-at and expires-at
window. Settings expose its safe version/source/freshness metadata. At the expiry
boundary, daily-cap and combined-cap admission fails before consuming rate capacity
or contacting the provider; rate-only and unthrottled operation remain independent
of Mr Patchy's spend guard. Updating the catalog still requires a reviewed source
change, and post-call estimates remain advisory rather than provider invoices.

This does not complete the program. Exact durable defer/resume for every manual and
plan path, automated/signed pricing-catalog updates, provider-invoice reconciliation,
long-horizon reports and full SQLite/MySQL reset/failover acceptance remain planned.
APP_VERSION/README/changelog/UI/API synchronize at v1.32.0 with major fixed at 1.
Rebuild the controller first to create the ledger table, then matching workers. No
target-helper/agent update, Docker publication, Git tag or schedule change is included.


## v1.33.0 — Fleet-wide provider backoff and Retry-After admission

Issue-first reconciliation read merged v1.32.0 main, repository instructions, this
checkpoint and PR #92. The first 100 open-issue and open-PR results were empty, so no
actionable report or unfinished fix competed with this roadmap batch. The separately
reported database-migration refusal remains blocked on categorized schema mismatch
output or a reviewed inventory; no database object is guessed or ignored.

This safe-transport milestone closes the cross-purpose provider-floor gap. Before
budget or rate admission, every current billable `ai.request` path reads one durable
fleet-wide backoff row. A transient 408, recognized rate-limit 429, supported 5xx,
timeout or connection failure updates that row under the distributed coordination
lock. Valid numeric or HTTP-date Retry-After values are retained as a hard floor.
Transient failures without one use bounded full-jitter exponential delay from 30
seconds through 30 minutes. The row contains only failure count, timestamps and a
fixed sanitized reason—never headers, provider bodies, keys, prompts or evidence.

No HTTP request is automatically replayed. Each transmitted attempt retains its own
call receipt and capped reservation; uncertain outcomes continue to count their full
reservation. Work refused by shared backoff creates no provider receipt and consumes
neither rate admission nor budget. Process-triage retries retain the shared next time,
decrement the unsent attempt and remain durably queued; manual retry cannot bypass a
provider floor. A successful response, or a completed non-transient provider error,
clears stale transient escalation only when that request began after the latest
failure; an older parallel success cannot erase a newer floor. Settings and AI worker
status expose only whether the shared floor is active, its consecutive count and next
eligibility.

Regression acceptance first failed because no `ai_provider_backoff` module existed.
Focused coverage spans cross-purpose refusal before rate/transport, restart-durable
state, exact Retry-After, bounded jitter growth, parallel success/failure ordering,
success/non-transient reset, process attempt preservation, manual-retry refusal and
safe UI/status fields. Local validation passed 1,539 tests with 8 skipped, 3 warnings
and 9 subtests, plus compile, JavaScript syntax, diff and version-consistency checks.
Exact-head SQLite, MySQL, browser and remaining CI checks remain mandatory.

This does not complete durable work scheduling. Calls already in flight when another
request discovers a floor cannot be recalled. Manual incident/release plans and
connection tests are safely rejected but are not yet stored as resumable work;
update-scoring retains its existing scheduler cadence rather than an exact per-batch
next time. Pricing-catalog lifecycle, invoice reconciliation, long-horizon spend
reports and multi-controller failover acceptance also remain planned.
APP_VERSION/README/changelog/UI/API synchronize at v1.33.0 with major fixed at 1.
Rebuild the controller first to create the provider-backoff table, then matching
workers. No target-helper/agent update, Docker publication, Git tag or schedule change
is included.


## v1.34.0 — Durable update-scoring deferral and exact resume

Issue-first reconciliation read merged v1.33.0 main, repository instructions, this
checkpoint and PR #93. The first 100 open-issue and open-PR results were empty, so no
actionable report or unfinished fix competed with this roadmap batch. The separately
reported database-migration refusal remains blocked on categorized schema mismatch
output or a reviewed inventory; no unknown database object is guessed or ignored.

This faster-triage milestone gives update scoring its own durable eligibility state.
A batch refused before provider transmission by shared rate, daily-spend or provider
backoff remains `deferred` with the exact shared next time rather than becoming
`error` and waiting for the former generic one-hour attempted-time guard. A transient
sent failure, including a valid Retry-After response, keeps its existing provider
receipt and spend reservation outcome and saves the resulting shared floor for the
next scheduler pass. Controlled deferral reclassifies the redacted run record without
copying provider bodies, headers, keys or package evidence into diagnostics.

An eligible pass does not bypass policy: global/per-server AI pause, host lifecycle,
data sharing, finite concurrency, provider backoff, spend and rate controls are all
rechecked. Changed package/distribution evidence creates a new exact identity and
supersedes the deferred one; removed updates and version/context changes do not remain
in the reported queue. Successful and superseded rows clear their saved eligibility.
Packages exposes the retained assessment time, while worker status reports scoring
deferred count and earliest next start alongside the shared controls.

Regression coverage first reproduced both defects: a pre-send shared-rate refusal
and a transmitted 503 with Retry-After each produced `error` instead of `deferred`.
Focused acceptance then covered zero transport for the rate refusal, exact provider
floor reuse, resume earlier than one hour, successful completion, stale-evidence
supersession, API/status visibility and pooled-schema upgrade behavior. Exact-head
SQLite, MySQL, browser and full-suite checks remain mandatory before merge.

This is not complete durable scheduling. Manual connection tests and incident,
startup and release plans still reject safely rather than becoming stored resumable
jobs. Pricing-catalog lifecycle, provider-invoice reconciliation, long-horizon spend
reports and complete multi-controller failover/reset acceptance remain planned.
APP_VERSION/README/changelog/UI/API synchronize at v1.34.0 with major fixed at 1.
Rebuild the controller first so `update_scores.next_at` is added before matching
workers start. No target-helper/agent update, Docker publication, Git tag or schedule
change is included.


## v1.35.0 — Durable incident/startup advisory-plan deferral

Issue-first reconciliation read merged v1.34.0 main, repository instructions, this
checkpoint and PR #94. The first 100 open-issue and open-PR results were empty, so no
actionable report or unfinished fix competed with this roadmap batch. The separately
reported database-migration refusal remains blocked on categorized schema mismatch
output or a reviewed inventory; no unknown database object is guessed or ignored.

This faster-triage milestone makes the existing durable `security-plan` and
`startup-plan` jobs survive controlled shared-AI waits. A shared smooth-rate,
daily-spend or provider-backoff refusal stores the exact next eligibility in the job
instead of ending it as failed. A global or per-server administrator pause retains
the job with an explicit indefinite resume wait. The scheduler excludes future and
paused plan jobs rather than occupying a worker slot or hot-looping provider policy.

Resume is never an authorization bypass. The normal host lifecycle/revision gate,
global and per-server AI state, current incident identity/evidence, data-sharing
policy, finite worker concurrency, provider floor, budget and rate admission all run
again. Pre-send refusal creates no provider receipt, rate start or spend reservation.
A transmitted transient failure retains its existing call receipt and settled or
uncertain reservation outcome; there is no immediate HTTP replay. Its sanitized run
is reclassified as deferred and the durable job becomes eligible for a later
scheduler attempt at the shared floor. Activity and AI worker status show the
retained plan count and exact next time or resume requirement without exposing raw
evidence or provider bodies.

Regression coverage first reproduced the defect: both a shared-rate refusal before
transport and a policy wait became terminal failed jobs. Focused acceptance then
covered zero provider transport, exact eligibility, early-execution refusal,
administrator pause, retained run diagnostics, successful resume, status/API/UI
visibility and pooled-schema upgrade. Exact-final-head SQLite, MySQL, browser and
full-suite checks remain mandatory before merge.

This does not make multi-stage release planning resumable. A release plan can perform
several paid calls without per-stage durable results; replaying the whole job could
duplicate a completed stage, so it remains safely terminal until stage-level
persistence exists. Interactive connection tests also remain non-durable. Pricing
catalog lifecycle, provider-invoice reconciliation, long-horizon spend reports and
complete multi-controller failover/reset acceptance remain planned.
APP_VERSION/README/changelog/UI/API synchronize at v1.35.0 with major fixed at 1.
Rebuild the controller first so `jobs.next_at` is added before matching workers
start. No target-helper/agent update, Docker publication, Git tag or schedule change
is included.


## v1.35.1 — Linux zero-tick process identity compatibility

Issue-first reconciliation read merged v1.35.0 main, repository instructions, this
checkpoint and merged PR #95. The first 100 open issues contained #97, a reported
fleet-wide collector identity failure, and roadmap issue #96; the first 100 open PRs
were empty. Neither issue had comments or a related open/merged fix. Issue #97 took
priority over the unfinished faster-AI roadmap. Issue #96's distribution/major OS
upgrade indicator is now tracked above and in `docs/UI_DESIGN.md`, but remains open
until its detection and UI acceptance are implemented.

Current main reproduced #97 by passing a valid Linux process identity with
`start_ticks=0`: `response_proc_identity`, collector validation and controller
ingestion all required every integer field to be strictly positive. Linux records
process start time in clock ticks after boot, so a process created during the first
tick may legitimately report zero; native PID 1 commonly exposes the boundary. The
collector caught the resulting `ValueError`, omitted the otherwise bound identity
and stored the fleet-visible generic finding.

The identity contract now permits zero only for `start_ticks`. PID, PID namespace,
procfs device and procfs inode remain strictly positive; negative, malformed,
changed or incomplete identities still fail closed. Collector validation,
controller ingestion, exact follow-up context, known-good eligibility and bounded
process-reference receipts share the corrected boundary. This does not authorize a
PID 1 response: the existing explicit `pid > 1` destructive-response rule remains.
Collector diagnostics now emit bounded reason/errno categories without copying raw
procfs content, paths or exception messages into alerts.

Regression coverage first failed on v1.35.0 for a PID 1-style zero-tick identity and
then verifies collector retention, controller acceptance, exact follow-up binding,
negative rejection and diagnostic redaction. Applicable target/controller, known-
good, response and full SQLite/MySQL/browser/SSH checks remain mandatory on the
exact final commit before merge. Deploy the controller/workers and use the existing
reviewed **Finish / verify installation** flow to update collectors. No database
schema change, Docker publication, Git tag or schedule change is included. Source,
README, changelog, UI/API metadata synchronize at v1.35.1 with major fixed at 1.

After this issue fix, priority returns to the faster-AI program's multi-stage release
plan persistence, remaining billable-path controls, pricing lifecycle and complete
multi-controller failover/reset acceptance. The database-migration refusal remains
blocked pending categorized mismatch output or a reviewed schema inventory.


## v1.35.2 — Bounded loss-aware observation batching

Issue-first reconciliation read merged v1.35.1 main, repository instructions, this
checkpoint and merged PR #99. No unfinished PR existed. Open issues included the
critical event-spool loss report #105, its broader reliability/observability follow-ups
#106–#108, confirmed deferred-plan defects #100–#102, investigation/recovery reports
#103–#104, CI maintenance #98 and distribution-upgrade roadmap #96. Issue #105 took
priority because it reports durable security-observation loss. None of #105–#108 had
comments or a related open/merged fix.

Current main reproduced the normal-load loss condition with 900 individually small
process observations: the combined JSON exceeded a single hard 2 MB ceiling, so the
target persisted zero events and incremented one generic `dropped` counter. The same
counter was also incremented when the 48 MB spool evicted its oldest batch, making the
reported `950 observation batches lost to the target size limit` unable to distinguish
oversize input from delivery backlog/capacity. The controller raised the unchanged
cumulative value on every poll, leaving a recovered server in attention indefinitely.

The target now serializes each process observation independently and partitions normal
snapshots into durable batches no larger than 256 KiB without splitting a record. A
single record exceeding that bound is explicitly rejected while its peers continue.
The existing 48 MB bounded spool remains fail-visible. Oversize-record and capacity-
eviction batch/observation counters are persisted separately, older generic counts are
retained as legacy/unclassified, and telemetry exposes queued bytes plus both limits.
The controller compares cumulative evidence with the previously stored target value:
only a positive delta creates a current integrity finding, with bounded reason detail;
unchanged historical loss stays available in telemetry and no longer claims ongoing
loss. Counter rollback after agent data replacement is handled conservatively as a new
baseline and later increases remain visible.

Regression coverage first executes the v1.35.1 implementation and confirms the 900-
record snapshot yields `pending=0, dropped=1`. The corrected implementation yields nine
bounded batches, no lost observation and unchanged ordering. Focused tests also cover
restart/ACK behavior, individual oversize rejection, forced-capacity eviction, distinct
reason counters, cumulative legacy preservation and active-alert delta semantics.
Exact-final-head SQLite, MySQL, browser, SSH/RPM and remaining CI checks are still the
merge gate. Deploy the controller and then use the existing reviewed agent verification
flow so targets receive the new batching logic. No database schema change, Docker
publication, Git tag or schedule change is included. Source, README, changelog and
UI/API metadata synchronize at v1.35.2 with major fixed at 1.

Issue #105 can close only after the exact tested merge and closure verification. Issues
#106–#108 remain open: configurable flush/capacity policy, negotiated compression,
resource-aware pressure controls, full dashboard/alert history and outage/disk-failure
acceptance exceed this focused fix. Confirmed #100–#102 remain the next issue-fix batch,
followed by safe crash/restart investigation #104. Issue #103 remains a policy question;
#98 and #96 remain lower-impact maintenance/roadmap work. Faster-AI roadmap development
resumes only after these higher-priority actionable fixes.


## v1.35.3 — Deferred advisory-plan contract and status corrections

Delivery record: version **v1.35.3**, implementation commit
[`8adc1765`](https://github.com/StealthCat/MrPatchy/commit/8adc1765a786b01393cf9682edb0a4d8894bd90a)
and [PR #110](https://github.com/StealthCat/MrPatchy/pull/110). The PR may merge only
after all applicable checks pass on its exact final head; the completion report records
that final head and merge commit.

Issue-first reconciliation read merged v1.35.2 main, repository instructions, this
checkpoint and merged PR #109. The first 100 open issues contained #96, #98,
#100–#104 and #106–#108; no open PR existed. Issues #100–#102 are three confirmed,
closely related regressions in the v1.35.0 deferred-plan delivery and took priority
over roadmap work. None had comments or another open/merged fix; PR #95 is their
common source. Issues #103–#104 require separate policy/crash-recovery work, and
#106–#108 remain broader spool reliability/observability milestones.

Current v1.35.2 reproduced all three reports in a disposable SQLite application.
Both operation APIs removed `payload`, while Activity looked inside that absent object,
so neither a timed eligibility nor administrator-resume wait could render. With one
eligible deferred plan and one future plan, status evaluated the future `plan_next`
branch first and reported `backoff`. An `AIError` with `policy_wait=True` and no timed
eligibility produced zero; both plan handlers treated zero as false and `ai_runs.defer`
rejected it, leaving the already-started diagnostic run in `error` although its job
was correctly requeued.

Operation list/detail APIs now expose one explicit `ai_deferred` Boolean derived from
the internal marker while continuing to exclude the complete payload. Activity reads
only that safe projection. Status counts eligible advisory plans separately and gives
eligible work precedence over another plan's future timestamp while preserving the
future `plan_next_at`. Incident and startup handlers distinguish a controlled zero
eligibility from `None`; the durable run becomes `deferred` with a bounded resume
message while the job remains queued at `next_at=0`. Every later execution still
rechecks host lifecycle, global/per-server pause, evidence, provider, rate and spend
controls; the correction creates no provider call or remediation authority.

Regression coverage uses the real list/detail API contract, proves the payload remains
private, exercises mixed eligible/future plans, and drives an untimed policy wait
inside an actual tracked incident-plan call. Existing timed resume, server pause,
scoring, retry, activity-detail, host-scope and JavaScript checks remain required,
followed by exact-final-head SQLite/MySQL/browser and remaining CI before merge.
Source, README, changelog and UI/API metadata synchronize at v1.35.3 with major fixed
at 1. No schema, target-helper/agent update, Docker publication, Git tag or schedule
change is included.

After these issue fixes, #104 is the next confirmed reliability investigation but
requires safe pre/post-transmission crash acceptance rather than automatic replay.
#103 remains a policy decision. Spool follow-ups #106–#108, CI warning #98 and OS-
upgrade roadmap #96 remain open. Faster-AI roadmap work resumes only after higher-
priority actionable issue fixes; multi-stage release persistence, pricing lifecycle,
invoice reconciliation and full controller failover/reset acceptance remain planned.


## v1.35.6 — Interrupted advisory-plan recovery

Delivery record: version **v1.35.6**, original implementation commit
[`7abe6f1e`](https://github.com/StealthCat/MrPatchy/commit/7abe6f1e65e09bb05d0f77c8cd9eac99990041c1)
and [PR #113](https://github.com/StealthCat/MrPatchy/pull/113), which addresses
[issue #104](https://github.com/StealthCat/MrPatchy/issues/104). The issue may close
only after every applicable check passes on the exact final PR head and that commit
is merged.

Issue-first reconciliation read merged v1.35.3 main, repository instructions, this
checkpoint, merged PR #110, all open issues and the absence of an open PR. Issues
#100–#102 were closed by v1.35.3. The remaining list included #96, #98, #103, #104,
#106–#108 and #111. Issue #111 was already claimed by a separate Codex session with a
documented AGENTS/task-instruction scope, so this run did not duplicate it. Issue #104
was the highest-impact independent reproducible report; its thread had no earlier
comments or related open/merged fix before this run claimed it.

A disposable SQLite application reproduced current v1.35.3 with a running security
plan, running diagnostic, missing usage receipt and uncertain spend reservation. A
worker invocation left both job and run permanently `running`; scheduler recovery
selected only release upgrades, and the unreconciled job kept the server quarantined.
The cause was the deliberate safety rule that refuses to replay running advisory work
without a complementary restart path to surface it for human review.

The elected scheduler now scans running incident/startup advisory jobs every five
seconds. It attempts the same distributed per-server lock used by job execution. A
live owner therefore remains untouched; after a process loss, the available lock lets
the scheduler atomically recheck and mark the job recovery-required plus the exact
host/incident-matched running diagnostic interrupted. No job is requeued and no
provider call is made. Existing call receipts and the independent spend ledger remain
unchanged, including conservative uncertain charges. The bounded job/run message
explains that a transmitted call without a receipt may still have incurred a charge.

Activity distinguishes this advisory recovery from a target mutation. An administrator
must explicitly confirm review of the retained run, per-call usage and spend reservation
before releasing the queue. The advisory-only reconciliation uses existing admin, CSRF,
audit and host-lock controls but does not issue an irrelevant SSH operation-status call;
all package/target operations retain their existing trusted-console verification.

Regression coverage exercises both advisory actions, live-lock exclusion, idempotent
recovery, zero replay, bounded diagnostics, receipt/ledger preservation, audit output
and the administrator reconciliation boundary alongside existing orphan and release-
resume tests. Exact-final-head SQLite, MySQL, browser, SSH/RPM and remaining CI checks
remain the merge gate. Source, README, changelog and UI/API metadata synchronize at
v1.35.6 with major fixed at 1. No schema, target helper, Docker publication, Git tag or
schedule change is included.

User-directed PR #113 integration (Codex session `c30b40e47808`) preserves merged
PR #112's v1.35.4 coordination rules and changelog, allocating v1.35.6 because PR #115
already proposed v1.35.5. Advisory-recovery exceptions are logged and paced at the
normal five-second interval without aborting unrelated scheduler admissions. Tests
adapted from the offered duplicate PR #114 exercise actual worker execution interrupted
before and after provider transmission, retained sent spend, no automatic replay,
separate distributed-lock ownership and unrelated-job/run scoping. All applicable
checks must pass on the final integration commit before merge; PR #115 must reconcile
its version and validation against the resulting main.

After this focused issue fix, #103 remains a policy decision, #106–#108 remain broader
spool reliability/observability work, #98 remains CI maintenance, #96 remains the OS-
upgrade roadmap, and #111 remains owned by its claimant. Faster-AI roadmap priority
then returns to multi-stage release-plan persistence, remaining billable-path controls,
pricing lifecycle and full multi-controller failover/reset acceptance.


## v1.35.7 — Failed sign-in and lockout auditing

Delivery record: version **v1.35.7**, branch `fix/failed-login-audit-v1.35.7`, which
addresses [issue #136](https://github.com/StealthCat/MrPatchy/issues/136); the PR
number and tested final commit are recorded on the pull request. Proposed merge order:
after PR #115 and PR #116 (both claim v1.35.5); PR #113 (v1.35.6) has merged and `main`
was merged into this branch. The version must be re-checked against current `main`
immediately before merging.

Before this change `POST /api/login` audited only successful sign-ins (`login`) and
authenticated state-changing requests. Failed passwords, unknown or disabled accounts,
bad MFA codes and rate-limit rejections left no audit history, so password spraying and
credential guessing were invisible to administrators. This was found by code review of
v1.35.3 and is a detection gap, not an authentication bypass.

Failed password sign-ins now record `login failed` with `<username> <address> <reason>`
where the reason is `unknown or disabled account`, `bad password` or `bad MFA code`.
The username is already restricted to `[A-Za-z0-9_.-]{1,64}` by the request model, so
it cannot inject log lines; the submitted password and one-time code are never
recorded. Rate-limit rejections record `login throttled` with the reason `account limit`,
`address limit` or `global limit`, once per limit and five-minute window, so rejected
requests cannot flood the audit table. The audit entries are written outside the global
login lock.

Unchanged: HTTP status codes and response bodies (a client still cannot distinguish an
unknown account from a wrong password), the 10-per-account / 50-per-address / 10,000
global thresholds, scrypt parameters, sessions, roles, CSRF and SSO. Audit reasons are
visible to administrators only. SSO (OIDC) failures are not covered by this change.
Known remaining items from the same review, deliberately separate: per-account
throttling for distributed guessing, the global 10,000-bucket lockout, serialising
logins on one lock during hashing, and purging expired sessions.


## v1.35.13 — Enrollment command temporary-file hardening

Delivery record: version **v1.35.13**, branch `fix/enrollment-temp-file-v1.35.5`; the
PR number and tested final commit are recorded on the pull request. User-directed integration follows PR #137, preserves merged advisory recovery, and allocates v1.35.13 above pending v1.35.12. Exact-final-head CI is required before merge.

The one-line enrollment command issued by `POST /api/hosts/{id}/enrollment-link`
previously downloaded the personalized installer to the fixed path
`/tmp/mrpatchy-enroll.sh` and then ran it with `sudo bash`. A fixed, predictable path
in a sticky world-writable directory lets a local user on the target pre-create or
swap the file before the administrator runs the command. Default Ubuntu/Debian
kernels (`fs.protected_symlinks=1`, `fs.protected_regular=2`) block the symlink and
pre-created-file variants, leaving a denial of service; targets with those protections
disabled remain exposed to execution of attacker-controlled content as root. This was
assessed by code reading and a sysctl check, not by a working exploit.

The command now creates an unpredictable owner-only (0600) file with `mktemp`,
downloads into it, runs it, and removes it:
`f=$(mktemp) && curl -fsSL '<url>' -o "$f" && sudo bash "$f"; rm -f "$f"`. The URL
remains shell-quoted. The downloaded installer content, token lifetime (one hour,
reusable), authentication, roles, audit and the manual download path are unchanged.
Making enrollment tokens single-use is deliberately not part of this change because a
partial download would then require issuing a new link.

Tests assert the command shape, that no fixed `/tmp/` path appears, that the URL
remains a single shell argument, and execute the generated command in a real shell
with stubbed `curl`/`sudo` to confirm a pre-existing `mrpatchy-enroll.sh` is ignored,
the file used is mode 0600, and it is removed afterwards. The browser fixture in
`tests/ui_enrollment.cjs` carries the new command string; it was updated but not
executed locally because Playwright and a supported Node version were not installed.


## v1.35.14 — CI runtime maintenance integration

User-directed integration of PR #115 / issue #98 preserves PR #137 login auditing and PR #116 enrollment hardening. All checkout/setup-python/setup-node actions use v7 and the browser job uses Node 26. Source, README and changelog agree at v1.35.14. Exact-final-head full CI is required before merge; no Git tag or Docker publication.


## v1.35.11 eBPF diagnostic lifecycle (#123)

A single bpftrace stderr warning previously persisted in `ebpf-diagnostic.json`
forever, and controller ingestion treated any nonempty diagnostic as a current
integrity issue regardless of its age or the collector state. A recovered or
intentionally disabled collector therefore kept the host in **attention**.

The collector now tags every recorded warning with the identifier of the bpftrace
run that emitted it, writes that run's `starting` status before its stderr reader
can record anything, and stores the time of the last state transition (`since`) in
`ebpf-status.json`. Under one lock shared with the stderr reader, a warning is
retired (state `historical`, with `retired_at`, `retired_reason` and the recovering
run) when the run delivers its first event, when eBPF is disabled and when the
collector restarts. Retirement preserves the original warning text and time; a later
warning from the current run is recorded as current again, so a persisting or new
fault is not suppressed.

Ingestion independently treats a diagnostic as history when it is retired, when the
collector is disabled, when it belongs to an earlier run than the current status, or
when it predates the current run's transition to active. A current-run warning,
a malformed or non-numeric diagnostic, and status from an older untagged collector
continue to raise the finding (fail closed) until the collector is upgraded through
normal agent maintenance. The delivered diagnostic is retained in host telemetry as
`ebpf_diagnostic`. eBPF status findings (`error`/`warning`/`unavailable`) are
unchanged.

Regressions drive the real collector loop with a fake bpftrace through failure,
recovery, a post-recovery warning, process exit, disable and restart, then deliver
the files through the bridge snapshot to controller ingestion. No schema, role,
audit, response-authorization, Docker publication or Git tag change is included.
Source, README, changelog and UI/API metadata synchronize at v1.35.11 with major
fixed at 1 (v1.35.7–v1.35.10 are reserved by pending PRs/claims #137, #115, #121,
#117, #131 and #124).

## v1.35.20 — Canonical execution-scan UID protocol (#117)

PR #174 fixes the native collector/controller UID type mismatch. Current main
reproduced zero triggers for the collector's decimal-string UID and one trigger when
only the UID became an integer; the rejected event also produced no coverage record.
The collector now validates and emits a bounded integer UID. Intake normalizes legacy
canonical decimal strings, while malformed verified records fail closed and increment
the existing coverage-loss counter.

Regression coverage drives the production parser through durable spooling, ingestion,
trigger creation and scheduler queueing, plus legacy normalization and invalid identity
accounting. Earlier exact-head checks passed after the first reconciliation; this
v1.35.20 reconciliation also preserves v1.35.16 enrollment hardening, login auditing
and CI maintenance, v1.35.17 populated SBOM repair, v1.35.18 AI-budget formatting and
v1.35.19 native Debian comparisons. It must pass all checks again before merge. No
schema, scope, role, response authority, policy default, Docker
publication, Git tag or schedule change is included. P1 issues
#118–#120 remain the next issue-first priority.

## v1.35.16 — User-directed integration of PRs #116, #137 and #115

Main advanced to v1.35.11 while initial integration CI was running. Combined PR #195 preserves that eBPF diagnostic lifecycle update and all original PR heads as ancestors, synchronizes source metadata at v1.35.16 (above pending v1.35.15), and carries the enrollment hardening, failed-login audit and CI runtime maintenance together. The connector cannot write the contributor fork, so the maintainer explicitly approved upstream publication. All nine applicable checks must pass on the exact final integration commit before merge. Verify original PRs and issues #136/#98 close after the tested merge. No Git tags or Docker publication.


## v1.35.17 — Populated SBOM export repair (#121)

Codex session `gfr-sbom-20261031` claimed issue #121 after reading current main
`3635d0a` (v1.35.6), all open issues and open PRs. No related PR or overlapping
claim existed. Pending #115/#116 require version reconciliation; #137 proposes
v1.35.7. This focused update proposes v1.35.17, subject to refreshing main before
merge and rerunning affected checks if integration changes the final head.

The current-main SBOM handler reproduced `NameError: name 'h' is not defined`
with a populated package result using its actual AST-extracted function and stub
session. Local full-app tests could not start because Windows application control
blocked a downloaded SQLAlchemy extension. Full application validation is delegated
to exact-final-head CI, not claimed as a local pass.

The endpoint now retains the resolved host for the existing Debian/RPM package URL
selection. Regression tests exercise populated Debian and RPM JSON exports, escaped
versions and architecture, host isolation, empty/missing hosts, unauthenticated
access and existing administrator/operator/viewer access for active, disabled and
deleted hosts. Existing permission and lifecycle decisions remain in force.

Source, README and changelog synchronize at v1.35.17, major fixed at 1. The linked
PR must record exact-head checks and merge evidence; #121 closes only after that
tested merge is verified. No schema change, target update or Docker publication is
included.

Integration checkpoint: original PR #138 head 02beaa1 passed all nine CI jobs (SQLite 1450 passed/129 skipped; MySQL 1445 passed/134 skipped). Main then advanced to 491df9e (v1.35.11). This merge preserves PR #183 diagnostics and all prior history, allocates v1.35.17 above pending versions through v1.35.15, and requires fresh exact-head CI before merge.

Dependency checkpoint: PR #138 now includes exact PR #195 head 0824d084 as an ancestor and depends on its tested merge first. Enrollment hardening, failed-login auditing and CI action upgrades remain owned by #195; all are preserved here. Fresh exact-head CI validates their combination with the SBOM repair. If #195 changes, refresh/reassess before merge.

## v1.35.18 — Accurate AI budget amounts

Codex session `grab-issue-2-20261031` claims issue #124 in isolated branch
`fix/budget-money-124`. Claim timestamp correction: the claim was posted before
19:21:27 UTC on 2026-10-31; its manually entered 19:24 timestamp was inaccurate.
Issue-first reconciliation listed all open reports and PRs #115, #116 and #137;
#121 was already actively claimed, so this work takes independent unclaimed #124.
Current main was v1.35.6 (`3635d0a`). Proposed v1.35.15 reserves room for pending
v1.35.7/v1.35.8 work and must be reassessed with main immediately before merge.

Executing the actual formatter extracted from current-main source reproduced
`10 -> 1`, `100 -> 1` and `1000000 -> 1`, while `10.000000` remained `10`.
The correction strips zeros only after a decimal point. Both settings request
models validate their float default cap. Regressions cover integral/fractional
and Numeric-style Decimal exponents, signed zero, omitted-cap persistence through
both settings APIs, and the real browser input/remaining-budget amount.

The local Windows host cannot import the Linux-only application's fcntl locking.
Local validation therefore covers the extracted formatter regressions, compilation,
JavaScript syntax, whitespace and version consistency. Exact-final-head Linux
SQLite/MySQL, browser, recovery, SSH/RPM, Docker and GCP checks remain mandatory
before merge. No schema, provider-call, admission-policy or operational authorization
change is included. Source, README and changelog synchronize at v1.35.15; no Git tag
or Docker publication is implied. The linked PR and final validation/merge receipt
are recorded in the issue checkpoints; close #124 only after tested merge verification.

Integration update: current main advanced to v1.35.11 in PR #183 while earlier
PRs remained pending. This merge preserves that diagnostics fix and allocates
v1.35.15 above main and pending v1.35.12/v1.35.13/v1.35.14 proposals.
All nine checks passed on original head 67b5f2e; full exact-head CI must pass
again on this integration commit before merge.

Dependency integration update: v1.35.18 stacks on exact PR #138 head
2bf15092 (v1.35.17), which includes PR #195 head 0824d084 (v1.35.16).
Preserve their SBOM, login-audit, enrollment and CI updates as actual ancestors.
Merge #195 then #138 before this PR. Full exact-final-head checks are required
again; the original budget implementation passed all nine checks. The earlier
v1.35.15 proposal is superseded by this explicit dependency order.


## v1.35.19 — Debian comparison process reuse (#128)

Codex session `grab-issue-3-20261031` claimed unowned issue #128 after checking
open issues, claims and related PRs against main 3635d0a (v1.35.6). An instrumented
execution of the actual current-main inventory helper requested 1,000 dpkg launches
for 1,000 identical pairs. The fix shares one native Debian comparator between APT
refresh and inventory reconciliation, skips exact equality and uses an inventory-local
512-entry LRU cache. Distinct version spellings still go to native dpkg, with a
ten-second timeout and explicit failure on native errors. No Python reimplementation
of Debian ordering, dependency or trust-policy change is introduced. RPM is unchanged.

Focused tests cover unchanged/mixed process counts, bounded cache eviction, timeout
and native errors, epoch/revision/tilde/equivalent spellings and refresh candidate,
hold, architecture and security-priority behavior. Windows standalone comparator
tests pass (four passed; native-dpkg case skipped); Linux native/full SQLite/MySQL,
browser, recovery, Docker/TLS, SSH/RPM and GCP checks remain the exact-head merge
gate. Version v1.35.12 follows pending allocations through v1.35.11 and must be
rechecked against main before merge. Source versioning publishes no Docker image;
no tags, schema, target helper or runtime authorization changes.

Integration checkpoint: preserve main 491df9e v1.35.11 and its eBPF diagnostic
lifecycle fix. Original head 611c6de passed all nine CI jobs, including MySQL
(1446 passed, 134 skipped), SQLite (1451 passed, 129 skipped), native benchmarks,
browser, recovery, SSH/RPM, Docker/TLS/proxy and GCP. Combined-head CI is required
again before merge; existing agent integration hold remains in force.

Final dependency integration: include PR #195 exact head 0824d084 (v1.35.16)
without modifying that workstream. Current source is v1.35.18, reserving v1.35.17
for PR #138. Preserve enrollment temp-file hardening, failed-login auditing and
CI runtime modernization. Original v1.35.12 validation remains historical; all
applicable checks must pass again on this combined head. Hold merge until #195
is tested/merged and its owner releases the integration hold.

Dependency checkpoint: preserve PR #138 exact head 2bf15092 and reserve
v1.35.19 after #139 planned v1.35.18. Await #139 stable combined head before
publishing final integration and restarting all exact-head checks.

Final combined dependency: PR #139 exact 914c6b83 includes #138 2bf15092
and #195 0824d084. Current source v1.35.19 follows those planned merges.
Retain the budget Decimal/default validation fix and SBOM host binding, then run
all exact-head checks before merge. No changes to dependency branches.


## v1.35.21 — Zero-server recovery backup

Delivery record: version **v1.35.21** (initially proposed as v1.35.9) on branch `claude/mr-patchy-issue-fix-e7s51r`,
addressing [issue #131](https://github.com/StealthCat/MrPatchy/issues/131) (Claude Code
session `session_01AfdfYaRTCpQyx5noPLyT4L`). The issue may close only after every
applicable check passes on the exact final PR head and that commit is merged.

Triage read v1.35.6 main, all open issues and the open PRs #115, #116 and #137. This
session first claimed #124 but released it, because a Codex session had claimed it
seconds earlier. #131 had no claim or related PR. It is separate from #120, which
concerns evidence and trust state omitted from successful backups.

Reproduction: a valid application-schema SQLite deployment with secret, TLS and Caddy
state but no `ssh/`, with only restic stubbed, raised `FileNotFoundError` in
`recovery.backup()` before restic was invoked. Enrollment creates `ssh/` lazily.

`scripts/recovery.py` now derives the servers that require an SSH identity (every
`hosts` row with `deleted_at=0`) from the bundled SQLite snapshot, or from a read-only
query alongside the MySQL dump. An absent `ssh/` becomes an explicit empty `0700`
bundle directory. A symlinked `ssh/` is still refused. Each required server must have
a regular, non-empty, non-linked `<id>.key` in the bundle, and server identifiers must
match the application's identifier pattern. Otherwise backup stops before restic runs.
The manifest stays format 1 and adds `ssh_hosts`. Activation applies the same check
before mutating any destination, using the union of the manifest list and, for SQLite,
the bundled database, so an edited manifest cannot hide an enrolled server. Bundles
written before this version, which lack the list, remain accepted. Activation sets
`ssh/` to `0700`.

Compatibility impact: a deployment with a non-deleted server whose key is missing,
which earlier versions backed up without any warning, now fails loudly until the key is
restored or the server is deleted. Major version stays 1.

Coverage: `tests/test_recovery_ssh.py` uses the real application schema to cover:
- zero-server backup and activation;
- a populated fleet, including rotation state;
- deleted servers that need no key;
- missing keys with and without `ssh/`;
- empty or symlinked keys and a symlinked directory;
- activation refusing a bundle without an enrolled key before any mutation, even with
  an edited manifest;
- malformed identifiers;
- legacy manifests.

`tests/test_final_features.py` adds a real restic empty-fleet backup, restore and
activation drill, which runs in the recovery CI job. Exact-final-head SQLite, MySQL,
browser, SSH/RPM and remaining CI checks are the merge gate. No schema, role, audit,
target helper, Docker publication, Git tag or response-authorization change is
included.

Integration: while PR #196 waited, the combined #116/#137/#115 integration (#195) and
#183 merged, moving main to v1.35.16; #138 then merged as v1.35.17, and #174 had also
used v1.35.9. This session respected the #195 integration hold, merged the resulting
main and re-allocated **v1.35.20**, newer than main and the pending #139 (v1.35.18) and
#168 (v1.35.19). Only shared version metadata conflicted; main's entries were kept
intact and this update's entries reapplied.


Final integration (Codex res-20261031): user requested resolution and merge of PR #196. Preserve main 8531ae0 (v1.35.20), including #139, #168 and #174. The earlier v1.35.20 allocation above is historical; current source is v1.35.21, before pending PR #203 v1.35.22. Preserve all main delivery notes and rerun every applicable CI job on this exact final head before merging. No Git tags or Docker publication.

## v1.35.29 — Deleted-server indirect read authorization

Owner: Codex `issue118-a53dc732a02d`, branch
`codex/deleted-host-read-boundary`, issue #118. Read current main `128704f`
(v1.35.21), AGENTS/CONTRIBUTING, checkpoint, 78 open issues and open PRs
#203/#206/#207. #119 and #205 are actively owned; #120 is a separate recovery
scope and #204 depends on active #203. No unrelated roadmap/UI changes selected.
The issue claim's initially written 21:25Z timestamp was inaccurate; the actual
run/checkpoint is 2026-10-31T21:19Z.

Reproduced on unmodified main using disposable SQLite and the real authenticated
FastAPI application: 14 failures / 12 passes in the new regression suite. Viewers
and operators received 200 for deleted-server query-scoped jobs, job output,
investigations and package history; global job/package pages included deleted
records. Direct host paths already returned 403. The cause was URL-only lifecycle
read authorization, without resolved-host checks in query/indirect endpoints.

The fix checks the resolved host before returning query-scoped records or job-ID
output. Job/package list filtering occurs in SQL before pagination. Retained
administrator access, disabled-server read policy, active-only default fleet
investigations, missing/mismatched scope responses and hostless jobs are preserved.
No response authority, schema, helper, audit policy or route-role changes.

Focused validation: 44 passed (26 new authorization cases plus lifecycle suite).
Full Python suite and exact-final-head CI remain required before merge. Source,
README and changelog use v1.35.29 above pending .22/.23/.24 allocations; integration
must recheck main/version order and preserve #206's independently owned role work.
No tags or Docker publication. Issue #118 stays open until a tested merge is
verified. All wider roadmap requirements remain tracked above.

## CI pipeline review (v1.35.24)

The owner requested a full CI review, committed directly to `main`. Changes are
confined to `.github/workflows/ci.yml`, a test-sharding hook in `tests/conftest.py`
and documentation. No application, role, audit, target helper, response-authorization
or Docker publication change is included.

- **Main verification.** The concurrency group was shared by every push to `main`,
  with `cancel-in-progress`. Each merge therefore cancelled the previous main run:
  runs 329, 331, 334, 335 and 337 (v1.35.16–v1.35.20) never completed on `main`.
  Push and manual runs now get unique groups. Only an older run of the same pull
  request (keyed by PR number, not branch name) is superseded.
- **Shell syntax.** `bash -n a b c` parses only `a`, so only
  `deploy/entrypoint.sh` had been checked. Each tracked `*.sh` is now checked on its
  own, as is every tracked `*.js`/`*.cjs` file, and `scripts/`, `tools/` and `tests/`
  are byte-compiled. All of them pass today.
- **Runner image (#197).** Every job is pinned to `ubuntu-24.04`. Adopting Ubuntu 26.04
  should be a separate, fully validated change.
- **Critical path.** A `static` job (10-minute limit) runs version, syntax and
  Compose checks without waiting for the SQLite suite. The serial MySQL suite took
  about 21 of its 30 minutes. It now runs as four isolated jobs (20-minute limit),
  each with its own MySQL 8.4 service. `MRPATCHY_TEST_SHARD=INDEX/TOTAL` assigns whole
  test files greedily by test count, so file order and module fixtures are preserved.
  Every file lands in exactly one shard, and an invalid specification is a usage error.
- **Duplication.** The restic backup/restore drill now runs in the `tests` job by
  installing restic, so the separate `recovery` job was removed. Native RPM unit tests
  use the runner's libdnf/libRPM rather than the matrix target, so they run in the
  `fedora:44` leg only. Pip and npm downloads are cached.

Check names change: `static` and `mysql (1)`–`mysql (4)` are added, and `mysql` and
`recovery` are removed. Branch-protection required checks must follow. Future exact-head
records should list the twelve resulting jobs rather than nine. Action references
remain major-version tags; SHA pinning belongs to supply-chain issue #201.

## v1.35.37 — Rollback adapter stream isolation (#150)

Issue-first triage on current main `6589f4d` found all open P1 issues already owned by
active PRs. Issue #150 was the highest-impact independent unclaimed P2 and had no
related fix. A disposable executable adapter reproduced both snapshot and rollback
misreporting successful JSON as `JSONDecodeError: Extra data` whenever it also emitted
a warning on stderr. `recovery_hook` now invokes the existing bounded subprocess
collector directly, parses stdout alone and rejects stdout above 20 KB before parsing;
stderr remains separately bounded and cannot corrupt the JSON response. Existing
root ownership, writable-bit, executable, operation, identifier and object-response
checks remain unchanged.

Focused regression coverage demonstrates the failure before the fix and covers both
operations, durable snapshot/rollback journal recording and the oversized-response
guard. Exact-final-head static, SQLite, four MySQL shards, browser, SSH/RPM,
Docker/TLS/proxy and GCP checks remain the merge gate. Version **v1.35.37** follows
active allocations through v1.35.36; major remains 1 and no Git tag or Docker
publication is included.

Final integration refresh: main advanced to `8fd8d49` (v1.35.29) after all twelve
checks passed on the earlier head. Preserve PR #212's durable recovery coverage and
PR #208's deleted-server read authorization, including their tests, recovery format
and delivery records. The combined v1.35.37 head requires a fresh full local run and
all twelve exact-head checks; the earlier green run does not authorize merge.

Second final integration refresh: all twelve jobs passed on combined head
`7b0cb3d54f56452ba6e054ab8db863550c2820f8`, and its local tree passed 1,670 tests,
11 skips and 9 subtests. Main then advanced to `db7871e` (v1.35.30) through PR #203.
Preserve its uncertain ordinary-patch outcome hold, remote-start classification,
receipts, audit records and regression suite unchanged. The new combined head again
requires the full local and twelve-job exact-head gates; neither earlier green run
authorizes merge.

Third final integration refresh: all twelve jobs passed on head
`0243975481869722bb39a3ae102779dea5b12ee3`, and its local tree passed 1,682 tests,
11 skips and 9 subtests. Main then advanced to `115e3bd` (v1.35.35) through PR #217,
and open PR #218 allocated v1.35.36. This fix is reallocated to **v1.35.37** and
preserves #217's sanitized, rate-limited rejected-SSO logging/auditing and tests.
The changed version/integration head must pass the full local and twelve-job exact-head
gates again; earlier results do not authorize merge.

Integration continuation — Codex `integration-6eac54918b34`, PR #208, 2026-10-31.
Accepted the explicit #118 handoff and retained the same branch. Reproduced again
on current main `fa5d933` (v1.35.24): 14 failed / 12 passed in
`tests/test_deleted_host_reads.py`. Merged that main into this branch, preserving
all CI pipeline review/sharding changes and both delivery entries. Allocated
v1.35.29 above pending proposals through .28; other owners retain their work and
must reconcile against final main when integrating. This independently scoped P1
read-boundary fix has no dependency on the separate route-role refactor #206.
No roadmap work started. Current open-issue listing returned all 78 reports;
#119/#120/#198/#205 have existing owned fixes, #204 depends on #203, and #140
remains actionable independent work for a later cycle after this integration.
Final local validation and all twelve applicable exact-head CI jobs are required;
no issue closure is claimed until the tested merge is verified. Keep schedule unchanged.


Before merge, main advanced to `6589f4d` (v1.35.25, PR #207 checkbox CSS).
Preserve that exact main and its stylesheet regression. The combined final tree
requires fresh exact-head CI and local focused authorization/CSS/lifecycle checks;
the preceding full local suite passed 1647 tests / 9 skipped / 9 subtests on the
pre-CSS integration tree. Earlier-head CI does not authorize this final integration.

## v1.35.27 — Durable controller recovery coverage (#120)

Codex `recovery-437f6ead2050` selected independent P1 #120 after reading main
fa5d933 (v1.35.24), repository instructions, the checkpoint, all 77 open issues
(one 100-item API page, no next link), six open PRs and candidate issue comments.
P1 #118/#119/#205 already have #208/#203/#209 and retain their owners; #204 depends
on #203. No roadmap work or competing fix was started. Claim comment's 21:40Z
was an inaccurate manually entered timestamp; actual claim was near 21:35Z.

On unchanged main, the new staged-bundle regression failed because
`evidence-archive/sample/content` did not exist after backup. The cause was the
explicit database/key/SSH/TLS-only allowlist in scripts/recovery.py. A format-2
manifest now inventories evidence-archive, vendor-packages, yara-rules and local
gcloud trees with names, sizes and hashes, explicit absence, and verified archive
IDs. Both restore and activation recheck coverage. Backup refuses missing files
for verified archives. SQLite activation independently checks retained SQL rows.
Private evidence/trust/GCP contents restore with 0700 directories, 0600 files and
app service ownership; links/special files are rejected. Format 1 remains readable
with an honest missing-coverage warning. External dependencies and reconstructible
caches are inventoried in docs/ENTERPRISE_RECOVERY.md. Existing response authority,
role/lifecycle and #131 SSH safeguards remain intact; mounted-volume retry work
remains separate in #151.

Validation at first publication: unchanged-main failure recorded; focused recovery
and final-feature suites 37 passed / 4 skipped locally (native restic/MySQL absent).
New tests verify an actual EvidenceArchive after a SQLite snapshot/activation and
reauthenticate signed vendor/YARA bundles using restored keyrings. They cover
modified/missing/extra files, links/FIFOs, missing verified files and legacy/absent
coverage. Native encrypted SQLite and MySQL dump/import drills are CI gates;
MySQL CI now installs restic and MariaDB clients. Full suite and exact-head CI are
pending. This is self-review, not independent approval. No issue closure before
all applicable exact-final-head checks pass and the tested PR merges.

Proposed version v1.35.27 follows main .24 and pending work through #210 .26;
recheck main and actively owned lower-version PR integration before merging.
Keep the same focused branch/PR if integration is still held. No Git tags, Docker
publication, schedule change or completed-roadmap claim.

Self-review/validation update (2026-10-31T21:44Z): full local Python suite on the
initial published tree completed with **1637 passed, 11 skipped, 9 subtests passed**.
The follow-up adds missing-trust warnings and staging-restore tamper coverage;
focused final recovery/final-feature validation with an extracted native restic
binary completed **42 passed, 1 skipped** (only the MySQL-specific drill). The
real encrypted SQLite evidence recovery and both existing restic drills pass.
No local MySQL server/client or Docker acceptance is claimed. All twelve exact-head
GitHub jobs must run after this follow-up, including the native MySQL drill.
PR #212 targets main, has the matching v1.35.27 label and Fixes #120. Initial
published commit 96c000071caee68ffc5287730e657454afa9a560 exactly matched the locally
tested tree. Active integration/version holds were posted on #203/#206/#207/#208/
#209 because main's direct CI update is already v1.35.24. Do not merge ahead of
that coordinated issue-fix sequence or reuse lower versions. Keep #120 open until
the tested final merge is verified; continue the same PR if this cycle ends first.


Final integration refresh (2026-10-31T21:54Z): all twelve checks passed on PR #212
head e4ea3714a60ad06139ea9c6cd9e95849831d8788 (run 41244989750). SQLite CI:
1521 passed / 129 skipped / 9 subtests. MySQL shards combined: 1517 passed /
133 skipped / 9 subtests; the native encrypted MySQL archive recovery drill is
included in successful shard 1. Browser, both SSH and RPM legs, GCP runtime and
static checks passed. Main advanced just before merge to 6589f4d (PR #207,
v1.35.25). Preserve its checkbox CSS/regression and delivery entry; retain
v1.35.27 and rerun ALL checks on this new merged final commit. No stale-combination
merge was attempted. #208's owner explicitly confirmed independent integration
and will refresh its .29 work if #212 integrates first. Current next-integration
proposal is #212 at .27; preserve other independently owned fixes and recheck
main immediately before merge. The earlier blanket hold was superseded by
PR #212's integration discussion. No issue closure before verified tested merge.


Coordinated P1 integration: preserve exact #212 head
`8253159beb1799986dec5f1644e67cd08174f4eb` (v1.35.27) as an explicit dependency
of #208 v1.35.29. Serial merge order agreed in PR discussions: #212, #208,
#203, then later versions. Recovery code, native validation and every delivery
entry remain intact. The combined final source receives fresh full local and
all twelve exact-head CI checks. Do not merge #208 before #212's tested merge is
verified; if its head changes, refresh/reassess this candidate. No other branch
ownership or schedule changes.


## v1.35.30 — Uncertain ordinary patch outcomes (#119)

MrPatchy hourly development, Claude Code session `session_01AfdfYehh8Cf5AJiiyGRkCf`,
claimed unowned issue #119 after reviewing all open issues, comments and PRs at
main 56d4eb7 (v1.35.19). Reproduced on that main: with reboot/rollback off, an
injected `RemoteProtocolError` on the patch send left the job `failed` and the
host unquarantined, so the next queued mutation ran.

The worker now tracks ordinary patch progress (not sent, sent, receipt received,
inventory observed). After the request is sent, a failure is held as
`recovery_required` unless `ssh.call` proves the remote command never started or
the bridge returned its own structured JSON failure (`ssh.RemoteFailure`). A
bridge exit without that receipt, a lost/truncated/invalid reply, a timeout, a
transport error after `exec_command`, and a failed post-patch inventory read are
all uncertain. Held jobs keep the receipt, the error and the operation identity
in output and audit (`uncertain patch <job id>`), block later queued work through
the existing quarantine states and are released only through the existing
reconciliation path; nothing is replayed. Once the post-patch inventory is
observed, a later health regression stays a terminal `failed` rollout stage.
Protected-patch, release-upgrade, role, response-authorization and audit
boundaries are unchanged. `repository`, `key` and `repair` mutations keep their
existing classification; tracked in follow-up issue #204.

Regressions in `tests/test_patch_outcome_uncertainty.py` cover lost and malformed
replies, timeouts, post-start transport errors, a bare bridge exit, post-patch
inventory failure, verified target failure, inactive and unreachable servers
(using the real `ssh.call`), the remote-start marker, structured-failure parsing
and a later queued job. First proposed as v1.35.22. While this PR waited, main
advanced through PRs #174 (v1.35.20), #196 (v1.35.21), the CI review (v1.35.24),
#207 (v1.35.25), #212 (v1.35.27) and #208 (v1.35.29), in the order agreed on
#203/#208/#212; all are preserved. v1.35.30 is newer than main and below the
later #213-#215 allocations. No schema, target helper or Git tag change; source versioning
publishes no Docker image.

Checkpoint v1.35.35 (#170): failed SSO callbacks are logged server-side with
the exception class and a fixed sanitized reason, and audited as `SSO login
failed` with issuer, hashed subject prefix and reason, rate-limited per
reason/subject per five minutes. Responses keep the generic 400 message; no
raw provider text, token or plain subject is recorded. Roles, successful-login
audit and response-authorization boundaries are unchanged.

## v1.35.32 — Independent periodic scheduler producers (#140)

Owner: Codex `scheduler-6eac54918b34`, branch
`codex/scheduler-tick-isolation`. Issue-first triage selected #140 after accepting
#118/#208's explicit integration handoff. Current main `fa5d933` reproduced all
seven injected producer failures in a disposable real application/SQLite loop:
queued-job dispatch was skipped and failing tasks retried each iteration. Cause:
a single outer exception boundary surrounded all producers and the rest of the
loop, with the shared schedule timestamp advanced only after every task succeeded.

Each leader producer now has its own deadline and failure count. A named failure
is logged and backed off at 30/60/120/240 seconds, capped at 300 seconds, without
skipping the remaining producers, polling, dispatch, cleanup, notification or AI
admission. Success restores 30-second cadence. Worker identity loss propagates
to the existing stop path rather than being treated as a retriable policy error.
Deadlines are process-local scheduling safeguards, not durable job claims or a
replacement for existing coordinator election, drain, leases and per-host locks.
No additional response authority, automatic replay or provider call is introduced.

Focused new loop/backoff/identity-loss and existing advisory restart, drain/control
and worker registry tests: 67 passed. Full final-tree local suite and all twelve
applicable exact-head GitHub jobs are required before merge. No UI changes were
made. The runtime pipeline remains a priority, but unrelated roadmap work waits
behind actionable issues. Wider issues/roadmap are not claimed complete.

Version/source/README/changelog use v1.35.32, major fixed at 1. Depends on the exact
#208 final integration head `a16688690e2a2486cfe3e281ddbae7dce2c09507` (v1.35.29),
which includes current main `6589f4d` (v1.35.25, #207). Merge #208 first after its
own exact-head checks; preserve other owners' mutation, recovery and route-role
work. Re-read main/open PR versions before integration, rerun affected checks if
head or integration changes, and verify #140 closes only after tested merge.
No Git tags, Docker publication or schedule changes.

Version allocation correction: another active owner had reserved v1.35.30 for
#203, and #213 reserves v1.35.31. Reassigned this update to v1.35.32 after the
fresh open-PR check. Preserve #203's independently owned worker mutation changes;
coordinate #208 then #203 integration before this later version. Earlier .30
candidate metadata/CI is superseded; final version metadata receives fresh CI.

Final review extended the same per-producer exception/backoff boundary to module
loading, so an unavailable optional producer dependency cannot skip healthy tasks
or the rest of the loop. A focused import-failure regression joins the seven real
loop failures and backoff/identity checks (67 focused tests pass). Superseded local
suite/CI results do not authorize this final runtime revision; rerun the full suite
and all applicable exact-head jobs on the final published tree.


Continuation integration (Codex scheduler-85a36b0d8f8a, 2026-10-31): SAME PR #214
accepts the released handoff after #212/#208/#203 merged. Current main db7871e
(v1.35.30) reproduces all seven producer-position failures: queued dispatch is
skipped and the failed producer retries every loop. Preserve all recovery,
read-authorization and ordinary-patch uncertainty implementation, regressions,
CI and delivery records while retaining independent periodic producers. No new
roadmap or unrelated UI scope. This run retrieved 73 open issues (under the
100-result limit) and nine open PRs; prior run's initial count was 77, not the
copied historical 78. Keep source v1.35.32 pending coordinated .31/#213 order;
refresh main and version allocations before merge. The earlier candidate's green
checks do not authorize this changed integration: require combined focused/full
local validation and all twelve exact-final-head CI jobs. No issue closure before
tested merge; no tags, Docker publication or schedule changes.

Coordinator integration v1.35.41 (2026-10-31): the historical candidate versions and
reservations above are superseded by the maintainer-directed batch in #222. PR #214
preserves current main through #221/#209, including rollback/SSO/recovery/patch-safety
and all delivery history. README has no source-version field. Final major-1 version
and the numbered changelog entry are allocated by the sole coordinator; all 13
applicable checks must pass on the final integrated head before merge.

## v1.35.22 — Per-route role declarations (#198)

Claude Code session `012YQAphimPkYCq5KWgr1sGh` claimed issue #198 after reading main
`1328a82` (v1.35.17), all open issues and open PRs. Pending #139, #168, #174 and #196
hold versions up to v1.35.20 and also edit `app/main.py`; this update proposes
v1.35.22, subject to refreshing main before merge.

`auth()` used to decide roles by testing the request path (`'/security' in path`,
`path.endswith('/patch')`, prefix lists), so a new route defaulted to viewer-readable
and any path ending in `/preview` was operator-writable. Roles are now declared per
route through `viewer_user`, `operator_user`, `admin_user` and `self_user`, which share
one `authenticate()` that keeps session, generation, CSRF and host lifecycle checks in
their existing order. `app/route_roles.py` builds an inventory of every route at
startup (including the SSO router) and raises if a route declares no role, declares
conflicting roles, or is public without being listed in `PUBLIC_ROUTES`.

The authenticated routes were migrated from the roles the old logic produced and compared
against it. The full suite caught one route the template comparison missed: operators may
run `refresh` through `/api/hosts/{id}/actions/{action}`, so `refresh` is now its own
operator route and the other actions stay admin. Old accidental matches (a concrete id such
as `patch` ending a path) no longer grant operator access. `tests/test_route_roles.py` pins
the full route-to-role table, proves unlisted routes fail closed, and drives a viewer
and an operator through every admin-only and operator route. #157 (viewer-readable
`/api/investigation-status`) is still a viewer route here; changing it is now a one-word
edit on the new mechanism and is left to that issue. Host-lifecycle and deleted-record
checks still read the path; they are not role decisions and were out of scope.

Coordinator integration v1.35.42 (2026-10-31): PR #226 preserves original #206
commits and current main through #214, including the deleted-server resolved-host
and SQL list-filter safeguards. The fork is read-only to this connection, so the
maintainer-directed batch #222 uses a writable upstream branch. Historical
candidate version .22 is superseded; README no longer tracks versions. Final
PR-bound version and all 13 exact-head checks are required before delivery and
verified #206/#198 closure. The separate #157 telemetry report stays open.

## v1.35.48 — Lifecycle-aware host metrics (#160)

PR #210 filters the Prometheus mrpatchy_hosts gauge to Host.deleted_at==0.
Soft-deleted history remains retained and administrator-readable; disabled,
non-deleted servers remain counted. Other metrics, route roles, audit retention
and runtime response authorization are unchanged. The final version/changelog
record is coordinator-owned under #222, and all 13 exact-head checks remain
required before merge and verified issue closure. No tags or Docker publication.

## v1.35.49 — Cache-aware artifact hash deadlines (#166)

PR #220 moves the initial shared-deadline check into the verified cache-miss
branch before data reads, retaining per-chunk checks. A matching cache hit still
checks device, inode, mtime, ctime and size and can return after the deadline.
Expired uncached empty/nonempty files perform no data reads. Existing file and
process identity checks, roles and response authorization remain unchanged.
This preserves the owner's corrected bebc0c9 handoff; legacy candidate versions
are superseded by coordinator #222's final version/PR-linked changelog. All 13
exact-head checks are required before merge and verified issue closure. Deploy
the agent update through the existing reviewed maintenance workflow; no tags.

## Password hashes and secret-key handling

- Passwords are stored as `scrypt$N$r$p$salt$digest` (currently N=2^17, r=8, p=1). Legacy `salt:digest` hashes (N=2^14) still verify and are replaced with the current format after a successful sign-in, so the cost can be raised later without breaking existing accounts.
- The Fernet instance is cached and reloaded only when `secret.key` changes (inode, size or mtime).
- The OIDC flow-cookie secret is derived from `secret.key` with HKDF-SHA256 and a purpose label; the Fernet key material is not reused directly.
- Threat model: `secret.key` lives on the same `/data` volume as the database. Encryption of stored secrets therefore only helps when the database is leaked without the volume (for example a database-only dump to MySQL). It does not protect against a compromise of the data volume.


### Production image digests — partial #201 checkpoint

This source checkpoint supersedes older statements in this historical log that
production Python/Caddy references remain tag-only. The application Dockerfile
keeps the existing `python:3.12-slim-bookworm` tag and binds it to the official
Docker Hub OCI image-index digest
`sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337`.
The deployed Compose Caddy image keeps `caddy:2.10`, bound to index digest
`sha256:c3d7ee5d2b11f9dc54f947f68a734c84e9c9666c92c88a7f30b9cba5da182adb`.
The CI Caddy adapter fixture uses that same complete image reference, so its
adapter/TLS checks cannot silently test a newer floating tag than deployment.
Focused regression tests reject missing/malformed digests and fixture drift.

Both pins are multi-platform index digests, not an amd64-only child manifest.
Direct official-registry reads on 2026-11-02 UTC verified the SHA-256 of the raw
index bytes against Docker-Content-Digest, and both indexes include Linux amd64
and arm64. Python also includes Linux arm/v7; Caddy includes arm/v6 and arm/v7.
Index availability is not a claim that every architecture was built or tested.
A digest fixes the selected bytes; it is not independent vendor signing or proof
of a vulnerability-free image. No runtime version family or response authority
is changed.

Refresh procedure: inspect the intended official tag with
`docker buildx imagetools inspect python:3.12-slim-bookworm` or
`docker buildx imagetools inspect caddy:2.10`; verify the index digest and required
platforms before updating the tag/digest pair. Update Caddy in both compose.yaml
and the CI adapter fixture together. Keep the readable tag, run the focused pin
and supply-chain tests, review upstream changes and run the full exact-head CI
including Compose configuration, production/GCP builds and real Caddy HTTPS
checks before coordinator integration. Existing Dependabot Docker coverage can
propose application Dockerfile changes; this checkpoint does not claim automatic
Compose digest refresh. Manual review remains required, including when a Python
minor-version proposal such as #287 needs a different matching digest and real
compatibility/build acceptance. Never pair a new tag with the old tag's digest.

Limits: apt, pip and the GCP CLI installation still resolve packages during the
build, so this is not a fully reproducible or hash-locked application build.
Python install hashes, dependency-vulnerability scanning policy and Compose
sandbox/resource hardening remain unfinished. The GCP Dockerfile's local
`BASE_IMAGE=mrpatchy:base`, Compose's locally built `mrpatchy:gcp`, and explicitly
parameterized SSH/RPM test-fixture bases remain build/test inputs, not falsely
claimed registry digest pins. #292's Actions pins and #302's CodeQL coverage are
separate deliveries whose history must be preserved during integration. #201
stays partial/open; no broader deployment/security roadmap completion is claimed.

### Compose capability bounding — partial #201 checkpoint

The complete Compose file now drops all Linux capabilities from `app`, `worker`
and `caddy` and adds back only what each needs. `app` and `worker` start as root
only for the entrypoint's `chown` of the data/TLS volumes and the `gosu` drop to
the unprivileged `mrpatchy` user, so they keep `CHOWN`, `SETUID` and `SETGID`.
`caddy` keeps `NET_BIND_SERVICE` for ports 80/443 and `DAC_READ_SEARCH` to read
the owner-only files on the read-only `/tls` mount. `no-new-privileges` is
unchanged. `tests/test_compose_capabilities.py` pins this exact set.

Limits: read-only root filesystems, PID/memory limits and GCP override services
remain unfinished under #201; the dependency-vulnerability gate is tracked by the
separate #369 checkpoint. Acceptance of the new capability set on a real Docker
host comes from the exact-head CI Compose and HTTPS checks; no local Docker was
available. No runtime response authority changes.

### Compose process-count bounding — partial #201 checkpoint

The production Compose `app`, `worker` and `caddy` services each set
`pids_limit: 1024`. This bounds fork exhaustion while retaining headroom for the
configured thread pools and subprocess work. Regression coverage requires every
declared production service to retain a numeric limit between 256 and 4096.
Custom overrides that legitimately need more than 1024 simultaneous processes in
one container must raise the limit explicitly.

This changes no API, schema, role, audit or runtime response authority. It does not
add memory limits, read-only root filesystems or GCP override-specific limits, and
it does not establish a live GitHub alert inventory; those #201 items remain open.
No Docker runtime was available locally, so exact-head CI supplies the image-build,
Compose/HTTPS startup and custom-binding acceptance.

### Resumable multi-stage release configuration reviews — worker checkpoint #366

Issue #366 implements the next bounded faster-AI increment. Distribution release
planning now seals each accepted configuration review before another provider call.
A controlled smooth-rate, daily-spend, provider-backoff or administrator-pause wait
leaves the job queued at the authoritative eligibility time (or indefinite resume
state) and leaves the plan non-approvable in `planning` state. Once policy permits
execution, an exact completed stage is reconstructed without another provider call.

Reuse is deliberately strict. The encrypted checkpoint and its digest must be valid,
and its versioned identity binds the host, target release, inspected inventory,
release runner, rewritten sources, simulated package transaction, every relevant
configuration's verified bytes/metadata/package state, selected model, review-policy
version, vendor-default bytes and package-news bytes. Any mismatch discards all saved
stage results and performs current-evidence reviews; a name, package or file hash by
itself is never sufficient. Completed plans remove the private progress envelope and
retain the existing digest-bound administrator GO/NO-GO decision, expiry, validation,
audit, lifecycle and response safeguards.

Focused regression coverage reproduces a wait after one accepted review, verifies the
job remains queued and the partial plan remains non-approvable, then proves exact
resume calls only the unfinished stage. A changed completed configuration proves the
conservative miss path re-runs both stages. This checkpoint does not make a provider
call interrupted without an accepted structured result safe to replay automatically,
does not expand release support or response authority, and does not complete the
remaining provider-invoice or multi-controller failover/reset roadmap. Coordinator
integration, exact-head full-suite/SQLite/MySQL checks and fresh code scanning remain
required before this increment is delivered.


### Retained AI spend history — worker checkpoint #372

This bounded faster-AI increment exposes retained daily accounting windows to
administrators instead of limiting Settings to the currently active window. The
report groups by each ledger entry's persisted reset time and IANA timezone, so a
later timezone change does not rewrite historical accounting. Settled calls use the
retained public-price usage estimate; reserved, transmitted, uncertain and unknown
unreleased states keep their conservative ceilings. Released unsent attempts do not
count. The report contains only aggregate amounts, counts and window boundaries—no
model names, keys, prompts, evidence, provider responses or pricing-source URLs.

The administrator API validates a trailing 1–90 day range and performs fixed-precision
SQL aggregation without materializing individual ledger records. Result groups are
bounded to four persisted reset/timezone combinations per requested day (at most 360),
and an explicit truncation flag discloses heavier configuration churn. AI Settings
offers 7-, 30- and 90-day views with loading, empty, error and truncation states and
states plainly that local public-price estimates are not provider invoices.

This checkpoint changes no admission, provider-call, pause, response-authorization or
ledger-retention behavior. Provider-invoice reconciliation, signed/automated pricing
catalog lifecycle and complete multi-controller failover/reset acceptance remain
planned. Coordinator integration, exact-head SQLite/MySQL/browser/full-suite checks
and fresh code scanning are still required before delivery.

### AI pricing catalog lifecycle alerts — worker checkpoint #370

This bounded faster-AI increment warns administrators through the existing durable
operational outbox and in-app notification history during the final seven days of a
catalog's reviewed window. The stable subject is deduplicated while unchanged,
escalates from medium to high and reopens delivery at expiry, and resolves when a
reviewed catalog refresh moves outside the warning window or enabled daily-cap
enforcement is removed. Only safe catalog version/status/expiry text is published;
the event contains no keys, prompts, evidence or provider receipts and links to the
administrator-only AI settings page. Per-user read/dismiss remains separate from
operational acknowledgement and neither changes admission nor performs remediation.
Rate-only, unthrottled, legacy and globally disabled AI modes do not receive this
spend-guard alert.

Focused acceptance covers the exact warning and expiry boundaries, repeated
collection, acknowledged-warning escalation, per-user revision visibility,
resolution and non-cap/disabled modes. This does not automate or sign catalog
updates, reconcile provider invoices, add provider-derived billing truth or complete
the remaining multi-controller/reset acceptance. Final delivery still requires the
coordinator's exact-head full test matrix and fresh code scan.

### Compose memory bounding — partial #201 checkpoint

The production Compose `app`, `worker` and `caddy` services set `mem_limit` with
defaults of 2 GiB, 4 GiB and 512 MiB, overridable through
`MRPATCHY_APP_MEM_LIMIT`, `MRPATCHY_WORKER_MEM_LIMIT` and `MRPATCHY_CADDY_MEM_LIMIT`.
A runaway container is OOM-killed and restarted (`restart: unless-stopped`) instead
of exhausting the host. Regression coverage requires every declared production
service to keep an overridable default between 256 MiB and 16 GiB. Large fleets with
heavy concurrent scanning or AI fan-out should raise the worker limit explicitly.

This changes no API, schema, role, audit or runtime response authority. Read-only
root filesystems, GCP override hardening and the live alert inventory remain open
under #201. No Docker runtime was available locally.
