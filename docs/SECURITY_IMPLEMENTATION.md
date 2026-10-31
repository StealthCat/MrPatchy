# Security implementation checkpoint

## Version policy: major fixed at 1

User instruction (2026-10-30): use **1.MINOR.PATCH** and keep the major number at
**1** until the user explicitly instructs otherwise. The initial transition is
`0.17.0` to `1.17.0`, preserving the existing minor/patch numbers. Subsequent
completed updates retain the existing patch/minor increment criteria and full
version monotonicity. This overrides automatic major bumps, including for breaking
changes; record compatibility impacts while keeping major 1.

All other versioning instructions remain in force: authoritative `APP_VERSION`,
synchronized README/changelog/UI/API metadata, versioned development and merge
commit subjects and PR titles/labels, exact-final-commit checks and skipped Git
tags. `AGENTS.md`, the source version checker and the scheduled development task
carry this policy. Roadmap completion remains governed by the existing completion
gate and issue-first workflow.

## Scheduled development completion gate

Before each scheduled development cycle, assess the current roadmap against current
`main`, the latest merged PR's actual changes and recorded validation, the
implementation checkpoint and any unfinished related PR. This is a read-only
assessment before any implementation, UI polishing, versioning or repository write.

- If the explicitly requested roadmap is feature complete and no unfinished in-scope implementation remains, stop that cycle without working on the code. Do not invent additional features, refactor, polish the UI or begin speculative bug hunts to fill the cycle.
- A completed cycle with no work must not change source, tests, documentation or the checkpoint; it must not bump a version or create commits, tags or PRs merely to record that nothing needs doing.
- Report briefly that no development is needed, citing this roadmap and the latest merged PR/commit used for the assessment. Keep the development schedule enabled; later cycles may resume when a new roadmap requirement or unfinished in-scope milestone is present.
- Proceed only when the assessment identifies a concrete outstanding roadmap requirement or unfinished related implementation. State the remaining work before starting it. Review/polish, versioning, testing, PR/merge and checkpoint requirements apply when there is actual work to deliver.
- Missing, contradictory or blocked evidence is not proof of completion. Report the uncertainty or blocker and stop without speculative code changes; retain honest outstanding requirements and limitations.

This gate takes precedence over instructions to always continue development or
produce another PR. Judge completion from the current repository and latest merged
work rather than stale milestone numbers or repeated historical requests.

## Development-cycle work budget

When the completion gate identifies remaining work, select a coherent batch of
actionable roadmap items aimed at about **40–50 minutes of productive work within
the allocated hour**, including implementation, relevant UI work, review,
validation and PR completion. A large milestone may fill the batch; combine
several small related items when appropriate.

- State the selected items and intended outcome before implementation, respecting dependency order and unfinished work from earlier runs.
- Reserve roughly the final 10–15 minutes for review, applicable tests/checks, version/changelog consistency, PR/merge handling and the checkpoint.
- If a small item finishes early and roadmap work remains, take the next coherent item only when it can reasonably be completed and validated within the remaining budget. Do not stop merely because one small milestone is finished.
- Preserve reviewable scope and passing checks on the exact final commit. Avoid risky late additions or overlapping development runs; leave a precise checkpoint and unfinished PR state if safe completion is not possible.
- This is a sizing target, not a mandatory minimum. Stop early for roadmap completion or a genuine blocker. Do not invent work, wait, repeat successful checks or change completed code simply to fill time.

The completion gate takes priority, and the development schedule is unchanged.

## Current implementation status

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

Limits: 16 explicit root directories, 2,000 examined files, 32 MiB per file, four-minute overall work budget and 30-second per-file scanner timeout. Symlinks are not followed during traversal. Virtual filesystem directories and the reserved quarantine directory are excluded. Exclusions and failures are reported as incomplete coverage. Scanning uses an opened descriptor and checks metadata before accepting the result. A compromised root/kernel remains outside this trust boundary. Reports never claim the server is clean.

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

After updating the controller, use the existing **Finish / verify installation** workflow to redeploy the updated collector to managed targets. Old collectors continue producing legacy receipts without freshness metadata. Automated tests simulate engine output, signature drift, path replacement, parent symlink races, empty-directory budgets, descriptor cleanup and AI evidence binding. A live ClamAV engine with production databases was not available in this development environment.

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
job to 30 minutes; PR and main-push triggers remain enabled.

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
database, application event records or AI packets. Each RPC has a 180-second SSH
deadline; the independent approval deadline applies throughout the entire transfer.
Slow links can exhaust that approval and leave an incomplete private transfer.

The root helper stages under
`/var/lib/mrpatchy-repair-staging/<operation-id>/`, on the approved filesystem.
Directories are root-owned mode 0700 and payloads/journals are root-owned mode
0600 with one link. The helper rejects unsafe ancestors, symlinks, hardlinks,
changed inode/ownership/permissions/attributes, unexpected root entries, changed
metadata and byte-hash mismatches. Staging inherits neither executable permission
nor the live pathname. Current scope continues to require the reviewed original
root/root ownership, supported original mode and no extended attributes. Original
permissions are still not authenticated vendor permissions. Concurrent malicious
root/kernel behavior and kernel-blocked I/O remain outside these guarantees.

A durable, fsynced intent binds the staging ID, full plan, selected manifest,
authentication digest and approval before a payload is created. Each chunk has a
separate exclusive intent before its append, requires the expected offset/length,
and is fsynced. An existing chunk intent is observed instead of appended again.
Interrupted or conflicting bytes cannot authorize a new append. The initial file
identity is retained independently so same-byte inode replacement is detected.
At finish, the helper hashes the whole selected file and freshly checks package
identity/unique ownership, retained original, protected parents and the empty live
pathname. An occupied path, including a legitimate deployment or symlink, is never
changed. A separate finish intent is fsynced before an atomic no-overwrite rename
from `payload.partial` to the **private** `payload` leaf. This rename does not
publish the file into the application. Finish intents are never automatically
replayed, including after a process restart or lost reply.

The controller commits uncertainty before asking for any target write. Lost
replies, protocol violations, changed scope/trust, expired approval and partial
transfers remain reviewable; no worker restart resumes the upload. **Verify staged
replacement** only reads existing journals, chunk progress, inode/metadata and
hashes. Missing operations create no directories. A lost final completion record
can be reconciled from a bound finish intent and independently verified final
payload; a partial file is never renamed by verification. `receiving` target
observations appear as **incomplete** in the controller because verification does
not continue a transfer. Use a new preparation and explicit approval after reviewing
an abandoned attempt; the old approval and events remain retained.

A positive **staged** receipt means the previously approved bytes are retained at
observation time. It is not permission to publish them, a continuing readiness
guarantee or a live-file repair result. Read-only status can verify historical
payloads after the original has been restored or the offline bundle removed. The
report separately records whether controller scope agreed and vendor authentication
could still be rechecked at that observation; historical authenticated hashes do
not establish current publisher trust or key revocations. No publication endpoint,
service restart, package script, process signal, incident resolution or automatic
file/process pause release is included in this milestone.

Staging and status can run through their owning file hold and process holds for
that same file response because they do not change the live file or process. Those
holds remain active. Other response holds and running/recovery-required Activity
jobs still block access. The exemption does not extend to quarantine restoration,
process recovery or other live changes. The staging directory is excluded from
scanner and custom-inventory traversal alongside existing evidence/response stores.

To bound abandoned storage, a target retains at most **eight staging operation
directories**, including incomplete ones: up to **256 MiB of payloads**, plus
bounded journals. Reaching this limit refuses new staging. There is no automatic
cleanup or browser deletion. Review storage and protected backups through the
trusted console before any deliberate retention cleanup. Configure broader
retention/external evidence storage in a subsequent milestone.

**Trusted replacement staging** shows approval actor/reason/deadline, state,
transfer progress, verified payload metadata and timestamped checks. Its paginated
history retains approval, start and every observation, including failed historical
checks, without storing payload bytes. `security_repair_stages` and
`security_repair_stage_events` participate in startup initialization and verified
offline SQLite/MySQL migrations. Approval metadata is retained and observation events
are append-only through the feature APIs, not cryptographically immutable; the latest
stage state/receipt changes on verification. Target staging directories need
separate protected backup; database migration moves metadata, not retained files.

Rebuild app/workers and redeploy current helpers with **Finish / verify
installation** before using staging. Tests cover chunk boundaries/request budgets,
typed approval/expiry, changed payload/trust/scope, related/unrelated holds,
interrupted append/finish, lost replies, root metadata and same-byte inode changes,
quota, read-only reconciliation, role/host boundaries, history and database copy.
Native SSH validation stages authentic signed Debian/RPM fixture bytes through the
real worker/bridge on Debian, Ubuntu, Fedora and AlmaLinux, verifies mode 0600,
tamper refusal, retained original and unchanged holds, and never publishes the live
file. The separate publication executor is described below. Browser tests cover the approval and verification/history flows at mobile and
desktop widths. Containers still stub systemd; live GCP/IAP, real-VM/SELinux,
low-bandwidth and failure/performance drills require operator validation.

## Separately approved live replacement publication

**Trusted replacement staging → Review replacement publication** requires a
separate reason and `PUBLISH`. STAGE, AI-plan review, process response and quarantine
approvals do not authorize this move. Choose a successful staged receipt observed
within five minutes, with unchanged pinned SSH host, original quarantine, selected
manifest, inode/hash and staging report digest, and successfully rechecked vendor
trust. The original must still be quarantined. The publication approval expires
after five minutes and binds the complete staged plan and exact private payload
identity. An existing active publication for the original prevents another approval.

Publication makes authenticated regular-file bytes available in the original live
pathname. Programs and supervisors may start using them immediately, including
execution when the selected mode permits it. The UI discloses that activation risk
before approval. Scope remains root/root single-link protected files under `/srv/`
or `/opt/`, excluding `/opt/drpatch`, on the approved filesystem. Only original modes
0600, 0640, 0644, 0700, 0750 and 0755, with no extended attributes, are supported.
These are the reviewed original permissions, **not authenticated vendor
permissions**. The executor does not reconstruct a whole package installation,
configuration semantics, generated files, symlinks, ACLs/capabilities or service
dependencies. Authenticated same-version bytes may still be vulnerable. Publication
is not a malware-eradication, service-health or clean-host verdict.

Approval creates a separate durable **publication pause** before queueing. Existing
file and process pauses remain independent. The worker reauthenticates the offline
artifact, selected bytes and publisher-key snapshot before target access and after
fresh independent current-helper verification. It ends MySQL snapshots before
checking the current scope again. Before a mutating RPC, it commits publication and
file uncertainty with holds and removes stale restoration readiness. A controller
or worker restart never automatically replays publication. A job left running must
first be reconciled in Activity using the existing target-operation lock proof.
Cancelling a still-queued publication releases only its newly created publication
pause; the owning file/process pauses and original evidence stay unchanged.

The helper locks the existing staging directory and reads its bound staging and
finish journals. It rehashes the approved staged inode, verifies its root-only
metadata/attributes and rechecks exact installed package version/architecture,
unique path ownership, unchanged protected ancestors, intact quarantined original
and an empty destination. RPM queries use `--noplugins`; no package verification or
installation script runs. A legitimate concurrent deployment, symlink or any other
occupied destination is never overwritten or removed. No arbitrary destination,
download, package install, service restart, process signal or AI-generated command
is accepted by this executor.

Under the original-response lock, a root-owned 0600 **publish-intent.json** binds
the publication ID, full plan and typed approval and is fsynced before permissions
or namespace changes. The helper rechecks approval expiry before intent, permission
change and rename. It applies the explicitly reviewed mode to the existing staged
inode, fsyncs it, verifies that identity/metadata still agree, then uses mandatory
`renameat2(RENAME_NOREPLACE)` to move that inode into the live pathname. Both parent
directories are fsynced. There is no overwrite fallback, new-inode copy or automatic
rollback to potentially malicious original bytes. If a rename fails after chmod,
the payload can remain at the changed mode inside the root-only 0700 staging
directory; it is not automatically retried or promoted to ready staging.

After the move, verification hashes the expected live inode, checks root ownership,
reviewed mode, size, link count and absence of attributes, and independently verifies
the retained original and protected parents. Package identity/owner and filesystem
observations are checked again around I/O. The root-only completion journal records
the publication ID, plan digest and payload metadata. A positive result requires
all current facts to agree. Concurrent privileged interference, compromised root/
kernel and unobservable changes between observations remain outside these bounds.
Each file hash has a 30-second userspace budget, package queries retain their
10-second limits, and publication/status RPCs have 300-second SSH deadlines.
Kernel-blocked I/O can exceed userspace deadlines.

The controller rechecks publisher trust and scope after the reply. A change detected
before the RPC prevents requesting the move. A change discovered during/after the
RPC retains uncertainty and pauses because bytes may already be live; no distributed
instantaneous revocation or safe automatic undo is claimed. Invalid receipts,
transport loss, contradictory facts and stale controller scope never become current
positive proof. Only classified stages and exception types are retained for errors;
arbitrary diagnostics and file contents are not copied into records or sent to AI.

**Verify replacement publication** is read-only. It can reconcile a lost reply or
missing final completion record from the existing bound intent, current live inode/
hash/permissions, exact package observations and retained original. It creates no
directories, changes no mode, renames nothing and never rewrites a completion record.
An existing intent binds its publication ID permanently; even a new approval/ID
cannot reuse it for another move. A private, fully verified staged inode with no
publication intent can report **not_started**; this does not automatically release
a pause or authorize retry. Partial/failed mutation, missing or modified evidence,
changed parent/package/live inode and corrupt journals remain uncertain. The stored
approval and observation history survive later failed checks. Rejected preflight
and cancelled unstarted approvals can be replaced by a new explicit approval;
attempts with an existing target intent need trusted-console review and normally a
fresh staging operation, rather than continuing an old move.

**Reviewed replacement publications** retains the actor, reason, approval deadline,
mode policy, state, independent pause and timestamped receipts/history. A verified
file response becomes **replaced**, keeping its original quarantine plan/evidence;
uncertain publication becomes **replacement_uncertain**. Original-file restoration
is not offered over a live replacement. Existing file-response and staging
verification endpoints route to publication verification while that publication is
active, so the legitimate new path is not misclassified by the old quarantine
protocol. Process reference observations can still inspect the retained original.
Previously prepared process recovery remains a separate explicit decision that may
resume malicious execution; publication sends no signal and clears no process pause.

**Review publication pause** requires a separate meaningful reason and the selected
typed phrase. **KEEP REPLACEMENT** requires a verified publication and successful
approved-trust recheck no more than five minutes old, matching the displayed receipt
and plan. After the operator reviews affected services, it clears that publication
pause and its owning file-response pause. Related process and unrelated response
pauses remain active, and the result reports whether server work is still paused.
**CONSOLE RECOVERED** is the operator's trusted-console assertion, archives the
publication and clears only its publication pause. It does not claim verification
or clear a remaining file pause; review that separately after console recovery and
fresh file-state checks. Neither review resolves the incident. There is no automatic
service-health approval, rollback, original restoration, resume or credential change.

Existing opt-in **Retained response monitoring** now covers both the approved live
replacement and its original held inode. Its queue binds the publication ID and
publication-plan digest as well as original plan, pinned host, policy and watch
revision. A successful check records **replacement_verified**; it does not turn an
unknown occupied path into an approved replacement. Old queued quarantine checks
without the publication binding are skipped after publication. Monitoring defers
while publication/process pauses or other running/recovery work require review.
The existing independent **pause on problem** choice controls whether an automatic
negative observation introduces publication/file pauses. Disabling the policy
during I/O cannot create a new pause; existing holds remain until reviewed. A newer
manual positive verification can supersede an old alert without deleting its check.
Published-file, original-evidence, identity, parent and package changes remain
negative observations, not permission to republish or overwrite anything.

Read-only status can still verify the previously approved hash when the local
offline bundle has expired, changed or been removed, while reporting the approved
trust recheck separately as unavailable/failed. That historical hash is not current
publisher authorization, and KEEP REPLACEMENT cannot use a failed trust recheck.
New staging/publication still requires currently authenticated operator-provisioned
Debian/RPM bundles. Automatic artifact/rule retrieval, key-revocation synchronization,
file retirement/rollback, wider permissions/paths and service orchestration remain
future work.

`security_repair_publications` and `security_repair_publication_events` are included
in startup initialization and verified offline SQLite/MySQL migration. Approval
metadata is retained; observation/review events are append-only through feature
APIs, while current state/receipt changes on verification. These are protected
application records, not cryptographically immutable evidence. Back up the original,
target staging/publication journals and active live files separately; database
migration copies metadata, not their bytes. Published journal directories are
active verification evidence and must not be deleted merely to free the existing
eight-operation staging quota. No automatic retention cleanup is introduced.

Rebuild app/workers and redeploy current helpers before use. Tests cover separate
approval, stale scope/trust, cancellation, holds, expiry at both mutation boundaries,
no-overwrite races, partial chmod/rename, lost replies/completions, read-only recovery,
live/original/journal tampering, metadata policy, immutable history, roles, host
boundaries and offline migration. Native SSH validation publishes real signed
Debian/RPM fixture bytes on Debian, Ubuntu, Fedora and AlmaLinux, checks the same
inode and reviewed mode with the original retained, separately reviews the hold,
then verifies scheduled replacement monitoring and a tamper pause. Browser checks
exercise PUBLISH, verification, separate pause review and paginated history at mobile
and desktop widths. Containers stub systemd; real-VM/SELinux, live GCP/IAP and broader
service, power-loss, filesystem, performance and recovery drills remain operator
acceptance work.

## Portable response records

**Servers → server → Security → Reviewed file responses → Export response record**
downloads the selected response's stored metadata as a versioned JSON attachment.
An administrator provides a meaningful reason, and the displayed plan digest must
still agree. Exports remain available for uncertain, restored and console-reviewed
responses, including through file/process/publication pauses. An active host worker
causes a conflict; export holds the same host operation lock while gathering records
and recording the export. No target connection, artifact authentication, preserved-byte
read, service action, process signal or AI call runs. Export changes no response state,
pause or incident assessment.

Version 1's nineteen explicit sections contain the selected file response; its current
incident, incident events and advisory plans; linked preservation/acquisition metadata
and acquisition observations; all stored file approvals/events; response-monitor checks;
process-reference observations and process responses/approvals/events; trusted repair
preparations; staging approvals and events; publication approvals and events. Records
are ordered by creation time then ID. This includes existing history beyond the UI's
twenty-row pages, including rejected or superseded operations. Current incident evidence
can represent a later detection than the original response; evidence digests and exact
stored snapshots remain in the record. Missing or cross-host primary incident,
acquisition or preservation links are listed explicitly and their records are omitted.
Child records require same-host parents bound to this response. Unrelated responses,
full scan reports, generic Activity payloads/outputs and global audit/settings are
excluded. Only host ID/name/pinned fingerprint and allowlisted monitoring policy/watch
fields are included; host inventory, telemetry and credential configuration are not.
Adding a database column does not automatically add it to an export.

The export is a controller metadata snapshot under the cooperating host lock, not a
fresh host assessment or a forensic snapshot of the whole database. It does not check
the current existence/hash of retained bytes, target journals, live replacements or
vendor artifacts. Preserve those separately with the existing controlled forensic and
backup workflows. Reasons, paths, AI advisory text and receipts can contain sensitive
investigation information; protect the JSON and checksum accordingly. No automatic
upload, deletion, retention cleanup, object-lock/WORM guarantee or cloud credentials
are introduced.

Every section has its record count, canonical byte length and SHA-256. A separate
digest covers the canonical record including export actor, reason, timestamp, unique ID,
scope and monitoring policy. Canonicalization is Python JSON with sorted keys, compact
separators, ASCII escaping and finite numbers only. The exact attachment, including
its trailing newline, has a whole-file SHA-256 returned in
`X-Response-Record-SHA256`. The browser preserves raw bytes rather than parsing and
reserializing 64-bit inode/timestamp integers. HTTPS browsers also compare the downloaded
bytes through Web Crypto before saving. A separate **Download checksum** produces a
standard SHA-256 sidecar. An export event records its ID, whole-file digest, size,
actor and reason in file-response history, and the generic audit separately records
ID/digest/actor. That event is committed before returning bytes and is outside the
current snapshot to avoid a self-referential hash. A later export includes it. Successful
generation records delivery intent, not proof that a browser saved the file.

`tools/verify_response_record.py` runs offline with Python 3's standard library:

```bash
python3 tools/verify_response_record.py response.json --sha256 <trusted-whole-file-sha256>
# Or compare the raw file with its retained sidecar:
sha256sum -c mrpatchy-response-<export-id>.json.sha256
```

The verifier rejects duplicate keys, unsupported schemas, missing section manifests,
changed record/section hashes, contradictory byte/row counts and a mismatched supplied
whole-file digest. Without `--sha256`, it checks internal consistency only. Retain the
whole-file digest through an independently trusted channel: an attacker able to rewrite
both the JSON and its hashes can forge a self-consistent export. Neither embedded nor
sidecar hashes authenticate the controller, prove past records were never deleted,
provide a trusted timestamp, establish current target trust or certify a clean host.
The application database remains mutable; this feature enables independent retention
but does not itself make evidence immutable.

Limits are **1,000 rows per section**, **5,000 total rows**, **16 MiB for the complete
attachment**, and a **30-second userspace work budget**. Histories are queried in bounded
streams. Exceeding a limit refuses the entire export with HTTP 413; no partial export,
success custody event or misleading completeness flag is returned. Database/kernel
blocking can exceed userspace deadlines. Large histories need an operator-managed,
protected offline database backup/export; automatic partitioning is not implemented.
No schema migration or target-helper update is needed for this feature. Rebuild the
controller app/workers. SQLite/MySQL tests cover lineage, host/role/CSRF boundaries,
missing references, response pauses, active-operation conflicts, exact integers,
complete history, refusal limits, audit digests and offline tamper verification.
Browser coverage verifies reason entry, exact-byte download, checksum download and
an oversized-export error without a partial success.

## Response service health observations

**Reviewed file responses → Check service health** lets an administrator select
**1–16 explicit systemd `.service` unit names** and supply a meaningful reason. Names
must start with an ASCII letter/digit, be at most 128 characters, and contain only
letters, digits, underscores, dots, `@`, colons and hyphens before the `.service`
suffix. Paths, glob patterns, leading options, duplicate names and other unit types
are refused. The operator chooses the expected services: no automatic file-to-service
mapping or discovery of every affected dependency is claimed. Each selected service
is expected to be loaded, active and successful; intentionally inactive services are
reported as problems rather than silently ignored.

The target uses only bounded `/usr/bin/systemctl show` requests, with an explicit
property allowlist: canonical ID, load/active/substate, result, main exit code/status,
main PID, restart count, invocation ID, unit fragment path and unit-file state. It
does not read `ExecStart`, environment, service logs or file contents. Every unit is
sampled twice. Matching samples are **healthy** only when loaded, active, running or
successfully exited, with a successful result, zero exit status, normal/no exit code,
and a nonzero main PID for running services. An active exited oneshot can be healthy
with PID zero. Disabled but already-active services are not failed solely for being
disabled. Canonical IDs can reveal aliases; changed identity, invocation, PID, restart
count or any other selected property between samples produces **changing**, not a
positive result. Missing/malformed properties, command diagnostics, nonzero command
exit, timeouts and unsupported systemd behavior produce unavailable coverage. No
arbitrary command output/diagnostics are retained.

Boot identity is checked before and after sampling. A missing or changed boot identity
prevents a positive aggregate result. Any unavailable/changing unit makes the aggregate
**unavailable**, while individual known problems remain visible. With complete stable
coverage, any unhealthy selected unit makes the aggregate **problem**; otherwise it is
**healthy**. These are point-in-time manager properties, not application endpoint,
network, database, dependency, workload or sustained-health tests. A running malicious
service can meet them. Unit file paths are reported, not authenticated, and compensated
changes between samples or compromised root/kernel/systemd remain outside this trust
boundary. Healthy never means that the file is trusted, containment succeeded, or the
server is clean.

Requests bind the original response plan, response state, pinned host and current
publication ID/plan. Those bindings are rechecked at execution, after mandatory fresh
independent agent verification, and after remote I/O using new database snapshots.
Changed scope produces a historical **skipped** observation and cannot become current
positive evidence. A single sample query has a three-second/8 KiB output budget; the
target has a 90-second userspace budget and SSH has a 120-second deadline. Failure
cleanup may terminate the check's own systemctl subprocess; it never signals an
observed service. Kernel-blocked I/O can exceed userspace deadlines.

An operator can explicitly select an earlier complete observation as a baseline. Its
host, response plan, exact ordered unit selection and report digest must still agree
before/after I/O. A baseline can precede quarantine/publication; the new observation
captures its own current response/publication binding. Comparison records every
changed allowlisted property and whether boot identity differs. It does not decide
whether a change was intentional, attribute it to file remediation, reject a reboot,
restart anything or automatically release a pause. Incomplete observations cannot be
baselines. Historical observations are never rewritten by later checks or comparisons.

Checks run through only their own file/publication and related process pauses, which
remain active. Other response holds, active jobs and recovery-required jobs still block
them. Pending response work must finish before a new service check is queued. The
worker/scheduler use this narrowly scoped exemption only for `response-service-health`;
mutation, restoration and process actions inherit no exemption. Service results do not
change file receipts, readiness, incident state or the existing `KEEP REPLACEMENT`
requirements. Review services and application-specific health independently before
using that separate pause review. No service start/stop/reload/restart, reset-failed,
process recovery, automatic rollback or automatic service monitoring is introduced.

**Service health history** provides paginated actor/reason, controller start/finish
times, exact samples, gaps, scope and baseline changes. File cards show the last
recorded observation, explicitly as historical metadata. The new
`security_response_service_observations` table is append-only through feature APIs
and is included in startup initialization and verified offline SQLite/MySQL migration.
Response-record exports now use **version 2**, adding a twentieth
`service_observations` section under the existing size/row budgets. The offline
verifier continues to accept original nineteen-section version 1 exports. These are
mutable application records with the same independent-retention/integrity limits
described above.

Rebuild app/workers and redeploy current helpers using the reviewed installation
workflow before use. Tests cover healthy/failed/inactive/oneshot/changing states,
bounded exact arguments, malformed properties, diagnostics, boot changes, sanitization,
queued/late pin/plan/state/publication changes, baseline changes, own/unrelated pauses,
roles, pagination, migration and versioned exports. Native SSH fixtures exercise real
worker/bridge dispatch on Ubuntu, Debian, Fedora and AlmaLinux with a recorded systemctl
stub; browser tests cover explicit units, baseline selection and history. Real service
managers, service-specific endpoints, live GCP/IAP and real-VM/SELinux acceptance remain
operator validation. Separately approved service orchestration remains a later milestone.

## Automatic service watches

**Reviewed file responses → Configure service watch** is off until an administrator
explicitly enables it. Enabling or reapproving a watch selects a **healthy manual
service observation no more than five minutes old**, its displayed report digest,
an interval of **5–1,440 minutes**, an independent **pause on problem** checkbox and a
meaningful reason. Automatic observations cannot authorize a watch. The exact ordered
service selection, pinned host, file-response plan/state, current publication ID/plan
and baseline report digest are retained. A new revision binds every policy edit;
stale edits are refused. A recent healthy baseline is a reviewed selection, not a
claim that a newer negative observation can be ignored: newer matching negative
observations still appear as problems.

One watch belongs to one file response. At most **500 watches per server** can be
enabled. The leader considers watches every thirty seconds, serializes queueing with
a dedicated queue lock and the server operation lock, and queues **at most one service
watch per server every five minutes**. Each watch's configured interval is a minimum;
due watches are ordered by oldest attempt to prevent an always-due watch monopolizing
the server. The UI shows the nominal minimum server rotation (`enabled watches × five
minutes`). Ordinary queued work takes precedence. Long intervals, busy queues, slow
checks, unavailable workers and pauses can extend actual coverage well beyond that
minimum. Coverage assessment uses the larger of the watch interval and nominal
rotation, plus five minutes' grace. Missing, future-dated, negative or older positive
observations are overdue. This is coverage accounting, not a real-time availability
guarantee. No service-check history is automatically deleted.

Scheduled work reuses the existing bounded read-only service protocol; it does not
install/restart/reload services, signal them or verify application endpoints. The
watch's revision, enabled flag, exact units, baseline digest and response/publication
scope are checked at queueing, before/after independent helper verification, and after
remote I/O using fresh database snapshots. A disabled/revised policy, changed baseline,
new publication, file-response state/plan change or host-key change prevents old work
from becoming current proof or creating a new pause. Scope changes stop that watch's
automatic reads and raise coverage/problem alerts until explicitly reapproved; the
watch never silently follows a new host or replacement. Historical observations and
policy events remain available. There is no instantaneous revocation of a read already
in progress; its stale result is retained as skipped history.

Automatic service reads have **no response-hold exemption**. File, publication,
process, service and recovery-required pauses defer them. Manual service reads retain
their narrowly scoped exemptions for their own response, including its service pause,
so an operator can collect a fresh observation before review. Unrelated pauses and
unreconciled running jobs still block manual work. A queued, deferred automatic read
does not block a manual service request; ordinary manual/mutating response work still
serializes. Scheduling and execution both enforce these distinctions.

A stable negative service result, missing/changed manager properties, helper failure,
SSH failure, invalid protocol or unavailable coverage appears as a problem. Only an
**enabled, unchanged watch whose pause-on-problem choice remains enabled after I/O**
may add a service pause. Overdue scheduling alone raises a coverage alert and does not
add a pause. A scope/policy mismatch is a skipped observation rather than authorization
to pause a changed response. The independent pause is stored on the service watch;
it does not change original-file, publication or process receipts, states or holds.
Server work gates and alerts include it even after monitoring is disabled.

Neither a healthy automatic/manual observation, disabling monitoring, changing its
interval nor unchecking pause-on-problem releases an existing pause. A paused watch
also cannot be rebound to different services or response/publication scope before
that pause is separately reviewed. A fresh manual healthy result can supersede an
older problem alert while leaving the independent pause active. Automatic checks
continue to defer while it is active.

**Review service pause** requires the current policy revision, a meaningful reason
and the selected typed phrase. **ACCEPT HEALTHY SERVICES** additionally binds a healthy
manual check no more than five minutes old, its exact report digest, the watch's exact
units and current file/publication/host scope. A stale, automatic, foreign or negative
observation cannot release it. **CONSOLE REVIEWED** records the administrator's explicit
trusted-console assessment without asserting verified service health. Either choice
clears **only that service pause**, reports whether any server pause remains, and
leaves file/publication/process/other-watch pauses and incident state unchanged. If a
watch remains enabled and the problem persists, a later authorized check can add a
new pause. Disabling it and separately reviewing the existing pause are distinct steps.

Service-health history records manual versus scheduled origin, watch revision, policy
agreement and whether an automatic result added a pause. File-response history retains
policy snapshots, actors/reasons, automatic observations and pause reviews as events.
Host alerts separately report service problems, overdue/limited coverage and active
service pauses. **Recurring service coverage** and per-response watch controls expose
these states in Security. Alerts use the existing configured notification system;
no new external account or notification credentials are introduced.

`security_service_watches` is registered at startup and included in verified offline
SQLite/MySQL migration. Response-record **version 3** adds a twenty-first `service_watch`
section for current policy/pause metadata; service observation and file-event sections
retain their associated history. The offline verifier accepts versions 1, 2 and 3.
The existing 1,000-section-row, 5,000-total-row and 16 MiB export budgets apply. These
records remain mutable application data with the independent-retention/integrity
limitations described above, not cryptographically immutable evidence.

Rebuild the controller app/workers. This feature reuses the service-health helper
introduced in the preceding milestone; targets must already have that verified helper.
Tests cover opt-in selection, fresh manual authorization, stale policies/baselines,
queued/helper/remote scope changes, pauses, disabling without release, manual recovery
past deferred reads, typed reviews, unrelated holds, fair rotation/cadence, coverage
alerts, role/CSRF/host boundaries, enabled-watch limits, versioned exports and offline
migration. Native Ubuntu, Debian, Fedora and AlmaLinux SSH fixtures check actual
worker/scheduler/bridge flow, failed-service pause, manual recovery, separate review
and unchanged file/publication holds using recorded systemctl stubs. Browser checks
cover enabling, disabling with a pause retained and independent typed pause review.
Real service managers, real workload health, live GCP/IAP and real-VM/SELinux acceptance
remain operator validation. Full service orchestration remains future work.


## Server management lifecycle

Administrators can disable, enable or delete a server from Servers, its overview,
its Settings → Server management section, or the Manage dialog.
Each change requires a meaningful reason and the lifecycle revision loaded by the
page. Delete also requires the exact server name. Role and CSRF checks apply. The
host executor lock and separate cross-process queue, poll, telemetry, control and AI
locks refuse transitions while cooperating work is active (HTTP 409). Running jobs
must finish or be reconciled; transitions do not kill remote work.

Disable suspends management and AI requests, cancels queued jobs and unstarted
schedule runs, records unstarted response rejection, and revokes enrollment links.
The local key, policy and history remain. Existing response/recovery holds remain.
Enable creates a new lifecycle revision and resumes future approved automation,
including security monitors and schedules. Old jobs cannot cross the revision and
cancelled jobs never restart. Reconcile existing holds after re-enabling. Disabled
connection and host-key settings may be edited locally; testing still requires
management to be enabled. Previously downloaded installer files cannot be revoked.

Delete is permanent removal from management with retained history. It is blocked by
running/recovery jobs and file, process, publication or service holds. It commits
disabled management and revoked links before local credential cleanup. Failed cleanup
leaves a disabled server for review and retry, rather than an active entry with a
partially removed key. Cleanup unlinks only this server's SSH keys/rotation files and
cached APT authentication through anchored, no-follow directories, and removes its
saved repository credentials and connection configuration. These are logical removals;
backups, old installer scripts, filesystem snapshots and crash leftovers are not
securely erased. It does not remove the remote agent, remote account, authorized key,
files or services. Use a trusted console for any separate remote decommissioning.

A deleted row is retained as a tombstone with its immutable identity and timestamps.
It cannot be enabled again. New enrollment creates a new identity. Deleted entries
are absent from the managed fleet and configuration selectors. The administrator's
Deleted servers view exposes read-only recorded inventory, patching, AI, operation and
security history, including response metadata exports. Deletion does not assert that
evidence is immutable or that a target is clean. Existing retention policies and
backup/integrity limits still apply; history is not purged by this action.

Startup upgrades existing SQLite/MySQL host tables idempotently; legacy servers
remain enabled. Verified offline migration carries lifecycle fields. Rebuild the
controller app and workers; no new remote helper is required. Tests cover role/CSRF,
stale revisions, queued work and enrollment revocation, in-flight locks, retained
holds, failure/retry cleanup, stale host objects, schema upgrades and offline copy.
Native SSH fixtures additionally disable/re-enable a live connection, delete its
local management identity and verify that another identity still reaches the same
remote agent. Browser tests cover list/workspace controls and retained security data.


## Planned: distribution and major-version upgrade availability indicators

Requested 2026-10-31 and tracked by issue #96; **planned, not implemented by the
v1.35.1 roadmap update**. Detect supported Linux distribution or major-version
upgrade offers independently from routine package candidates. The initial families
are Debian/Ubuntu and Fedora/RHEL-compatible systems. A newer release existing is
not sufficient: use the distribution's supported upgrade path and distinguish an
offered upgrade from supported-but-not-offered, unsupported, stale, unreachable and
failed/unknown detection states. Inventory and explicit refresh record the checked
time, current distribution/version, offered target and bounded diagnostic evidence.
Detection is read-only and never authorizes or starts a release upgrade.

Use one backend/API source of truth. A current verified offer produces a prominent
but unobtrusive notification card on the server Overview front page with current and
target versions plus a deep link to release-upgrade details. Show the same accessible
icon/badge beside that server in the standard directory, fleet cards/search results
and other reusable server references. The icon has a text alternative/tooltip and
must not rely on color alone. Stale, unavailable, failed or unsupported checks never
create a false upgrade-available badge. Clear the status only after refreshed
evidence shows no eligible offer, including after a completed upgrade.

Integrate with the planned durable notification/event identity so an unchanged
offer does not flood global alerts, while a newly offered, changed, cleared or
reopened status can produce the appropriate revision. Respect current server/role
visibility, escape distribution-controlled text, preserve Back/Forward and view
context, and retain the existing explicit reviewed GO workflow for any actual
upgrade. Acceptance requires backend detection fixtures for each supported family,
stale/error/unsupported cases, synchronization and permissions, plus inspected
mobile/tablet/desktop renders for Overview and every standard server-reference
component. Issue #96 remains open until end-to-end detection and UI acceptance land.


## Execution-triggered scoped scanning

Security now offers an independent **Execution-triggered scans** policy. It is off
by default. Administrators select 1–16 canonical, non-overlapping directories,
15–300 seconds of debounce, a 5–60 minute minimum interval and 1–12 scans per rolling
hour (defaults: 30 seconds, 15 minutes and four scans/hour). Saving requires the
current policy revision, a reason and the server operation lock. It never installs
ClamAV, updates signatures, enables AI, approves a response or starts remediation.
The existing opt-in automatic scanner incident-plan setting still applies to any
new detections, using its existing quota, evidence binding and AI cost logging.

Only **newly persisted spool events** can introduce triggers: no existing observations
or process snapshots are backfilled. A candidate must report eBPF capture and verified
identity, a canonical executable path strictly below the configured directories, a
SHA-256 digest and a UID. Target observation time must be after policy activation,
no more than 120 seconds old and no more than five seconds ahead. This requires
reasonably synchronized clocks. Samples, unverified short-lived executions, hashes
that could not be captured and out-of-scope paths are not eligible. These checks do
not independently attest a compromised root/kernel or guarantee lossless eBPF capture.

Triggers bind host identity, lifecycle revision, policy revision, path/hash, source
observation, UID, observation time and controller receipt time. Identical path/hash
pairs receive at most one trigger per policy revision, irrespective of repeated
executions, network changes or replayed spool batches. A policy save establishes a
new revision and activation time, invalidates pending triggers and cancels unstarted
jobs. Running work must finish before policy changes. Disabling server management
also cancels pending/queued triggers; re-enabling never resumes them. Histories remain
available, including under Deleted servers. Changing the policy can allow a later,
newly observed execution of the same identity to prompt a new scan.

Intake examines at most 128 process records per event, accepts at most 128 distinct
identities per server per rolling hour and retains at most 128 outstanding triggers.
Overflow and unexamined tails increment explicit coverage counters; these are counts
of omitted observations, not necessarily distinct executables. History has no automatic
purge policy, consistent with existing security evidence. Plan database storage and
independent retention accordingly.

The leader batches up to 32 debounced triggers into a single scoped scan. Jobs and
trigger bindings commit atomically. It waits for a fresh server contact (within two
minutes), completed enrollment, an enrolled baseline and host pin, and an idle queue.
Every file, process, publication, service and recovery hold defers automatic scans;
there are no response-hold exemptions. Manual/scheduled ClamAV and YARA queue checks
include execution scans to avoid overlapping automatic requests. All execution-scan
attempts, including failures and cancellations, consume the configured rolling-hour
and cooldown budgets across policy revisions. Triggers expire after 15 minutes even
if queue pressure, holds or a longer cooldown prevents timely use; they are not
silently replayed later. A known failed/interrupted operation is reconciled as history,
not retried automatically. Queue a manual scan or review/re-save the policy when an
additional attempt is appropriate.

Before any helper contact, execution rechecks the current policy, exact directories,
host pin/lifecycle revision, trigger/job binding and expiry. A fresh independent agent
health check is mandatory; changed access paths or helpers are not accepted. The scope
is checked again after that verification and after remote scanning, using fresh
sessions. Invalidated approvals do not send a scanner request. Results received after
a scope change are retained as incomplete coverage, including their findings, rather
than promoted to current proof. Transport/helper/protocol failures remain visible in
operation and trigger history. A changed pin cannot even initiate helper verification.

The scanner uses the existing read-only directory protocol and budgets: at most 2,000
files/10,000 traversal entries, 32 MiB per file, bounded engine time and explicit
signature/coverage gaps. Roots and reported engine must match the requested ClamAV
scope. An execution is **only a scheduling hint**. This scans configured live directories;
it does not capture a historical executable descriptor, establish that a particular
triggering file was reached within the budget, or prove that its bytes still match the
earlier event hash. Findings retain the actual scanner-observed path/hash and coverage,
not an inferred match to the triggering executable. Trigger metadata and this limitation
are attached to the immutable scan receipt; incident/AI coverage context identifies
that origin. Missing/stale signatures, exclusions, limits and a missing engine remain
incomplete coverage and never establish a clean server.

The policy/status panel exposes trigger history, queue/job IDs, aggregate states,
coverage drops and collector issues. Recent failed, incomplete, skipped or expired
work and recent intake drops produce an execution-scan coverage alert through the
existing notification system. A later positive scan does not erase an earlier coverage
gap. Counters are retained, while recent-gap alerts age out after an hour; unresolved
queued expiry remains a coverage limit. eBPF capture failures and lost spool data also
retain their existing collector integrity/coverage alerts. No eligible events is not
proof of a clean host or complete coverage. Files never executed, file-write events,
unsupported kernels, scripts interpreted by other executables and broader runtime
mechanisms still require other detection approaches.

The trigger table and policy settings are initialized at startup and copied by verified
offline SQLite/MySQL migration. Relevant scan receipts, including their automation
metadata, remain part of existing portable response exports. Rebuild/restart controller
app/workers; this milestone requires no new target helper. Targets must already have
verified existing scanner/eBPF support and separately installed ClamAV/signatures.
Native CI exercises the real policy/scheduler/worker/SSH path using **injected verified
execution metadata** and an intentionally absent scanner, proving incomplete coverage
and unchanged fixture bytes. It does not certify real eBPF capture or live ClamAV
signature efficacy. Unit tests cover ingestion, replay, timing/scope, quotas, holds,
lifecycle/policy revocation, storage failure, helper/remote races, failure history,
roles/CSRF and offline migration. Browser tests cover opt-in policy and trigger history.
Real VM/eBPF/ClamAV performance and failure drills remain operator acceptance work.


## Fleet security coverage overview

The administrator-only **Security coverage** workspace lists managed servers with
independent latest ClamAV and YARA receipts, signature validity at viewing time,
scan-age limits, latest attempts and open/acknowledged scanner incident counts.
Search is literal by server name; pagination is bounded, with page-scoped totals.
Disabled servers retain clearly labeled historical results; deleted entries remain
in the existing Deleted servers workflow. Reads never contact targets.

Latest results are selected independently per engine, so a newer YARA receipt cannot
hide an older failed ClamAV attempt. Failed and pending attempts are visible even
without a scan receipt. ClamAV build age and YARA expiry are reassessed at read time.
The recurring ClamAV interval supplies its age budget when enabled; otherwise the
view uses 24 hours. YARA uses a separate fixed 24-hour display threshold, not an
automatically configured YARA schedule. Completed attempts without matching receipts
are shown as missing coverage rather than allowing older results to hide the gap. Recorded coverage is never a clean-host or
complete-protection verdict. Scope, gaps and links lead to existing server controls.

This adds fleet-level scanner visibility; cross-source threat correlation, external
retention and broader runtime coverage remain unfinished. No target helper upgrade
or database schema change is required. Unit/API checks cover engine separation,
failures, expiry, disabled/deleted hosts, search, pagination and administrator access;
browser checks cover the overview and navigation.

The “No durable receipt” label means no engine-specific receipt exists in durable
scan history. It does not assert that a legacy installation or external scanner
has never scanned that server. Unbound legacy latest-report settings are not
promoted into current engine coverage.


## Cross-source incident evidence pivots

The server Security tab now offers **Related evidence** on each scanner incident.
This administrator-only read searches stored records on the same server: immutable
ClamAV/YARA findings, retained process observations, startup/custom-file inventories,
local package-database discrepancies and authenticated vendor comparison findings.
It distinguishes same path/hash, same hash at another path, same path with a different
hash, and path-only records without an observed hash. A vendor artifact's expected
hash is never treated as the observed target hash. Execution identity verification
and capture method remain visible; unverified records are not promoted to proof.

The responsive dialog provides receipt IDs, controller receipt times, separate target
observation times, source labels, coverage gaps and links to existing source histories.
It preserves the existing raccoon dialog and visual theme. Only whitelisted metadata
is returned; command arguments, environments, raw scanner output and file contents
are not added to this view. No target contact, AI upload, authorization changes or
remediation occurs. Existing advisory plans retain their original evidence scope.

Each page examines up to 50 receipts **per source**, independently of how many match.
Use Older records even after an empty page when older receipts remain. Per receipt,
search bounds are 100 scanner findings, 256 process/inventory entries, 200 vendor
findings and 16 package groups of at most 200 discrepancies each. Omitted entries or
package groups are counted. At most five matching entries and five coverage gaps
are shown per matching receipt, with omission counts and source-history links.
Coverage-limited receipt counts include nonmatching receipts. These are bounded search
summaries, not an exhaustive forensic timeline or a complete coverage assessment.

Paging fixes a controller receipt-time upper boundary and binds the incident's scan
and evidence digest; changed evidence requires reopening the dialog. Ordering is
deterministic, but this is not an immutable cross-source snapshot: normal process
observation retention can remove rows while paging. Historical collection gaps,
backdated imports, unknown metadata and a compromised root/kernel remain limitations.
No match is not proof that a file never ran, was absent or was harmless. A shared
hash/path does not establish causation, persistence execution or malicious intent.

No schema or remote helper upgrade is required; rebuild the controller app. Tests
cover exact matching, cross-host isolation, expected/observed hash separation,
malformed historical receipts, independent pagination, time/digest guards, explicit
bounds, administrator access, deleted-server history, safe output and absence of
remote/provider calls. Browser tests cover the dialog, older/empty pages, escaping
and mobile width. Broader behavior/threat intelligence correlation, independently
reviewed cross-source AI evidence, retention, engine maintenance and the other major
work listed above remain unfinished.


## Per-server AI integration pause/resume

Implemented: administrators can pause or resume AI independently for each server from
the persistent AI integration panel on every server tab. The stored setting defaults
to resumed for existing servers and survives controller restarts and offline database
migration through the existing settings table. Management-disabled servers can preconfigure the AI state without re-enabling
management. Deleted servers expose read-only state.
Changes require a reason, current revision and CSRF protection, and record actor,
time and reason in audit history. Non-AI inventory, patching, schedules, scanning and
monitoring remain operational. Historical results and activity remain available.

Automatic triage and scoring skip paused servers without starving other servers.
Scanner auto-proposal scheduling skips paused hosts. Manual and queued proposal
execution recheck the state. Every host-scoped provider request also rechecks fresh
state immediately before network I/O, including second triage calls, release
configuration AI and shared fleet scoring batches. A batch containing a newly paused
server is rejected in full; no paused-server payload is sent. Existing retry/quota
limits apply after resuming. Failed/blocked attempts remain visible in AI activity
and job output, with a controlled pause diagnostic rather than a provider failure.

Cross-process per-server provider locks serialize state changes with outbound requests.
A pause/resume attempted during a request returns HTTP 409 **without changing state**;
retry after it finishes. A successful save prevents subsequent requests, but cannot
retract data already sent or erase provider retention. Already returned results may
finish local validation/persistence. A resumed server still requires global AI enablement,
a valid model/key, feature settings, eligibility and quotas. Global diagnostic model
checks carry no server data and remain available. No target helper or schema upgrade
is required; rebuild the controller. Broader correlation, retention and other major
work above remain unfinished.


## Planned: faster parallel AI triage and configurable spending controls

Requested 2026-10-30; **the program remains unfinished**. v1.18.0 provides the baseline/transport/timing foundation, v1.22.0 adds bounded
cross-server threaded process triage and renewable claims, and v1.28.0 adds the first
strict zero-provider exact-candidate lookup as checkpointed below. Native complete-
context collection, revocation/contradiction review, same-server parallelism, broader
fairness and shared controls remain unfinished. The inspection baseline below is
historical.
Inspection baseline: main `8bee5b64`, source v0.16.0, latest merged PR #71.
No live deployment timing or provider benchmark was available; the following are
verified code constraints rather than a measured diagnosis of one deployment.

### Current constraints and capability contract

- `worker_registry.POOL_CAPACITY['ai']` is fixed at one. The scheduler retains one `ai_task`, and `ai_cycle` runs one process investigation and then one update-scoring batch sequentially. Raising a pool size alone does not enable parallel triage.
- `worker.investigate_one` holds the fleet-wide `ai-triage` lock for the entire investigation. Per-server provider locks also serialize outbound calls for a server. The current reconciliation routine assumes exclusive execution and would interrupt valid concurrent runs if reused unchanged.
- An investigation can require two sequential model calls with allowlisted SSH evidence collection between them. `ai._request` used top-level `httpx.post` at this baseline; v1.18.0 adds the
  bounded reusable transport and stage diagnostics described below. At this baseline most failed/interrupted investigations wait one hour before retry; v1.19.0 adds the bounded process-triage scheduling described below.
- Process investigations and score batches have independent rolling-hour hard allowances, defaulting to 20 each. Incident/startup plans additionally share a fixed ten-per-hour allowance. Cost receipts are retrospective estimates; they do not implement daily budget admission.
- Existing behavior IDs include the server ID, so retained assessments/approvals do not provide a fleet-wide exact-match known-good cache. The current Retry action only accepts unapproved pending/error items; it cannot explicitly re-triage a completed safe/cache result.

Improve throughput and time to a useful assessment while retaining the configured
model and reasoning effort, all currently authorized evidence, conditional follow-up
checks, identity/freshness checks, structured-output validation, explanations,
uncertainty, redacted run/cost diagnostics and operational authorization. Do not
silently substitute a weaker model, reduce effort, truncate required evidence,
skip follow-up checks or treat an unavailable assessment as benign to claim speed.
Concurrency primarily reduces queue delay; measure single-investigation latency
separately instead of promising a fixed production speedup.

### Parallel execution and latency work

- Add a bounded, configurable `ThreadPoolExecutor` for independent triage tasks, with an initial target default of four concurrent investigations subject to load validation. Expose actual configured/active/queued AI capacity. Retain a supported serial setting and validate configuration/resource bounds.
- Replace the single AI future/global execution lock with short atomic per-item claims, renewable leases and worker/boot ownership. Use independent database sessions and explicit run/policy context per task; never share mutable ORM sessions across threads. Completion must verify claim ownership and current evidence before accepting a verdict.
- Support concurrent investigations across servers and independent subjects on one server where safe. Preserve locks for conflicting target mutations and evidence collection. Replace the all-exclusive per-server provider gate with concurrency-safe in-flight admission that still serializes pause changes against new calls, rechecks policy before every call and never sends paused-server evidence. A pause cannot retract an already sent request.
- Make orphan reconciliation lease/heartbeat-aware; do not interrupt all running records when any worker starts a task. Recover expired work without concurrent duplicate claims, repeated acceptance or silent loss. Handle leader transfer, worker crash, restart, graceful drain and interrupted second-stage investigations honestly. A lost provider response may still be billable; do not promise exactly-once provider execution.
- Schedule investigations, scoring and other AI purposes fairly, with explicit priority/aging and bounded per-host occupancy so a busy server or slow scoring batch cannot monopolize all capacity. Release execution slots while waiting for rate refill, budget reset or retry; do not sleep in a worker thread holding a database/host lock. Keep coordinator election separate from execution so supported workers can consume claimed AI work without becoming competing schedulers.
- Reuse lifecycle-managed HTTP clients/connection pools with bounded pool/connect/read deadlines and safe per-request credentials; close them on drain/shutdown. Keep slow provider/SSH operations outside database transactions wherever possible. Measure candidate-query/index and repeated evidence-collection costs before optimizing them.
- Deduplicate identical queued subjects and reuse valid immutable evidence with subject identity, evidence revision/hash, authorization scope, model/prompt/policy version and explicit freshness rules. For fleet-wide known-good assessment reuse, apply the exact-match contract below. Never apply an unmatched cross-host verdict, suppress a new incident or widen data sharing to improve cache hits. Keep stable instruction/schema prefixes and lossless input formatting where provider caching helps.
- Replace blanket one-hour retry with classified handling: honor provider Retry-After and rate signals, use bounded exponential backoff with jitter for transient network/429/5xx failures, and surface authentication/billing/schema/configuration blockers until corrected. Preserve attempt/cost receipts and bounded retries; manual retry cannot bypass policy, reservations or shared admission.

### Fleet-wide exact-match known-good cache

Additional user requirement (2026-10-30): once an item has completed triage and is
known good/safe, reuse that assessment on another server when it is **the exact
same item and relevant context**. Do not pay for another AI investigation unless
explicitly requested or the entry no longer matches/is no longer valid.

- Persist a fleet-scoped assessment cache separate from per-server observations. Each cache hit records the receiving server/observation, originating triage run and evidence, fingerprint version, matching fields, original classification/confidence/limitations and hit time. Retain whether the source was an AI assessment or an explicit administrator known-good approval; reuse must not silently turn an AI classification into administrator approval or a clean-host claim.
- Define a versioned canonical fingerprint from verified artifact bytes (SHA-256 plus relevant script/interpreter/library/config identities), package/vendor provenance and versions, effective behavior and security-relevant context. Include execution privilege/account semantics, startup mechanism/command/trigger when applicable, relevant network/service/container context and all follow-up evidence on which the safe assessment depended. Keep evidence-completeness/trust boundaries and model/prompt/policy versions in the eligibility contract. A filename, package name or executable hash alone is insufficient.
- A reusable key must permit an actual exact match across servers: exclude host ID and documented observation-only differences such as PID/timestamp/ephemeral source ports from the canonical key, while retaining them in local records. Normalize only proven non-security differences; missing/unknown fields, unverified identity or incomparable context are cache misses, not wildcard matches. Validate required local evidence read-only before reuse; matching cannot be inferred by AI similarity.
- Cache only completed, validated safe/known-good outcomes whose required evidence and explicit scope permit reuse. Pending, partial, failed, suspicious or unknown assessments are ineligible. Changed bytes, provenance, privileges, behavior, configuration, applicable threat evidence or assessment policy invalidate eligibility. Revoking a trusted entry blocks subsequent reuse across the fleet and marks linked assessments for review without rewriting their original history. Stronger new detector/incident evidence always remains visible and actionable.
- On an eligible hit, reuse the assessment without any provider call or duplicate AI budget reservation, mark it clearly as **Cached known good** and keep its explanation/source link. An unchanged valid exact match must not be periodically re-triaged solely because another server or day is encountered. Continue normal collection, signature scanning and deterministic protection; a cache hit does not authorize containment or suppress future changed evidence.
- Add an explicit administrator **Re-triage** action for completed/cached safe items, separate from retrying failed work. It bypasses cache lookup for the selected observation while respecting pause, data-sharing, throttling, daily reservations and current evidence. Show whether the user is refreshing one observation or revoking/replacing the shared entry, require explicit scope for fleet trust changes and audit both. Preserve prior assessments; a new suspicious/unknown result revokes the corresponding reusable safe entry and schedules linked review.
- Keep cache records and their minimum provenance independent of ordinary AI-log pruning; unavailable source evidence must never leave an unverifiable trusted hit. Respect fleet/tenant access boundaries, protect cached evidence and expose cache hit/miss/invalidation reasons and saved calls/cost estimates. Cache lookup may serve retained/local assessments while provider AI is paused; it cannot bypass a restriction on sharing evidence or making a new call.
- Validate exact cross-server hits with zero provider calls, same-name/different-hash and same-hash/different-behavior misses, script/config/provenance/privilege changes, incomplete/unverified evidence, revoked entries, concurrent first encounters, manual re-triage, changed follow-up evidence, log retention and role isolation on SQLite/MySQL. Preserve per-host observations/audit and existing explicit approval boundaries.

### Throttling, daily cap and unthrottled operation

Provide administrator-controlled modes in Settings with clear effects before save:

| Mode | Admission behavior |
| --- | --- |
| Rate throttle | Smoothly pace eligible work at configured rates using shared token/leaky-bucket admission; defer it durably until refill instead of consuming an hourly allowance in a burst and stopping. |
| Daily spend cap | Allow work while its conservative reservation fits the configured USD/day budget; queue remaining work until the next calendar-day reset. A rate throttle may also be enabled. |
| Unthrottled | Apply no Mr Patchy rate or spend allowance; run as quickly as configured concurrency, resources and provider limits permit. |

- Separate concurrency (simultaneous work), pacing (work/calls/tokens per time) and cost budget in the API/UI. A throttle is an upper pacing target, not guaranteed throughput or a lifetime total. Unthrottled never disables global/per-server AI pause, feature opt-ins, data-sharing controls, finite resource bounds, provider restrictions, authorization or response safeguards.
- Apply one distributed admission/accounting layer to every billable provider path: process triage and follow-ups, retries, scoring batches, manual/automatic scanner and startup plans, release configuration/planning and saved-settings model tests. Remove or explicitly migrate hidden hard allowances, including incident plans; preserve separate anti-abuse protections and deduplication with explained states. Background and manual work cannot bypass the selected mode.
- Migrate existing hourly settings to an explicit, reviewable pacing policy with conservative defaults and an administrator preview/audit. Do not silently switch an installation to unthrottled operation, reinterpret zero ambiguously or increase spending through an unnoticed change of accounting units. Treat budget/rate deferral as queued work, not a failed attempt or a reason to discard evidence.
- In cap mode configure a positive USD amount, an explicit IANA timezone and the next calendar-day reset, including daylight-saving transitions. Changes to amount/timezone/mode are revision-checked and audited; prevent resets, restarts, clock changes or mode toggles from silently granting duplicate budget.
- Reserve cost atomically before admitting each paid call, accounting for all outstanding reservations across workers/purposes, selected model/tier, bounded input and output/reasoning tokens, supported charges and the potential follow-up stage. Define whether an entire multi-stage run is reserved in advance or deferred between stages; never skip a required stage or accept an incomplete verdict because funds run out.
- Reconcile reservations to returned usage and a retained price snapshot using decimal currency arithmetic. Failed/refused/incomplete responses and retries may cost money. Missing usage, unknown prices, timeouts and lost responses are uncertain costs, never zero: retain a conservative reservation and expose a reconciliation state; block capped admission if a safe bound cannot be calculated. Do not release a possibly billed reservation merely because a lease expires or a day resets. Attribute cross-midnight calls consistently and show outstanding exposure against available headroom.
- Keep the budget/reservation ledger durable and independent of configurable AI-log history pruning. Serialize competing admissions/settings changes without holding a lock across network I/O; reconcile crash/partial-write recovery without double spending or double release. Explain that locally estimated spend is not an exact provider invoice guarantee, and identify any unbounded pricing/usage uncertainty rather than claiming an enforceable cap for unsupported billing.
- In Settings, Investigations, AI activity and worker health show selected mode, configured/effective concurrency/rate, queued/active count, oldest wait, blocked reason, next eligible time/reset, estimated spend, reserved/uncertain spend and remaining budget. Keep private evidence and credentials out of metrics. Integrate readable glass/tab/menu layouts and mascot guidance with existing role/audit boundaries.

### Finite implementation and acceptance milestones

1. **Baseline, transport and known-good reuse:** record queue/admission/provider/SSH/persistence stage timing, p50/p95 end-to-end latency, throughput, calls/tokens/cost, errors and backlog age for representative one/two-stage workloads; add safe client pooling, evidence deduplication and the fleet-wide exact-match known-good cache with explicit re-triage, without changing the capability contract.
2. **Threaded execution:** deliver configurable concurrent tasks, atomic claims/leases, context/session isolation, fair scheduling, pause-safe same-host/cross-host admission, drain and recovery. Compare serial and parallel execution on identical delayed I/O fixtures: four eligible independent investigations must actually overlap and complete materially faster than their serial sum without lost work or reduced checks. Report measured production limits separately.
3. **Shared controls and UI:** deliver pacing, daily cap and unthrottled settings, conservative migration, complete billable-path coverage, reservations/reconciliation and clear queue/spend diagnostics. Document operator tuning and upgrade behavior; changing a label or merely raising existing limits does not complete this milestone.
4. **End-to-end acceptance:** on SQLite and MySQL validate multi-thread/multi-process claims, supported multi-worker admission, contention/fairness, policy/evidence changes, stale/replayed results, provider limits, bounded retries, lease loss/crash/drain, unknown pricing/usage, simultaneous budget admissions and settings changes, two-call reservations, midnight/DST/reset and retained ledgers after history pruning. Verify disabled/paused/data-sharing/role/CSRF behavior and representative benign/suspicious/unknown outcomes with all original evidence checks and response gates intact. Record before/after performance and capability-equivalence results before marking the program complete.

Issue reproduction/fixes retain priority over these roadmap milestones. Reconcile
unfinished related work first and use the existing cycle budget, source/PR versioning
and exact-final-commit CI gates. The scheduled task carries the same requirements;
the feature remains outstanding until runtime behavior and acceptance are delivered.


## Portable per-server scanner records

Administrators can use **Security → Export scanner record** without preparing a file
response. The same control is available in retained Security history for disabled or
deleted servers. It exports four host-scoped sections: durable ClamAV/YARA scan
receipts, scanner incidents, incident/review events and advisory AI plans. Rows are
ordered deterministically. It does not contact a target, call AI, read acquired file
bytes, change incident/plan/response state, upload evidence or delete records.

The export uses explicit field projections. Finding paths, hashes, large integer file
identities, scanner scope/state, signature/rule provenance, coverage gaps, review
reasons and advisory text remain sensitive investigation metadata. Raw scanner output
and unrecognized fields are excluded. It does not include startup/package inspections,
execution observations/triggers, file-response custody, AI usage records, job payloads,
credential/connection configuration or unbound legacy latest-report settings. Use the
existing response-record exports separately for individual file-response custody and
monitoring. Events without an attributable incident parent are excluded. Missing scan
and advisory evidence references are reported; none are fabricated. These flags do
not prove that all historical records were ever collected or remain in the database.

The controller holds the cooperating host operation lock while building the record,
so workers and manual scanner reviews cannot change that host's scanner evidence
between sections. This is not protection against direct database edits, compromised
controllers or unsupported writers. The export is refused as a whole at 1,000 rows
per section, 5,000 total rows, 16 MiB or a cooperative 30-second build budget checked
between rows. This budget is not a database statement timeout. Oversized histories
need a future segmented export workflow; partial success and silent row truncation
are not allowed. Unknown fields are projected out by design, not preserved as a full
raw database backup. Original evidence digests remain opaque source references;
the reduced projection does not reproduce every input needed to recompute them.
Bundle integrity verification is separate from original plan approval binding.

A successful export records its export ID, whole-file SHA-256 and actor in the audit
log, after the snapshot is built; its timestamp and reason are in the record. This
records creation, not proof the browser retained the download. The UI preserves raw
bytes, checks SHA-256 when Web Crypto is available, and offers a separate checksum
download. Protect both artifacts and retain the checksum through an independently
trusted channel. `tools/verify_response_record.py` verifies this scanner format (v1)
and existing response formats (v1–v3), offline using the Python standard library:

```
python tools/verify_response_record.py mrpatchy-scanner-EXPORT_ID.json --sha256 TRUSTED_DIGEST
```

The verifier checks the envelope, canonical record hash, section counts/byte sizes,
section hashes, row bounds and optional whole-file trusted digest; duplicate JSON
keys and changed content fail. Self-consistent hashes alone do not authenticate the
controller, establish historical completeness, certify current file/host state or
provide immutable storage. This milestone adds a bounded independent-retention path
for scanner metadata. Retention policies, automatic deletion, other-source exports,
external immutable storage and independent audit retention remain unfinished.

No schema or target-helper upgrade is needed; rebuild the controller. Unit/API and
offline verifier tests cover host isolation, safe projection, raw integer fidelity,
missing references, inactive/deleted history, roles/CSRF, audit, host-lock contention,
limits and tampering. Browser tests exercise downloads, separate checksums and
responsive review while retaining the established raccoon dialog and visual style.


## Planned: CVE exposure-window exploitation monitoring and automatic containment

Requested roadmap addition (2026-10-29); not yet implemented. This milestone expands
the current manually reviewed response model with policy-authorized automatic
containment. Existing implementations and their documented limits remain unchanged
until the corresponding detection and response milestones are completed.

### Exposure tracking and monitoring

- Correlate published CVEs and trusted vendor/distribution advisories with each endpoint's installed packages, versions, services and relevant configuration. Account for distribution backports and version semantics; distinguish confirmed applicability, uncertain applicability and unaffected endpoints.
- Record an exposure timeline from the CVE publication/release date through verified installation of the appropriate fix. Start active CVE-specific monitoring as soon as applicability is established, including when a patch is not yet available. Review retained telemetry back to publication when available; explicitly show late enrollment, ingestion delays, offline periods and other historical gaps rather than implying retroactive monitoring.
- Correlate CVE-specific exploitation indicators and behavior with available execution/eBPF, process, file, integrity, service, application-log and network evidence. Record detection-rule provenance/version, freshness, confidence, affected CVE and supporting events. Vulnerable-package presence, CVSS severity or an AI assertion alone is not proof of exploitation.
- Keep the exposure window open until the fixed package/version is verified and any required service restart or reboot activates the fix. A failed install, partial update, stale inventory or still-running vulnerable code must not close it. Reopen exposure on rollback or reintroduction of an affected version. Preserve the publication, detection, patch-install and effective-fix timestamps.

### Automatic quarantine or termination

- Provide an administrator-configurable automatic-response policy per server/CVE or applicable policy group. Once enabled, confirmed exploitation meeting the policy's evidence/confidence threshold automatically quarantines the identified malicious file/artifact and/or terminates the identified malicious process, as appropriate, without requiring approval for each incident. Include a monitor-only mode and explicit action scope/exclusions.
- Implement bounded typed quarantine and process-termination executors with fresh host, process start-time and file-identity checks immediately before action, least-privilege helpers, duplicate suppression and recovery records. Distinguish file quarantine from endpoint network isolation; add endpoint isolation only through a supported, separately scoped policy with a recovery path.
- Preserve sufficient evidence before action when feasible without delaying urgent containment, record attempted and completed actions separately, and alert on detections, response failures and uncertain outcomes. Unsupported or ambiguous targets produce an actionable incident/coverage gap rather than an invented successful containment.
- Keep deterministic detection and policy-authorized containment operational when AI is unavailable or paused for a server. Optional AI enrichment must honor the global and per-server AI controls; AI output alone must not authorize termination or quarantine.
- Installing the patch closes the verified exposure window but does not resolve an existing exploitation incident or automatically release quarantined artifacts. Continue incident investigation and recovery tracking independently.

### Visibility, delivery and acceptance

- Add server and fleet views for affected CVEs, exposure duration, monitoring coverage/gaps, patch availability and expected/actual installation, detection evidence, automatic-response policy and action history. Notify administrators promptly and retain actor/policy, CVE/rule version, timestamps and outcome in auditable incident records; preserve the established Mr Patchy theme and mascot.
- Deliver applicability/exposure tracking, CVE-specific detectors, typed automatic containment and UI/audit integration as coherent milestones. Include SQLite/MySQL migration support where needed and document supported platforms, detectors and coverage limits.
- Validate with controlled exploitation simulations and benign lookalikes, vendor backports, patch/reboot/rollback transitions, delayed/offline telemetry, false positives, process reuse/file replacement races, policy changes, AI pause, duplicate events, helper failures and quarantine recovery. Add real-target acceptance and response drills before claiming supported automatic protection. Missing detections never certify an endpoint as unexploited.


## Planned: known and unknown malware detection with automatic response

Requested roadmap expansion (2026-10-29); not yet implemented as an end-to-end
capability. Existing bounded ClamAV/YARA scanning, evidence pivots and manually
reviewed response operations are prerequisites. Reuse the CVE automatic-containment
pipeline above; malware protection must also operate without a known CVE, known
signature or an active CVE exposure window, and continue after patch installation.

### Detection and AI-enabled triage

- Detect known malware using maintained ClamAV signatures, authenticated YARA rules and trusted hash/indicator intelligence. Reuse the planned engine/signature-maintenance work and report provenance, freshness and coverage. Support scheduled and event-driven inspection, including execution and file-write events as those collectors become available.
- Add AI-enabled triage to discover and investigate previously unknown malware from correlated execution/process ancestry, suspicious file changes, persistence, package/vendor integrity discrepancies, service activity and available network/log telemetry. Signature-free behavioral evidence must be usable; lack of a known malware hash or CVE must not prevent an investigation.
- Produce evidence-linked classifications, confidence, explanation, competing benign explanations and recommended actions. Bind the model result to the exact server, observed file/process identities, evidence revision and model version. Separate suspected behavior, confirmed malicious activity and unknown/incomplete results; an unfamiliar binary or model confidence alone does not establish malware.
- Treat endpoint strings, logs and file-derived content as untrusted model inputs. Use bounded structured analysis and validated output types; model output must not become arbitrary shell commands or widen the authorized response scope. Use configured providers and data-sharing controls with bounded/redacted payloads; respect global and per-server AI pause, quotas and activity logging.
- Known-malware scanning and deterministic behavioral detection/response continue when AI is paused or unavailable. Show missing AI investigation coverage explicitly and retain unresolved evidence for later eligible triage.

### Automatic quarantine and termination

- Provide configurable server/group automatic-response policies for known malware and evidence-supported unknown-malware classifications, including action scopes, exclusions, confidence/evidence thresholds and monitor-only mode. Once enabled, qualifying detections automatically quarantine malicious artifacts and terminate associated verified malicious processes, performing both when applicable, without requiring approval for each incident.
- Unknown-malware containment may rely on AI-assisted behavioral classification with corroborating observed evidence and validated policy rules; it must not require a known signature. A bare model verdict alone must not authorize a destructive action. Ambiguous findings remain visible for investigation and escalation.
- Share the typed, identity-checked executors, policy rechecks, duplicate suppression, evidence preservation, alerts and recovery records from the CVE milestone. File quarantine must not be reported as stopping an already running process. Process termination must not be reported as removing persistence or quarantining a file. Report each action's actual outcome independently.
- Track related process trees and persistence artifacts within explicit policy scope, detect recurrence, and escalate unsupported/fileless activity or incomplete containment. Preserve quarantine contents for controlled false-positive restoration, maintain an audit trail, and require separate recovery review before restoring artifacts or restarting affected services.

### Delivery and acceptance

- Add server/fleet malware incidents showing known versus AI-discovered findings, evidence/confidence, detection coverage, response policy and quarantine/termination outcomes. Reuse the existing Security workspace, notifications and Mr Patchy visual style rather than creating duplicate incident systems.
- Deliver maintained known-malware detection, cross-source AI triage, general automatic response and recovery/UI integration as tracked milestones. Update this checkpoint with implemented scope and remaining limitations after each milestone.
- Validate known-malware fixtures, controlled unknown-behavior simulations and benign administrative lookalikes, false-positive restoration, AI outages/pause and prompt-injection attempts, evidence changes, process reuse, file replacement, concurrent/replayed detections and partial response failures. Include supported-platform real-target response drills; document measured detection limits without claiming universal detection or a clean endpoint.


## Planned: comprehensive startup and scheduled-task awareness

Requested roadmap expansion (2026-10-29); not yet implemented end to end. Reuse
existing File integrity inventories, approved baselines, scheduled inspections,
startup incidents, vendor comparisons and AI activity logging. The existing bounded,
metadata-only startup inventory and advisory plans do not satisfy this broader
requirement.

### Discovery and change tracking

- Automatically discover system-wide and per-user cron jobs, including root/user crontabs, system crontabs, cron directories, anacron and queued at jobs. Inventory individual jobs with their source file/entry, schedule, execution account and referenced command/script, rather than only hashing the containing file.
- Discover vendor, administrator and per-user systemd units, services, timers, drop-ins, overrides, enablement links, generated and transient units. Resolve the effective configuration and precedence; show enabled, disabled, masked, active and inactive entries and timer/service relationships. Include applicable SysV init scripts/runlevel links, rc.local and other supported init systems.
- Extend discovery to comparable boot, login and event-triggered execution mechanisms: system/user shell startup files, XDG autostart, SSH rc hooks, udev rules, loader/preload configuration and module-load/modprobe configuration, as applicable to supported platforms. Maintain a documented extensible mechanism catalog with distribution-specific locations and an administrator-configurable additional scope.
- Record file/entry identity, owner, permissions, timestamps, hashes, symlink targets, trigger, effective command and relevant referenced executables/scripts. Read configuration as data without sourcing scripts or executing jobs. Safely inspect supported runtime mechanisms through read-only interfaces; do not silently treat currently excluded runtime paths or symlink targets as covered.
- Run initial discovery and recurring reconciliation, with change-triggered collection where supported. Retain additions, modifications, deletions and baseline history and link meaningful changes to incidents. Paginate/segment large inventories so current 256-entry and time budgets do not silently become a claim of complete coverage. Report unsupported mechanisms, inaccessible accounts/paths, remote homes, races and omissions explicitly.

### Package-default versus custom provenance

- Attribute each file and effective entry to its installed package/version where possible using distribution-native ownership metadata. Compare against authenticated exact-version vendor artifacts/defaults when available; package ownership alone must not mean an entry is an unchanged package default.
- Distinguish verified unchanged package defaults, package-owned but modified configuration, package/installer-generated entries whose default cannot be verified, custom/unmanaged entries and unknown origin. Track administrator overrides/drop-ins separately from the vendor unit they modify; distinguish individual custom jobs within otherwise package-owned files.
- Retain provenance sources and verification strength. Legitimate conffile edits, generated configuration, local packages and configuration-management output require context; custom or modified does not by itself mean malicious, and package-provided does not by itself mean benign. Administrator-approved baselines record acceptance without fabricating vendor authenticity.

### Explained AI triage

- When AI triage is enabled, assess custom and modified entries at initial discovery and after meaningful changes, with configurable scheduling and an explicit data-sharing policy. Provide an evidence-linked assessment of likely benign, suspicious or unknown, confidence, and a plain-language explanation of why. Include apparent purpose, trigger/schedule, execution user/privilege, effective commands and referenced scripts, relevant changes, provenance and supporting/contradicting observations.
- Inspect bounded relevant configuration/script content where authorized; metadata alone may not explain behavior. Redact credentials and sensitive values, record omissions, treat file text as untrusted input, and never execute submitted content or follow model instructions as commands. Bind results to exact entry/file hashes and evidence revisions; changed evidence makes older assessments stale.
- Explain concrete factors such as expected backup/update work, administrator-approved automation, unusual privilege or writable execution paths, obfuscation, download-and-execute behavior, suspicious destinations and persistence changes. Distinguish observed facts from hypotheses; insufficient evidence produces unknown rather than a forced benign/malicious verdict.
- Respect global and per-server AI pause, quotas, retries and AI activity/cost logging. Inventory, provenance and deterministic change alerts remain operational without AI; show paused, pending, failed and stale assessment states. Existing manual advisory plans remain distinct from this new classification workflow.

### Visibility and acceptance

- Add searchable server/fleet views for mechanism, job/unit, schedule/trigger, account, enabled state, package/custom origin, current versus baseline changes, AI assessment, explanation and linked incidents. Allow reviewed benign/false-positive decisions bound to the observed version; future changes require reassessment and retain audit history.
- Feed evidence-supported suspicious findings into the planned malware investigation/response policy. A custom entry or AI suspicion alone does not authorize quarantine, termination or deletion; reuse the established evidence and response-policy checks.
- Validate native Debian/RPM and supported init/cron layouts, per-user/root jobs, unit precedence/drop-ins, transient/generated entries, package defaults versus legitimate edits, malicious and benign lookalikes, prompt injection/redaction, referenced-file changes, large inventories, offline/permission gaps and AI pause. Include real-target acceptance and migration/helper documentation. Do not mark this requirement complete solely because the existing metadata inventory or manual AI plan exists.


## v0.3.0 — opt-in cross-source advisory AI evidence

Delivery: [PR #55](https://github.com/StealthCat/MrPatchy/pull/55); initial implementation
commit [fbf4c149](https://github.com/StealthCat/MrPatchy/commit/fbf4c14996c57ef1f138840c1caa98747d1d385d).
The PR records final validation and its actual merged main commit. No Git tags are created.

The completion gate identified cross-source AI evidence binding as unfinished after
[PR #54](https://github.com/StealthCat/MrPatchy/pull/54), merged as
`a3b0ff9e8e2bc01ca4ac2bf72c0133cf2762e822`. This update adds explicit per-request
sharing consent to manual scanner incident plans. The existing Related evidence
projection supplies matching scanner, execution, startup/custom inventory and package
integrity metadata from the newest 50 receipts per source at capture time. Existing
five-match/receipt, source entry and gap bounds remain visible. Snapshots above
64 KiB are refused before provider I/O; use scanner-only planning or manual review.
No arguments, environments, raw logs or file contents are added by this feature.
Existing scanner finding payloads and their sharing controls remain unchanged.

Related references are source-qualified; exact/path-only/different-hash matches,
unverified executions, missing sources and truncation counts remain distinct.
Endpoint strings are untrusted inputs, not instructions. Typed advisory output may
reference only supplied evidence IDs and never authorizes shell commands or response
actions. The controller retains the bounded shared snapshot, host, model and digest
inside the plan for inspection. Changes/deletion of contributing projected receipts,
incident evidence or review state during generation or before approval reject the
plan. Approval rechecks the same historical time boundary; newer receipts lie outside
that snapshot and do not establish its present-day completeness. Backdated additions
within its bounded search can invalidate it. This is not a live process identity check.

The manual opt-in is stored in the queued job, with actor/scope audit. Global and
per-server AI checks, activity/model/usage records, quotas and the final provider
boundary still apply at execution. Automatic plans remain scanner-only. Historical
plans keep their former binding and approvals execute no target action. No schema
or target helper upgrade is needed; rebuild the controller and restart workers.
Scanner exports retain their existing reduced plan projection; related snapshot
contents are not added to that format, and its original digest remains opaque.

Source versioning starts at 0.3.0 after former API metadata 0.2.0: APP_VERSION drives
FastAPI, health and authenticated UI metadata; README and numbered CHANGELOG entries
are checked against source and the PR base in CI. Versioned commit/PR subjects are
required. Git tags are skipped by explicit user instruction; source versioning does
not announce a Docker image. This section is the continuation checkpoint for this
version; the resulting versioned PR and merged commit in GitHub identify delivery.

Still unfinished: signature-free correlated investigations, behavioral/network/log
collectors, CVE applicability/effective-fix exposure tracking, validated detectors,
policy-authorized automatic quarantine/termination, maintained signatures/engines,
retention/immutable storage and real-target response acceptance. This bounded
scanner-led advisory enrichment does not complete general malware protection.


## v0.4.0 — stored startup-file review workspace

Delivery: [PR #56](https://github.com/StealthCat/MrPatchy/pull/56), initial implementation
[18261e91](https://github.com/StealthCat/MrPatchy/commit/18261e91011dfda311cea175e81e1e5e76155be2).
The PR records exact final checks and its actual merged main commit.

After [PR #55](https://github.com/StealthCat/MrPatchy/pull/55), the startup roadmap
remains unfinished. This milestone adds File integrity → Browse startup files:
search by path/mechanism, deterministic 25-file pages, current receipt time/ID,
baseline-change labels and a revision guard covering receipt contents and the
reviewed baseline. The source remains the existing bounded 256-entry metadata
inventory. Symlink targets are displayed without following them. Incomplete/stale
receipts, missing roots, skips and unsupported mechanism families remain visible.
Removed files remain in baseline differences; this view lists current stored entries.
Origin is explicitly not assessed: package ownership and authenticated defaults are
not fabricated from path names or baseline acceptance. No AI upload, remote contact,
job execution, baseline approval or response action occurs. Administrator access and
retained disabled/deleted history follow existing security-history controls.

This delivers review visibility and an initial extensible mechanism catalog, not
comprehensive discovery. Still planned: individual cron/anacron/at entries, vendor/
user/runtime systemd units and precedence, broader boot/login/event mechanisms,
segmented inventories and referenced scripts, native package ownership plus exact
vendor-default verification, configured AI classifications/redaction, alerts and
real-target acceptance. CVE monitoring, automatic containment, general malware
protection and evidence retention remain planned. No schema or agent upgrade is
needed; rebuild the controller. Git tags remain omitted by user instruction.


## v0.4.1 — server deletion in Settings and Manage

Delivery: [PR #57](https://github.com/StealthCat/MrPatchy/pull/57), initial implementation
[09986a37](https://github.com/StealthCat/MrPatchy/commit/09986a373c01bac11a68510998e44e88b412398d).
The PR records final validation and its actual merged main commit.

The user reported that deletion was missing from server settings. Inspection of
main after [PR #56](https://github.com/StealthCat/MrPatchy/pull/56), commit
`372783ce95b67b7626bad7849783f337480175e3`, confirmed that lifecycle buttons existed
on the server list/header but were missing from the Manage dialog, and there was no
dedicated server Settings tab. This fixes that discoverability gap with a shared
administrator-only Server management section in both locations. A Settings shortcut
and links to connection/maintenance/agent controls make the page discoverable.
Disabled servers retain enable/delete controls; deleted servers show retained-history
information and no lifecycle mutations. Existing connection/tab URLs remain valid.

The same reviewed lifecycle endpoints and confirmation dialog are reused. The exact
name, reason, CSRF/role checks, revision guards, active-work/hold restrictions, audit,
local-credential cleanup and retained-history semantics are unchanged. Opening the
settings or dialog never performs deletion. The remote agent remains installed.
No schema or remote-helper upgrade is needed; rebuild the controller and confirm
version 0.4.1 or later in its UI. Git tags remain omitted by user instruction.

This is a focused requested usability fix. Comprehensive startup discovery,
provenance/AI classifications, CVE monitoring, automatic containment and retention
remain unfinished as tracked above.


## Planned: separate controller and remote-worker deployments

Requested roadmap addition (2026-10-29); not yet implemented as a supported
standalone-worker workflow. Existing app/worker containers, MySQL job coordination
and the shared-local-volume deployment are prerequisites. Deliver deployment
separation and supported remote-worker setup as one coherent feature, with
incremental milestones where needed.

### Deployment files and runtime roles

| File | Supported deployment |
|---|---|
| `compose.yaml` | Complete single-machine app, worker and Caddy installation |
| `compose.controller.yaml` | Web app and Caddy with workers deployed separately |
| `compose.worker.yaml` | Workers only, supporting multiple replicas on one host or a standalone worker machine |

- Preserve the existing one-command complete installation and its persistent data. Reuse service definitions where practical to avoid drift. Provide role-specific environment examples and document supported combinations with the GCP override.
- Give workers a role-specific startup path that does not initialize web/TLS configuration, require a local Caddy/app container or inherit a local-app Compose dependency. Keep web administration and TLS configuration in the controller role.
- Support independent app/worker deployment and same-host worker scaling without fixed container-name conflicts. Use compatible versioned application images and explicit schema/protocol compatibility checks so mismatched workers fail clearly before claiming jobs.

### Database, secrets and persistent state

- Use MySQL 8+ for supported multi-machine deployments. Retain SQLite for the local/shared-local-filesystem deployment; do not present a network-mounted SQLite database as the remote-worker solution.
- Define and implement how remote workers obtain required encryption material, per-target SSH identities, encrypted database/repository configuration, trust bundles, trusted scanner/vendor artifacts, evidence files and other centrally required state currently under `/data`. Separate worker-local disposable caches from persistent shared state. A common database URL alone must not count as complete remote-worker provisioning.
- Provide an explicit supported secure provisioning/storage arrangement with access controls, rotation, backup and recovery instructions. Do not silently generate an unrelated encryption key on a worker or duplicate secrets into ordinary logs/environment examples. Detect unavailable/mismatched keys, storage and permissions before work begins.
- Extend database activation and maintenance/migration safeguards across worker machines; a local filesystem maintenance lock must not imply that remote workers have stopped. Preserve the elected coordinator, atomic SQL job claims, per-host operation locks and existing recovery holds.

### Worker management and installation

- Give each worker a distinct identity, heartbeat, readiness/health state and configurable concurrency. Expose worker version, last contact, active jobs and meaningful connection/configuration failures in the controller, with administrator access and existing audit conventions.
- Add graceful drain for maintenance/upgrades: stop accepting new jobs, finish or safely record active work, and preserve explicit recovery state after interruption. Detect lost workers without replaying destructive target operations or inventing successful completion.
- Offer installation modes for complete installation, controller only and join as worker. Validate database/TLS connectivity, compatible schema/version, required secrets/storage and target/repository connectivity for the chosen role. Provide clear independent start, scale, drain, upgrade, removal and troubleshooting instructions.
- Document required network paths and authentication for the selected topology. A worker-only machine must start successfully without local web/TLS services; existing SSH host verification and least-privilege target access continue to apply.

### Acceptance and rollout

- Validate all three Compose configurations and documented environment/GCP combinations, plus backward-compatible upgrades from the existing complete installation.
- Exercise multiple same-host workers and a real separate-host worker against MySQL. Prove that competing workers do not execute the same job twice, per-host serialization remains intact, and coordinator/worker restart, database disconnection, lost locks and partial operations retain honest failure/recovery state.
- Cover missing/mismatched secrets, inaccessible shared state, incompatible versions, heartbeat expiry, drain during active jobs, restart after interrupted mutation, migration with remote workers, and backup/restore. Do not mark this feature complete solely because the YAML files were split.


## Planned: deployment health dashboard and GCP integration node

Requested roadmap addition (2026-10-29); not yet implemented. Extend the deployment
separation feature with a unified operational view of the Mr Patchy installation.

### Component health dashboard

- Provide a dashboard covering all deployed Dockerized controllers, workers, agents and integration nodes, including the dedicated GCP integration node. Include managed endpoint agents through their existing collection/verification signals, with their actual Docker/systemd deployment type shown rather than assuming every agent is containerized.
- Maintain an inventory of expected/registered components so stopped or missing nodes remain visible. Show distinct identity, role, machine/location, version/image, last heartbeat, uptime where available, liveness/readiness, healthy/degraded/offline/unknown state and an explained health reason. Show worker concurrency, queued/active jobs and drain state, with links to relevant configuration, jobs and diagnostics.
- Distinguish container/process liveness from successful service readiness and from fresh endpoint telemetry. Apply explicit heartbeat/freshness thresholds; stale, inaccessible or unsupported observations must not appear healthy. Expose available resource metrics and recent failure summaries with clear unavailable states.
- Use authenticated component reporting/read-only health checks, bounded safe diagnostics and administrator access. Exclude credentials/tokens and sensitive raw telemetry from dashboard responses. Collect supported runtime metadata without granting the web application unrestricted Docker-daemon control.
- Integrate with existing alerts/audit records and preserve the established Mr Patchy theme. Validate missing/stopped nodes, startup/restart, version mismatch, stale clocks/heartbeats, partial network failure, permission boundaries and large deployments across local and remote-worker topologies.

### Dedicated GCP integration Docker node

- Add an optional `gcp-integration` service/node, using the GCP Compose configuration and compatible complete/controller-only/remote-worker installation modes. Give it its own runtime configuration, health/readiness checks, identity and heartbeat, and include it in the deployment dashboard.
- Initially support the existing GCP authentication, project/zone/instance lookup, connection verification and IAP transport workflows through this node. Define an authenticated, scoped service interface for controller/worker requests and how remote workers reach supported tunnels. Preserve per-target SSH identities, host-key pinning, operation deadlines and recovery semantics.
- Isolate Google Cloud CLI dependencies and cloud credential/configuration state in the integration runtime, with explicit least-privilege IAM/federation setup, persistent-state handling and rotation/backup documentation. Use fixed supported operations rather than caller/model-provided arbitrary cloud or shell commands. Return actionable redacted auth, permission, API and tunnel failures without exposing credentials.
- Update GCP installation/upgrade tooling and documentation for the dedicated node, including migration from the existing GCP-ready app/worker image arrangement, clear connectivity tests and supported version combinations. Preserve existing GCP connection functionality during migration.
- Validate controller and remote-worker routing, credential expiry/missing permissions, node outage/restart, tunnel interruption, duplicate requests and honest incomplete/recovery outcomes. Include non-production live-GCP acceptance; successful container startup alone does not complete the integration.

## Implemented in v0.5.0: successful enrollment returns to server Overview

Requested workflow addition (2026-10-29); implemented by the v0.5.0 checkpoint below.

- At the end of adding a server, once the backend confirms installation and verification have completed successfully, close the enrollment/installation workflow and navigate directly to that specific server's Overview page.
- Refresh the server's displayed state and retain a clear success confirmation. Generate/install-script completion or a pending background job is not sufficient to trigger the redirect.
- Keep failed, incomplete, cancelled or timed-out installation on the relevant progress/error step with actionable status and retry/recovery controls. Handle a lost response or page reload without creating a duplicate server or replaying installation blindly.
- Add browser coverage for successful installation/verification, correct server ID and Overview tab, pending/failure states and retry/reload behavior, preserving existing role and server-lifecycle checks.


## v0.5.0 — verified enrollment completion and resumable progress

Delivery: [PR #59](https://github.com/StealthCat/MrPatchy/pull/59), initial implementation
[d929c96e](https://github.com/StealthCat/MrPatchy/commit/d929c96ecaa2f1a7824bf245144227132e53a1f0).
The PR records final-head check results and the actual merged main commit.

Completion-gate base: main `c9e152e` ([PR #58](https://github.com/StealthCat/MrPatchy/pull/58)),
source 0.4.2. Its four-file roadmap/version diff and nine successful exact-head
checks were inspected; no unfinished PR was open. The broader roadmap is not
feature complete. This milestone implements the enrollment workflow above.

The final step waits for a backend deploy job with matching host/action and complete
state, refreshes the host list, closes the dialog and opens that server’s Overview.
Installer generation and queued/running states do not redirect. The success notice
is retained for this account/tab, describes completed verification rather than
claiming ongoing agent health, and clears when a new deployment starts.

Only host/job IDs and the pre-submit job-ID boundary are kept in tab-local session
storage, scoped to the signed-in username. Reload/login restores saved progress.
Pending jobs are read rather than requeued; failed/interrupted/cancelled jobs keep
errors and Activity links with explicit retry. A lost POST response is resolved
only when exactly one new same-host deploy job is found in the newest 100 jobs;
ambiguous/missing results remain unconfirmed with a status-check control. This is
conservative browser recovery, not backend idempotency across independent tabs or
operators. Stop tracking clears browser progress without cancelling/replaying work.
Session/modal guards prevent late responses from navigating another dialog/account.

Browser fixtures validate pending→reload→failure→explicit retry, lost response,
wrong-server rejection, correct Overview routing and retained success after reload,
with desktop/mobile screenshots. The full local UI suite and 21 lifecycle/version
tests passed; JS syntax, whitespace and version consistency passed. Existing backend deployment verification and
recovery gates are reused unchanged. No schema or helper upgrade is required;
rebuild the controller. Versioned PR records final validation and merged commit.
Git tags remain omitted by user instruction.

Still planned: separate controller/remote-worker deployment and shared state,
component health dashboard and GCP node, complete startup/task discovery/provenance
and explained AI classifications, CVE exposure/detectors, policy-authorized
automatic quarantine/termination, general malware protection, retention/immutable
storage and native/real-target acceptance. Do not treat this workflow as completing
those requirements.


## Planned: live in-app notifications and human-attention alerts

Requested 2026-10-30; **planned, not implemented by this roadmap update**.
The existing `operations.Alert` records and SMTP/webhook outbox provide durable
operational alerts; significant-triage event production must be added. The UI reads
existing alerts in the Operations panel. Its transient toast helper and periodic view refresh
are not an asynchronous notification center. Reuse this foundation while retaining
the existing external delivery configuration and alert lifecycle.

### Notification icon and review workspace

- Add a persistent Notifications bell/icon to the authenticated application shell on desktop, tablet and mobile, with an accessible unread count and severity cue that works on every page. Use the established glass palette, status colors, icons and Mr Patchy mascot without obscuring the alert text.
- Open a compact recent-notification panel and provide a dedicated paginated notification center with Unread/All and severity/server/type filters. Each entry shows what happened, why attention is needed, severity/source, server or component, occurrence time, read state and a deep link to the exact triage result, incident, operation, coverage problem or pending review. Preserve navigation context and show an honest unavailable/retained-record state when a linked object is gone.
- Update the icon, count, panel and appropriately bounded non-disruptive in-app alerts while any workspace or dialog is open, without manual refresh, navigation, lost selections/form content, scroll jumps or stolen focus. Urgent actionable events must remain discoverable in the notification center after a toast disappears. Keep keyboard/focus behavior, screen-reader announcements, reduced-motion and responsive/contrast fallbacks; do not flood live regions during replay.
- Keep per-user read/unread/dismiss state durable and synchronized across sessions/tabs. Viewing, reading or dismissing a notification does not globally acknowledge/resolve an incident, approve an AI result or run a response. Offer any permitted acknowledgement/review through the existing role-checked workflow, with explicit labels and audit where appropriate.

### Actionable sources and durable event identity

- Publish attention events for failed/blocked/interrupted operations, recovery/response holds, required human approval or reconciliation, meaningful node/agent/service health or coverage failures and AI configuration/budget blockers. Include significant validated triage results and planned malware, CVE exploitation and suspicious startup findings as their producers are implemented. Define severity/significance policy explicitly; distinguish an advisory AI assessment from a confirmed detector observation.
- Link events to the actual subject and evidence revision, not only a host/kind aggregate. Deduplicate repeated unchanged observations and group related occurrences without suppressing distinct findings. New, reopened, materially changed or escalated findings must resurface even after an earlier notification was read or acknowledged. Routine successes and unchanged known-good cache hits must not create a notification storm.
- Persist stable event IDs, occurrence/revision and safe subject metadata with the originating state change, using a transactional outbox or equivalent committed-event record. Never announce a rolled-back result. Support replay and idempotent consumers across multiple workers/controllers and restarts; an in-memory callback in one process is insufficient. Integrate the current aggregate Alert lifecycle carefully without silently changing global acknowledgement or resolution behavior.

### Asynchronous delivery and access control

- Provide authenticated server push, preferably Server-Sent Events for the one-way event feed, with heartbeat, automatic reconnect and event-ID/cursor replay. Use authoritative paginated catch-up for first connection, page reload, sleeping/offline tabs and reconnect. If history was pruned or a cursor is invalid, explicitly resynchronize counts/history and disclose the gap. A documented polling fallback may provide degraded delivery; periodic whole-page refresh alone does not satisfy live notifications. See the [EventSource standard](https://html.spec.whatwg.org/multipage/server-sent-events.html).
- Deliver already committed events through the shared durable store or a supported cross-process broker so a worker-created result reaches a browser connected to any controller. Keep streaming independent of triage execution slots and long-lived database transactions. Bound connection counts, per-client buffers, replay batches and message sizes; handle slow clients with explicit reconnect/catch-up rather than unbounded memory or silent event loss.
- Validate the existing HTTPS/Caddy path for streaming, flushing, heartbeat timeouts, disconnect cleanup and reconnect behavior. Show connection/degraded state and last synchronization time; a connected stream is not evidence that collectors or AI are healthy. In-app alerts work without browser/OS notification permission and without configuring SMTP/webhooks.
- Filter event payloads, list/detail reads and unread counts by the user's current role and subject access before transmission. Recheck/terminate streams on session expiry, logout, account disable or permission changes; reset all account-scoped client state during account switching. Use authenticated same-origin transport, avoid credentials in event/query data and preserve CSRF protection for read-state/acknowledgement mutations. Escape all untrusted text and keep secrets, raw prompts/provider bodies and unnecessary endpoint evidence out of notifications.
- Keep deterministic human-attention notifications available when AI is disabled, paused or unavailable. Significant new findings may create an alert, but delivery/read state never grants destructive-action authority or bypasses the existing reviewed/automatic response policies. Preserve the existing SMTP/webhook channel behavior unless separately changed by an administrator.

### Finite delivery and acceptance milestones

1. **Event model and producers:** deliver subject/revision-aware committed events, source/severity policy, safe deduplication/reopening/escalation, recipient authorization and per-user read state, with migration/retention and existing alert-lifecycle coverage.
2. **Live transport:** deliver authenticated streaming, reconnect/replay/catch-up, bounded resources, current-permission checks and cross-worker/controller operation through the existing HTTPS deployment. Healthy connected-browser acceptance should show committed events within five seconds; document measured latency and degraded/fallback limits separately.
3. **Notification UI:** deliver the persistent icon/badge, recent panel, dedicated pages/filters, safe deep links and live toasts without disturbing active work. Verify per-user multi-tab synchronization and existing acknowledgement/response boundaries.
4. **End-to-end acceptance:** validate actual server-generated live updates in two browser sessions, significant triage and human-attention sources, unread/read/dismiss behavior, distinct/replayed/duplicate/reopened events, permissions/account switching, malicious text, disconnect/sleep/reload/replay gaps, retention, slow clients, worker/controller restart/failover, AI pause/outage and SMTP/webhook independence on SQLite/MySQL. Review keyboard/screen-reader behavior plus actual mobile/tablet/desktop renders before marking the requirement complete.

Track this addition in the scheduled development task and UI design guide. Preserve
issue-first priority, the current AI performance program, the fixed major-1 policy,
the cycle budget and exact-final-commit version/CI/merge requirements.


## Planned: complete UI rework with glass styling and extensive mascot use

Requested roadmap addition (2026-10-29); not yet implemented as a complete rework.
The current glass theme, existing mascot artwork and incremental UI polish are
starting points, not evidence that this milestone is finished. Use
[the UI design guide](UI_DESIGN.md) to maintain one consistent design system.

### Brand, mascot and visual direction

- Retain the established color scheme and its status meanings: smoky blue/teal surfaces with mint actions/healthy states, amber attention and coral errors/critical priorities. Preserve Mr Patchy's established raccoon identity, patched overalls and character.
- Use the mascot as extensively as possible throughout the application: sign-in, navigation, page introductions, dashboard summaries, onboarding, guided workflows, loading/empty/error/success states, notices and help. Add reference-consistent poses, expressions and contextual illustrations where needed, with treatments that keep nearby text, controls and operational status easy to read.
- Deliver a polished glass-like appearance through a coherent system of layered translucent surfaces, controlled blur, subtle highlights, borders, shadows and background depth. Give dense text/tables dependable reading surfaces and clear visual hierarchy; readability must hold over every background and state.
- Use as many graphics and graphic details as needed to achieve the desired result, including custom illustrations, icons, supporting textures, diagrams, progress treatments and data visualizations. Keep visual identity consistent, optimize assets and provide text equivalents. Operational graphics must reflect real recorded data and explicit unknown states.

### Information architecture and uncluttered navigation

- Rework the whole application, including authentication, fleet/server overviews, enrollment, packages/repositories, schedules, AI investigations/logs, security/startup/integrity/response workflows, history/audit, deployment/worker/GCP health, users and settings. Apply the same system to the other planned roadmap features as they are implemented.
- Audit the current routes, long pages, repeated controls, oversized dialogs and crowded toolbars. Define a clear navigation map with dedicated pages for major tasks, contextual tabs for related views and grouped menus for secondary actions. Split dense workspaces into focused sections; use progressive disclosure for advanced or infrequent controls.
- Make the current location and selected server/view obvious through consistent page titles, active navigation/tab states and useful context links. Support deep links, browser Back/Forward, stable tab selection and sensible preservation of filters/search/pagination without losing the user's place during refresh.
- Prefer focused pages and tabs for substantial workflows and detail records; keep menus discoverable and dialogs suited to brief contextual tasks and confirmations. Retain direct access to essential actions, explicit destructive-action confirmations and existing role/approval/recovery boundaries.
- Standardize readable typography, spacing, table density, labels, search/filter controls, pagination, primary/secondary actions and status summaries. Keep warnings, coverage limitations, AI uncertainty, pending work and recovery-required states prominent and understandable.

### Shared components, graphics and accessibility

- Establish reusable design tokens and components for the application shell, page headers, tab sets, menus, glass panels, tables, forms, dialogs, charts, notifications and mascot-supported states. Consolidate inconsistent one-off styling as each workspace is migrated.
- Keep keyboard navigation, visible focus, meaningful labels, screen-reader semantics, contrast and touch targets usable. Honor reduced-motion/reduced-transparency preferences and provide legible fallbacks when glass effects are unsupported.
- Verify mobile, tablet and desktop layouts, including narrow navigation, dense tables and lengthy evidence/log content. Optimize graphic delivery and glass effects so the redesign stays responsive and avoids obstructed controls, text overflow and layout shifts.
- Preserve accurate data, input escaping, authorization, audit history, selections and background refresh behavior throughout the redesign; visual changes must not silently change operational decisions.

### Delivery and completion criteria

- Deliver a finite sequence of coherent milestones: route/navigation and visual-system plan; shared shell/components and graphic assets; focused migration of all workspaces; then whole-application usability/accessibility and visual consistency review. Size each cycle using the existing development work budget and record migrated versus outstanding screens.
- Update the UI design guide, navigation documentation and actual application screenshots with the implemented design. Capture representative populated, loading, empty, error, warning and success states at mobile/tablet/desktop sizes; inspect the rendered text and controls as well as the artwork.
- Exercise critical end-to-end workflows through the new pages/tabs/menus: login, enrollment and Overview landing, server selection, update selection/approval, scheduling, AI pause/investigation, security evidence/response review, jobs/history, deployment health and settings. Include direct links, Back/Forward, keyboard navigation, permissions and long-content/failed-loading cases.
- Mark the rework complete only after the defined screen inventory has been migrated and the readability, usability, navigation, visual and regression criteria are met. Existing glass CSS, a few mascot placements or one polished screen do not complete the milestone. Once complete, the existing completion gate prevents open-ended cosmetic work merely to fill scheduled cycles.


## v0.6.0 — server workbench navigation foundation

Delivery: [PR #61](https://github.com/StealthCat/MrPatchy/pull/61), initial implementation
[f1d7e077](https://github.com/StealthCat/MrPatchy/commit/f1d7e0776b81e72137b6caf1e1ad3709e3133e61).
The PR records exact final-head checks and the actual merged main commit.

Completion-gate base: main `49c6722` ([PR #60](https://github.com/StealthCat/MrPatchy/pull/60)),
source 0.5.1. The actual five-file roadmap/design/version diff, nine successful
exact-head checks, current checkpoint and absence of open PRs were inspected.
The full UI rework is a concrete outstanding requirement, alongside the previously
recorded security, startup, deployment and retention roadmap.

This first UI milestone defines a finite screen inventory in
[UI_DESIGN.md](UI_DESIGN.md#screen-migration-inventory), maps server navigation and
implements a shared glass disclosure component with the established mascot. The
server header and four primary routes are compact, secondary pages are grouped,
and navigation precedes AI policy content. Current page/server, deep links and
role/lifecycle restrictions remain explicit. Settings/deletion stays directly
accessible. Native keyboard interaction, Escape/outside dismissal, responsive
in-flow mobile grouping and transparency/forced-color fallbacks are included.

Server/fleet package filters are kept separately in session memory during route
changes and refresh; sign-out/reload clears them. Installation selections remain
fresh and still require review. No provider/target calls or mutation decisions are
introduced by navigation. Review also fixed pre-existing unescaped server-name
and architecture text in the workspace header, with malicious-markup browser
coverage; endpoint/user-controlled text remains literal. No schema/helper upgrade is needed; rebuild controller.
Local validation: full browser suite passed, the final navigation fixture passed
at 320/390/768/1440 widths, 21 lifecycle/version tests passed, and JS syntax,
whitespace and source-version consistency passed. Reviewed desktop/tablet/mobile
screenshots are linked in the design guide. Versioned PR records final CI
validation and the merged commit; Git tags are skipped.

Still unfinished: all content-family migrations and application-wide UI acceptance
listed in the screen inventory; comprehensive startup discovery/provenance/AI
classifications; CVE exposure/detectors and automatic containment; general malware
protection; remote-worker deployments/shared state, health dashboard and GCP node;
retention/immutable storage and native/real-target acceptance. This milestone does
not claim complete UI redesign or complete endpoint protection.


## v0.7.0 — searchable server directory and focused Overview pages

Delivery: [PR #62](https://github.com/StealthCat/MrPatchy/pull/62), initial implementation
[2f70aea0](https://github.com/StealthCat/MrPatchy/commit/2f70aea0971c3149f626cb6a0a7b3f2dd0f96011).
The PR records final-head CI and the actual merged main commit.

Completion-gate base: main `716d8f5` ([PR #61](https://github.com/StealthCat/MrPatchy/pull/61)),
source 0.6.0. Its actual navigation/header/filter diff, committed responsive renders,
recorded validation and nine successful exact-head checks were inspected; no PR was
open. The roadmap is not complete. This cycle advances the finite Servers/Overview
screen family, with implementation and acceptance described in UI_DESIGN.md.

The directory uses local read-only search, enabled/disabled filters and 24-card
pages; it retains filters/page position during navigation/refresh and resets them
on sign-out/reload. Existing Open/Manage/Inspect, lifecycle confirmation and deleted
history workflows are reused. Empty results are distinct from an empty fleet.
Overview now has deep-linked Summary, System & collector and Patching status pages,
with Back/reload/server-switch context, explicit stored-data limitations and
recovery warnings. No operational permission, provider call or target action is
introduced by browsing. Rebuild controller; no schema/helper upgrade is needed.

This is a partial UI migration. The fleet dashboard, onboarding, shared global
shell/states, remaining dense content/detail dialogs and lifecycle/AI-control
presentation remain in the finite inventory. Comprehensive startup discovery,
provenance/classification, CVE monitoring/automatic containment, general malware
protection, independent remote workers/shared state, component/GCP health,
retention/immutable storage and native/real-target acceptance remain unfinished.
Local validation: full browser suite passed; expanded focused directory/Overview
checks passed at 320/768/1440, including roles, malicious text, pagination/context,
future timestamps and recovery warnings. The 21 lifecycle/version tests, JS syntax,
whitespace and version consistency passed. Reviewed responsive renders are linked
in UI_DESIGN.md. Versioned PR records final CI and actual merge; Git tags are omitted.


## v0.8.0 — worker registration and role-specific startup foundation

Delivery: [PR #63](https://github.com/StealthCat/MrPatchy/pull/63), initial implementation
[eeb3a3ac](https://github.com/StealthCat/MrPatchy/commit/eeb3a3acd24878b1de20f89307b04727ae0a9c6e).
The PR records exact final-head checks and the actual merged main commit.

Completion-gate base: main `bc613af2` ([PR #62](https://github.com/StealthCat/MrPatchy/pull/62)),
source 0.7.0. The actual directory/Overview diff, recorded validation/renders and
nine successful exact-head checks were inspected; no PR was open. Worker identity,
heartbeat and role-specific startup are concrete unfinished deployment/dashboard
requirements. This milestone delivers their foundation, not supported remote workers.

Every scheduler runtime registers a generated or configured identity, boot ID,
static source version and reported Docker/process type. A dedicated cross-process
identity lock rejects collisions and exits scheduling after ownership loss. Hashed
setting keys avoid SQL collation aliasing between distinct case-sensitive IDs. Bounded
15-second self-reports include actual default pool capacities, current futures,
coordinator flag and uptime. Graceful pool shutdown records stopped; abrupt loss
becomes stale after 120 seconds. Invalid/future clocks (five-second tolerance),
old versions and unknown readiness are distinguished. Default generated boot rows
are retained; stable per-instance IDs reuse their row and retain audit events.
No automatic retention/deletion or readiness certification is introduced.

Administrator-only Activity → Workers exposes read-only 50-record pages with
coverage limits, role/deep-link/pagination/empty/error-safe presentation and the
established glass/mascot style. Records live in existing settings/audit tables,
already included in offline migration; no new schema/helper upgrade is needed.
The complete Compose worker explicitly selects worker startup, prepares only data
ownership and skips controller TLS initialization. App/Caddy bootstrap is unchanged.
Source version comes from the single static authority without importing the web app.
Rebuild/restart controller and workers; old workers remain unregistered.

Validation covers exclusive identity, heartbeat/stop, stale/future/version projection,
secret-field exclusion, roles, lost-lock admission blocking and leader release,
role startup and static metadata. A real disposable local worker process registers,
rejects a duplicate identity in a second process and stops under SIGTERM. This is
local/SQLite process acceptance, not separate-host/MySQL storage or target recovery
acceptance. Existing claims, per-host/recovery locks, coordinator election and
fixed concurrency remain unchanged. The full local regression suite passed (1,245 passed / 7 skipped before final
collation/lock-uncertainty refinements); the final focused registry/version/GCP
suite passed 20 tests, and full plus focused browser checks passed. JS/Python/shell
syntax, whitespace and version consistency passed. Final PR records exact-head CI.
Git tags are omitted by user instruction.

Still planned: complete/controller/worker deployment files and installer modes,
remote shared keys/database profiles/artifacts/evidence/state preflight, schema/
protocol compatibility gating, configurable concurrency, drain, cross-host migration
and failure acceptance. Also unfinished: expected nodes, controller/endpoint/GCP
health and dedicated GCP node, remaining UI migrations, comprehensive startup
provenance/classification, CVE and general-malware automatic containment,
retention/immutable storage and native/real-target recovery acceptance. Fresh loop
reports or a YAML role flag do not complete those requirements.


## v0.9.0 — cooperative worker drain and configured concurrency

Delivery: [PR #64](https://github.com/StealthCat/MrPatchy/pull/64), initial implementation
[f4d19d05](https://github.com/StealthCat/MrPatchy/commit/f4d19d057ef5495dc8d35103353791a8330c841c).
The PR records exact final-head checks and the actual merged main commit.

Completion-gate base: main `076ea6cf` ([PR #63](https://github.com/StealthCat/MrPatchy/pull/63)),
source 0.8.0. Its actual registry/worker/entrypoint/UI/test diff, checkpoint,
recorded validation and all nine successful exact-head checks were inspected;
no PR was open and no Git tags existed. Worker drain and configurable concurrency
were concrete unfinished items in the deployment roadmap. The selected batch
implements these together with operational UI and focused acceptance. The full
roadmap is not complete.

Administrator-only controls persist a desired drain/resume revision in existing
settings rows, keyed by exact worker identity hash and bound to the displayed boot.
Requests require a reason, current revision, fresh compatible report, role and CSRF.
A cross-process control lock serializes competing requests. Changed/stopped/stale/
unknown boots and mismatched versions reject control. A new boot does not inherit
the previous boot's request, including for stable identities. Requests are audit
records, not job cancellation, process shutdown or maintenance certification.

Before each admission tick, the worker reads current control state; uncertainty
blocks that tick. A tick already in progress can finish. Observed drain releases
the coordinator role and prevents new scheduling, job/release-observation claims,
polls, AI cycles, notifications and cleanup. Already assigned work finishes under
existing locks, including queued executor polls, notifications and a whole assigned
AI cycle. Draining/drained state includes all assigned work rather than only running
threads. Fresh drained means this boot self-reports no assigned work; it is not
independent readiness, a fleet-wide maintenance lock or proof of successful target
operations. Stop/loss and interrupted mutations retain existing honest recovery
semantics. Resume respects existing global/per-server AI and lifecycle/response gates.
All-worker drain pauses background work, though controller queue submissions remain
available. Requests, observed control revisions, drained transitions and stops are
audited. Failed acknowledgement writes retry without admitting work or inventing
acknowledgement. No destructive response action is authorized by these controls.

`MRPATCHY_JOB_CONCURRENCY` supports 1–8 (default 2),
`MRPATCHY_POLL_CONCURRENCY` 1–32 (default 8), read at runtime startup. Invalid
values refuse startup. Executors and both new-job and release-observation admission
use the same configured limits; AI remains one task. The complete Compose worker
forwards the settings. The UI reports these actual limits, running and queued polls,
notification assignment, requested and observed revisions. Controls stay with the
identity before horizontal scrolling; glass/mascot styling and explained stale/
unknown/compatibility states remain. Rebuild/recreate controller and workers together;
no schema or agent upgrade is needed. Settings and audit records already participate
in offline database migration. Git tags remain omitted by user instruction.

Validation includes real local process drain/resume/SIGTERM, exclusive identities,
concurrent stale-revision rejection, restart isolation, role/CSRF/input checks,
unreadable/invalid control, failed acknowledgement retry, coordinator handoff while
assigned work finishes, no claims while drained, resume with one-job admission,
capacity bounds, audit and no target/provider contact from control requests.
Browser checks cover exact identity/boot/revision requests, double submission,
pending acknowledgement, stale conflict, resume, unauthorized controls and actual
320/768/1440 layouts plus confirmations. Final validation and delivery references
are recorded below and in the resulting versioned PR.

Remaining deployment work: separate deployment files and complete/controller/join
installer modes; secure remote keys/profiles/trust/artifacts/evidence/shared state;
readiness and schema/protocol compatibility admission gates; expected/controller/
endpoint/GCP health and dedicated GCP node; cross-host migration, storage and drain/
interrupted-mutation acceptance. Local cooperative drain/configurable pools do not
complete remote deployment or the unified dashboard. Remaining security work includes
comprehensive startup discovery/provenance/AI classification, CVE monitoring and
evidence-qualified automatic containment, known/unknown malware protection,
retention/immutable storage and native/real-target recovery. The finite full-UI
migration inventory remains unfinished in UI_DESIGN.md.

Local validation: full Python suite **1,267 passed / 7 skipped**; focused registry/
control suite **33 passed**. Full browser suite and focused worker control flows
passed, and five reviewed renders are linked in UI_DESIGN.md. Python compilation,
JS/shell syntax, whitespace and source-version consistency passed. All applicable
GitHub checks must pass on the exact final PR head before merge; the PR records
those checks and the actual merged commit.


### Unfinished PR #64 — validation gate and next-cycle handoff

**Not merged; main remains v0.8.0 / `076ea6cf`.** Continue/reconcile PR #64 before
another milestone or PR. Target v0.9.0 remains unpublished/unmerged; keep that
version for completion of this coherent update. No Git tags were created.

Implementation/test head `b8e90229485185f680e751d11297ef7b6e66fd80`, tree
`e20403a7d059e72fd0f03ff4f29f4ea5943669b2`, passed eight of nine jobs in
[run 41010603882](https://github.com/StealthCat/MrPatchy/actions/runs/41010603882).
MySQL failed `tests/test_plan_evidence.py::test_newer_receipts_are_outside_snapshot`:
related-evidence plan approval returned 409, expected 200 (1 failed / 1,146 passed /
127 skipped). Earlier [run 41009205410](https://github.com/StealthCat/MrPatchy/actions/runs/41009205410)
failed the related `test_opt_in_projection_binding_review_and_legacy` with the
same status mismatch. Worker registry/control tests passed in both MySQL runs.
The final local full suite passed 1,267 / 7 skipped and the focused related-plan
suite passed 10 tests, so local SQLite has not reproduced the approval failure.
The root cause is **unconfirmed**; do not label it fixed, relax approval/evidence
checks, skip the test or blindly rerun until green. No plan authorization code
was changed in this cycle. A separate collection-time future-heartbeat fixture
was corrected and validated; that does not fix/explain the approval failure.

Next validation work: obtain the failing approval response detail and compare the
captured versus persisted/reconstructed evidence digest, snapshot time boundary,
numeric types and retained rows under actual MySQL. Investigate storage/transaction/
serialization or timing differences using fixture data; those are hypotheses,
not established causes. No Docker/MySQL server is available in this local runtime;
the CI MySQL service is available for targeted reproduction/diagnostics. Preserve
all stale/change/deletion/foreign-evidence and authorization rejection tests.

Review also identified an unfinished worker-control edge case: the existing valid
configured identities `.` and `..` are normalized by URL processing. The UI builds
an identity path using encodeURIComponent, which leaves these dot segments intact;
controls reach the wrong route (404). Before merging, move the exact identity into
a validated request body or another normalization-safe contract, preserve all valid
existing identities, and add backend/browser regression coverage for dot identities
and ordinary case-sensitive IDs. Do not silently break their registration contract.
No late speculative implementation was added for this finding.

This checkpoint-only revision records the blocked handoff; it does not turn prior
checks into passes. Any eventual final implementation/metadata commit must run all
applicable checks and pass on that exact head before merge. The PR records current
head/check links and remains unfinished. The broader remaining roadmap above is
unchanged, and the existing schedule stays enabled.


### PR #64 reconciliation — exact evidence boundary and identity-safe controls

This supersedes the two unresolved findings in the preceding handoff. Completion
gate rechecked main `076ea6cf` / PR #63 (v0.8.0), its actual changes/recorded checks,
repository instructions and the only unfinished related PR #64. The broader roadmap
remains incomplete. This cycle reconciles that existing update, keeps target
v0.9.0 and does not start another PR or create Git tags.

The approval failure was reproduced against a disposable native MySQL 8.0.46.
The captured cutoff `1793340981.9435813` persisted in a JSON scope as
`1793340981.943581`, changing the reconstructed evidence digest even though no
receipt changed. The failed HTTP response was the existing stale-plan rejection.
The only scope difference observed at that reproduction was the numeric cutoff.
The issue is confirmed, rather than merely inferred from the previous CI failures.

New related-evidence plans use scope version 2 with a controller-generated
`as_of_hex` string holding the exact binary floating-point cutoff. Reconstructing
evidence parses that canonical bounded text and uses the original cutoff for the
same receipt queries/digest. Stored numeric snapshot timestamps remain historical
presentation metadata and can be rounded by MySQL. No digest comparison, stale/
deleted/changed evidence check, scope-host boundary, approval expiry, advisory-only
restriction or provider-output validation is relaxed. A one-bit change to the exact
cutoff still changes the digest and rejects approval. Missing/malformed/nonfinite/
overflowed exact cutoffs reject safely. Legacy version 1 scopes and scanner-only
plans remain readable/reviewable when their original digest still matches; old v1
plans with already-rounded boundaries may require regeneration. No historic plan,
evidence or digest is rewritten to force approval.

Worker control now uses `POST /api/operations/workers/control` with validated exact
`worker_id` in its JSON body, preserving the previously accepted `.`/`..` and case-
sensitive identities. The unreleased draft path-based route is removed. Boot/
revision/role/CSRF/freshness/version checks and audit are preserved. Backend tests
exercise drain/resume for dot and case identities plus invalid paths; browser
requests assert exact identity/boot/revision and exercise these names without URL
normalization. The established glass/mascot presentation is unchanged and reviewed
again at phone/tablet/desktop sizes.

Focused local validation: 55 tests passed on SQLite and 55 passed on native MySQL
8.0.46, including original approval failures, deterministic JSON-rounding simulation,
exact-boundary tampering, malformed/nonfinite/overflowed values, legacy approval,
retention/foreign-evidence rejection and all worker controls. MySQL was extracted
into disposable local storage and run with the tests; it changes no user database
or application deployment. Final full regression/browser results and exact-final-
head GitHub checks are recorded in the PR before any merge. CI's MySQL 8.4 check
remains mandatory. This resolution does not complete remote worker/state/readiness/
migration acceptance, the full health/GCP dashboard or the security/UI roadmap.

Reconciliation local validation completed: full Python suite **1,279 passed / 7
skipped**, focused SQLite/native-MySQL suites **55 passed each**, full browser suite
passed (including dot/case identity requests) and actual 320/768/1440 renders were
re-reviewed. UI markup/style and the committed v0.9 screenshots remain representative;
only control transport changed. Python compilation, JS syntax, whitespace and
source/README/changelog version consistency passed. No outstanding finding from
the prior handoff remains locally; all nine exact-final-commit CI jobs, including
MySQL 8.4, must pass and mergeability/base/head must be rechecked before merging.
The PR records those results and the actual merged commit when delivered.


## v0.10.0 — AI activity detail pages and scoped navigation

Delivery: [PR #65](https://github.com/StealthCat/MrPatchy/pull/65), initial implementation
[83a11f2c](https://github.com/StealthCat/MrPatchy/commit/83a11f2c6647f82efa908e5dd95cf018abaeb6d7).
The PR records final-head validation and the actual merged main commit.

Completion gate: inspected main `b62c4ce2` / [PR #64](https://github.com/StealthCat/MrPatchy/pull/64),
its actual worker/evidence/UI diff, recorded exact-head nine-check success, current
instructions/checkpoint and open PRs (none). The roadmap is unfinished. This batch
advances the finite Investigations/AI activity UI family: saved run detail pages,
scoped list context and honest cost/timeline states, rather than additional remote
worker deployment work. Version 0.10.0 is a compatible navigation feature update.

Fleet links use `#ai-logs/run/ID/summary` (or `/cost`, `/timeline`); server links use
`#servers/HOST/ai/run/ID/summary`. List Inspect run links now open pages instead of
a long modal. Native links support direct navigation, Back/Forward and reload.
Purpose and pagination are remembered separately for fleet and each server during
navigation/refresh; reload/sign-out clears memory. Switching servers returns to
that server's AI list rather than carrying an unrelated run ID. Summary shows
saved diagnostics and missing timestamps honestly; Cost retains usage/rate details
and partial/unavailable limitations; Timeline shows saved stages without claiming
current health, response execution or successful remediation. Shared-batch amounts
remain whole-run estimates, not per-server charges. Empty/missing/failed details
keep actionable list/retry links, and delayed responses cannot overwrite a newer
view. No browsing operation retries AI or changes trust/response policies.

Optional host_id on the existing administrator detail endpoint now verifies the
same direct, durable shared-batch or legacy score membership used by the list.
Unrelated/missing host/run contexts return 404; global administrator access remains
available. Disabled/deleted history remains governed by existing role/history
rules. The browser sends host_id for server details. All text remains escaped and
raw prompts/provider credentials are not newly exposed. The malformed Process
triage option in the existing list filter was fixed while exercising real filtering.

Backend acceptance covers direct/shared/legacy membership, unrelated/missing
contexts, roles and absence of target/provider calls. Browser acceptance covers
cost uncertainty/legacy receipts, routes/reload/Back, scoped and paginated context,
server query/routing, unauthorized detail navigation, literal untrusted diagnostics,
missing records and delayed-response races, plus actual 320/768/1440 renders.
Shared glass navigation, readable responsive facts and existing mascot illustrations
are reused. No new artwork or operational/approval controls are introduced.

This is a partial screen-family migration. Investigation evidence/details, other
AI control/loading states, the remaining finite UI inventory, full remote worker
provisioning/state/readiness/migration acceptance, deployment/GCP dashboard/node,
startup provenance/classification, CVE/known/unknown malware automatic protection,
retention and native real-target acceptance remain unfinished. Rebuild controller;
no agent/schema upgrade is needed. No Git tags by user instruction. The versioned
PR records exact final-head checks, delivery and actual merged commit.

Local validation: full Python suite **1,282 passed / 7 skipped**; focused AI
cost/scope tests **42 passed**; full browser suite and expanded focused run-page
checks passed. Five reviewed desktop/tablet/phone and cost/timeline renders are
linked in UI_DESIGN.md. Python/JS compilation, whitespace and version consistency
passed. Final PR must pass all nine applicable checks on its exact final head
before merge; its delivery record retains the actual merge and validation links.


## v0.11.0 — Stored startup Files and Coverage pages

Delivery: [PR #66](https://github.com/StealthCat/MrPatchy/pull/66), initial implementation
[93bd1a34](https://github.com/StealthCat/MrPatchy/commit/93bd1a344fb0d1f6e25328de04b6f096d6a999ea).
The PR records final-head validation and the actual merged main commit.

Completion gate: inspected current main `bf34c2c6` /
[PR #65](https://github.com/StealthCat/MrPatchy/pull/65), its actual AI activity
changes and recorded exact-final-head nine-check validation, repository instructions,
implementation checkpoint and open PRs (none). The roadmap remains unfinished.
This compatible feature update advances the finite security/startup screen family;
comprehensive startup collection/provenance/classification is not claimed complete.

Server More sections → Startup files now opens `#servers/HOST/startup/files` or
`/coverage`. File integrity's existing Browse startup files control opens the same
workspace instead of a long modal. Files displays escaped metadata, origin explicitly
not assessed, hashes or symlink targets (not followed), search and bounded paging.
Coverage presents the stored receipt scope, mechanism counts, missing roots, skipped
entries, baseline state and explicit gaps. These are observed files, not individual
jobs, effective commands, authenticated package defaults or malware classifications.
Viewing/refreshing never queues collection, approves a baseline or sends AI requests.

Deep links, Back/Forward, reload and server switching preserve the selected page.
Search/page/receipt revision are remembered per server during navigation/refresh,
clearing on reload/sign-out. Queued responses cannot overwrite a newer route.
Changed receipt/baseline revisions reject stale browsing; Refresh latest inventory
clears the revision/page and explicitly reviews the latest receipt, retaining the
search. Empty/failed states offer actionable explanation and never retain stale rows.
Administrators can review disabled/deleted retained history; viewer roles make no
inventory request. Existing lifecycle and response authorization boundaries remain.

The responsive workspace retains shared glass surfaces, mint accents, readable
wrapping and Mr Patchy's established artwork. The generic AI policy panel remains
on other server pages and is omitted from this read-only page. Actual 320/768/1440
Files and desktop/phone Coverage renders were reviewed and are linked in UI_DESIGN.md.

Local validation: full Python suite **1,283 passed / 7 skipped**; focused startup/
baseline tests **15 passed**; full browser suite passed, including search/paging,
Back/reload, receipt change/explicit refresh, empty results, escaping, inactive
history and role restrictions. JS syntax, whitespace and source/README/changelog
version consistency passed. The resulting PR records exact-final-head nine-check
validation and the actual merged main commit; all checks must pass before merge.

Remaining: comprehensive cron/anacron/at and effective system/user/runtime systemd
discovery, broader startup mechanisms, authenticated default provenance, bounded
consented AI classification and native acceptance; other security/response/recovery
UI screens; full UI migration; remote worker state/readiness/provisioning and
migration/failure acceptance; complete component health/GCP integration node; CVE
and known/unknown malware automatic protection and real-target/recovery acceptance;
retention and independent evidence/audit requirements. Existing AI pause remains
implemented. No collector, agent, schema, provider or response-pipeline change is
introduced. Rebuild the controller and keep worker source versions matched.
No Git tags by user instruction; the schedule remains unchanged.


## v0.12.0 — Expected-worker inventory foundation

Delivery: [PR #67](https://github.com/StealthCat/MrPatchy/pull/67), initial implementation
[4b5bd105](https://github.com/StealthCat/MrPatchy/commit/4b5bd10520a9a918c7e15700255d480c248a8928).
The PR records final-head validation and the actual merged main commit.

Completion gate: inspected main `8f1bcc3c`, latest merged
[PR #66](https://github.com/StealthCat/MrPatchy/pull/66), its actual startup
workspace diff and recorded nine-check final-head validation, current instructions,
implementation checkpoint and related open PRs (none). The explicit component
health roadmap still lacks expected-node visibility. This batch adds bounded
expected-worker inventory and its responsive UI; it does not certify readiness
or complete the all-component dashboard/remote deployment roadmap.

Controller deployment configuration `MRPATCHY_EXPECTED_WORKER_IDS` optionally lists
at most 100 unique case-sensitive stable worker identities. Complete Compose passes
it only to the app, and .env.example/README document matching unique per-worker
IDs, replica constraints, restart and backup/removal semantics. Invalid entries,
empty members, duplicates or oversized configuration show an explicit diagnostic.
Unset configuration is unconfigured, never a claim that every worker is present.
The configuration is persisted by the administrator's deployment environment, not
an application mutation endpoint. No new secret or schema is introduced.

The existing administrator-only worker endpoint returns expectations independently
of registration pagination. Exact hashed identity lookup avoids MySQL collation
aliases; a mismatched/corrupt identity is missing, never an unrelated registration.
Missing is not proof that a process is stopped: database reachability, configuration
and actual deployment require investigation. Registered expectations reuse the same
freshness, future-clock, stopped, version and drain interpretation as registrations.
Safe projected identity/state/reason/age fields exclude arbitrary report secrets.
Readiness remains not assessed. Listing never writes registration, contacts a target
or provider, or changes scheduler admission. Existing drain/recovery authorization
remains unchanged. Removing expectations retains all registration/audit history.

Activity → Workers now places responsive expected-worker cards above registered
history, retaining glass surfaces, state accents and the raccoon identity. Empty
and invalid configuration, escaped untrusted identities and role boundaries are
browser tested. Actual 320/768/1440 renders were reviewed and linked in UI_DESIGN.md.
Focused backend acceptance covers absent/missing/mismatched identities, case-sensitive
IDs, pagination independence, invalid/oversized/duplicate configuration, stale/future
reports, stopped/version/drained states, no mutation and safe projection.
Final local and exact-head CI results, versioned PR and actual merged commit are
recorded in the delivery PR before merging. No Git tags by user instruction.

Remaining: expected controller/endpoint-agent/GCP integration nodes and actual
deployment type, readiness/preflight, diagnostics/alerts, optional GCP node, secure
remote-worker shared state/installer/migration/failure acceptance; comprehensive
startup discovery/provenance/AI classification; CVE and known/unknown malware
automatic protection and real-target recovery; retention/independent evidence and
the remaining finite UI migration. Existing per-server AI pause remains implemented.
Rebuild controller and keep worker source versions matched; no agent/schema update
is needed. The existing schedule remains unchanged.

Local validation: full Python **1,294 passed / 7 skipped**; focused worker tests
**24 passed**; full browser suite and final focused expected-worker browser checks
passed. JS/Python syntax, whitespace and source-version consistency passed. Final
CI must validate all nine jobs on the exact final PR head before merge.


## v0.13.0 — Controller/key worker startup admission foundation

Delivery: [PR #68](https://github.com/StealthCat/MrPatchy/pull/68), initial implementation
[0d75d861](https://github.com/StealthCat/MrPatchy/commit/0d75d86194253e66569789b6572e78e217d36120).
The PR records final-head validation and the actual merged main commit.

Completion gate: inspected main `67325483`, latest merged
[PR #67](https://github.com/StealthCat/MrPatchy/pull/67), its actual expected-worker
API/Compose/UI diff and recorded exact-head nine-check validation, instructions,
checkpoint and related open PRs (none). The roadmap is unfinished. This batch
advances the concrete missing/mismatched encryption-state/version startup gate,
with native acceptance and honest worker UI. It is not full remote deployment
readiness or shared-state provisioning. Source version is 0.13.0.

Controller startup publishes a versioned encrypted canary in the existing settings
table, after normal database initialization and before serving. Existing receipts
must have recognized format/version and decrypt with the private current key;
invalid/foreign receipts are never replaced to force success. Compatible source
upgrades retain the encrypted canary and update the receipt's source version.
The canary contains no credentials or endpoint evidence. The key must be a private
44-byte regular file owned by the runtime; symlink/nonregular/public keys refuse
the check. This uses the existing secret.key generated by normal controller
bootstrap, not a new worker key or export of secret material.

`MRPATCHY_REQUIRE_CONTROLLER_STATE=1` makes standalone worker startup verify that
receipt with its existing local key and exact source version, before worker init
or job admission. Missing/wrong/unreadable keys, absent/invalid receipts, wrong
version, database failure and invalid gate configuration refuse startup. The worker
never generates a replacement key, bootstraps tables or repairs a receipt to pass.
Complete Compose enables the gate and retains its controller health dependency.
Native/legacy processes default to not_checked unless opted in. Controller must
start successfully before upgraded strict workers. Restore the correct protected
key/profile/database configuration after failure; do not delete validation state.
Normal backup/restore and source upgrade instructions remain in README.

Registration exposes only verified-at-startup/not_checked; absent or unsupported
reports become unknown. The UI distinguishes verified, not enabled and unreported
checks beside the identity before phone-table scrolling, with explicit limitations.
This is startup evidence, not current readiness: it does not verify SSH identities,
trust/artifacts/evidence mounts, schema/protocol compatibility, target access,
ongoing state/key freshness or correct selection among cloned databases sharing
the same key. No admission/freshness claim is made for embedded/legacy workers
that did not run this gate. No target/provider operation or new remote auth
interface is introduced. Existing coordinator, claims, locks and drain remain.

Focused tests cover a real strict worker started after real controller bootstrap,
registration/duplicate identity, drain/resume and graceful stop; a real empty-state
worker refusal without key or tables; legacy opt-out; missing/mismatched/public/
symlink/FIFO/invalid keys; invalid/missing/boolean-format/wrong-marker/version
receipts; database-error redaction and no repair; controller refusal without
rewriting foreign/malformed state. Browser checks cover all displayed gate states
and preserve roles/drain; actual 320/768/1440 renders are linked in UI_DESIGN.md.
Final local and exact-head CI validation, versioned PR and merged commit are
recorded in the delivery PR before merging. No Git tags by user instruction.

Remaining: full schema/protocol and shared-state preflight, safe remote key/SSH/
profile/trust/artifact/evidence distribution, separate Compose/installer modes,
cross-host migration/maintenance and real remote failure/recovery acceptance;
controller/endpoint/GCP health, diagnostics/alerts and optional GCP node; startup
discovery/provenance/classification; CVE/known/unknown automatic protection and
real-target recovery; retention/independent evidence and remaining UI migration.
Existing AI pause remains implemented. Rebuild/restart controller before matched
workers; no endpoint-agent or schema migration is needed for this source update.
The existing schedule remains unchanged.

Final local validation: full Python **1,314 passed / 7 skipped**; focused preflight/
worker acceptance **44 passed**; full browser suite and final focused worker UI
checks passed. Actual phone/tablet/desktop renders were reviewed after moving the
startup result beside identity. Python/JS syntax, whitespace and version consistency
passed. All nine checks on the exact final PR head remain mandatory before merge.

CI reconciliation: initial final-head run 41033997788 passed eight checks, but
MySQL exposed a race in the existing descendant-process test: `/proc/PID/stat`
disappeared after exists() and before read_text(). This represents a reaped child,
already an intended success condition. The assertion now reads once and handles
only FileNotFoundError as exit, preserving timeout, zombie handling, survivor
failure and process cleanup. No runtime process-killing code or preflight check
is relaxed. The corrected versioned commit must rerun all nine checks; the failed
head is not mergeable under this task's gate. Final results are recorded in PR #68.

Native diagnostic reconciliation: repeated local descendant checks exposed host
procfs mounted across PID namespaces. A child reported PID 7, but `/proc/7/stat`
was an unrelated sites-preview process; syscall getpid() returned 5 while
`/proc/self/stat` returned host PID 97810 (NSpid 97810/5). The test now checks
existence with namespace-correct kill(pid, 0), and reads procfs zombie state only
when self PIDs prove namespace agreement. Disappearance remains success; a live
child still fails the same two-second deadline. No process-killing runtime code
is changed and no native assertion is skipped. The corrected final head reruns
all nine checks, superseding prior validation heads.


## v0.14.0 — Required schema structure and receipt-protocol admission

Delivery: [PR #69](https://github.com/StealthCat/MrPatchy/pull/69), initial implementation
[0ae5577b](https://github.com/StealthCat/MrPatchy/commit/0ae5577b2aa82541517a905c86079654f26eceea).
The PR records final-head validation and the actual merged main commit.

Completion gate: inspected main `e2573f9f`, latest merged
[PR #68](https://github.com/StealthCat/MrPatchy/pull/68), its actual startup-gate,
UI and descendant-test changes, recorded exact-head nine-check validation, current
instructions/checkpoint and open related PRs (none). The roadmap remains
unfinished. This batch advances the explicitly remaining schema/protocol gate
with bounded structure validation, native refusal acceptance and honest UI scope.
It does not complete full schema compatibility or remote shared-state readiness.

Controller receipts now include receipt protocol 1 and a SHA-256 digest of the
source-required table names, column names and ordered primary-key columns. Model
registration is centralized and can run without web bootstrap or DDL, allowing
controllers and workers to derive the same requirements. Normal controller init
still performs its existing creation/migrations; worker verification does not.
This digest describes source requirements, not a controller certificate that the
live database is correct. Strict workers independently inspect the live database
using the existing session before worker init or admission. Missing tables/columns,
views in place of tables, incorrect primary keys or unavailable inspection refuse
startup without registering, creating/altering tables or repairing the receipt.
Extra tables/columns are allowed for additive compatibility.

Valid legacy v0.13 receipts upgrade on controller restart with the encrypted canary
retained. Unknown/boolean/missing/partial protocol metadata, malformed requirements
or same-source-version digest mismatches refuse; stripping current receipt fields
cannot masquerade as a legacy upgrade. Worker failures retain safe redacted
diagnostics. Private-key/source-version checks and existing coordinator, claims,
locks, drain and response authorization remain unchanged. Native/legacy opt-out
behavior remains explicit under MRPATCHY_REQUIRE_CONTROLLER_STATE. Complete
Compose keeps strict admission enabled; start the upgraded controller first.

Registered-worker reports add a bounded schema_structure enum independently of
the key result. Workers shows verified-at-startup, not enabled or not reported
beside identity before phone-table scrolling. A shared explanation covers the
required structure and unassessed types/other constraints, reducing repeated row
text. The existing glass palette, mascot and role/control safeguards remain.
Browser fixtures now derive matching runtime versions from health metadata.
Reviewed phone/tablet/desktop renders are linked in UI_DESIGN.md.

Focused validation covers legacy upgrade/canary retention, malformed/unknown
protocol and requirements refusal without rewrite, real SQLite table/column/PK/
view drift, additive compatibility and SQL observation proving no DDL/DML during
verification. Native strict workers refuse dropped tables/columns and missing
primary keys before init; database schema is unchanged and no registration appears.
A subprocess proves model registration imports no web runtime and creates no
tables. Permission diagnostics remain redacted. Existing real strict/legacy worker
registration, duplicate identity, drain/resume and graceful-stop acceptance remains.
Focused preflight/worker tests: **61 passed**. Full local regression and exact-final-
head CI results, the versioned PR and actual merged main commit are recorded in
the delivery PR; all nine applicable checks must pass before merging.

Limits/remaining: types/lengths, nullability, defaults, indexes, foreign/check
constraints, data validity, worker job/wire protocol, ongoing drift and atomic
cross-host migration fencing are unassessed. Metadata inspection is point-in-time,
not proof that concurrent or later DDL cannot change state. Secure remote SSH/key/
profile/trust/artifact/evidence provisioning, separate Compose/installer modes and
real remote failure/recovery acceptance remain planned. Controller/endpoint/GCP
health, alerts/diagnostics and optional GCP node; comprehensive startup discovery/
provenance/classification; CVE/known/unknown automatic protection and real-target
recovery; retention/independent evidence and remaining UI migration also remain.
Existing AI pause remains implemented. Rebuild/restart controller before matched
workers; this update adds no endpoint-agent or schema migration. No Git tags by
user instruction; the existing schedule remains unchanged.

Local UI acceptance: full browser suite and final focused schema-status checks
passed, including verified/disabled/unreported states, roles, drain and responsive
layout. Final 320/768/1440 renders were reviewed after consolidating repeated scope
text. Initial full Python regression passed **1,327 tests / 7 skipped**; the final
run includes added native refusal/current-receipt cases, with its result recorded
in the delivery PR. Python/JS syntax, whitespace and version consistency passed.


## v0.15.0 — Focused fleet Overview and server-attention review

Delivery: [PR #70](https://github.com/StealthCat/MrPatchy/pull/70), initial implementation
[305fee9c](https://github.com/StealthCat/MrPatchy/commit/305fee9c4bc9b7d5dd6bda1f7a78ece34899a0c4).
The PR records corrected full regression, exact-final-head validation and the actual merged commit.

Completion gate: inspected fresh main `5a2bcc62`, latest merged
[PR #69](https://github.com/StealthCat/MrPatchy/pull/69), its actual schema/receipt,
UI and native-test changes, recorded validation and all nine successful exact-head
checks, current instructions/checkpoint and open related PRs (none). The roadmap
remains unfinished. This cycle selects the explicitly remaining fleet-dashboard
screen migration from the finite UI inventory, with routes/context, honest stored
observations, responsive surfaces and workflow/visual acceptance.

Overview now has Summary (`#overview`), Server attention (`#overview/attention`)
and Monitoring (`#overview/monitoring`) pages. Summary separates compact counts,
a review queue, mascot guidance and three server previews. Server attention shows
read-only twelve-card pages with search and groups for review, expired/unknown/
disabled/recent contact. Monitoring separates expected collection timing and gaps
from observed success, with existing server, operation and authorized coverage/
worker links. Shared route navigation supports deep links, Back/Forward and reload;
unknown detail routes normalize to Summary. The obsolete Overview-only table
renderer is removed as part of its card migration; lifecycle/inspection controls
remain on existing server/directory workspaces.

Freshness is a narrow UI interpretation of stored observations: within two minutes,
reported online, no stored integrity findings/error, and management enabled.
Missing/nonfinite/nonpositive/future timestamps are unknown; expired contact is
stale; disabled management is separate. No contact state certifies per-collector
freshness, successful patching, clean endpoints or component readiness. The legacy
API online metric is unchanged. Dashboard totals and host snapshots are separate
reads and may differ during concurrent changes. No target probe, provider call,
trust approval or response mutation is added. Existing AI pause, lifecycle,
response authorization, role and audit behavior remain unchanged.

Search/filter/page context survives navigation and refresh in account-session
memory, clears on sign-out/reload, and clamps when results shrink. Focused controls
suppress automatic refresh. Stale render revisions cannot replace newer pages;
loading/error/retry states keep escaped diagnostics. Long names/diagnostics wrap,
solid reading panels and responsive card/control layouts preserve glass colors,
contrast and the established mascot. Phone guidance gives links their full width;
forced-color/reduced-transparency behavior reuses the shared system. Actual
320/768/1440 renders were inspected; selected images are linked in UI_DESIGN.md.

Focused browser acceptance covers deep links, Back/reload, context retention,
clamping/search/groups/empty results, disabled/future/missing contact, exact freshness
boundaries, role visibility, escaped names/diagnostics/errors, retry, delayed
responses, correct server destinations and absence of writes. Source version,
README and numbered changelog are synchronized at v0.15.0. Full local regression
and exact-final-head nine-check results, versioned PR and actual merged commit
are recorded in the delivery PR; final checks must pass before merging.

Remaining: onboarding and full UI-family/state-system acceptance; all other finite
screen migrations; full controller/worker remote deployment, secure shared keys/
profiles/trust/artifacts/evidence, schema types/other constraints/job protocol,
atomic cross-host maintenance/migrations and real remote failure/recovery tests;
all-component health/readiness/alerts and optional GCP node; comprehensive startup
job discovery/effective configuration/provenance/classification; CVE exposure and
known/unknown automatic protection with real-target recovery; retention and
independent evidence. This completes only the bounded fleet-dashboard migration.
Existing per-server AI pause remains implemented. Rebuild controller and keep
workers matched; no endpoint-agent/schema upgrade. No Git tags; schedule unchanged.

Validation reconciliation: initial full local Python run reported **1 failed,
1,330 passed / 7 skipped**. The unchanged descendant timeout test expired its
300 ms timer before the fixture interpreter published the forked child's PID
(FileNotFoundError), so it never reached its survivor assertion. Its Popen test
wrapper now waits at most five seconds for PID publication and parent exit before
the same 300 ms bounded-command timeout starts. Failed fixture setup kills/cleans
its process group. The same namespace-aware two-second live-descendant assertion
and cleanup remain; runtime process-killing code is unchanged. Focused and full
regressions must be rerun, and all nine final-head checks remain mandatory.

Local UI validation: full browser suite passed, plus final focused fleet checks
and reviewed 320/768/1440 renders. A test refresh race was corrected by waiting
for the old rendered section to detach before changing filters. Version/lifecycle
checks **21 passed**; syntax, compile, whitespace and version consistency passed.
Final corrected Python and CI results are recorded in the delivery PR.


## v0.16.0 — Historical snapshot pages and issue-first development

Issue-first inspection: current main `11f43581` (v0.15.0), repository instructions,
checkpoint, latest merged PR #70 actual changes/recorded validation and all nine
successful exact-head checks were inspected. The open-issues API returned an empty
first page (100/page), and open PRs were empty. No issue was fixed, deferred or
closed; no issue-list access failure occurred. The feature roadmap is unfinished.
The newer user instruction supersedes roadmap-only no-op wording: reproducible
issues take priority even after feature completion. AGENTS.md now records triage,
reproduction, linked Fixes/Closes PRs and post-merge closure verification.

Selected finite UI milestone: replace server inventory/observation history dialogs
with focused list/detail routes while retaining package history, administrator UI
boundaries, host-scoped records and lifecycle/AI/response safeguards. History now
offers Package changes, Inventory revisions and Process observations. Each record
has a deep link, identity/timestamp facts and escaped, scrollable evidence. Detail
responses must match record and server identities before display. Back/Forward,
reload and recovery links use normal routes. Lists retain offset independently by
server/type, clearing on reload/sign-out. Server switching retains type but drops
the previous server's detail identity. Inspection links navigate into these pages.
Missing/expired/mismatched records never masquerade as successful inspection.

History remains read-only retained evidence, not current state/protection. Existing
offset paging may shift during collection/retention and full pages may be followed
by an empty page; Previous remains available. No new target/provider call, backend
authorization, schema, agent, AI pause or response behavior is introduced. Solid
reading surfaces, responsive record rows and shared glass navigation reuse the
mascot/palette. Actual 320/768/1440 renders were inspected and linked in UI_DESIGN.

Validation: focused snapshot browser checks passed; full browser and final exact-
head CI results are recorded in the delivery PR. Backend history/version/lifecycle
checks: 48 passed. Browser checks cover routes, scoped offset, Back/reload, both
record kinds, escaping, missing/mismatched records, retry, empty pages, inactive
history, delayed-response races, server switching, roles and no writes. All nine applicable final-head checks must pass before merge.

Remaining: Activity/audit and other finite UI families, onboarding, shared long-
output/state-system and whole-application acceptance; independent remote workers/
controller Compose/install modes, shared keys/profiles/trust/artifacts/evidence,
full schema/job compatibility and cross-host migrations/recovery acceptance; full
component dashboard/readiness/alerts and optional GCP node; comprehensive startup
discovery/provenance/classification; CVE exposure and known/unknown automatic
protection with real-target recovery; retention/independent evidence. This is not
full roadmap completion. Rebuild controller before matched workers; no agent/schema
upgrade. Version v0.16.0 is synchronized; Git tags skipped, schedule unchanged.

Delivery: [PR #71](https://github.com/StealthCat/MrPatchy/pull/71), initial source
[8e339964](https://github.com/StealthCat/MrPatchy/commit/8e339964518534cfafdf539f40f697e4d83ffec6).
The delivery PR records final local/CI outcomes and actual merged main commit.
Validation reconciliation restored an adjacent recovery-summary helper removed
during editing, and narrowed a generic snapshot test mock that had intercepted
history details without identity fields. Identity checks and operational approvals
were retained; final browser checks are required on the corrected source.


## v0.17.0 — Activity/audit list and detail review

Issue-first completion gate: inspected fresh main `8bee5b64` (v0.16.0), repository
instructions/checkpoint, latest merged PR #71 actual history/route/API fixture
changes and recorded validation, including all nine successful exact-head checks.
The accessible open-issues API returned an empty first page (100/page), and no PRs
were open. No issue was fixed, deferred or closed; no list-access failure occurred.
The roadmap remains unfinished. Selected batch: dedicated Activity/audit review
pages, bounded audit pagination/details, expected-server job reads, preserved
list context, role/scope/native regression tests and responsive visual acceptance.

Activity now separates Operations, Audit trail and Workers. Audit list reads accept
offset/limit with default/max 200, reject invalid pagination and order equal-time
entries by descending ID. The UI pages fifty entries and offers administrator-only
entry deep links. Fleet and server operation details display escaped stored output
and identity/timestamp facts without replaying jobs. Expected host_id reads reject
wrong-server jobs, while existing unscoped reads and payload exclusion remain.
Frontend record/server identities are checked before display. Existing operator/
viewer job-read access and administrator audit access remain; no new authorization
or action privilege is introduced. Existing list cancellation/reconciliation
confirmations, queue locks and backend checks are unchanged.

Fleet/server operation and audit offsets survive navigation independently, clearing
on reload/sign-out. Back/reload/deep links, missing-record retry and historical
uncertainty remain explicit. Offset lists may shift during collection/retention;
full pages can be followed by an empty page with Previous still available. Shared
glass navigation, solid reading panels, responsive facts and established mascot
artwork are reused. Actual 320/768/1440 detail renders were inspected and linked
in UI_DESIGN.md. No target/provider operation is performed by detail viewing.

Validation: focused activity/operations/version tests 25 passed. New tests cover
equal-time audit ordering, disjoint pages/details, invalid limits, missing records,
operator/viewer audit denial, job server mismatch and payload omission. Browser
checks cover audit pagination/context, Back/reload, escaped text/errors, retry,
role gates, expected-server transport, identity mismatch and absence of writes.
A browser assertion was corrected to wait for the server body instead of matching
the previous fleet detail during navigation; scope checks remain enforced. Full
local regressions and all nine exact-final-head CI results are recorded in the
delivery PR and must pass before merge.

Remaining: operational-control/state-system and shared filter/long-output/UI
families, onboarding and full application acceptance; independent remote controller/
worker Compose/installer modes, keys/profiles/trust/artifacts/evidence provisioning,
full schema/job compatibility, cross-host maintenance/migration and real remote
recovery acceptance; all-component health/readiness/alerts and optional GCP node;
comprehensive startup job discovery/provenance/classification; CVE exposure and
known/unknown automatic protection with real-target recovery; retention and
independent evidence. No full-roadmap completion is claimed. Version v0.17.0 is
synchronized. Rebuild controller before matched workers; no agent/schema upgrade.
Git tags skipped; existing schedule unchanged.

Delivery: [PR #72](https://github.com/StealthCat/MrPatchy/pull/72), initial source
[89d849d7](https://github.com/StealthCat/MrPatchy/commit/89d849d798f0115cef99f7307b56ea8a7264644f).
The PR records corrected full local regressions, final-head CI and the actual
merged main commit. No source changes may be added after validation without
rerunning applicable checks.


Concurrent-main reconciliation: while PR #72 was validating, the independent
roadmap PR #73 (v0.16.1) appeared and merged as `3f39ffda`. This branch was held
until that merge, then current main was integrated with both changelog entries
and all new AI roadmap text retained. Source remains v0.17.0, above v0.16.1.
The new parallel-triage, exact known-good cache and AI spending-control program
remains planned, not implemented by Activity review. Runtime/UI/test files are
unchanged by this reconciliation; version consistency is checked against the new
base and all nine checks must rerun on the reconciled final head before merge.


## v1.18.0 — AI timing baseline and bounded reusable transport

Issue-first completion gate inspected current main `76fb0686` (v0.17.0), repository
instructions/checkpoint, latest merged PR #72 actual changes and recorded validation,
including all nine successful exact-final-head checks. Open issues returned an empty
100-item first page; open PRs were empty. No issue fix, deferral or closure is claimed.
The faster-triage roadmap is explicitly unfinished. Selected coherent milestone:
measure the current serial pipeline; add reusable provider transport, bounded stage
diagnostics, capability/transport acceptance and readable existing timeline display.

Billable requests now reuse one lazily initialized HTTP client per process, with
16 maximum connections/keepalives and 30-second idle expiry. This transport bound
is not AI execution concurrency: runtime AI capacity remains one. Credentials are
supplied only on a newly built request; only the ordinary negotiation/user-agent
header defaults are allowlisted. Credentials and prior response cookies are not
merged from client state. Response cookies are discarded. Redirects and automatic
retries remain disabled; each future retry must re-enter policy and have a receipt.
Existing HTTPS certificate/proxy configuration remains in use. Pool/connect waits
are bounded to five/ten seconds (or a smaller existing request budget); read/write
budgets remain. An idle pool closes during cooperative worker drain. Shutdown waits
for borrowed sends before close; later use can create a fresh pool. No client opens
at module import. Model discovery remains its separate, nonbillable GET path.

Existing AI run events now carry allowlisted monotonic elapsed timings: provider
policy admission, request transport, attempted-call/usage persistence, total tracked
run; process triage additionally records observed queue age, scheduler admission,
allowlisted SSH follow-up evidence and evidence/result persistence. Queue age uses
the observation wall-clock timestamp, includes paused/backoff/ineligible time, and
is omitted when invalid/future. Timings overlap; they must not be summed. Provider
completion means transport returned, not an accepted verdict: HTTP/provider errors
and structured validation retain their separate existing diagnostics. Tracked-run
time excludes initial run creation/admission and final timing-flush overhead; the
benchmark's outer run duration includes the entire invocation.

Timing events preserve measurement-end timestamps while buffering at most 32 rows
for one diagnostic transaction at completion or the batch bound. Context variables
isolate independently tracked threads/nested runs. Timing flush failures emit only
a controlled coverage warning, never a provider body, evidence, credential, fabricated
usage or result retry. Crashes/diagnostic failures can lose a buffered batch; existing
history pruning removes these metrics. This diagnostic history is not the future
independent spend ledger or trusted-assessment cache. Run state/last diagnostic,
usage uncertainty, model/schema/token budgets, full evidence and optional second
call, per-server/global pause/lifecycle locks and response authorization remain.

The same disposable harness ran against archived main and the candidate: 20 queued
investigations, ten one-stage and ten two-stage, fixed synthetic evidence, 20ms
loopback provider and 10ms SSH waits, identical model/schema/token budget assertions.
Both completed all 30 calls and requested evidence, 3,000 input/600 output fixture
tokens, zero errors, no implicit approvals and no paid/external calls. Cost is
unavailable for the synthetic model, never represented as zero. Raw stage p50/p95,
backlog-age, tokens and throughput are in
[the paired fixture report](benchmarks/ai-transport-v1180.json).

| Metric | v0.17.0 serial baseline | Pooled + batched timings |
| --- | --- | --- |
| Connections / provider calls | 30 / 30 | 1 / 30 |
| Outer-run p50 / p95 | 99.143 / 127.634 ms | 95.806 / 128.597 ms |
| Fixture throughput | 11.879 runs/s | 10.288 runs/s |
| Provider + receipt p50 / p95 | 33.544 / 59.166 ms | 34.396 / 60.517 ms |
| Receipt-persistence p50 / p95 | 2.700 / 4.301 ms | 3.029 / 10.959 ms |
| Usage-persistence p50 / p95 | 2.194 / 5.060 ms | 3.280 / 11.772 ms |

The final pair was slower overall (1.684s baseline / 1.944s candidate); an earlier
20-run pair was faster (2.255s / 1.812s). Both samples are retained in the report.
Connection reuse is established; consistent throughput improvement is not.
These are small paired loopback samples under shared local load, including
startup and diagnostic costs, not a TLS/live-provider benchmark, production speed
promise or proof of threaded throughput. Initial eight-run pooled samples were
slower. The harness removes ambient proxy configuration only for its loopback
fixture and disables delayed-ACK artifacts; runtime timing writes were batched to
remove avoidable per-stage transactions. No model/evidence capability was reduced.

Validation covers actual socket reuse, request-local parallel credentials, no cookie
forwarding/redirect/retry, finite timeouts, in-flight close ordering, idle reopen,
full one/two-stage result/evidence equivalence, redaction, unknown-cost timeout
receipts, independent thread contexts and diagnostic-failure isolation. Existing
provider mocks now patch the new billable transport seam; the first full local run
was interrupted after stale mocks missed that boundary. A subsequent full run
exposed a legacy SQLite DDL fixture failure after the new four-thread test expanded
the connection pool. A standalone reproduction on unchanged archived main confirmed
stale per-connection schema metadata (duplicate dpkg_state ADD COLUMN). The new
thread test now disposes its expanded pool in finally before later destructive DDL
fixtures; production migration code/assertions are unchanged. Broader cross-host
migration fencing remains planned. Corrected focused/full
results and final exact-head CI are recorded in the delivery PR; all nine checks
must pass before merge. Timeline workflow/phone/tablet/desktop renders reuse the
existing glass theme/mascot and are linked in UI_DESIGN.md.

Next priority (still planned): conservative versioned canonical evidence/context
fingerprints and persistent fleet exact-known-good reuse with provenance, audited
revocation and explicit completed-item Re-triage; then threaded claims/renewable
leases, fair independent scoring, pause-safe concurrent provider admission and
recovery, shared throttling/daily reservation/spend/unthrottled controls, migration
and complete SQLite/MySQL acceptance. The first finite program milestone is only
partially complete: evidence/cache reuse and end-to-end capability/performance
acceptance remain. Classified Retry-After/jitter handling is not implemented here;
legacy hourly allowances and one-hour retry behavior remain. Broader deployment,
startup awareness, CVE/malware protection, health and full UI work remain tracked.
Rebuild controller before matched workers; no endpoint-agent/schema upgrade.
Source/README/changelog version is v1.18.0. No Git tags; schedule unchanged.


Local validation before concurrent-main reconciliation: corrected Python regression
**1,347 passed / 7 skipped**; subsequent final transport/timing checks **10 passed**
(including preserved negotiation headers and a real response timeout without retry).
Full browser suite passed; actual 320/768/1440 timing timelines were inspected.
Existing focused AI/model/settings/release coverage **161 passed**, and legacy
completion/security/two-stage coverage **53 passed**. Final exact-head CI and
integration/version-policy validation are recorded in the delivery PR.


Concurrent-main reconciliation: publication was held while independent PR #74
validated and merged as v1.17.0 / `493f374c`. Fresh instructions, actual PR changes,
all nine successful exact-head checks and empty open issue/PR lists were inspected.
The major-1 pin/checker and full planned live-notification roadmap are retained.
This compatible feature batch is now v1.18.0. Historical baseline AI runtime is
unchanged by the v1.17.0 metadata/policy update. All nine checks must run on this
integrated final head; earlier-head checks do not authorize its merge. If its PR
remains open, reconcile/finish that PR before starting cache or other roadmap work.

Delivery: [PR #75](https://github.com/StealthCat/MrPatchy/pull/75), initial source
[e7fa6a64](https://github.com/StealthCat/MrPatchy/commit/e7fa6a6493fa6ef7ecf278698f16fcb79c1937c2).
The PR records the final integrated head, all CI results and actual merged commit
(or the precise pending state). Integrated version/worker/preflight checks: **75
passed**; final focused timeline workflow and recaptured major-1 phone/tablet/
desktop renders passed. Both paired benchmark samples are retained: connection
reuse is established, while consistent throughput improvement remains unproven.
Resume an open delivery PR before new cache work; do not infer completion or merge
without all nine applicable exact-final-head checks and unchanged base/mergeability.

## v1.18.1 — Pooled-schema initialization prerequisite

Issue-first gate: inspected main `3e7cfa3b` (v1.18.0), instructions, latest PR #75
actual changes/checkpoint and recorded validation, including all nine successful
exact-head checks. Open issues and open PRs returned empty 100-item first pages.
No issue is claimed fixed, deferred or closed. The roadmap remains unfinished.
The v1.18.0 checkpoint recorded an initialization failure after warming four SQL
connections. This cycle selects that concrete defect as a safe-threading prerequisite,
without claiming to implement the cache, parallel scheduler or spending controls.

Reproduction on current main: four sessions load schema state, one pooled connection
drops the legacy `packages.dpkg_state` column, then two `init()` calls attempt the
normal idempotent upgrade. Both pytest and a separate disposable SQLite process
failed with duplicate-column ADD COLUMN. A variant dropping two columns happened
to pass, so the single-column reproduction is retained; no speculative fix was
made from that passing variant. Reflection on another warmed connection can retain
SQLite's previous per-connection schema view while DDL runs on a different connection.

Initialization now performs an actual SQLite catalog query to refresh that view,
then runs create_all, column reflection and the existing upgrades on one connection.
Existing defaults and MySQL FLOAT-to-DOUBLE migration definitions remain unchanged.
Single-controller/migration-owner startup remains required. This is not global
migration fencing or a promise of atomic MySQL DDL (which can commit implicitly).
No repair of lost records, general schema/type compatibility or ongoing readiness
is claimed. The new tests warm four connections, remove each existing host/package
upgrade column, initialize twice and verify required columns and retained host data.
The timing test's pool-disposal workaround is removed so later DDL tests exercise
the production fix with warmed connections.

Validation: the single-column test failed before the fix; the standalone reproduction
now passes. Initial focused pooled/completion/preflight checks passed 64 tests.
Final expanded focused and full regression results and all nine exact-final-head
CI checks are recorded in the delivery PR. No UI behavior or assets changed;
existing browser/native startup checks still apply. Rebuild controller before matched
workers; no endpoint-agent upgrade, new schema definition or Git tags. Source,
README and changelog are synchronized at v1.18.1; major remains pinned at 1.

Next priority remains the faster-triage program: conservative canonical evidence/
context fingerprints, durable exact known-good reuse/provenance/revocation and
explicit completed-item Re-triage; then claims/leases, isolated sessions/context,
pause-safe parallel scheduling/admission, fairness/recovery and shared throttle/
daily reservations/spend/unthrottled controls. Preserve full capability and complete
SQLite/MySQL acceptance before declaring those features implemented. Notification,
remote deployment, protection/startup discovery and full UI milestones remain planned.
If this delivery PR is open, finish/reconcile it before starting further work.

Delivery: [PR #76](https://github.com/StealthCat/MrPatchy/pull/76), initial source
[8b19311d](https://github.com/StealthCat/MrPatchy/commit/8b19311d39b663daec490d1c8acc6a2877400f7f).
Expanded local initialization, settings, timing and preflight coverage: **82 passed /
1 skipped**. The delivery PR records full local regression, all nine final-head
checks, the actual merge commit or precise unfinished state. Finish an open PR
before new cache work. No UI change or new schema definition; existing browser,
MySQL and native startup checks remain mandatory on the exact final commit.


## v1.19.0 — Classified durable process-triage retries

Issue-first/completion gate: inspected current main `a63396f5` (v1.18.1), AGENTS,
CONTRIBUTING, this checkpoint, PR #76's actual source/test changes and recorded
validation, including nine successful checks on final head `1fd5d4ab`. Open issue
and PR collections returned empty 100-item first pages; no issues are claimed
fixed, deferred or closed. The roadmap is unfinished. No active fix needed
reconciliation. The selected coherent faster-triage milestone is classified
transport failure handling, durable bounded process retry scheduling and explained
queue eligibility. The broader cache/threading/shared-controls program stays planned.

A new `ai_triage_retries` table retains subject, hashed model/key configuration,
attempt count, deferred/blocked/interrupted state and next/provider-floor timestamps.
It contains no key, provider body or process evidence. Only the existing distributed
`ai-triage` lock mutates retry state; no lock is held merely waiting for eligibility.
The existing lock still spans an actual investigation and concurrency remains one.
This is not per-item leases, distributed provider pacing or parallel execution.

Transport errors carry controlled classifications. Network/timeouts, explicit
rate-limit/slow-down responses and HTTP 408/500/502/503/504 without a contradictory
known configuration/billing code get bounded exponential jitter (30–60 seconds for
the first retry, increasing upper bound) and valid numeric/HTTP-date Retry-After
floors. Unsupported/unclassified 429s are conservatively review-blocked rather
than assumed transient billing. Malformed headers fall back to jitter; parseable
excessive delays outside the supported ten-year bound block automatic scheduling
for operator review instead of being clamped into an earlier automatic retry.
No untrusted header text is persisted. There are at most five automatic attempts
per subject/configuration, including interrupted attempts. Transport itself never
replays a paid call. The worker returns while waiting; another eligible subject can
run. Retry scheduling is durable across fresh sessions/processes and normal AI-log
pruning. Legacy attempts and crash recovery retain a one-hour wait; exhausted
interrupted work requires review rather than retrying forever.

Authentication, billing, schema/request/model, invalid/incomplete/refused structured
output and unclassified/internal/SSH failures do not loop automatically. They require
a changed model/key or an explicit administrator Retry after review. Enable toggles
do not reset attempt limits. Configuration changes cannot bypass a saved provider
delay. Manual Retry is audited and still respects CSRF/roles, lifecycle, provider
floors and existing hourly admission. A pause between stages defers work until
resume without counting that policy deferral toward the automatic-failure limit;
resume retains global/per-server checks and does not reset hourly accounting.

Models, token limits, full authorized input, conditional SSH checks, second-stage
requests, structured validation and advisory/approval boundaries are unchanged.
A lost follow-up response retains collected evidence and both call receipts; a
later retry performs the complete investigation and required checks again. Failed
calls can be billable; missing usage remains unavailable/uncertain, never free.
This milestone does not add a durable budget ledger or promise exactly-once paid
execution. AI run/call diagnostic retention remains unchanged. Retry state alone
is retained independently until a successful result or explicit reset clears it.

Investigations and AI status explain eligible/review-blocked/paused counts and
per-item retry state/attempts/eligibility. Paused/inactive work does not count as
eligible. Eligibility is not a start guarantee: the existing serial worker and
rolling-hour process/scoring/plan allowances remain. Other AI purposes retain
their old scheduling; central classification metadata does not add automatic
replays to tests, plans, scoring or manual calls. Shared Retry-After admission
across purposes/workers is still part of the planned shared-controls milestone.
The established glass palette and mascot are reused; actual 320/768/1440 renders,
text escaping, early-retry feedback and reload behavior are covered by browser tests.

Validation before publication: initial integrated coverage passed 122 tests. Extra
crash/pause/follow-up cases exposed a missing local API import and mislocated test
fixture lines; both were corrected before publication. Corrected policy/queue tests
passed 56 tests, then the expanded final retry module passed 28 tests, including a
separate process reading persisted eligibility. Full local regression/browser and
all nine exact-final-head SQLite/MySQL/native checks are recorded in the delivery
PR; no merge is allowed before their success. Source/README/changelog are v1.19.0,
major fixed at 1. Rebuild controller first to initialize the new table, then matched
workers; no endpoint-agent upgrade or Git tags. The development schedule is unchanged.

Remaining priority: full verified context collection/canonical fingerprints and
persistent fleet exact-known-good reuse with provenance/revocation/manual Re-triage;
atomic per-item claims/renewable leases, independent sessions, pause-safe same-host
and cross-host threaded tasks, fairness/scoring admission and recovery; shared
pacing/daily reservations/uncertain-charge ledger/unthrottled controls plus migration
preview, complete billable-path coverage and SQLite/MySQL end-to-end acceptance.
Do not treat this retry submilestone as completion of finite milestone 1 or the
faster-triage program. Notifications, remote deployment/shared state/health/GCP,
startup/provenance, malware/CVE automatic containment and full UI work remain
unfinished. Finish/reconcile this delivery PR before starting new roadmap work.


Delivery: [PR #77](https://github.com/StealthCat/MrPatchy/pull/77), initial published
source [e7c9afd4](https://github.com/StealthCat/MrPatchy/commit/e7c9afd4f95e93a5f4af9d85952a76fe216e3ab6).
The versioned delivery PR records the final published head/tree, final local and
SQLite/MySQL/browser/native validation and actual merge SHA, or precise unfinished
state. Check this PR before any new implementation; the initial source reference
is not a claim that CI finished or that a merge occurred. All nine applicable
checks must succeed on the final head, with current main, title/label and
mergeability rechecked. No source edits are added after those final checks.


## v1.20.0 — Durable assessment provenance and explicit completed-item Re-triage

Issue-first gate: inspected main `5166ba93` (v1.19.0), instructions, the current
checkpoint and latest PR #77 actual changes/recorded validation. Its final head
`e98f0c7d` passed all nine checks; the interrupted delivery is fully reconciled.
Open issues and PRs returned empty 100-item first pages. No issue fix, deferral or
closure is claimed. The roadmap remains unfinished. This coherent faster-triage
batch selects durable assessment provenance and explicit completed-item refresh,
which are prerequisites for safe known-good cache reuse. It does not invent a
cache hit from the current incomplete cross-server context.

New `ai_behavior_assessments` records retain each newly completed process result,
its full saved evidence snapshot, each supplied initial/follow-up input after the
unchanged input limits, the requested model and original run ID. A digest binds
versioned instructions, schema, output/input/connection budgets captured for each
stage. These are local per-observation records, not a fleet canonical fingerprint,
verified package-default proof, memory attestation or reusable trust entry. Failed,
refused and incomplete runs do not create a completed assessment. The current
result and retained record are committed together; history persistence failure
rejects completion rather than fabricating provenance. Normal diagnostic pruning
does not delete assessments. Original run diagnostics may expire independently.
There is no automatic history deletion or immutable external custody yet; retained
snapshots/inputs contain sensitive authorized process evidence and require storage
planning. No credentials/provider raw bodies are added to these records.

New `ai_behavior_refreshes` retains an administrator's explicit request ID, reason,
actor, previous assessment ID and whether approval was withdrawn. Re-triage only
accepts completed low/medium/high/unknown observations on an active managed server.
It is distinct from Retry for failed/pending work, and it requests fresh work for
one observation, without changing fleet trust. Legacy current results are preserved
only when needed and clearly labelled unverified legacy snapshots: no original
model, run ID, exact input binding or assessment time is invented from today's
settings. Already-retained matching results are referenced without duplication.
A new request preserves the prior result, resets pending state, withdraws approval
only with explicit confirmation, and audits both the request and any withdrawal.
Fresh AI output never restores administrator approval or authorizes a response.

A revision digest rejects changed results/approvals while ignoring observation-only
last-seen changes. The distributed triage lock excludes an in-flight assessment;
the host queue lock serializes approval changes. The pre-lock read transaction is
ended and state re-read under the host lock so MySQL repeatable-read cannot hide
a concurrent approval. Duplicate/stale requests do not queue another refresh.
The request remains durable through failed attempts and the existing retry flow;
successful result/history persistence completes it in the same transaction. Its
explicit bypass-cache intent is retained for future cache integration; no runtime
cache lookup exists yet. A later independent administrator approval can hold work
under the existing approved-behavior filter; revoke that approval to resume it.

The web request sends no provider call. Workers continue to recheck global/server
AI pause, lifecycle and saved configuration and preserve hourly limits, provider
delay floors, original model/token budgets, supplied evidence and conditional SSH
follow-ups. Failed calls may still be billable. Scoring/plans and response gates
are unchanged; no new budget ledger, parallelism or provider-wide admission is
claimed. This submilestone improves explicit control and retained provenance, not
paid-call throughput or automatic cross-host reuse.

Administrator history list/detail endpoints enforce subject/server identity and
roles, paginate summaries without loading all evidence into the list response,
and retain read-only access for inactive/deleted servers. UI fleet/server deep
links preserve pagination, Back/reload and server scope; sign-out clears context.
The shared glass surfaces, mascot and confirmation dialog show current approval
separately from historical advisory results, require a reason and explicit approval
withdrawal, preserve stale-form feedback and guard duplicate submission. Text is
escaped; optional evidence/provenance reading surfaces wrap long values. Review
covers actual phone/tablet/desktop history/confirmation renders. A phone overflow
was caught before publication and corrected with a scoped digest-wrap rule; browser
assertions remain enabled. Focused browser fixtures wait for the actual new server
workspace rather than accepting a heading left over from the fleet page.

Validation: initial integrated tests passed 57 cases; expanded approval-race,
pause and transaction-rejection coverage is included in the final focused suite.
Full local, browser and all nine exact-final-head CI results are recorded in the
delivery PR. SQLite/MySQL acceptance remains mandatory before merge. Source,
README/changelog/UI/API are v1.20.0; major remains 1. New tables require controller-
first startup and matched workers; no target-helper/agent upgrade or Git tags.
The schedule remains unchanged. Finish an open delivery PR before new work.

Finite remaining known-good program, in dependency order:
1. Collect/validate complete local artifact/script/interpreter/library/config,
   authenticated provenance, privilege/account/behavior/startup/network/container
   context and explicit coverage, bound to a stable process/evidence identity.
   Current executable hashes and bounded follow-up metadata are insufficient.
2. Define a versioned canonical host-independent fingerprint and strict missing/
   changed/unverified-context misses, binding all required follow-up evidence and
   policy versions. The new per-observation revision/policy digests are not this key.
3. Publish/reuse only complete validated safe outcomes, retain AI-versus-admin
   classification provenance and per-host hits, enforce explicit refresh bypass,
   audited fleet revocation/invalidation and linked review on contradictions. Valid
   unchanged cross-server hits must make zero provider calls/reservations and cannot
   suppress stronger threat evidence or imply approval.
4. Validate contextual misses, concurrent first encounters/revocation/manual refresh,
   retention and role isolation on SQLite/MySQL with full runtime acceptance.

Claims/renewable leases, independent sessions/run contexts, fair pause-safe threaded
execution and scoring admission, shared rate/daily reservations/uncertain-charge
ledger/unthrottled settings and all-billable-path migration/acceptance remain next
parts of the faster-triage program. Notifications, remote deployments/shared state/
health/GCP, startup provenance, CVE/malware protection and full UI work remain planned.
This batch does not complete finite faster-triage milestone 1 or the whole roadmap.


Pre-publication acceptance: final focused assessment, policy/retry/timing/cost,
identity, database settings and preflight coverage passed **148 tests / 1 skipped**.
Focused browser acceptance passed, including escaped results, required approval
withdrawal, stale-form feedback, duplicate submission, Back/reload, server scope,
roles, phone/tablet/desktop and late-lookup dialog isolation. Full local regression,
complete browser suite and exact-final-head CI/merge results are recorded in the
delivery PR. No source changes are added after its final-head checks.


Delivery: [PR #78](https://github.com/StealthCat/MrPatchy/pull/78), initial source
[51a28362](https://github.com/StealthCat/MrPatchy/commit/51a28362e41e347c5baa76b05d37be2bb30e7fae).
Full local regression completed **1,403 passed / 7 skipped**, plus nine version-policy
subtests. The delivery PR records the final published head/tree, complete browser
and all nine applicable SQLite/MySQL/native CI results, and actual merge SHA or
precise unfinished state. Finish this PR before new cache/threading work. Do not
infer a successful merge from this source reference or earlier-head checks.


Final boundary acceptance adds simultaneous duplicate refresh POSTs: exactly one
intent and one prior result are retained, with one successful and one rejected
request and no provider call. The assessment module passes **20 tests**, including
this additional case. Full local regression above preceded that final case; final
SQLite/MySQL CI includes it. A valid 192-character executable filename reproduced
phone overflow in the new header before final freeze. Scoped history-header and
confirmation-name wrapping now passes the retained viewport assertions; the normal
and long-name history/dialog renders were inspected. The complete browser suite is
rerun for this final UI/test change. No broader styling or authorization change is
included. Recheck all nine checks on the new final head; earlier-head success is
not final acceptance.


## v1.20.1 — Standalone migration registry regression

User-reported blocker takes priority over the unfinished faster-triage batch. Fresh
issue/PR inspection on main `a7187941` returned empty 100-item first pages; no GitHub
issue number or issue closure is claimed. PR #78 and its actual changes/final-head
validation remain the latest merged reference. The roadmap is still unfinished.

Reproduced the exact reported refusal in separate startup and migration processes
against unmodified main. Normal startup registers `ai_triage_retries`,
`ai_behavior_assessments` and `ai_behavior_refreshes`; the offline command's second,
stale registration list omitted all three. Existing tests preload `app.main` through
conftest, filling shared SQLAlchemy metadata and masking the standalone defect.
The reproduced dry run exited nonzero, preserved the source and created no target.

The migration metadata entry point now calls the existing `db.register_models()`
used by startup. It imports mappings only, without web startup, workers, DDL or
source upgrades. Unknown tables/views, mismatched columns, offline assertion/lock,
source read-only checks, running-job rejection, empty-destination rules, transaction
verification and activation safeguards remain unchanged. No table is ignored or
deleted. Source/README/changelog/UI/API become v1.20.1, major pinned at 1; Git tags
remain skipped and no published-image claim is made.

A new fresh-process regression initializes the current source independently, seeds
all three affected tables, and runs dry-run/copy in new interpreters without importing
main/worker. It verifies table fingerprints, retained assessment inputs, retry state
and refresh approval intent, plus rejection of unknown tables/views. The same test
fails on archived main with the exact reported error and passes with the shared
registry. Focused/full and all nine exact-head results and actual merge references
are recorded in the delivery PR; do not infer a successful merge from this checkpoint.

The earlier v1.21.0 identity-bound follow-up/context roadmap batch is isolated in
`feat/verified-triage-context-v1.21.0`, not part of this fix and not merged or claimed
complete. It must be reconciled with this patch before later publication; retain
major 1 and the actual current version sequence. No unrelated roadmap PR should
be merged while this reported migration fix is unfinished. The broader canonical
cache, threaded execution, shared spending/throttle controls and remaining roadmap
stay planned. Schedule unchanged.

Delivery: [PR #79](https://github.com/StealthCat/MrPatchy/pull/79), initial published
fix [d95fbd06](https://github.com/StealthCat/MrPatchy/commit/d95fbd0684916c9ac7b67e3b0c9eef63883da701).
The PR records exact final head/tree, all nine CI results, full local validation
and actual merged commit (or precise unfinished blockers). Finish this fix before
resuming isolated roadmap work; never use earlier-head checks to authorize a merge.


## v1.21.0 — Identity-bound follow-up artifact and privilege context

Issue-first gate read main `a7187941` (v1.20.0), AGENTS/CONTRIBUTING, the checkpoint,
PR #78's actual code/test changes and its recorded final-head validation. All nine
checks passed on `c03156f5`; actual main tree matches that tested source. Empty
100-item first pages prove no open issues or unfinished PRs. No issue fix, deferral
or closure is claimed. The roadmap remains unfinished. This faster-triage batch
selects stable local context acquisition and honest coverage review, a concrete
prerequisite of finite cache milestone 1; it does not implement canonical reuse.

Existing allowlisted follow-up requests now add a bounded v2 context receipt. The
helper opens the kernel procfs root and pins one process directory with no-follow
directory opens. It captures boot/PID/start ticks, proc identity, UID/GID/groups,
available capabilities/security flags, PID/network/mount/user namespaces, executable
metadata and hashes, and supported script/executable mapping file hashes/metadata.
Maps and cgroup contents are compared locally and retained only as digests, not raw
AI evidence. Raw arguments/environment and script bytes are not added. The existing
conservative interpreter parser reads bounded cmdline only to identify a script;
inline/modules/unknown options and inaccessible artifacts remain unverified.

Executable, process, credentials, namespaces, maps and cgroup samples are checked
before/after collection; all artifact identities are collected again after optional
package/service reads. Changes reject the candidate as a whole, without retaining
a mixed verified package/service/context result. Searches are capped at 4,096
entries/10 seconds, hashes retain their 128 MiB/per-file two-second bounds, metadata
reads are bounded, and final rechecks fit an 80-second total collection envelope.
The worker supplies the observed effective UID when available; a different account
is not an acceptable current match. No caller-selected path is opened as arbitrary
evidence: executable selection still requires a live matching proc executable.

The receipt is explicitly **one current matching executable**, not the historical
observation's original process. Before/after agreement is not an atomic snapshot,
memory attestation or protection against a compromised target kernel/root. Package
ownership remains unauthenticated local metadata. Required authenticated provenance,
configuration, effective startup/behavior and complete security-relevant dependencies
remain unfinished. Every receipt therefore has `cache_eligible=false` and explicit
gaps. No cross-host verdict reuse, periodic-retriage exemption, cache hit, revoked
trust propagation or throughput/paid-call saving is claimed. Context/PID/digest
fields are not a canonical host-independent key.

Existing one/two-stage model flow, 64 KB evidence limit, output tokens/schema, AI
pause/data sharing/admission, retained exact inputs and response gates remain.
Oversized combined evidence fails under the existing limit rather than dropping
collected evidence for speed. Failure does not imply benign behavior. Full future
cache context acquisition is not enabled by increasing the helper's metadata.

Assessment detail now has a shared glass coverage notice, collected time, sampled
identity/account and verified-artifact count with keyboard-operable gap details.
Missing/old/failed context is explained; current approval and advisory historical
results remain distinct. Text is escaped, and fleet/server routes and roles remain.
Actual 320/768/1440 views, missing/failed states and injection cases are validated.
No UI-only roadmap batch or broad styling change is included.

Initial focused acceptance passed **157 tests / 1 skipped**, followed by updated
UID/UI coverage; final results are recorded in the delivery PR. Local child-procfs
inspection is unavailable in this execution environment: the explicit live-process
case skips locally, while deterministic pinned-directory/race/file tests run.
Native Ubuntu/Debian/Alma/Fedora SSH acceptance exercises the installed sudo bridge
with a live interpreter fixture in CI; SQLite/MySQL/browser and all nine checks on
the exact final head remain mandatory before merge. No live provider is contacted.

Deploy new controller/matched workers and use the existing reviewed Agent upgrade
workflow to install both helper and collector on each target. Older helpers remain
readable but supply no new context; history says it is unavailable. No new schema,
automatic target update or Docker-image publication is implied. APP_VERSION/README/
changelog/UI/API are v1.21.0; major stays 1. Git tags are skipped and schedule unchanged.

Next priority remains the finite known-good program: complete authenticated/context
collection, strict versioned host-independent fingerprint, durable safe publication/
lookup/hit provenance with explicit refresh bypass, audited fleet revocation and
contradiction review, then full SQLite/MySQL runtime acceptance. Threaded per-item
claims/renewable leases and fair isolated execution, shared smooth rate/daily-spend/
unthrottled controls and the independent uncertain-charge ledger remain planned.
The broader notifications/deployment/health/GCP/startup/CVE/malware/full UI roadmap
also remains unfinished. Finish any open delivery PR before beginning another batch.

Local pre-publication checkpoint: full Python regression completed **1,416 passed /
8 skipped**, plus nine version-policy subtests. Complete browser suite passed,
including context missing/failed states, escaping, approval/refresh flows, scoped
history, Back/reload and actual phone/tablet/desktop renders. Reviewed images are
linked in UI_DESIGN.md. A new user-reported offline migration failure interrupted
publication: its reproducible fix takes priority and is isolated in PR #79. This
v1.21.0 batch is saved locally and has no remote runtime/CI acceptance or merge yet.
Reconcile it with the eventual PR #79 main commit before publishing; these local
checks do not authorize merging a future combined/final commit. Native target
acceptance, all nine final-head checks and the broader cache program remain open.


Reconciliation: reported migration PR #79 merged as `8d2087a5` (v1.20.1), with
all nine exact-head checks successful. This batch now includes that fix and its
fresh-process regression; 1.20.1 changelog/history are retained below 1.21.0. Review
found the new helper import had omitted the trusted install path required by
Python `-I`; a real isolated-entrypoint regression fails before the path restoration
and passes afterward. Native acceptance remains required. Coverage rendering also
tolerates malformed/null artifact entries without treating them as verified. Final
combined local focus/browser, exact-head CI and actual merge references are recorded
in the delivery PR. Earlier local-only checkpoint above is superseded by this
reconciliation; it does not claim cache/runtime-program completion.


Combined pre-publication acceptance after PR #79 reconciliation and loader review:
**63 focused tests passed / 1 skipped**; focused real-browser history/context/refresh
acceptance passed, including null/untrusted evidence, missing/failed context, roles,
Back/reload and phone/tablet/desktop views. The earlier full **1,416 / 8 skipped**
regression and complete browser run predate this final loader/guard reconciliation;
all nine final-head CI checks cover the combined source before any merge. No source
change is permitted after that final-head acceptance without applicable new checks.

Delivery: [PR #80](https://github.com/StealthCat/MrPatchy/pull/80), initial published
source [0bb3797a](https://github.com/StealthCat/MrPatchy/commit/0bb3797a8b11906fb855bdbc695212738cc8ba67).
It targets the actual post-fix main `8d2087a5`. Final published head/tree, all nine
SQLite/MySQL/browser/native acceptance results and actual merged commit (or exact
unfinished blockers) are recorded in that PR. Reconcile this delivery before new
roadmap work; no earlier-head or local-only result authorizes merging.


## v1.22.0 — Concurrent cross-server process triage with renewable claims

Issue-first reconciliation inspected actual main `2e823b76` / PR #80, current
instructions and checkpoint, its code and all nine successful main checks. Open
issue and PR lists were empty. No reported issue or issue closure is claimed.
The faster-triage program remains unfinished. This batch selects a runtime
concurrency increment independently of the larger authenticated-context/cache
program; none of the v1.21.0 context gaps become cache eligibility.

`MRPATCHY_AI_CONCURRENCY` sizes the real shared AI executor from 1–8 tasks, default
4. Independent servers can overlap full one/two-stage process investigations.
Only one process investigation per host is admitted across supported workers,
preserving existing host lifecycle and provider serialization and bounding a noisy
host's occupancy. The coordinator alone schedules update scoring; other workers
can consume process work. Alternating purposes gives scoring an opportunity even
at concurrency 1, but this is not a complete priority/aging or same-host fairness
implementation. There is no unbounded future queue or sleep for deferred work.

Short `ai-triage` transactions atomically claim the subject, record its run and
consume the existing rolling-hour allowance. No provider/SSH operation holds that
lock or an ORM read/write transaction. Each task has copied input/configuration,
independent SQL sessions and ContextVar run/policy/timing state. A claim binds
subject, host, token, worker/boot, run, exact assessment revision and API
configuration. Its 120-second lease renews every 15 seconds while work runs.
Historical observations with a missing server record retain their existing local
advisory path; they cannot request SSH evidence. Disabled/deleted servers remain
excluded. Full regression caught and corrected an overly strict initial host filter
that would have removed this uncertainty-preserving capability.
Provider requests, SSH collection and fenced persistence verify ownership, expiry,
unchanged evidence/approval/configuration and matching worker boot. Result,
retained assessment, explicit-refresh completion and retry removal share one
transaction. Approval changes during a request remain and prevent stale acceptance.
Retry/re-triage reject the claimed subject while other subjects remain usable.

Reconciliation interrupts only expired/orphaned process runs, never another
worker's live claim. Expired attempts keep existing one-hour interrupted recovery
and bounded retry accounting. Tokens prevent an old owner accepting a result or
deleting its successor's claim. Cooperative drain and signal shutdown block new owner admission but keep
scheduler heartbeats and assigned lease renewal alive until work finishes.
Stale worker heartbeats, lost scheduler identity and new boot identities fence old
work.
Already sent calls cannot be recalled. Their usage/uncertain-cost receipts survive
fencing; this is not exactly-once billing or a daily-spend ledger. SQLite workers
still need the supported shared local lock/data filesystem; MySQL named locks and
a common database do not solve the outstanding remote shared-state requirements.

The existing model/effort, 64 KB input and output/schema limits, conditional
allowlisted evidence, per-call pause/lifecycle checks, structured validation,
retained assessment provenance, role/CSRF and explicit response authorization remain.
AI never grants an administrator approval. Existing hourly limits remain; faster
work can reach them sooner. This does not implement smooth pacing, daily USD caps
or unthrottled mode. Configuration changes fence old results; policy disable/pause
cannot retract evidence already sent.

Investigations and fleet AI activity show active claims, queued work and fresh
reported AI slot capacity; worker rows show actual active task counts. Missing
legacy counts are unavailable. Capacity includes draining registrations and is
explicitly not a guarantee of available/readiness-verified slots. Existing glass
styling, mascot, routes and roles remain. Browser acceptance checks phone/tablet/
desktop rendering, escaping and navigation with these fields.

Acceptance includes four genuinely overlapping independent investigations with
one/two model stages, identical model/schema/output limits and all SSH requests,
atomic hourly admission, duplicate subject/host suppression, thread context
isolation, fresh-process claims, approval/evidence/configuration/boot/expiry/token
changes, lease renewal and successor fencing, live-run reconciliation, bounded
scheduler slots, purpose alternation and drain. SQLite local and MySQL CI run the
same acceptance. `tools/benchmark_ai.py` supports serial/parallel identical delayed
loopback I/O; raw paired fixture measurements are in
`docs/benchmarks/ai-parallel-v1220.json`. They do not establish production latency
or capacity. Local focused and full/browser/exact-final-head CI results are recorded
in the delivery PR; all nine applicable checks must pass before merge.

Drain/stop old workers first, upgrade/start the controller to initialize
`ai_triage_claims`, then start matching workers. Mixed old/new workers are
unsupported because old orphan reconciliation assumes fleet exclusivity. The
shared startup model registry includes claims in offline SQLite/MySQL migration
and schema preflight. No target-helper/collector upgrade is needed for this batch.
APP_VERSION/README/changelog/UI/API synchronize at v1.22.0; major stays 1.
No Git tags, Docker publication or schedule change is made.

Remaining: complete authenticated/context collection and strict host-independent
known-good publication/hit/revocation/refresh acceptance; safe same-host concurrency,
broader priority/aging and supported remote-worker recovery; shared throttle/daily
reservations/uncertain-charge ledger/unthrottled controls and all-billable-path
migration. Notifications, deployment/health/GCP, startup/CVE/malware protection,
retention and the full UI roadmap remain unfinished. This batch does not complete
the finite faster-triage program. Reconcile any open delivery PR before new work.


Delivery: [PR #81](https://github.com/StealthCat/MrPatchy/pull/81), initial published
source [1fd7de00](https://github.com/StealthCat/MrPatchy/commit/1fd7de005e567e9a5d7cfe925156c2ffafa549b3).
Its initial published tree matches reviewed local source
`3dc6d2c9669701c0f9c0e6b6b01ad46cf273e323`. Final local focused concurrency,
worker lifecycle, shutdown/drain, fresh-process migration and schema preflight
acceptance passed **114 tests**. The complete local browser suite and final
v1.22.0 focused responsive acceptance passed; reviewed final renders are linked
in UI_DESIGN.md. Full final-source Python regression, exact published final head/
tree, all nine applicable CI checks and completed overall workflow, and actual
merge SHA (or precise unfinished blockers) are recorded in PR #81. Finish this
delivery before beginning another roadmap batch. No earlier-head result authorizes
a merge; source changes after final validation require applicable new checks.


MySQL gate reconciliation: initial frozen head `5e674dba` passed eight checks,
but MySQL's full suite failed the required two-stage completion regression
(1,322 passed / 131 skipped; workflow 41155439850). Local SQLite full regression
above had passed, so it did not authorize a merge. A deterministic DB-write
normalization fixture then reproduced the same one-call rejection on unchanged
code: the ORM retained an original numeric timestamp while stored JSON differed
by one floating-point ULP; the next strict claim check rejected it.

Fenced mutations now flush and refresh the row before hashing its stored revision.
The follow-up model receives a copy of that same re-read evidence representation.
No hash tolerance, rounding-based comparison, missing-evidence allowance or bypass
is introduced. Native completion acceptance also compares supplied follow-up
evidence to the stored observation and retains safe run diagnostics on failure.
The deterministic regression fails before and passes after this correction;
combined claims/history/retry/policy/completion acceptance passed **107 tests**
on the corrected source, including the additional diagnostic/binding assertions. Final revalidation and the
corrected final published head/tree/CI/actual merge are recorded in PR #81. All
nine checks must pass on that corrected head; the prior freeze is superseded.

The post-correction paired benchmark retains identical eight investigations and
12 calls: 3.505s serial / 1.492s at four threads (about 2.35× throughput). Raw
measurements replace the pre-correction sample in the linked report; neither
measurement claims production performance. The complete local/browser/native
validation is rerun on the corrected final source before delivery.


Final admission review also checks the blocking lock acquisition result before
any claim/run/attempt mutation. A refusal regression verifies that no work is
created and an unowned lock is never released. Claims/completion acceptance passed
**52 tests** after this guard. This guard joins the same unmerged v1.22.0 update;
its final source receives a fresh complete CI run, including browser acceptance.
The corrected 426551c1 database run and any transient browser timeout/retry are
retained in PR #81; only all-success checks on the final published commit permit
merge. No checks or UI assertions are weakened to obtain a pass.


## v1.23.0 — Bind follow-up evidence to the recorded process identity

Issue-first reconciliation inspected main `de18cee4`, repository instructions, this
checkpoint and merged PR #81's actual changes and exact-head validation. The empty
100-item open-issue page and open-PR page establish that no issue fix or unfinished
delivery competes with this batch. PR #81 delivered bounded cross-server claims and
threaded execution, but the faster-triage and exact-known-good programs remain
unfinished. This batch selects the next dependency-ordered context milestone.

New periodic process samples retain a validated identity containing boot ID, PID,
start ticks, PID namespace and the pinned proc-directory device/inode. Execution-event
samples retain the same identity when the process is still observable; an exited or
unreadable process remains useful evidence without inventing identity. The behavior
deduplication key deliberately excludes this observation-only identity. Pending/error
work adopts a newer verified identity for the same behavior, while completed results
and assessment history do not silently move to a different process. Missing or
malformed identity never replaces a verified one.

When a follow-up is requested, the controller supplies the saved identity to the
allowlisted evidence action. The target opens only that PID and requires all identity
fields, executable path/bytes and account/context to match before and after package or
service reads. PID reuse, target restart, namespace change, proc-directory replacement,
exit or any sampled context/artifact change refuses the entire receipt. Another process
with identical path/hash/account is never substituted. The selector remains local and
is removed from provider input while retained in the assessment snapshot. Older observations omit the
identity and retain the prior bounded current-equivalent scan plus the explicit
`original_observation_process_not_identified` gap.

An exact match removes only that single gap and reports scope
`recorded_process_identity`. It remains ineligible for fleet reuse. Authenticated
package provenance, relevant configuration, startup/effective behavior, historical
network coverage, arguments/environment, executed-script and memory attestation remain
strict missing-context failures. No canonical fleet key, trusted-cache publication or
hit, implicit approval, response authorization or provider-input expansion is added.

Acceptance covers every identity-field mismatch, PID substitution refusal, before/
after races, legacy fallback, malformed target data, behavior-key stability and
pending-versus-completed identity updates. Native Linux SSH acceptance creates a live
script process, records its exact identity and requires the returned context to match
it. Assessment UI acceptance distinguishes recorded versus sampled scope with the
existing responsive/escaped glass surface. Full local/browser and all nine exact-final-
head CI results plus actual merge state are recorded in the delivery PR.

Upgrade controller/workers together and use the reviewed Agent upgrade workflow to
install both helper and collector. There is no schema change, target auto-upgrade,
Docker publication or Git tag. APP_VERSION/README/changelog/UI/API synchronize at
v1.23.0; major remains 1 and the schedule is unchanged.

Remaining priority: complete authenticated package/configuration/startup/network and
behavior coverage, then define the strict host-independent canonical fingerprint and
deliver durable exact-known-good publication/hit/revocation/manual-refresh acceptance.
Safe same-host scheduling/fairness, distributed pacing/daily reservations/uncertain-
charge ledger/unthrottled controls and the other requested roadmap programs remain
unfinished. This batch does not complete the finite faster-triage roadmap.

Pre-publication validation on the selected source passed **1,459 tests / 8 skipped**
plus nine version-policy subtests, the 186-case focused AI/context suite and the
complete browser suite. The final 320/768/1440 exact-identity renders were inspected
without horizontal overflow. The versioned delivery PR records the exact published
head/tree, all nine final-head SQLite/MySQL/browser/native checks, completed workflow
and actual merge SHA or a precise unfinished blocker. No earlier-head result permits
merge, and a final source change requires applicable revalidation.


## v1.23.1 — Actionable database migration schema diagnostics

Issue-first reconciliation read main `d1df85e3`, repository instructions, this
checkpoint, merged migration fix PR #79 and latest merged PR #82. The first 100-item
open issue and PR pages were empty. The chat-reported generic source-schema refusal
was reproduced by removing the v1.22.0 `ai_triage_claims` table from an otherwise
current disposable source. A fully initialized v1.23.0 source passed standalone
dry-run/copy coverage, and current startup initialization restored the missing table
before a successful dry run. Without the deployment's schema inventory, the report
cannot establish whether its cause is a missed upgrade, a custom table/view or a
different mismatch; no source object may be guessed away.

The strict refusal now includes bounded, terminal-escaped lists of missing tables,
unexpected tables and unexpected views. Current startup remains the only supported
repair for missing current objects. Unexpected objects still require separate review;
the copier does not ignore, delete, rename or accept them, and source reads remain
read-only. Fresh-process regressions demonstrate the old generic message before the
change and distinguish all three categories afterward. APP_VERSION/README/changelog/
UI/API synchronize at v1.23.1; major remains 1. No schema, endpoint helper, Docker
publication, Git tag or schedule change is introduced.

The user's actual refusal remains open until its new diagnostic or an independently
reviewed schema inventory identifies the category and the documented repair succeeds.
The faster-triage priority remains unchanged: complete verified context and the
host-independent exact-known-good cache, then safe same-host fairness and shared
throttle/daily-spend/unthrottled controls. Notifications and the broader security,
deployment and UI roadmaps also remain unfinished.


## v1.24.0 — Host-independent exact-match fingerprint contract

Issue-first reconciliation read current main `3b8406a4`, repository instructions,
this checkpoint and merged PR #83. The first 100-item open issue and open PR pages
were empty, so no actionable report or unfinished delivery competed with roadmap
work. The user's database-migration refusal remains blocked on the new v1.23.1
category detail or a separately reviewed schema inventory; no object is guessed away
and no closure is claimed.

This dependency-ordered faster-triage milestone adds a controller-side versioned
canonical known-good evaluator. A candidate exists only for a completed low-risk AI
assessment with the recorded model/policy digest, exact recorded process scope and an
explicit complete verified-manifest contract for artifact bytes, authenticated
provenance, configuration, effective privileges/startup/network/execution/memory,
required follow-up evidence and coverage. Every manifest digest contributes to the
key. Model or policy changes produce a different key. Missing, partial, malformed,
oversized or unverified context returns bounded human-readable miss reasons and no
fingerprint.

Host/server identity, PID/start/proc identity, collection time and ephemeral source
ports are accepted only in an isolated observation section and excluded from the
canonical key. The same complete contract therefore fingerprints identically across
servers/days, while any observation-only field embedded in canonical evidence is a
hard miss rather than a silently normalized match. Unknown canonical component fields
remain included in the digest, so future security-relevant additions cannot be ignored
without a fingerprint change. Current v1 follow-up receipts do not claim the new
complete manifest and remain ineligible.

Authenticated Assessment detail exposes only this readiness result. It escapes miss
reasons and states that even an eligible fingerprint is an unpublished candidate.
There is no cache table, lookup, provider-call avoidance, implicit approval, response
authorization, detector suppression, target-helper/schema change, Docker publication,
Git tag or schedule change. APP_VERSION/README/changelog/UI/API synchronize at
v1.24.0; major remains 1.

Focused acceptance proves host/PID/time/ephemeral-port independence, per-domain
sensitivity, model/policy sensitivity, incomplete/unverified failure, canonical host
field rejection, retained-history API behavior and escaped UI output. The finite
known-good program remains unfinished: next collect/authenticate the required
manifests, then add durable publication and atomic cross-server lookup/hit provenance,
zero-provider-call reuse, audited revocation/invalidation, contradiction-linked review,
manual Re-triage bypass and SQLite/MySQL concurrency/role acceptance. Safe same-host
fairness and shared throttle/daily-spend/unthrottled controls follow under the existing
priority; notification and broader security/deployment/UI roadmaps remain planned.


## v1.25.0 — Controller-authenticated artifact provenance binding

Issue-first reconciliation read current main `d80965e0`, repository instructions,
this checkpoint and merged PR #84. The first 100-item open-issue and open-PR pages
were empty, so no actionable GitHub report or unfinished delivery competed with this
roadmap batch. The chat-reported database-migration refusal remains blocked on its
v1.23.1 mismatch category or separately reviewed schema inventory; no object is
ignored or guessed away and no closure is claimed.

This next dependency-ordered exact-known-good milestone persists the complete
controller-authenticated vendor package manifest with the existing signature proof
and target verification receipt. Storage and later binding strictly revalidate the
bounded manifest, Debian/RPM authentication fields and complete target receipt. A
matching follow-up can bind only its exact executable path and SHA-256 from a
same-server inspection whose entire authenticated regular-file scope matched. Target
package ownership, a name/hash alone, changed bytes, incomplete verification and
malformed or contradictory receipts remain misses.

The bound versioned artifact and provenance components include stable file/package/
proof digests. Authentication time, inspection identity and server/PID/proc identity
remain in the isolated observation section and do not alter cross-server canonical
components. The observation section is retained in assessment history but stripped
from provider-bound evidence. Existing AI model/effort, structured validation,
optional second-stage evidence and response authorization are unchanged.

Only `package_authentication_missing` is removed. Configuration, effective behavior,
follow-up and complete-coverage components remain explicitly incomplete, so current
assessments still produce no known-good fingerprint and every investigation still
contacts the provider. There is no cache table, publication/lookup/hit, implicit
approval, deterministic-protection suppression, schema/helper change, Docker
publication, Git tag or schedule change. APP_VERSION/README/changelog/UI/API
synchronize at v1.25.0; major remains 1.

Focused acceptance covers Debian/RPM persistence, tampered proof/manifest/receipt
refusal, exact and changed artifact matches, malformed follow-up failure, stable
cross-host canonical components with local observations, retained assessment history
and provider-input redaction. The finite program remains unfinished: collect complete
configuration/behavior/follow-up/coverage manifests, then implement durable safe-only
publication and atomic cross-server zero-call lookup, audited invalidation/revocation,
contradiction-linked review, explicit Re-triage bypass and SQLite/MySQL race/role
acceptance. Shared pacing/spend modes and remaining roadmap programs follow under the
existing priority.


## v1.26.0 — Exact authenticated follow-up evidence manifests

Issue-first reconciliation read current main `ec0c046f`, repository instructions,
this checkpoint and merged PR #85. The first 100-item open-issue and open-PR pages
were empty, so no actionable GitHub report or unfinished delivery competed with this
roadmap batch. The chat-reported database-migration refusal remains blocked on its
v1.23.1 mismatch category or separately reviewed schema inventory; no object is
ignored or guessed away and no closure is claimed.

This dependency-ordered exact-known-good milestone completes only the canonical
follow-up receipt component. After exact controller-authenticated artifact/provenance
binding, Mr Patchy validates the full supported target v2 receipt and hashes its sorted
requested checks, credentials/capabilities, executable and mapped/script artifact
identities/metadata, maps and cgroup digests, optional package/service/executable
results, declared gaps and collection-policy requirements. Unknown, missing,
oversized, malformed or internally inconsistent fields fail closed and retain the
original package-authentication gap.

The evidence digest excludes only process-instance identity and namespace inode
values. PID/start/boot/proc values remain in the isolated observation record, and the
presence of all required namespace kinds remains bound. Check ordering is normalized;
different check sets, credentials, artifact bytes/metadata, context hashes, optional
results or coverage declarations produce different manifests. Cross-server tests use
different process and namespace instances with otherwise exact receipts and produce
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

This does not complete the program. Exact durable defer/resume for every manual and
plan path, pricing-catalog update/expiry controls, provider-invoice reconciliation,
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
