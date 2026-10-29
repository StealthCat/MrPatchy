# Security implementation checkpoint

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

- General malware protection: known-malware detection, AI-enabled triage of previously unknown malware, and automatic file quarantine plus malicious-process termination; see the planned milestone below.
- CVE exposure-window exploitation monitoring with automatic quarantine or termination of detected malicious artifacts/processes; see the planned milestone below.
- Configurable evidence retention, external immutable storage and independent audit retention. Bounded per-server scanner record exports now complement file-response exports; automatic deletion and external storage are not implemented.
- Broader behavioral/threat-intelligence correlation and cross-source AI investigation evidence. Read-only exact file identity pivots now connect scanner, execution and integrity receipts; AI evidence binding across these sources remains unfinished.
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

Administrators can disable, enable or delete a server from Servers or its overview.
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
