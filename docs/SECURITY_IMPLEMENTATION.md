# Security implementation checkpoint

This branch is an incomplete first stage of the proposed endpoint protection expansion. It must not be represented as complete malware protection or automated incident response.

Implemented: administrator-only, on-demand and interval-scheduled read-only ClamAV scan jobs; a server Security tab with scan policy, coverage, paginated scan history, incidents and response plans. Scan receipts are stored in dedicated tables and are never overwritten by a later scan. Repeated path/hash detections on the same host update an incident while retaining each scan receipt. Historical reports from the first draft remain readable as a legacy latest report; new scans use durable history.

Administrators can request an AI response plan for an incident. Generation uses the saved AI settings, caps requests at ten per hour across the fleet, validates allowed advisory action types and evidence IDs, and records the model run and usage through existing AI activity logging. Evidence changes during generation reject the result. Scanner failures do not require a working AI provider.

Plans are advisory manual tasks. Approval never executes shell commands, quarantines files, isolates hosts, or marks an incident remediated. A plan must match the current incident evidence and be reviewed within 24 hours. Approved reviews expire after one hour. Repeat detections supersede prior approvals. The UI identifies expired approvals. No user-facing claim of automated remediation is made.

New tables are included in the offline SQLite/MySQL migration metadata. Security records currently have no automatic deletion policy; size storage accordingly. Engine installation and external evidence storage remain unfinished. Signature age assessment is described below. Automatic proposal generation is available as described below.

Prerequisites: install ClamAV and current signatures on the managed target and redeploy the Mr Patchy collector/bridge using the existing reviewed installation workflow. No scanner installation or signature updates are performed automatically. Engine version is captured with the scan report.

Limits: 16 explicit root directories, 2,000 examined files, 32 MiB per file, four-minute overall work budget and 30-second per-file scanner timeout. Symlinks are not followed during traversal. Virtual filesystem directories and the reserved quarantine directory are excluded. Exclusions and failures are reported as incomplete coverage. Scanning uses an opened descriptor and checks metadata before accepting the result. A compromised root/kernel remains outside this trust boundary. Reports never claim the server is clean.

Still required before the requested system is complete:

- Configurable retention and external immutable evidence storage; broader behavioral and threat-intelligence correlation.
- Event-triggered scans, YARA integration, authenticated rule distribution, trusted vendor package verification and approved custom baselines.
- Runtime detection integration, persistence inventory, fleet correlation and agent tamper monitoring.
- Follow-up AI evidence collection tools; approved typed execution of response plans. Current AI plans use scanner evidence only.
- Execution-time identity revalidation, race-resistant quarantine, restore workflows, external host isolation and recovery-path testing.
- Typed remediation executors, trusted restoration, credential rotation tasks, rebuild escalation and post-action verification.
- Coverage dashboards, incident/plan/quarantine views, policy settings, offline delivery and independently retained audit evidence.
- Browser coverage and real scanner/OS integration tests, performance tests and failure-injection response drills.

No destructive security response is enabled in this checkpoint.


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
