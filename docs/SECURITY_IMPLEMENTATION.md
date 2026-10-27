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
