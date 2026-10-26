# Security implementation checkpoint

This branch is an incomplete first stage of the proposed endpoint protection expansion. It must not be represented as complete malware protection or automated incident response.

Implemented: administrator-only, on-demand, read-only ClamAV scan jobs; a server Security tab; scan counts, findings and coverage gaps. The latest report is stored centrally. Existing job history preserves execution status, but immutable incident/evidence history is not yet implemented.

Prerequisites: install ClamAV and current signatures on the managed target and redeploy the Mr Patchy collector/bridge using the existing reviewed installation workflow. No scanner installation or signature updates are performed automatically. Engine version is captured with the scan report.

Limits: 16 explicit root directories, 2,000 examined files, 32 MiB per file, four-minute overall work budget and 30-second per-file scanner timeout. Symlinks are not followed during traversal. Virtual filesystem directories and the reserved quarantine directory are excluded. Exclusions and failures are reported as incomplete coverage. Scanning uses an opened descriptor and checks metadata before accepting the result. A compromised root/kernel remains outside this trust boundary. Reports never claim the server is clean.

Still required before the requested system is complete:

- Persistent scans, findings, evidence references, incidents and plan revisions with retention and migration coverage.
- Scheduled and event-triggered scans, YARA integration, authenticated rule distribution, trusted vendor package verification and approved custom baselines.
- Runtime detection integration, persistence inventory, fleet correlation and agent tamper monitoring.
- Bounded AI evidence tools, source-linked findings, structured remediation plans and per-incident API costs.
- Expiring approvals bound to artifact identity, race-resistant quarantine, restore workflows, external host isolation and recovery-path testing.
- Typed remediation executors, trusted restoration, credential rotation tasks, rebuild escalation and post-action verification.
- Coverage dashboards, incident/plan/quarantine views, policy settings, offline delivery and independently retained audit evidence.
- Browser coverage and real scanner/OS integration tests, performance tests and failure-injection response drills.

No destructive security response is enabled in this checkpoint.
