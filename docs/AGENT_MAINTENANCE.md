# Agent health and controlled maintenance

Each administrator server workspace has an **Agent health** tab. Mr Patchy
compares a live receipt with both the enrolled baseline and the helpers shipped
with the controller. An older matching enrolled digest is **outdated**; unexpected
content, missing helpers, wrong file metadata or an inactive/disabled collector
are **drifted**. This is suspected tampering or configuration drift, not a malware
verdict. The receipt identifies the actual paths and service configuration.

The privileged bridge computes this receipt without importing the inspected
collector or helpers. Reads reject symlinks, writable/unowned parent directories,
non-regular or oversized files and observed file replacement. The expected
manifest is calculated centrally; target hashes never become the desired
baseline. Files, service state, unit fragment and drop-ins are checked afresh.
A compromised root/kernel or malicious bridge can lie; this is not remote
hardware attestation. Existing telemetry freshness/error alerts remain separate.

Checks run approximately every five minutes when the controller can acquire the
host lock, including when collector telemetry is unavailable. Jobs/recovery locks
remain authoritative. Offline/unsupported verification is shown as unavailable;
it never triggers blind installation. Hosts enrolled before this protocol need
one **Finish / verify installation** using trusted helpers, or a personalized
installer rerun from a trusted console if their bridge cannot be trusted.
The known enrolled release comparison remains visible even without live checks.

Automatic upgrades and repairs are separate, administrator-only per-server
options, off by default. Both must be enabled for a mixed outdated/drifted state.
There is at most one pending maintenance operation per host, no scheduling ahead
of other queued operations, at most two update attempts in a rolling 24 hours and
at least one hour between attempts. Settings are checked again when a queued
operation executes, together with the controller release and a fresh receipt.
Manual **Upgrade / repair agent** uses the same trust checks; it does not bypass
a changed bridge, sudo policy, key or unsafe installation path.

While the bridge and access policy still match the enrolled trusted baseline,
maintenance can replace collector/helper/unit files from the controller release,
restore their modes/ownership, reload systemd and enable/restart the collector.
A changed privileged bridge, authorized_keys, sudoers policy, unknown systemd
unit/drop-in, unsafe parent directory or changed optional observability override
blocks automated repair and requires console investigation. SSH host pins and
keys are never replaced automatically. Cloud permissions, OS Login, OS packages,
malware quarantine and general host remediation are outside this operation.

The job preserves the pre-update receipt before mutation and the verified final
receipt on success. The baseline advances only after the deployed manifest and
service state pass verification. Failed/uncertain updates retain the prior
baseline and error evidence; they do not claim successful recovery. If the bridge
was successfully replaced but confirmation was lost, trusted-console/manual
verification can be required before further automatic changes. Atomic individual
file replacement does not provide a multi-file filesystem transaction or rollback;
the durable baseline and retry limits make partial failures visible.

Policies and latest status use existing Settings storage and participate in the
offline SQLite/MySQL migration. Jobs and audits provide history; retention and
external immutable evidence storage remain separate unfinished work.

## Verification before polling and after installation

Due independent checks now run before normal telemetry polling on enrolled hosts.
A drifted, blocked or unavailable result pauses telemetry ingestion and blocks new
ordinary remote jobs. Agent checks, agent maintenance and the reviewed installation
workflow remain available; ongoing release recovery observation is not cancelled.
An agent-health alert is retained even while the last telemetry is old. A successful
Finish installation uses the independent bridge receipt and updates health and
baseline together. An unenrolled managed `observability.conf` blocks maintenance
even when it has not yet been loaded by systemd.

Checks are periodic, not continuous attestation. Existing helpers must be upgraded
through Finish installation to obtain the latest bridge behavior. Unknown or
unsupported status receipts fail closed; review Agent health and use a trusted
console if necessary. A compromised root/kernel and arbitrary dormant systemd
configuration outside the managed-file set remain outside this guarantee.
