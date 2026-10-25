# Distribution release upgrades

Mr Patchy can prepare and execute an adjacent release transition from a single **GO** decision. **No-go** records the declined plan and performs no upgrade. This is separate from ordinary package patching and its reboot policy: release approval explicitly includes package additions/removals, service interruption, reboot and one snapshot rollback.

## Supported paths

| Installed release | Planned destination | Executor |
|---|---|---|
| Ubuntu 22.04 LTS | Ubuntu 24.04 LTS | Official `do-release-upgrade`, noninteractive frontend |
| Ubuntu 24.04 LTS | Ubuntu 26.04 LTS | Official `do-release-upgrade`, only when Ubuntu offers that stable LTS path |
| Debian 11 | Debian 12 | Minimal APT upgrade, followed by the reviewed version-pinned package transaction |
| Debian 12 | Debian 13 | Minimal APT upgrade, followed by the reviewed version-pinned package transaction |
| Raspberry Pi OS / Raspbian | Next major image | Migration required; in-place execution is blocked |

Execution supports single-architecture amd64 and arm64 systemd hosts. It does not skip releases, enable development releases, or guess a derivative's upgrade procedure. Raspberry Pi OS is detected through OS identity, vendor packages and repository definitions, including 64-bit installations identifying as Debian.

Ubuntu's native upgrader can make additional package decisions through vendor migration hooks. The plan clearly labels the central APT package list as an **estimate** for Ubuntu; GO authorizes the named release transition. Debian re-simulates the complete transaction on the target, verifies that the minimal stage is a subset of approval, and pins exact versions in both stages. Each pinned stage is simulated before execution; additions/removals outside its approved transaction trigger recovery. Installed versions are verified afterward. Existing automatic/manual dependency markings are preserved, and newly introduced dependencies are marked automatic.

## Use the workflow

1. Upgrade the central deployment, then use **Servers → Manage → Finish / verify installation** on the target. This installs and verifies the release runner and adds it to integrity monitoring. Recent older bridges are updated automatically in two deployment passes when necessary.
2. Configure the OpenAI integration in Settings and prepare the recovery prerequisites below.
3. Open **Servers → Manage → Plan distribution upgrade → Prepare upgrade plan**. Planning collects current inventories/configuration evidence; package resolution and archive inspection happen centrally. It does not run a target APT upgrade.
4. Review the destination, package additions/removals, repository changes, configuration explanations/diffs and blockers. Plans are saved and may be reopened. **GO** is available only for a completed, unblocked plan.
5. Choose **GO · Execute approved plan** or **No-go · Keep current release**. There are no additional routine approval prompts during execution. Unexpected state stops the job or invokes the already-approved rollback rather than expanding the plan.

![Release upgrade review with illustrative fixture data](screenshots/release-upgrade.webp)

The target runner verifies inventory, repository keys, configuration hashes/ownership/modes and its own code against the approved plan. The bridge and root-owned recovery/validation hooks are bound by SHA-256, owner and mode too; replacing them requires a new plan. Update helpers and regenerate old, unexecuted plans before using this release. Do not redeploy helpers while an upgrade is running. Approval is bound to a SHA-256 digest and expires after 24 hours. A changed target or expired plan requires regeneration and another GO. Maintenance windows gate job start; they do not terminate an upgrade already in progress.

## What the plan contains

- Adjacent destination release and current target inventory fingerprint.
- Central native APT simulation using the target architecture and captured signing keys.
- Distribution source rewrites; third-party sources/backports are disabled rather than blindly redirected. Pinning, aliases such as `stable`, mixed vendor stanzas and unsupported mirrors require preparation.
- Package-owned conffiles for changed installed packages, current SHA-256/metadata, authenticated new package defaults and available packaged `NEWS` material.
- AI-proposed complete configuration content, reasons, blockers and unified diffs. The AI cannot choose commands, target paths or validators.
- The set of previously running services required to recover after reboot; transient login/SSH session units are excluded.
- Hashes and metadata of the bridge, rollback adapter and optional site-validation hook.
- Explicit authorization for reboot and one snapshot rollback, independent of routine patch settings.

Protected/executable configuration such as PAM, sudoers, systemd and cron is never rewritten by the AI. Unmodified vendor-owned protected files remain under distribution package management. Locally modified protected files block the plan. Deleted/moved vendor conffiles, unreadable/symlinked files, unsupported validators and uncertain AI migrations also block GO.

AI review covers **installed package-owned configuration files**, not every arbitrary application file on a server. Custom applications, virtual environments, database format migrations and data outside the recovery snapshot require a site-specific recovery/validation adapter. A syntactically valid configuration is not proof that an application works; test the complete workload in a clone before approving its production transition.

## AI privacy and bounds

Preparing a plan sends eligible configuration **contents**, new vendor defaults and package news to the configured OpenAI Responses API. This differs from process investigations, which do not send file contents. The preparation screen discloses this before planning starts. Do not use it for configurations your API provider may not process.

Potential password/token/private-key material, compound keys such as `db_password`/`client_secret`, and credentials embedded in URLs block automatic AI review. Detection is heuristic, not guaranteed secret discovery. No AI-generated shell command is executed. Proposed configuration can still change service behavior, so administrators must review the actual diff before GO. The exact approved content is frozen; the model is not asked to improvise repairs during execution.

Limits: 256 configuration files, 128 KiB per file, 2 MiB collected configuration evidence, 32 AI file reviews per plan, 3 MiB final plan, 512 MiB individual downloaded archive and 1 GiB expanded archive stream. Limits fail closed. Release planning has its own per-plan request cap; the process-investigation hourly cap does not cover these calls. API usage incurs the configured account's normal charges. Plans are encrypted in the database; plan/diff APIs are administrator-only.

## Recovery prerequisites

`/etc/mrpatchy/rollback` must implement the existing `probe`, `snapshot` and `rollback` JSON protocol and be root-owned, executable and not group/world-writable. For release upgrades, `probe release-upgrade` must additionally return:

```json
{"ready": true, "release_upgrade_ready": true}
```

`release_upgrade_ready` is an adapter's **explicit attestation**, not something Mr Patchy can infer from the presence of Btrfs. Return it only after testing recovery of the OS, bootloader/kernel files, package database, application data and every relevant mount/subvolume, including any external `/boot` or `/var`. Have a tested external backup and console/rescue access. Coordinate database quiescing inside the snapshot adapter. Snapshot IDs must identify the complete recovery point.

The bundled simple Snapper root adapter deliberately does **not** assert this flag. A root-only snapshot may omit `/boot`, database subvolumes or external volumes and is insufficient for an automatic release recovery claim. Extend/replace it for the actual deployment after a full recovery drill; do not merely add the flag to bypass a blocker.

For configuration types without a built-in syntax validator, install a root-owned executable `/etc/mrpatchy/release-validate`. Mr Patchy calls only this fixed interface:

```text
/etc/mrpatchy/release-validate validate /opt/drpatch/releases/JOB_ID/plan.json
```

Return zero only when the planned deployment is valid. When present during planning, the hook runs after configuration writes and again after reboot, including plans with no edited files or only built-in validators. Its hash/metadata must still match the approved plan. Rollback verifies the original inventory/configurations and running services separately; the forward-migration validator is not used to validate the older restored configuration. It should verify site-specific configurations/data migrations and reject unsupported changes. Built-in validators cover SSH server, nginx, Apache, Postfix, Dovecot and Chrony configuration paths. Application migration code is administrator-provided; the AI does not install arbitrary executable hooks.

Preflight requires healthy services, clean dpkg state, no held/broken packages, at least 8 GiB free on `/` and 512 MiB on `/boot`, no existing `policy-rc.d`, and an offered Ubuntu LTS path where applicable. Keep the installed release fully updated and reboot any pending kernel update before planning. Disk thresholds are floors, not a calculated guarantee for every workload.

## Execution and recovery states

The detached systemd service holds the target mutation lock while upgrading. It journals snapshot creation, package execution, configuration application and reboot intent. A temporary `policy-rc.d` returns 101 to defer maintainer-script service starts until configuration is ready; its exact owned content is removed and the directory synced **before** any reboot is scheduled or rollback hook is called. A replaced guard is preserved and quarantines the operation for console recovery. Package maintainer scripts may still stop services or perform other migrations.

After the upgrade, the runner writes the frozen configuration edits, invokes fixed validators, checks dpkg, records reboot intent and schedules reboot. The central worker verifies the release, reviewed configuration hashes, collector health and previously running services before marking the plan complete. Transient reboot/health errors are retried for 15 minutes; the overall observation budget is four hours from execution start. These deadlines and structured recovery receipts are persisted separately from presentation logs, so a worker restart cannot reset the budget or lose a receipt to log truncation.

A package/configuration failure invokes one snapshot rollback. Persistent post-reboot failure also requests that rollback. The central receipt survives a root filesystem rollback and can verify the restored boot even when the target journal has reverted. Verification requires the original inventory fingerprint (OS, package database, repositories and keys), approved configuration hashes/metadata, clean dpkg state, healthy collector and original running services. A changed boot ID and generic health alone are insufficient. Normal and rollback reboots use distinct timers; an outstanding normal reboot timer is stopped before an explicitly requested rollback. A verified rollback leaves the upgrade job failed and the plan `rolled_back`.

After a central worker restart, workers resume **observing** running release jobs under the host lock. They never replay an accepted package transaction. Lost SSH replies are followed by receipt observation, never blind resubmission. Missing receipts after submission, unverified rollback or a target that never returns become `recovery_required` and generate a persistent recovery alert; subsequent host mutations remain quarantined. If power is lost mid-upgrade, a transient systemd service does not replay on boot: inspect the journal and recover through the trusted console.

Use Activity's reconciliation only after inspecting target package/service/boot state, snapshot status, `mrpatchy-release-*` services/timers and `/usr/sbin/policy-rc.d`. A process/power failure may leave the temporary service-start guard in place; verify its exact Mr Patchy contents before removing it. Do not release the queue while an upgrade or delayed reboot is still active.

Protected diagnostics are under `/opt/drpatch/releases/JOB_ID/`: `plan.json`, `state.json`, and `runner.log`. Logs may contain package output and remain root-readable on the target. Job progress is available in the web UI without streaming raw package logs to non-administrators.

## Validation and references

Automated tests exercise source transformation, Pi identification, immutable approval, expiry/roles, detached submission, package-default extraction, upgrade/rollback sequencing, crash/restart receipts and deadlines, original-system rollback checks, helper binding, both pinned Debian stages and auto/manual dependency markings, guard cleanup, credential filtering, lock-resource cleanup and delayed browser GO responses. CI runs the normal MySQL, SSH enrollment and deployment suites as well. These tests do not perform a real operating-system release upgrade or boot a real rollback snapshot. Validate each supported path and adapter in a disposable clone matching the production workload before use.

Primary references:

- [Ubuntu release upgrade procedure](https://documentation.ubuntu.com/server/how-to/software/upgrade-your-release/)
- [Ubuntu noninteractive upgrader implementation](https://git.launchpad.net/ubuntu-release-upgrader/tree/DistUpgrade/DistUpgradeViewNonInteractive.py)
- [Debian 13 upgrade procedure](https://www.debian.org/releases/trixie/release-notes/upgrading.html)
- [Raspberry Pi OS major-version guidance](https://www.raspberrypi.com/documentation/computers/os.html)
