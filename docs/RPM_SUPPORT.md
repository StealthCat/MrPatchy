# Fedora and DNF/Yum targets

Mr Patchy supports RPM inventory, central DNF repository checks, exact-version patching, scheduled/high-priority patching, repository editing, signing-key import, integrity monitoring and recovery evidence. Fedora and modern Enterprise Linux systems using DNF (including DNF-backed `yum`) use this backend. Debian, Ubuntu and Raspberry Pi OS continue using APT.

## Target prerequisites

Install these **before** running the enrollment script, using your distribution's trusted repositories:

```bash
sudo dnf install python3 python3-dnf python3-rpm openssh-server sudo openssl
# On SELinux-enabled hosts:
sudo dnf install policycoreutils-python-utils
sudo systemctl enable --now sshd
```

DNF5 installations also need the `python3-dnf` DNF4 compatibility API. Legacy Yum 3/Python 2 systems are not supported. Offline enrollment never downloads prerequisites. The bootstrap sets persistent SELinux labels for `/opt/drpatch` and its SSH directory; it does not disable SELinux. Test enrollment with your host's enforcing policy before fleet rollout.

Rebuild the central Docker image after upgrading, then finish/verify enrollment to deploy the RPM helper. The helper is root-owned and included in the five-minute managed-file integrity checks.

## Inventory and repository checks

The collector reads the **local RPM database**, repository definitions, variables, module selections and version locks. It does not contact repositories. Central DNF uses a separate per-host cache and install root; it does not install target packages centrally. Native RPM epoch/version/release comparison handles epochs, prereleases and snapshot versions. All installed versions of multiversion packages remain in inventory; the package table uses the newest version for update comparison.

Configure `.repo` files under `/etc/yum.repos.d` in the Repositories menu. Standard `$releasever`, `$basearch`, `$arch` and captured DNF/Yum variables are expanded. Enabled/disabled sections, exclusions, includes, repository priority/cost and standard module selections are carried into discovery. Standard DNF4 versionlock lists and DNF5 versionlock TOML conservatively hold the entire named package. Changing a lock on the target requires a fresh inventory before approval.

Trust rules:

- Package GPG verification and TLS certificate verification are always required. Keys must be local `file:///etc/pki/rpm-gpg/...` references captured in inventory.
- Standard Fedora repositories can use HTTPS metadata without a detached `repomd.xml` signature. DNF verifies metadata checksums; HTTPS metalinks also provide metadata hashes. HTTP sources require `repo_gpgcheck=1`.
- Unsigned HTTPS mirror lists are restricted to HTTPS mirrors. A list with no HTTPS mirrors fails closed. Use an HTTPS base URL or signed metadata when necessary.
- Upload private repository CAs under **Repository access** for central checks. Target `sslcacert` remains a separate target configuration. Central proxy/mirror settings and scoped credentials remain central; credentials require direct base URLs.
- Verify signing-key fingerprints independently before upload. RPM keys enter the target's global RPM trust database and can validate packages from any repository. Missing package signing keys are **not** automatically accepted during installation.
- Unsupported active repository options, custom repository directories, nonempty transaction flags, remote signing-key URLs and client-certificate/subscription plugin requirements produce blockers. Configure a supported trusted mirror or adapter; target plugins and secrets are not copied into the central resolver.

Critical updateinfo severity maps to Critical; Important/High severity or security advisory type maps to High. Missing advisory metadata leaves normal priority, not an assertion that a package is safe. Manual priority overrides and existing high/critical scheduling rules still apply. RPM packages do not use the Debian OSV matcher.

## Installation and recovery

RPM previews review available exact-version candidates. Full dependency solving happens **on the target immediately before installation**, using its RPM database. It can add required dependencies; package removals, obsoleting replacements, downgrades and changes to version-locked packages are prohibited. All downloaded RPM signatures are verified before the transaction starts. RPM's native `%config`/`%config(noreplace)` behavior applies; inspect `.rpmnew`/`.rpmsave` files as part of configuration management.

Kernel packages may coexist. Automatic pruning of old install-only kernels is disabled to preserve the no-removal policy; manage disk space and reviewed old-kernel cleanup separately. Changes to core kernel/runtime packages request a reboot, but only the existing explicitly approved reboot policy can authorize it. This conservative detection is not an exhaustive restart assessment for every third-party package.

**Repair broken package state** rebuilds and verifies the RPM database. It does not run an unreviewed `distro-sync` or repair arbitrary dependency problems. Existing snapshot/recovery policies still require your tested provider adapter and original-state verification.

RPM **distribution release upgrades are not included**. The release-upgrade button and API are blocked for these hosts; the existing Ubuntu/Debian upgrade workflows remain available for their supported targets.

## Validation

CI runs native libRPM/libdnf metadata tests, including epoch ordering, advisories, exclusions, locks, certificate failures and corrupted indexes. Fedora and AlmaLinux disposable targets exercise real SSH/sudo enrollment, signed exact-version RPM installation, unsigned-RPM rejection, repository backups and key rotation. Their systemctl is a test stub: real systemd, enforcing SELinux, reboot, recovery adapters and production repositories require acceptance testing on your hosts.
