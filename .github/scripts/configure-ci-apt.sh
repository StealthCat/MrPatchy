#!/usr/bin/env bash
# Runner-only setup: retain signed repositories while avoiding a stalled mirror.
set -euo pipefail
apt_root=${MRPATCHY_CI_APT_ROOT:-/etc/apt}
for source in "$apt_root/apt-mirrors.txt" "$apt_root/sources.list" "$apt_root/sources.list.d/ubuntu.sources"; do
  if [ -f "$source" ]; then
    # Hosted runners list regional Azure and EC2 archive mirrors; both have stalled
    # dependency setup, so route them to the primary archive. Signed-By is untouched.
    sudo sed -E -i \
      -e 's|https?://azure\.archive\.ubuntu\.com/ubuntu|https://archive.ubuntu.com/ubuntu|g' \
      -e 's|https?://[a-z0-9-]+\.ec2\.archive\.ubuntu\.com/ubuntu|https://archive.ubuntu.com/ubuntu|g' \
      "$source"
  fi
done
sudo mkdir -p "$apt_root/apt.conf.d"
printf '%s\n' 'Acquire::Retries "2";' 'Acquire::http::Timeout "30";' 'Acquire::https::Timeout "30";' |
  sudo tee "$apt_root/apt.conf.d/99-mrpatchy-ci-network" >/dev/null
