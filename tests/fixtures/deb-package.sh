#!/usr/bin/env bash
# Disposable CI image only: install a package with known file checksums.
set -euo pipefail
root=/tmp/patchy-deb-fixture
mkdir -p "$root/DEBIAN" "$root/usr/share/patchy-fixture"
printf '1\n' > "$root/usr/share/patchy-fixture/version"
cat > "$root/DEBIAN/control" <<'CONTROL'
Package: patchy-fixture
Version: 1.0-1
Architecture: all
Maintainer: Test <fixture@example.invalid>
Description: Disposable Mr Patchy integrity fixture
CONTROL
(cd "$root" && md5sum usr/share/patchy-fixture/version > DEBIAN/md5sums)
dpkg-deb --build "$root" /tmp/patchy-fixture.deb
dpkg -i /tmp/patchy-fixture.deb
