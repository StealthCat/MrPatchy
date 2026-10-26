#!/usr/bin/env bash
# Disposable CI image ONLY: this replaces the image's repository definitions.
set -euo pipefail
mkdir -p /tmp/fixture-gnupg /tmp/fixture-build/{BUILD,RPMS,SOURCES,SPECS,SRPMS} /tmp/fixture-repo /etc/pki/rpm-gpg
chmod 700 /tmp/fixture-gnupg
export GNUPGHOME=/tmp/fixture-gnupg
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key 'Patchy disposable fixture <fixture@example.invalid>' rsa2048 sign 0
signing_id=$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" { print $10; exit }')
gpg --armor --export "$signing_id" > /etc/pki/rpm-gpg/fixture.asc
rpm --import /etc/pki/rpm-gpg/fixture.asc
for version in 1 2 3; do
  cat > /tmp/fixture-build/SPECS/patchy-fixture.spec <<SPEC
Name: patchy-fixture
Version: $version.0
Release: 1
Epoch: 1
Summary: Disposable Mr Patchy integration fixture
License: MIT
BuildArch: noarch
%description
Disposable CI test package.
%install
mkdir -p %{buildroot}/usr/share/patchy-fixture
printf '%s\\n' '$version' > %{buildroot}/usr/share/patchy-fixture/version
%files
/usr/share/patchy-fixture/version
SPEC
  rpmbuild --define '_topdir /tmp/fixture-build' -bb /tmp/fixture-build/SPECS/patchy-fixture.spec
  package=/tmp/fixture-build/RPMS/noarch/patchy-fixture-$version.0-1.noarch.rpm
  if [ "$version" != 3 ]; then
    rpmsign --define "_gpg_name $signing_id" --define "_openpgp_sign_id $signing_id" --define '_gpg_path /tmp/fixture-gnupg' --define '__gpg /usr/bin/gpg' --addsign "$package"
  fi
  if [ "$version" = 1 ]; then rpm -i "$package"; fi
  if [ "$version" = 2 ]; then cp "$package" /tmp/fixture-repo/; fi
done
createrepo_c /tmp/fixture-repo
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout /tmp/fixture.key -out /etc/pki/fixture-ca.pem -subj /CN=localhost -addext subjectAltName=IP:127.0.0.1 -addext basicConstraints=critical,CA:TRUE
mkdir /tmp/original-repos
mv /etc/yum.repos.d/*.repo /tmp/original-repos/
cat > /etc/yum.repos.d/fixture.repo <<'REPO'
[fixture]
name=Disposable fixture
baseurl=https://127.0.0.1:8443
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/fixture.asc
sslcacert=/etc/pki/fixture-ca.pem
REPO
cat > /tmp/serve-fixture.py <<'PY'
import functools,http.server,ssl
server=http.server.ThreadingHTTPServer(('0.0.0.0',8443),functools.partial(http.server.SimpleHTTPRequestHandler,directory='/tmp/fixture-repo'))
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain('/etc/pki/fixture-ca.pem','/tmp/fixture.key')
server.socket=context.wrap_socket(server.socket,server_side=True);server.serve_forever()
PY
