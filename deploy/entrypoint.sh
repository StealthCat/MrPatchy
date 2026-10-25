#!/bin/sh
set -eu
umask 077
mkdir -p /data /tls
chown mrpatchy:mrpatchy /data /tls
gosu mrpatchy python -m app.tls
exec gosu mrpatchy "$@"
