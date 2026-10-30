#!/bin/sh
set -eu
umask 077
role=${MRPATCHY_RUNTIME_ROLE:-controller}
case "$role" in
  worker)
    mkdir -p /data
    chown mrpatchy:mrpatchy /data
    ;;
  controller)
    mkdir -p /data /tls
    chown mrpatchy:mrpatchy /data /tls
    gosu mrpatchy python -m app.tls
    ;;
  *) echo "Unsupported MRPATCHY_RUNTIME_ROLE (controller or worker required)" >&2; exit 1 ;;
esac
exec gosu mrpatchy "$@"
