#!/bin/sh
set -eu
umask 077
mkdir -p /data /tls
chown mrpatchy:mrpatchy /data /tls
if [ ! -f /tls/Caddyfile ]; then
  python - <<'PY'
import os,re
from pathlib import Path
name=os.environ.get('DOMAIN','localhost')
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*',name): raise SystemExit('Invalid DOMAIN')
Path('/tls/Caddyfile').write_text('{\n admin 0.0.0.0:2019\n}\n'+name+' {\n tls internal\n encode zstd gzip\n reverse_proxy app:8000\n}\n')
PY
  chown mrpatchy:mrpatchy /tls/Caddyfile
fi
exec gosu mrpatchy "$@"
