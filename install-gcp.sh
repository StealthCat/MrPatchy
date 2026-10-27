#!/usr/bin/env bash
# Set up the controller runtime. No project IAM/firewall/VM mutations.
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
usage() {
  cat <<'USAGE'
Usage: ./install-gcp.sh --project PROJECT --zone ZONE --instance INSTANCE
       [--public-url https://patchy.example.com:8443] [--credential-dir DIRECTORY]
Requires Docker with Compose v2, Python 3, and access to the Docker daemon.
Run from the checked-out Mr Patchy repository on the controller host.
An attached GCE service account is used by default. For WIF, provide a directory
containing credentials.json and its referenced token files (mounted at /gcp).
Existing .env is preserved; --public-url is required for a fresh installation.
The script builds the gcloud image, configures both runtimes, checks instance-read
access, and starts Mr Patchy. IAM, APIs and SSH firewall setup are prerequisites.
USAGE
}
project='';zone='';instance='';url='';credentials=''
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0;;
    --project|--zone|--instance|--public-url|--credential-dir)
      (($#>=2)) || { usage >&2; exit 2; }
      case "$1" in
        --project) project=$2;; --zone) zone=$2;; --instance) instance=$2;;
        --public-url) url=$2;; --credential-dir) credentials=$2;;
      esac; shift 2;;
    *) usage >&2; exit 2;;
  esac
done
[[ "$project" =~ ^[a-z][a-z0-9-]{4,61}[a-z0-9]$ && "$zone" =~ ^[a-z][a-z0-9-]{1,61}[a-z0-9]$ && "$instance" =~ ^[a-z][a-z0-9-]{0,61}[a-z0-9]$ ]] || { usage >&2; exit 2; }
command -v docker >/dev/null; command -v python3 >/dev/null
docker compose version >/dev/null
docker info >/dev/null
python3 - "$project" "$zone" "$url" "$credentials" <<'PY'
import json,os,re,secrets,sys
from pathlib import Path
from urllib.parse import urlsplit
project,zone,url,credentials=sys.argv[1:]
for name in ('.env','.env.gcp','compose.gcp-auth.json'):
    if Path(name).is_symlink():raise SystemExit('Refusing symlink: '+name)
# Validate before writing any deployment settings.
if not Path('.env').exists():
    parsed=urlsplit(url)
    if not re.fullmatch(r'https://[A-Za-z0-9.\-:\[\]]+/?',url) or parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('','/') or parsed.query or parsed.fragment or any(c.isspace() for c in url):
        raise SystemExit('Provide --public-url with an HTTPS origin for a fresh install')
    port=parsed.port or 443
    if not 1<=port<=65535:raise SystemExit('Invalid public port')
if credentials:
    directory=Path(credentials).resolve(strict=True)
    if directory.is_relative_to(Path.cwd()):raise SystemExit('Keep credential files outside the repository and Docker build context')
    config=json.loads((directory/'credentials.json').read_text())
    if config.get('type')!='external_account' or 'executable' in config.get('credential_source',{}):
        raise SystemExit('Use a trusted WIF external_account config without executable credential sources')
    override={'services':{service:{'volumes':[{'type':'bind','source':str(directory).replace('$','$$'),'target':'/gcp','read_only':True}]} for service in ('app','worker')}}
else:
    override=None
    if Path('compose.gcp-auth.json').exists():
        raise SystemExit('Existing WIF mount retained. Re-run with --credential-dir or review/remove compose.gcp-auth.json to switch identity.')
if not Path('.env').exists():
    with open('.env','x') as f:
        f.write('ADMIN_PASSWORD='+secrets.token_hex(24)+'\nDOMAIN='+parsed.hostname+'\nPUBLIC_URL='+url+'\nHTTPS_PORT='+str(port)+'\n')
    os.chmod('.env',0o600)
Path('.env.gcp').write_text('GCP_PROJECT='+project+'\nGCP_ZONE='+zone+'\n')
os.chmod('.env.gcp',0o600)
if override:
    Path('compose.gcp-auth.json').write_text(json.dumps(override));os.chmod('compose.gcp-auth.json',0o600)
PY
docker build -t mrpatchy:base .
bash ./gcp-compose.sh build app worker
if [[ -n "$credentials" ]]; then
  bash ./gcp-compose.sh run --rm --no-deps app gcloud auth login --cred-file=/gcp/credentials.json --quiet
fi
# Token output is discarded, never printed or stored in a deployment file.
for service in app worker; do
  bash ./gcp-compose.sh run --rm --no-deps "$service" gcloud version
  bash ./gcp-compose.sh run --rm --no-deps "$service" gcloud auth print-access-token >/dev/null
  bash ./gcp-compose.sh run --rm --no-deps "$service" gcloud compute instances describe "$instance" --project="$project" --zone="$zone" --format='value(status)'
done
bash ./gcp-compose.sh up -d --wait
printf '%s\n' 'Mr Patchy GCP runtime is ready. The initial admin password is in .env.' \
  'Enroll the target using its personalized installer, pin its verified host fingerprint, then select Google Cloud IAP in Server / Connection.' \
  'Use ./gcp-compose.sh for future compose operations. Instance-read success does not prove IAP tunnel or guest SSH access.'
