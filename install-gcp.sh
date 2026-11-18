#!/usr/bin/env bash
# Set up the controller runtime. No project IAM/firewall/VM mutations.
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
usage() {
  cat <<'USAGE'
Usage: ./install-gcp.sh --project PROJECT --zone ZONE --instance INSTANCE
       [--public-url https://patchy.example.com:8443] [--credential-dir DIRECTORY]
       [--mode complete|controller|worker] [--workers N]
Requires Docker with Compose v2, Python 3, and access to the Docker daemon.
Run from the checked-out Mr Patchy repository on the controller host.
An attached GCE service account is used by default. For WIF, provide a directory
containing credentials.json and its referenced token files (mounted at /gcp).
Existing .env is preserved; --public-url is required for a fresh installation.
The script builds the gcloud image, configures both runtimes, checks instance-read
access, and starts Mr Patchy. IAM, APIs and SSH firewall setup are prerequisites.
--mode complete (default) runs the app, Caddy and the bundled worker (compose.yaml).
--mode controller runs only the app and Caddy (compose.controller.yaml); background
jobs wait until workers are started separately with compose.worker.yaml.
--mode worker joins N worker replicas (--workers, 1-16, default 1) on this Docker host
to the controller installed here with --mode controller, as a separate Compose project.
It reuses the controller's project, zone, identity, data volume and database, and never
changes the controller. Use ./gcp-compose.sh --workers for later worker operations.
An installation is never switched between modes; see docs/COMPOSE_CONFIGURATION.md.
USAGE
}
project='';zone='';instance='';url='';credentials='';mode=complete;workers=''
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0;;
    --project|--zone|--instance|--public-url|--credential-dir|--mode|--workers)
      (($#>=2)) || { usage >&2; exit 2; }
      case "$1" in
        --project) project=$2;; --zone) zone=$2;; --instance) instance=$2;;
        --public-url) url=$2;; --credential-dir) credentials=$2;; --mode) mode=$2;;
        --workers) workers=$2;;
      esac; shift 2;;
    *) usage >&2; exit 2;;
  esac
done
[[ "$mode" == complete || "$mode" == controller || "$mode" == worker ]] || { usage >&2; exit 2; }
if [[ "$mode" != worker && -n "$workers" ]]; then
  echo '--workers applies only to --mode worker' >&2; exit 2
fi
if [[ "$mode" == worker ]]; then
  workers=${workers:-1}
  [[ "$workers" =~ ^([1-9]|1[0-6])$ ]] || { echo '--workers must be 1-16' >&2; exit 2; }
  # The worker joins the controller's recorded identity and URL; it never sets its own.
  [[ -z "$url" ]] || { echo '--public-url belongs to the controller; --mode worker does not accept it' >&2; exit 2; }
  [[ -z "$credentials" ]] || { echo '--mode worker reuses the controller identity; rerun --mode controller with --credential-dir to change it' >&2; exit 2; }
fi
[[ "$project" =~ ^[a-z][a-z0-9-]{4,61}[a-z0-9]$ && "$zone" =~ ^[a-z][a-z0-9-]{1,61}[a-z0-9]$ && "$instance" =~ ^[a-z][a-z0-9-]{0,61}[a-z0-9]$ ]] || { usage >&2; exit 2; }
command -v docker >/dev/null; command -v python3 >/dev/null
docker compose version >/dev/null
docker info >/dev/null
if [[ "$mode" == worker ]]; then
  # Validate the recorded controller and the shared volume/database before writing .env.worker.
  python3 - "$project" "$zone" <<'PY'
import json,os,re,subprocess,sys
from pathlib import Path
project,zone=sys.argv[1:]
for name in ('.env','.env.gcp','.env.worker','compose.controller.gcp-auth.json','compose.worker.gcp-auth.json'):
    if Path(name).is_symlink():raise SystemExit('Refusing symlink: '+name)
def values(name):
    found={}
    if Path(name).exists():
        for line in Path(name).read_text().splitlines():
            key,sep,value=line.partition('=')
            if sep:found[key.strip()]=value.strip()
    return found
recorded=values('.env.gcp')
existing=recorded.get('MRPATCHY_GCP_MODE') or ('complete' if Path('.env.gcp').exists() else None)
if existing is None:
    raise SystemExit('No controller installation found here; run ./install-gcp.sh --mode controller first')
if existing!='controller':
    raise SystemExit('This installation uses --mode '+existing+', which already runs its own worker; --mode worker joins only a --mode controller installation')
if recorded.get('GCP_PROJECT')!=project or recorded.get('GCP_ZONE')!=zone:
    raise SystemExit('--project and --zone must match the controller recorded in .env.gcp')
if Path('compose.controller.gcp-auth.json').exists() and not Path('compose.worker.gcp-auth.json').exists():
    raise SystemExit('The controller uses WIF but compose.worker.gcp-auth.json is missing; rerun ./install-gcp.sh --mode controller --credential-dir DIRECTORY')
def render(*args):
    # Rendered output can contain DATABASE_URL credentials: never print it or Compose errors.
    result=subprocess.run(['bash',*args,'config','--format','json'],capture_output=True,text=True)
    if result.returncode:return None
    try:return json.loads(result.stdout)
    except ValueError:return None
def shared(config,service):
    try:
        volume=config['volumes']['app-data']['name'];database=config['services'][service]['environment']['DATABASE_URL']
    except (KeyError,TypeError):return None
    return (volume,database) if isinstance(volume,str) and isinstance(database,str) else None
controller=render('./gcp-compose.sh')
state=shared(controller,'app') if controller else None
name=controller.get('name') if controller else None
if not state or not isinstance(name,str):
    raise SystemExit('Could not render the controller configuration with ./gcp-compose.sh config')
volume,database=state
if subprocess.run(['docker','volume','inspect',volume],capture_output=True).returncode:
    raise SystemExit('Controller data volume '+volume+' does not exist on this Docker host; start the controller first')
name_pattern=r'[a-z0-9][a-z0-9_-]{0,62}'
worker=values('.env.worker')
created=not Path('.env.worker').exists()
if created:
    # Rendered Compose output escapes "$" as "$$"; .env.worker stores the literal value.
    database=database.replace('$$','$')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+',volume) or any(c in database for c in "'\r\n"):
        raise SystemExit('The controller data volume or DATABASE_URL cannot be written safely to .env.worker; prepare it from .env.worker.example')
    project_name=name+'-workers'
    if not re.fullmatch(name_pattern,project_name):raise SystemExit('Cannot derive a valid worker project name from '+name)
    lines=[line for line in Path('.env.worker.example').read_text().splitlines()
           if not line.startswith(('MRPATCHY_CONTROLLER_DATA_VOLUME=','COMPOSE_PROJECT_NAME='))]
    # Single quotes keep Compose from interpolating "$" in credentials.
    lines+=['','# Written by install-gcp.sh --mode worker from the controller configuration.',
            'COMPOSE_PROJECT_NAME='+project_name,'MRPATCHY_CONTROLLER_DATA_VOLUME='+volume,"DATABASE_URL='"+database+"'"]
    with open('.env.worker','x') as f:f.write('\n'.join(lines)+'\n')
else:
    project_name=worker.get('COMPOSE_PROJECT_NAME','').strip("'\"")
    if not project_name:
        raise SystemExit('.env.worker has no COMPOSE_PROJECT_NAME; add one (for example '+name+'-workers) so the worker project never replaces the controller')
    if not re.fullmatch(name_pattern,project_name):raise SystemExit('.env.worker sets an invalid COMPOSE_PROJECT_NAME')
os.chmod('.env.worker',0o600)
if project_name==name:
    raise SystemExit('.env.worker COMPOSE_PROJECT_NAME must differ from the controller project '+name)
joined=render('./gcp-compose.sh','--workers')
if not joined or shared(joined,'worker')!=state or joined.get('name')!=project_name:
    if created:Path('.env.worker').unlink()
    raise SystemExit('.env.worker does not use the controller data volume and DATABASE_URL; review it against the controller configuration')
PY
  docker build -t mrpatchy:base .
  bash ./gcp-compose.sh --workers build worker
  # One-off worker containers take a dynamic management address, never the app's control IP.
  # The controller's /data/gcloud sign-in is shared; token output is discarded, never printed.
  bash ./gcp-compose.sh --workers run --rm --no-deps worker gcloud version
  bash ./gcp-compose.sh --workers run --rm --no-deps worker gcloud auth print-access-token >/dev/null
  bash ./gcp-compose.sh --workers run --rm --no-deps worker gcloud compute instances describe "$instance" --project="$project" --zone="$zone" --format='value(status)'
  bash ./gcp-compose.sh --workers up -d --wait --scale worker="$workers"
  printf '%s\n' "Mr Patchy GCP workers are running: $workers replica(s) joined to the controller on this Docker host." \
    'Check them in Activity -> Workers. Use ./gcp-compose.sh --workers for future worker operations; ./gcp-compose.sh still operates the controller.'
  exit 0
fi
python3 - "$project" "$zone" "$url" "$credentials" "$mode" <<'PY'
import json,os,re,secrets,sys
from pathlib import Path
from urllib.parse import urlsplit
project,zone,url,credentials,mode=sys.argv[1:]
# Role-specific WIF overlays for compose.controller.yaml and compose.worker.yaml; the combined
# compose.gcp-auth.json names both services and would add a partial service to a role file.
ROLE_AUTH={'compose.controller.gcp-auth.json':'app','compose.worker.gcp-auth.json':'worker'}
# Each mode's Compose files; the WIF overlay is appended when one is in use.
MODES={'complete':('compose.yaml:compose.gcp.yaml','compose.gcp-auth.json'),
       'controller':('compose.controller.yaml:compose.controller.gcp.yaml','compose.controller.gcp-auth.json')}
base_files,auth_file=MODES[mode]
for name in ('.env','.env.gcp','compose.gcp-auth.json',*ROLE_AUTH):
    if Path(name).is_symlink():raise SystemExit('Refusing symlink: '+name)
def recorded_mode(values):
    for key,(files,_) in MODES.items():
        if values==files or values.startswith(files+':'):return key
    return None
# Never switch an existing installation between modes: the bundled worker would be
# orphaned (complete -> controller) or a second worker set added (controller -> complete).
recorded={}
for name in ('.env','.env.gcp'):
    if Path(name).exists():
        for line in Path(name).read_text().splitlines():
            key,sep,value=line.partition('=')
            if sep and key.strip() in ('COMPOSE_FILE','MRPATCHY_GCP_MODE'):recorded[key.strip()]=value.strip()
# Releases before --mode wrote .env.gcp without a mode, and only installed the complete stack.
existing=recorded.get('MRPATCHY_GCP_MODE') or ('complete' if Path('.env.gcp').exists() else None)
if not existing and 'COMPOSE_FILE' in recorded:
    existing=recorded_mode(recorded['COMPOSE_FILE'])
    # Complete mode keeps its earlier behavior of replacing a custom COMPOSE_FILE.
    if existing is None and mode=='controller':
        raise SystemExit('Existing .env sets an unrecognized COMPOSE_FILE; review it before using --mode controller')
if existing and existing!=mode:
    raise SystemExit('This installation uses --mode '+existing+'; refusing to switch to --mode '+mode+'. Follow the migration steps in docs/COMPOSE_CONFIGURATION.md instead.')
# Validate before writing any deployment settings.
if not Path('.env').exists():
    parsed=urlsplit(url)
    if not re.fullmatch(r'https://[A-Za-z0-9.\-:\[\]]+/?',url) or parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('','/') or parsed.query or parsed.fragment or any(c.isspace() for c in url):
        raise SystemExit('Provide --public-url with an HTTPS origin for a fresh install')
    try:port=parsed.port
    except ValueError:raise SystemExit('Invalid public port')
    if parsed.netloc.endswith(':'):raise SystemExit('Invalid public port')
    if port is None:port=443
    if not 1<=port<=65535:raise SystemExit('Invalid public port')
elif url:
    print('Warning: existing .env kept; --public-url ignored.',file=sys.stderr)
if credentials:
    directory=Path(credentials).resolve(strict=True)
    if directory.is_relative_to(Path.cwd()):raise SystemExit('Keep credential files outside the repository and Docker build context')
    config=json.loads((directory/'credentials.json').read_text())
    if config.get('type')!='external_account' or 'executable' in config.get('credential_source',{}):
        raise SystemExit('Use a trusted WIF external_account config without executable credential sources')
    override={'services':{service:{'volumes':[{'type':'bind','source':str(directory).replace('$','$$'),'target':'/gcp','read_only':True}]} for service in ('app','worker')}}
else:
    override=None
    if Path(auth_file).exists():
        raise SystemExit('Existing WIF mount retained. Re-run with --credential-dir or review/remove '+auth_file+' to switch identity.')
if not Path('.env').exists():
    with open('.env','x') as f:
        f.write('ADMIN_PASSWORD='+secrets.token_hex(24)+'\nDOMAIN='+parsed.hostname+'\nPUBLIC_URL='+url+'\nHTTPS_PORT='+str(port)+'\n')
    os.chmod('.env',0o600)
# Plain `docker compose` reads .env from this directory: persist the GCP overrides there
# so upgrades and migrations that skip ./gcp-compose.sh cannot silently drop the gcloud runtime.
compose_files=base_files+(':'+auth_file if override or Path(auth_file).exists() else '')
wanted={'COMPOSE_FILE':compose_files,'GCP_PROJECT':project,'GCP_ZONE':zone}
lines=Path('.env').read_text().splitlines()
seen=set()
for i,line in enumerate(lines):
    key=line.split('=',1)[0].strip()
    if key in wanted and '=' in line:
        lines[i]=key+'='+wanted[key];seen.add(key)
lines+=[k+'='+v for k,v in wanted.items() if k not in seen]
Path('.env').write_text('\n'.join(lines)+'\n')
os.chmod('.env',0o600)
Path('.env.gcp').write_text('GCP_PROJECT='+project+'\nGCP_ZONE='+zone+'\nMRPATCHY_GCP_MODE='+mode+'\n')
os.chmod('.env.gcp',0o600)
if override:
    Path('compose.gcp-auth.json').write_text(json.dumps(override));os.chmod('compose.gcp-auth.json',0o600)
    for name,service in ROLE_AUTH.items():
        Path(name).write_text(json.dumps({'services':{service:override['services'][service]}}));os.chmod(name,0o600)
PY
docker build -t mrpatchy:base .
if [[ "$mode" == controller ]]; then
  # Controller only: no worker service exists. A one-off app container would take the
  # running app's fixed control IP, so sign in and check inside the started app instead.
  # Token output is discarded, never printed or stored in a deployment file.
  bash ./gcp-compose.sh build app
  bash ./gcp-compose.sh up -d --wait
  as_app=(exec -T --user mrpatchy -e HOME=/home/mrpatchy app)
  if [[ -n "$credentials" ]]; then
    bash ./gcp-compose.sh "${as_app[@]}" gcloud auth login --cred-file=/gcp/credentials.json --quiet
  fi
  bash ./gcp-compose.sh "${as_app[@]}" gcloud version
  bash ./gcp-compose.sh "${as_app[@]}" gcloud auth print-access-token >/dev/null
  bash ./gcp-compose.sh "${as_app[@]}" gcloud compute instances describe "$instance" --project="$project" --zone="$zone" --format='value(status)'
  printf '%s\n' 'Mr Patchy GCP controller is ready. The initial admin password is in .env.' \
    'No worker runs in this mode: background jobs wait until you start workers, for example with ./install-gcp.sh --mode worker (see docs/COMPOSE_CONFIGURATION.md).' \
    'Use ./gcp-compose.sh for future controller compose operations. Instance-read success does not prove IAP tunnel or guest SSH access.'
  exit 0
fi
bash ./gcp-compose.sh build app worker
if [[ -n "$credentials" ]]; then
  bash ./gcp-compose.sh run --rm --no-deps worker gcloud auth login --cred-file=/gcp/credentials.json --quiet
fi
# Use the worker's dynamic management-network address for temporary containers.
# A one-off app container would inherit the running app's fixed control IP.
# Both services share the image, runtime UID and /data/gcloud credentials.
# Token output is discarded, never printed or stored in a deployment file.
bash ./gcp-compose.sh run --rm --no-deps worker gcloud version
bash ./gcp-compose.sh run --rm --no-deps worker gcloud auth print-access-token >/dev/null
bash ./gcp-compose.sh run --rm --no-deps worker gcloud compute instances describe "$instance" --project="$project" --zone="$zone" --format='value(status)'
bash ./gcp-compose.sh up -d --wait
# Exec bypasses the entrypoint's gosu: select the service user and home explicitly.
# Check each real runtime after startup without allocating another fixed IP.
for service in app worker; do
  bash ./gcp-compose.sh exec -T --user mrpatchy -e HOME=/home/mrpatchy "$service" gcloud version
  bash ./gcp-compose.sh exec -T --user mrpatchy -e HOME=/home/mrpatchy "$service" gcloud auth print-access-token >/dev/null
  bash ./gcp-compose.sh exec -T --user mrpatchy -e HOME=/home/mrpatchy "$service" gcloud compute instances describe "$instance" --project="$project" --zone="$zone" --format='value(status)'
done
printf '%s\n' 'Mr Patchy GCP runtime is ready. The initial admin password is in .env.' \
  'Enroll the target using its personalized installer, pin its verified host fingerprint, then select Google Cloud IAP in Server / Connection.' \
  'Use ./gcp-compose.sh for future compose operations. Instance-read success does not prove IAP tunnel or guest SSH access.'
