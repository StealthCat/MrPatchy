# Build a custom Mr Patchy Compose deployment

From a Mr Patchy source checkout, install the host-side YAML dependency and open
the menu (Python 3.10 or newer):

```sh
python -m pip install -r requirements-configure.txt
python tools/configure_compose.py
```

Choose **Container layout** for apps + workers, apps only, or workers only. Each
selected role can have 1–16 containers. Other menu entries configure the image,
project/storage/database, network/ports, worker concurrency, worker IDs and memory.
**Preview YAML** shows the result. **Save YAML** previews it again and asks before
writing. Quit, Ctrl+C or end-of-input cancels without saving.

The default is a separate `mrpatchy-custom` project with one app, one worker and
Caddy, saved as `compose.custom.yaml`. The generator reads the maintained
`compose.yaml` and optional `compose.gcp.yaml` templates, retaining health checks,
privilege restrictions, read-only roots, persistent mounts and worker drain time.
It does not start containers, create a database, copy secrets, modify `.env`, or
change a running installation. It creates a new configuration; it does not import
arbitrary hand-edited Compose files.

## Fixed controller and worker files

Without the generator, the repository also provides two fixed role files next to
the complete single-machine `compose.yaml`:

| File | Services | Use |
|---|---|---|
| `compose.yaml` | app, worker, Caddy | Complete single-machine installation (unchanged) |
| `compose.controller.yaml` | app, Caddy | Controller with workers deployed separately |
| `compose.worker.yaml` | worker | Workers only, scaled on the controller's Docker host |

`compose.controller.yaml` extends the `app` and `caddy` services from `compose.yaml`.
It therefore keeps the same environment, health checks, capability limits, read-only
roots, memory/PID limits, networks and volume names. `compose.worker.yaml` repeats
the `compose.yaml` worker definition without the dependency on a local app, and a
test keeps the two in sync. It has no Caddy, TLS mount, published port, admin
password or fixed container name. `MRPATCHY_WORKER_ID` is always empty in this file,
so replicas never share one configured ID. Each replica instead claims a distinct
generated identity that persists in `worker-identities/` on the shared data volume,
so restarts, container recreation and `git pull` upgrades reconnect under the same
registrations rather than adding new ones (see "Worker identity persistence" below).

```sh
# Controller (project "mrpatchy", data volume "mrpatchy_app-data").
docker compose -p mrpatchy -f compose.controller.yaml up -d --build --wait

# Three workers on the same Docker host, as a separate project.
MRPATCHY_CONTROLLER_DATA_VOLUME=mrpatchy_app-data \
  docker compose -p mrpatchy-workers -f compose.worker.yaml up -d --build --scale worker=3
```

The worker file requires `MRPATCHY_CONTROLLER_DATA_VOLUME`. Compose refuses to render
without it and marks the volume external, so it never creates an empty replacement.
Start the controller first and build both projects from the same checkout. Workers
keep `MRPATCHY_REQUIRE_CONTROLLER_STATE=1`, so a worker that can't verify the
controller receipt, schema contract and matching encryption key admits no work.
The controller disables its embedded scheduler. Background jobs therefore wait
until at least one worker is running. Leave `MRPATCHY_EXPECTED_WORKER_IDS` empty
with these files: `compose.worker.yaml` never assigns a fixed worker ID, so any IDs
listed there (for example from an earlier single-machine `.env`) are reported as
missing workers.

To move an existing `compose.yaml` installation to the role files, keep the project
name so the controller reuses the `mrpatchy_app-data` volume, and remove the bundled
worker in the same step. Compose only warns about the old `worker` container; without
`--remove-orphans` it keeps running beside the new worker replicas, with any fixed
`MRPATCHY_WORKER_ID` from `.env`:

```sh
docker compose -p mrpatchy -f compose.controller.yaml up -d --build --wait --remove-orphans
```

To scale, rerun the worker command with a new `--scale` value. Before planned
maintenance, drain workers in the UI and verify their state; `docker compose stop`
also drains active jobs within the worker's long stop grace period.

The following remain unsupported in this increment:
- Workers on another machine: a Docker volume name doesn't share the encryption key, SSH identities, artifacts or locking state across hosts.
- Combining the role files with `compose.gcp.yaml`, which also defines a worker.
- Network-mounted SQLite.

Use `compose.yaml` (optionally with `compose.gcp.yaml`) for those installations.

## Use the generated YAML

Prepare `.env` from `.env.example`, following the normal installation instructions.
Set `ADMIN_PASSWORD` for deployments with apps. Set `DOMAIN` and `PUBLIC_URL` for
your real address. Secrets remain `${...}` references in generated YAML; values
from the current shell or `.env` are never read into the saved file.

```sh
docker compose --env-file .env -f compose.custom.yaml config --quiet
docker compose --env-file .env -f compose.custom.yaml up --build -d --wait
```

Use **only the generated file** with `-f`, not an overlay on `compose.yaml`; merging
the default file would reintroduce unwanted services. Continue using the same
project name and generated file for subsequent commands. A new project name
creates separate project volumes unless an existing data volume was selected.
Use a free control subnet and host ports when running multiple projects on one host.

Build paths are relative to the output file, even when saved outside the checkout.
Regenerate after moving either the output or source directory (cross-drive Windows
paths are absolute). Keep custom YAML and its backups out of source control if you
add private settings manually. Regenerate after template/security updates; existing
output files are snapshots. Existing output is never silently replaced: the menu
requires `REPLACE`, and a `.bak` is kept. If that backup already exists, choose a
new output name or manage the backup yourself. The two maintained templates cannot
be overwritten by this tool.

## Apps, workers and shared state

All generated app and worker containers mount the same `app-data` volume. SQLite
is suitable for this shared-local-volume layout. Selecting MySQL makes
`DATABASE_URL` required; supply the existing MySQL URL in `.env`. This option does
not provision MySQL or migrate data. An existing saved database profile in `/data`
continues to follow Mr Patchy's normal database-selection rules; this generator
does not replace it.

Apps always have their embedded scheduler disabled. An app-only deployment
therefore needs separately running workers using the same data and database for
background processing. Worker-only output has no app, Caddy, TLS mount, published
ports or dependency on a missing app. It requires the **existing controller data
volume name on the same Docker host** (for example `mrpatchy-custom_app-data`).
Compose marks it external and refuses to create an empty replacement. Start the
controller first and use the same Mr Patchy version and database selection. Existing
worker preflight still verifies the controller receipt, schema contract and private
encryption key. Supplying only a MySQL URL is not sufficient: workers also need
the matching key, SSH material, artifacts and local locking state.

An external Docker volume name does not share data across machines. Remote-host
workers, network-mounted SQLite and a full HA cluster are outside this generator's
validated deployment scope; see the outstanding cluster roadmap (#446–#454).

Worker IDs default to unique persistent generated identities even if `.env` contains
a single `MRPATCHY_WORKER_ID`, preventing accidentally duplicated IDs. An optional prefix
assigns `<prefix>-1`, `<prefix>-2`, etc., and configures the generated apps' expected
worker inventory. Prefixes must be unique across every stack using the same state.
When workers are in a separate stack, configure the controller's
`MRPATCHY_EXPECTED_WORKER_IDS` in its environment as appropriate. Drain workers
through the existing UI and verify their state before planned maintenance.

## Worker identity persistence

A worker or embedded scheduler without `MRPATCHY_WORKER_ID` generates its identity
once and stores it in a numbered slot under `DATA_DIR/worker-identities/<role>/`
(`/data` in Compose). On each start the process takes the lowest slot whose identity
is not held by another running process, using the same cross-process identity lock
that rejects duplicate IDs. As a result:

- Restarting, recreating or upgrading (`git pull` then `up --build`) a worker keeps its
  ID and reuses its existing registration with a new boot ID.
- Replicas sharing one data volume take distinct slots, so `--scale worker=3` keeps
  the same three IDs across recreation. Which replica container holds which ID may
  change; the set of identities stays stable.
- Workers and the embedded scheduler use separate slot pools.
- An explicit `MRPATCHY_WORKER_ID` always takes precedence and is not written to a slot.

Scaling down leaves the higher slots unused; their registrations remain as stale
history. When a process ends without releasing its lock (for example a MySQL lock
held until the server notices a lost connection), a replacement starts under the
next free slot until the old lock clears. If the data volume is not writable or every
slot is held, the process logs a warning and uses a boot-only identity. An unreadable
or invalid slot file is logged and skipped, not overwritten. Deleting
`worker-identities/` makes the next starts generate new identities.

## Multiple apps: topology, not an HA guarantee

Additional services are named `app-2`, `app-3`, etc. Initial Compose startup waits
for each preceding app's health check before starting the next, avoiding concurrent
initial schema/key/TLS bootstrap. Workers and Caddy wait for the last app. Apps have
dynamic addresses and share the `app` DNS alias used by the existing Caddy
`app:8000` upstream. Only Caddy publishes ports; its fixed control address remains
the sole trusted forwarding hop.

The shared DNS alias does **not** provide guaranteed even load balancing, backend
readiness filtering or failover. Compose startup dependencies do not serialize
automatic container restarts, implement migration fencing or coordinate concurrent
TLS changes. Use one controller owner for upgrades and TLS administration; stop
other app instances during those operations and bring them back in order. Shared
local storage, a single Caddy and unverified active/active behavior mean this is
not production HA or independent failure domains. Additional containers do not
complete the active/active, redundant-ingress or shared-storage roadmap.

## Build options and repeatable generation

`build` uses the normal Dockerfile; `gcp` applies the existing GCP build and
environment additions to every selected app/worker (set `GCP_PROJECT` and
`GCP_ZONE`, and prepare existing GCP credentials). `image` uses your supplied
compatible Mr Patchy image/tag or digest, with no build section. No image is
published by this tool. Keep apps and workers on the same source version.

The flags support repeatable generation without menu input:

```sh
# Two apps and four workers, with non-default ingress ports.
python tools/configure_compose.py --non-interactive --apps 2 --workers 4 --http-port 8080 --https-port 8443 --output compose.custom.yaml

# Controller-only stack; workers must be deployed separately.
python tools/configure_compose.py --non-interactive --apps 1 --workers 0 --output compose.controllers.yaml

# Worker-only stack on the controller's Docker host.
python tools/configure_compose.py --non-interactive --apps 0 --workers 3 --project mrpatchy-workers --external-data-volume mrpatchy-custom_app-data --output compose.workers.yaml

# Inspect an image-based deployment without writing a file.
python tools/configure_compose.py --print --runtime image --image registry.example/mrpatchy:tested --apps 1 --workers 2
```

`--help` lists all settings. `--overwrite` explicitly enables backup/replacement
in non-interactive mode. Generated port, subnet, concurrency and memory selections
take precedence over the corresponding legacy `.env` defaults; remaining template
environment references (including credentials, OIDC and drain timing) are retained.

## Validation

```sh
python -m pip install -r requirements-configure.txt pytest
python -m pytest --noconftest tests/test_compose_configurator.py -q
```

The tests cover layouts, state requirements, preserved service restrictions,
ordered startup, network/port consistency, GCP/image builds, input handling and
safe file replacement. With Docker Compose installed, nine tests additionally run
`config --format json` on mixed, app-only and worker-only layouts across all three
build options. These validation commands do not start containers or prove HA.
