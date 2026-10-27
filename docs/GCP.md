# Google Cloud VM connections

Mr Patchy polls over a new SSH connection for each operation. The collector does not maintain an outbound connection to the controller. The controller must reach the VM's SSH service, directly or through Google IAP. Changing the HTTPS/enrollment port does not change that requirement.

## Choosing a route

Under **Servers → server → Connection**, administrators can save and test either:

- **Direct SSH**: a private address reachable over the VPC/VPN, or a reserved static external address with a firewall restricted to the controller. Ephemeral external IPs can change after stop/start. Updating this address preserves the enrolled key, pinned fingerprint and server history.
- **Google Cloud IAP**: project ID, zone, instance name and SSH port. The stored direct address is ignored for transport. The Google Cloud CLI resolves the instance and opens an authenticated stdio tunnel to its primary internal interface. No external address or inbound controller-to-VM route is needed.

Both routes retain the same per-server key, forced command, restricted sudo and pinned SSH host fingerprint. IAP does not provision guest keys or grant shell/root access. No metadata, IAM, firewall or VM lifecycle mutations are made by this integration. A replaced VM with a different SSH host identity fails verification; verify it through a trusted console before changing the pin.

## IAP runtime setup

The default Mr Patchy image does not include Google Cloud CLI. Install a supported CLI distribution in a derived image, or mount a Linux CLI installation into the container. It must be executable by the `mrpatchy` runtime user (UID 10001), including its Python dependencies. For example, after installing the CLI under `/opt/google-cloud-sdk` on the Docker host, merge this into your Compose override for both the web application and worker services:

```yaml
services:
  app:
    volumes:
      - /opt/google-cloud-sdk:/opt/google-cloud-sdk:ro
    environment:
      PATH: /opt/google-cloud-sdk/bin:/usr/local/bin:/usr/bin:/bin
      CLOUDSDK_PYTHON: /usr/local/bin/python
      CLOUDSDK_CONFIG: /data/gcloud
  worker:
    volumes:
      - /opt/google-cloud-sdk:/opt/google-cloud-sdk:ro
    environment:
      PATH: /opt/google-cloud-sdk/bin:/usr/local/bin:/usr/bin:/bin
      CLOUDSDK_PYTHON: /usr/local/bin/python
      CLOUDSDK_CONFIG: /data/gcloud
```

The CLI configuration directory must be writable by UID 10001. Configure a dedicated runtime identity using your organization's attached service account or workload identity federation process. Run CLI setup/verification as UID 10001, using the same environment as the application; a developer's host CLI login is not the container's identity. This integration uses **gcloud credentials**, not an uploaded API key or an implicit assumption that Application Default Credentials have configured gcloud. Do not put credential JSON into the UI, repository, or connection settings.

Enable the Compute Engine and IAP APIs. Grant the runtime identity `iap.tunnelInstances.accessViaIAP` (usually `roles/iap.tunnelResourceAccessor`, scoped to the intended instances) and `compute.instances.get` / `compute.instances.list`. Use IAM conditions to restrict destination ports where appropriate. Do not grant Owner, Editor, OS Admin Login, or metadata-write permissions just to use this transport.

Allow inbound TCP from the documented IAP range `35.235.240.0/20` to the VM's configured SSH port, scoped to the intended VMs. Allow outbound HTTPS to Google APIs and IAP from the runtime. The VM must be running and listening on that port. IAP does not start stopped/preempted VMs.

Verify `gcloud version`, `gcloud auth list`, and an instance read under the runtime identity before selecting IAP:

```sh
gcloud compute instances describe INSTANCE --project=PROJECT --zone=ZONE \
  --format='value(status,networkInterfaces[0].networkIP)'
```

Verify this in both app and worker containers; otherwise manual connection tests may pass while background polling fails.

Then save the route and use **Test saved connection**. This performs a read-only bridge snapshot with a 30-second total operation budget and verifies the pinned host identity. Normal polling remains responsible for ingesting telemetry and checking collector freshness/integrity. No cloud credentials or subprocess stderr are returned to the browser.

## Guest authentication and disconnects

Google documents that local users can use authorized_keys with OS Login, provided their usernames and UIDs differ from OS Login users. Mr Patchy uses its own local `drpatch` account. Do not enroll that username through metadata or OS Login. Google guest-agent management and OS Login policy transitions can affect keys; verify `/opt/drpatch/.ssh/authorized_keys`, the local account, effective sshd configuration and authentication logs from a trusted console. Re-run the server's personalized installer when repairing its managed files. Do not disable OS Login project-wide as a workaround.

The SSH transport sends keepalives every 20 seconds to reduce idle-path drops during long scans or patches. Connections still have finite operation deadlines. A failed operation is never transparently replayed: inspect the job/recovery state before retrying a patch. Cloud maintenance, preemption, tunnel expiry, or network loss can still interrupt an operation. IAP permission/network failures and guest SSH authentication failures are different problems.

The controller currently has no automatic Compute inventory synchronization, lifecycle scheduling, or OS Login key provisioning. A read-only Compute API inventory integration could add explicit stopped/preempted states and discovery later; it is not required for the IAP route. OS Config patch orchestration is not used because it would introduce a second patch executor alongside Mr Patchy's existing approval/recovery workflow.

## Validation and limits

Automated tests exercise direct and subprocess-tunneled SSH, large responses, early exit-status delivery, EOF/timeouts, child cleanup, missing CLI, route validation, stale edits, permissions and browser forms. They do not authenticate against a live Google project. Validate one non-production VM with your actual IAM, guest image and runtime credentials before enabling fleet-wide IAP.

References:

- https://docs.cloud.google.com/iap/docs/using-tcp-forwarding
- https://docs.cloud.google.com/compute/docs/oslogin
- https://docs.cloud.google.com/compute/docs/connect/add-ssh-keys
- https://docs.cloud.google.com/compute/docs/ip-addresses/configure-static-external-ip-address
- https://docs.cloud.google.com/sdk/docs/install

## Installer for a GCP-ready controller

From a trusted checkout on a Linux Docker host with Compose v2 and Python 3:

```sh
./install-gcp.sh --project YOUR_PROJECT --zone us-central1-a --instance TEST_VM \
  --public-url https://patchy.example.com:8443
```

The installer preserves an existing `.env`, or creates one with a random initial
administrator password and mode 0600. It builds the regular image and a derived
image using Google's signed APT repository for Google Cloud CLI, configures both
app and worker, checks token acquisition without printing the token, verifies
instance-read access from each runtime, then starts the stack. Docker itself,
Google APIs, IAM grants and the IAP SSH firewall rule must already be configured
as described above. No cloud IAM, metadata, firewall or VM mutations are made.
A successful instance read does not prove IAP tunnel or guest SSH authentication;
finish enrollment and use **Test saved connection** on a non-production VM.

A clean installation on GCE can use its attached service account. Outside GCE,
pass `--credential-dir /absolute/path/to/trusted-wif-directory` outside the
repository and Docker build context. This directory
must contain `credentials.json` with a trusted Workload Identity Federation
`external_account` configuration. Referenced token files must be available under
`/gcp` inside the containers. The directory is mounted read-only in both services;
UID 10001 must be able to traverse/read it. Service-account private-key files and
executable credential sources are rejected by this installer. Review federation
endpoints and rotate external token material using your identity provider's
workflow. Never commit credentials. Existing authenticated gcloud configuration
lives in the persistent application data volume; changing identity requires an
explicit review of that configuration, not just deleting a mount definition.

Use `./gcp-compose.sh logs`, `./gcp-compose.sh up -d`, and
`./gcp-compose.sh down` for this installation. For application upgrades, pull the
reviewed release and rerun `install-gcp.sh` with the same project/zone/instance and
identity arguments so the base and Google CLI images are rebuilt. Using plain
`docker compose` omits the GCP override. `.env.gcp` and generated credential mount
definitions are ignored by Git. The installer does not grant the Mr Patchy guest
account OS Login or replace pinned SSH identities.

CI builds the derived image, verifies Google CLI runs as UID 10001 and validates
the combined Compose configuration. Installer tests use a fake Docker command to
verify argument handling, identity configuration and token redaction. Live GCP
IAM, federation and IAP access still require validation in your project.
