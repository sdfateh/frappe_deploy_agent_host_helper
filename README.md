# Frappe Host Helper

The Frappe Host Helper is a standalone, root-owned systemd service installed
once on each managed server. It is the only long-running Deploy Agent component
allowed to invoke `docker compose exec`. The unified Agent container receives
only its Unix socket; it does not receive the Docker socket, Docker CLI,
Compose paths, or database root passwords.

This repository also carries the hardened one-container `compose.yml`, the
enrollment/bootstrap client, discovery utility, diagnostics, and the root-owned
Controller-approved updater. One reviewed Git checkout installs the complete
managed-server side. It does not contain either Frappe custom app.

Generated site Administrator passwords are held in a local encrypted SQLite
vault only until the Controller acknowledges their dedicated signed handoff.
They are never placed in the normal operation result or logs.

## Requirements

- Linux with systemd
- Python 3.10 or newer with the `venv` module and `python3-pip`
- Docker Engine with the `docker compose` plugin
- A Server Agent record and one-time install token from the Controller
- One MariaDB root password for each configured Bench
- A pushed, scanned Agent image digest configured on the Controller

The Agent environment contains no Cloudflare or AWS credentials. Those secrets
are configured only on the central `frappe_controller` runtime.

The policy must contain the real, existing Compose file, sites directory,
staging directory, database password file, domain suffixes, allowed operations,
and the UID used by the Agent containers. The default container UID is `10001`.
Do not install the example policy unchanged.

`sites_path` is validated on the host and must be a real, existing directory
there. `container_sites_path` is the absolute path where that same bench's
sites directory appears *inside* the backend container (for example
`/home/frappe/frappe-bench/sites`); it is only used when invoking commands
through `docker compose exec` and is not checked against the host filesystem.
The two may differ, for instance when the sites data lives in a Docker-managed
named volume rather than a host bind mount: point `sites_path` at the volume's
real host location and `container_sites_path` at its in-container mount point.

## Install or upgrade

### Simple setup (recommended)

On the Controller, open the **Server Agent** record and click **Generate Install
Token**. Then run its displayed command from this repository on the managed
server:

```console
sudo ./setup.sh \
  --controller https://controller-agent.example.com \
  --agent-id agent-01
```

Paste the one-time token when prompted, select a Bench only if more than one is
found, and enter the MariaDB root password. Setup creates an Ed25519 signing
key, enrolls its public key over HTTPS, discovers Docker Compose, generates all policies, installs
the Host Helper, and starts the unified Agent. You do not edit `.env`,
`host-helper.production.json`, or `benches.yaml`.

For automation, pass a root-owned mode-`0600` token file:

```console
sudo ./setup.sh --controller https://controller-agent.example.com \
  --agent-id agent-01 --enrollment-token-file /root/enrollment-token
```

Check the installation with `sudo ./setup.sh doctor` or
`sudo ./setup.sh doctor --json`.

### Manual setup

Clone or extract a reviewed release, prepare the policy and password files, and
run the installer with sudo:

```console
sudo ./install.sh --config /root/host-helper.production.json
```

That command installs and starts the Host Helper and installs the Docker Compose
assets without starting containers. To validate, install, and start the full
per-server stack in the same operation:

```console
sudo ./install.sh \
  --config /root/host-helper.production.json \
  --agent-env /root/frappe-agent.production.env \
  --start-agent
```

The completed Agent environment may keep `FRAPPE_HOST_HELPER_GID=auto`; the
installer replaces it with the server's actual socket-group GID before Compose
validation. It also assigns that `frappe-agent` group to
`TRAEFIK_DYNAMIC_CONFIG_PATH` and applies mode `2775`; the Agent can then
manage Traefik route files without manual permission changes. The environment
must reference an immutable registry digest, not a mutable image tag.

If the Agent containers use a different UID:

```console
sudo ./install.sh \
  --config /root/host-helper.production.json \
  --agent-uid 20001
```

The installer is idempotent. It:

1. verifies root, systemd, Docker Compose, Python, and the release contents;
2. creates the `frappe-agent` socket group when it is absent;
3. installs a content-addressed release under
   `/opt/frappe-host-helper/releases/`;
4. creates an isolated virtual environment with the pinned dependency;
5. installs and validates the root-owned policy;
6. checks every configured database password file is root-owned and mode
   `0600`;
7. atomically points `/opt/frappe-host-helper/current` at the release;
8. installs the hardened Compose file and protected environment template;
9. optionally validates and atomically installs the completed Agent environment, then
   grants its `frappe-agent` group access to the configured Traefik dynamic
   directory;
10. enables and restarts `frappe-host-helper.service`; and
11. with `--start-agent`, pulls and starts the unified Agent and waits for its
    health check; and
12. enables the digest-pinned upgrade timer.

When replacing a different policy, the installer preserves the previous policy
as `/etc/frappe-deploy-agent/host-helper.json.previous`.

## Installed layout

```text
/opt/frappe-host-helper/
├── current -> releases/<version>-<content-hash>
└── releases/
    └── <version>-<content-hash>/
        ├── .venv/
        └── host_helper/

/etc/frappe-deploy-agent/
├── host-helper.json
└── secrets/

/opt/frappe-deploy-agent/
├── compose.yml
└── upgrade_agent.py

/etc/frappe-agent/
├── agent.env
├── agent.env.example
├── benches.yaml
└── signing/
    └── agent-signing-key.pem

/etc/systemd/system/frappe-host-helper.service
/etc/systemd/system/frappe-agent-updater.{service,timer}
/run/frappe-agent/helper.sock
```

The runtime socket is owned by `root:frappe-agent` with mode `0660`. Add the
reported group GID to the Agent container and mount only the socket:

```yaml
services:
  frappe-deploy-agent:
    volumes:
      - /run/frappe-agent/helper.sock:/run/frappe-agent/helper.sock
    group_add:
      - "${FRAPPE_HOST_HELPER_GID}"
```

Do not mount `/var/run/docker.sock` or install the Docker CLI in the Agent
container. Only the root-owned, fixed updater service uses Docker to replace an
approved immutable image digest.

## Multiple Benches

One helper instance can manage multiple local Benches. Each Bench has a
separate policy entry with its exact paths, service, site suffixes, data-update
grants, and concurrency limit. Overlapping Compose files, host paths, or domain
suffixes are rejected.

Protocol-v2 requests contain an exact local `bench_id` and one typed operation.
The helper constructs every command from its root-owned policy. Requests cannot
supply argv, shell, Python source, SQL, Compose paths, service names, secret
references, or database passwords.

Linux peer credentials are checked with `SO_PEERCRED`; a socket client whose UID
is absent from `allowed_uids` is rejected. Disconnecting a client cancels its
active subprocess with `SIGTERM` followed by `SIGKILL`. Output is bounded and
sensitive command values are redacted from logs.

## Operations

```console
sudo systemctl status frappe-host-helper
sudo journalctl -u frappe-host-helper
sudo systemctl restart frappe-host-helper
sudo systemctl status frappe-agent-updater.timer
sudo docker compose \
  --env-file /etc/frappe-agent/agent.env \
  --file /opt/frappe-deploy-agent/compose.yml \
  ps
```

Upgrade the Host Helper together with its matching Deploy Agent release. Keep
the earlier content-addressed release directory until rollback is no longer
required.
