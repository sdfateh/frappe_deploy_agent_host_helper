# Frappe Host Helper

The Frappe Host Helper is a standalone, root-owned systemd service installed
once on each managed server. It is the only Deploy Agent component allowed to
invoke `docker compose exec`. The Agent API and Operation Worker receive only
its Unix socket; they do not receive the Docker socket, Docker CLI, Compose
paths, or database root passwords.

This repository also carries the hardened `compose.yml` and `.env.example` for
the per-server Deploy Agent API, Operation Worker, and Redis. One reviewed Git
checkout can therefore install the host service and the complete container
stack on a managed server. It does not contain either Frappe custom app.

## Requirements

- Linux with systemd
- Python 3.10 or newer with the `venv` module and `python3-pip`
- Docker Engine with the `docker compose` plugin
- A completed helper policy based on `host-helper.example.json`
- One root-owned mode-`0600` MariaDB password file for each configured Bench
- A completed Agent environment based on `.env.example` when starting Docker
- A pushed, scanned Agent image digest referenced by that environment

The policy must contain the real, existing Compose file, sites directory,
staging directory, database password file, domain suffixes, allowed operations,
and the UID used by the Agent containers. The default container UID is `10001`.
Do not install the example policy unchanged.

## Install or upgrade

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
validation. The environment must reference an immutable registry digest, not a
mutable image tag.

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
9. optionally validates and atomically installs the completed Agent environment;
10. enables and restarts `frappe-host-helper.service`; and
11. with `--start-agent`, pulls and starts Agent, Worker, and Redis and waits for
    their health checks.

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
└── compose.yml

/etc/frappe-agent/
├── agent.env
└── agent.env.example

/etc/systemd/system/frappe-host-helper.service
/run/frappe-agent/helper.sock
```

The runtime socket is owned by `root:frappe-agent` with mode `0660`. Add the
reported group GID to both Agent containers and mount only the socket:

```yaml
services:
  frappe-deploy-agent:
    volumes:
      - /run/frappe-agent/helper.sock:/run/frappe-agent/helper.sock
    group_add:
      - "${FRAPPE_HOST_HELPER_GID}"

  frappe-operation-worker:
    volumes:
      - /run/frappe-agent/helper.sock:/run/frappe-agent/helper.sock
    group_add:
      - "${FRAPPE_HOST_HELPER_GID}"
```

Do not mount `/var/run/docker.sock` or install the Docker CLI in either Agent
container.

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
sudo docker compose \
  --env-file /etc/frappe-agent/agent.env \
  --file /opt/frappe-deploy-agent/compose.yml \
  ps
```

Upgrade the Host Helper together with its matching Deploy Agent release. Keep
the earlier content-addressed release directory until rollback is no longer
required.
