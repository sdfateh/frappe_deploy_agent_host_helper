#!/usr/bin/env bash
set -Eeuo pipefail

readonly INSTALL_ROOT="/opt/frappe-host-helper"
readonly CONFIG_ROOT="/etc/frappe-deploy-agent"
readonly CONFIG_TARGET="${CONFIG_ROOT}/host-helper.json"
readonly SERVICE_TARGET="/etc/systemd/system/frappe-host-helper.service"
readonly SOCKET_GROUP="frappe-agent"
readonly SOCKET_PATH="/run/frappe-agent/helper.sock"
readonly AGENT_STACK_ROOT="/opt/frappe-deploy-agent"
readonly AGENT_CONFIG_ROOT="/etc/frappe-agent"
readonly AGENT_COMPOSE_TARGET="${AGENT_STACK_ROOT}/compose.yml"
readonly AGENT_ENV_TARGET="${AGENT_CONFIG_ROOT}/agent.env"
readonly AGENT_ENV_EXAMPLE_TARGET="${AGENT_CONFIG_ROOT}/agent.env.example"

config_source=""
agent_env_source=""
agent_uid="10001"
start_agent="false"
release_staging=""
config_temporary=""
current_temporary=""
agent_env_temporary=""

usage() {
    cat <<'EOF'
Usage: sudo ./install.sh --config /absolute/path/host-helper.json [options]

Installs or upgrades the Host Helper and the hardened Agent Docker Compose stack.
The helper always starts. The Agent containers start only with --start-agent.

Options:
  --config PATH      Completed host-helper JSON policy (required).
  --agent-env PATH   Completed Agent environment file to validate and install.
  --agent-uid UID    Container UID allowed to use the socket (default: 10001).
  --start-agent      Pull and start Agent, Worker, and Redis after installation.
  -h, --help         Show this help.
EOF
}

fail() {
    printf 'frappe-host-helper install: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [[ "${release_staging}" == "${INSTALL_ROOT}"/.install.* && -d "${release_staging}" ]]; then
        rm -rf -- "${release_staging}"
    fi
    if [[ "${config_temporary}" == "${CONFIG_TARGET}".new.* ]]; then
        rm -f -- "${config_temporary}"
    fi
    if [[ "${current_temporary}" == "${INSTALL_ROOT}"/.current.* ]]; then
        rm -f -- "${current_temporary}"
    fi
    if [[ "${agent_env_temporary}" == "${AGENT_ENV_TARGET}".new.* ]]; then
        rm -f -- "${agent_env_temporary}"
    fi
}
trap cleanup EXIT

while (($#)); do
    case "$1" in
        --config)
            (($# >= 2)) || fail "--config requires a path"
            config_source="$2"
            shift 2
            ;;
        --agent-uid)
            (($# >= 2)) || fail "--agent-uid requires a value"
            agent_uid="$2"
            shift 2
            ;;
        --agent-env)
            (($# >= 2)) || fail "--agent-env requires a path"
            agent_env_source="$2"
            shift 2
            ;;
        --start-agent)
            start_agent="true"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

[[ ${EUID} -eq 0 ]] || fail "run this installer as root with sudo"
[[ -n "${config_source}" ]] || fail "--config is required; do not install the example unchanged"
[[ "${start_agent}" != "true" || -n "${agent_env_source}" ]] || fail "--start-agent requires --agent-env"
[[ "${agent_uid}" =~ ^[0-9]+$ ]] || fail "--agent-uid must be a non-negative integer"
((agent_uid <= 4294967295)) || fail "--agent-uid is outside the supported range"

for command in python3 install systemctl docker groupadd getent readlink sha256sum cmp cut tr mktemp mv ln rm sleep; do
    command -v "${command}" >/dev/null 2>&1 || fail "required command is missing: ${command}"
done
[[ -d /run/systemd/system ]] || fail "systemd is not running on this server"
systemctl is-active --quiet docker.service || fail "docker.service must be active"
docker compose version >/dev/null 2>&1 || fail "the Docker Compose plugin is required"
python3 -m pip --version >/dev/null 2>&1 || fail "python3-pip is required"

source_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -f "${config_source}" && ! -L "${config_source}" ]] || fail "configuration must be a regular file, not a symlink"
config_source="$(readlink -f -- "${config_source}")"
if [[ -n "${agent_env_source}" ]]; then
    [[ -f "${agent_env_source}" && ! -L "${agent_env_source}" ]] || fail "Agent environment must be a regular file, not a symlink"
    agent_env_source="$(readlink -f -- "${agent_env_source}")"
fi

required_sources=(
    __init__.py
    data_update_contract.py
    executor.py
    observability.py
    protocol.py
    server.py
    requirements.txt
    VERSION
    .env.example
    compose.yml
    frappe-host-helper.service
)
for source_name in "${required_sources[@]}"; do
    [[ -f "${source_root}/${source_name}" ]] || fail "release is incomplete: ${source_name} is missing"
done

python3 - <<'PY' || fail "Python 3.10 or newer is required"
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY

if ! getent group "${SOCKET_GROUP}" >/dev/null; then
    groupadd --system "${SOCKET_GROUP}"
fi
socket_gid="$(getent group "${SOCKET_GROUP}" | cut -d: -f3)"

install -d -o root -g root -m 0755 "${INSTALL_ROOT}" "${INSTALL_ROOT}/releases"
install -d -o root -g root -m 0755 "${CONFIG_ROOT}"
install -d -o root -g root -m 0700 "${CONFIG_ROOT}/secrets"
install -d -o root -g root -m 0755 "${AGENT_STACK_ROOT}" "${AGENT_CONFIG_ROOT}"

[[ ! -L "${AGENT_COMPOSE_TARGET}" ]] || fail "refusing to replace a symlinked Agent Compose target"
[[ ! -L "${AGENT_ENV_EXAMPLE_TARGET}" ]] || fail "refusing to replace a symlinked Agent environment example"
install -o root -g root -m 0644 "${source_root}/compose.yml" "${AGENT_COMPOSE_TARGET}"
install -o root -g root -m 0600 "${source_root}/.env.example" "${AGENT_ENV_EXAMPLE_TARGET}"

if [[ -n "${agent_env_source}" ]]; then
    [[ ! -L "${AGENT_ENV_TARGET}" ]] || fail "refusing to replace a symlinked Agent environment target"
    agent_env_temporary="${AGENT_ENV_TARGET}.new.$$"
    install -o root -g root -m 0600 "${agent_env_source}" "${agent_env_temporary}"
    python3 - "${agent_env_temporary}" "${socket_gid}" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
expected_gid = sys.argv[2]
lines = path.read_text(encoding="utf-8").splitlines()
indexes = [
    index for index, line in enumerate(lines)
    if line.startswith("FRAPPE_HOST_HELPER_GID=")
]
if len(indexes) != 1:
    raise SystemExit("Agent environment must define FRAPPE_HOST_HELPER_GID exactly once")
index = indexes[0]
configured_gid = lines[index].split("=", 1)[1]
if configured_gid == "auto":
    lines[index] = f"FRAPPE_HOST_HELPER_GID={expected_gid}"
elif configured_gid != expected_gid:
    raise SystemExit(
        f"FRAPPE_HOST_HELPER_GID must be auto or the installed group GID {expected_gid}"
    )
for forbidden in ("DB_ROOT_PASSWORD", "FRAPPE_COMPOSE_FILE"):
    if any(line.startswith(f"{forbidden}=") for line in lines):
        raise SystemExit(f"legacy secret {forbidden} is forbidden in the hardened Agent environment")
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
    docker compose \
        --env-file "${agent_env_temporary}" \
        --file "${source_root}/compose.yml" \
        config --quiet
    if [[ -e "${AGENT_ENV_TARGET}" ]] && ! cmp -s "${AGENT_ENV_TARGET}" "${agent_env_temporary}"; then
        install -o root -g root -m 0600 "${AGENT_ENV_TARGET}" "${AGENT_ENV_TARGET}.previous"
    fi
    mv -fT -- "${agent_env_temporary}" "${AGENT_ENV_TARGET}"
fi

version="$(tr -d '[:space:]' < "${source_root}/VERSION")"
[[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] || fail "VERSION is invalid"
content_hash="$({ cd -- "${source_root}"; sha256sum "${required_sources[@]}"; } | sha256sum | cut -c1-12)"
release_name="${version}-${content_hash}"
release_path="${INSTALL_ROOT}/releases/${release_name}"

if [[ ! -d "${release_path}" ]]; then
    release_staging="$(mktemp -d "${INSTALL_ROOT}/.install.XXXXXXXX")"
    install -d -o root -g root -m 0755 "${release_staging}/host_helper"
    for source_name in __init__.py data_update_contract.py executor.py observability.py protocol.py server.py; do
        install -o root -g root -m 0644 \
            "${source_root}/${source_name}" "${release_staging}/host_helper/${source_name}"
    done
    install -o root -g root -m 0644 "${source_root}/requirements.txt" "${release_staging}/requirements.txt"
    python3 -m venv --without-pip "${release_staging}/.venv"
    site_packages="$("${release_staging}/.venv/bin/python" -c 'import site; print(site.getsitepackages()[0])')"
    PIP_ROOT_USER_ACTION=ignore python3 -m pip install \
        --disable-pip-version-check --no-cache-dir \
        --target "${site_packages}" \
        --requirement "${release_staging}/requirements.txt"
    (
        cd -- "${release_staging}"
        .venv/bin/python -c \
            'from host_helper.protocol import HelperConfig; from host_helper.server import main'
    )
    mv -- "${release_staging}" "${release_path}"
    release_staging=""
fi

config_temporary="${CONFIG_TARGET}.new.$$"
install -o root -g root -m 0600 "${config_source}" "${config_temporary}"
[[ ! -L "${CONFIG_TARGET}" ]] || fail "refusing to replace a symlinked configuration target"

"${release_path}/.venv/bin/python" - "${config_temporary}" "${agent_uid}" "${SOCKET_GROUP}" "${SOCKET_PATH}" <<'PY'
import os
import stat
import sys

from host_helper.protocol import HelperConfig

config = HelperConfig.from_file(sys.argv[1])
agent_uid = int(sys.argv[2])
if agent_uid not in config.allowed_uids:
    raise SystemExit(f"configured allowed_uids must include agent UID {agent_uid}")
if config.socket_group != sys.argv[3]:
    raise SystemExit(f"socket_group must be {sys.argv[3]}")
if str(config.socket_path) != sys.argv[4]:
    raise SystemExit(f"socket_path must be {sys.argv[4]}")
for bench in config.benches:
    metadata = bench.db_root_password_file.stat()
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise SystemExit(
            f"database password file for {bench.bench_id} must be root-owned with mode 0600"
        )
print(f"validated {len(config.benches)} bench policy entr{'y' if len(config.benches) == 1 else 'ies'}")
PY

if [[ -e "${CONFIG_TARGET}" ]] && ! cmp -s "${CONFIG_TARGET}" "${config_temporary}"; then
    install -o root -g root -m 0600 "${CONFIG_TARGET}" "${CONFIG_TARGET}.previous"
fi
mv -fT -- "${config_temporary}" "${CONFIG_TARGET}"

current_temporary="${INSTALL_ROOT}/.current.$$"
ln -s "releases/${release_name}" "${current_temporary}"
mv -fT -- "${current_temporary}" "${INSTALL_ROOT}/current"
install -o root -g root -m 0644 "${source_root}/frappe-host-helper.service" "${SERVICE_TARGET}"

systemctl daemon-reload
systemctl enable frappe-host-helper.service >/dev/null
systemctl restart frappe-host-helper.service
systemctl is-active --quiet frappe-host-helper.service || fail "service failed to start; inspect journalctl -u frappe-host-helper"

for _attempt in {1..20}; do
    [[ -S "${SOCKET_PATH}" ]] && break
    sleep 0.25
done
[[ -S "${SOCKET_PATH}" ]] || fail "service is active but the helper socket was not created"

if [[ "${start_agent}" == "true" ]]; then
    docker compose \
        --env-file "${AGENT_ENV_TARGET}" \
        --file "${AGENT_COMPOSE_TARGET}" \
        up --detach --wait --wait-timeout 120
fi

printf '\nFrappe Host Helper %s installed successfully.\n' "${version}"
printf 'Release: %s\n' "${release_path}"
printf 'Socket:  %s\n' "${SOCKET_PATH}"
printf 'Agent Compose: %s\n' "${AGENT_COMPOSE_TARGET}"
if [[ -n "${agent_env_source}" ]]; then
    printf 'Agent environment: %s\n' "${AGENT_ENV_TARGET}"
else
    printf 'Prepare %s from %s before starting the Agent.\n' "${AGENT_ENV_TARGET}" "${AGENT_ENV_EXAMPLE_TARGET}"
    printf 'Set FRAPPE_HOST_HELPER_GID=%s (or auto before running this installer again).\n' "${socket_gid}"
fi
if [[ "${start_agent}" == "true" ]]; then
    printf 'Agent, Worker, and Redis are running.\n'
else
    printf 'The Agent Docker stack was installed but not started.\n'
fi
