#!/usr/bin/env bash
set -Eeuo pipefail

readonly INSTALL_ROOT="/opt/frappe-host-helper"
readonly CONFIG_ROOT="/etc/frappe-deploy-agent"
readonly CONFIG_TARGET="${CONFIG_ROOT}/host-helper.json"
readonly SERVICE_TARGET="/etc/systemd/system/frappe-host-helper.service"
readonly SOCKET_GROUP="frappe-agent"
readonly SOCKET_PATH="/run/frappe-agent/helper.sock"

config_source=""
agent_uid="10001"
release_staging=""
config_temporary=""
current_temporary=""

usage() {
    cat <<'EOF'
Usage: sudo ./install.sh --config /absolute/path/host-helper.json [--agent-uid UID]

Installs or upgrades the standalone Frappe Host Helper, validates its root-owned
bench policy, enables the systemd service, and prints the socket group GID needed
by the Deploy Agent containers.

Options:
  --config PATH    Completed host-helper JSON policy (required).
  --agent-uid UID  Container UID allowed to use the socket (default: 10001).
  -h, --help       Show this help.
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

required_sources=(
    __init__.py
    data_update_contract.py
    executor.py
    observability.py
    protocol.py
    server.py
    requirements.txt
    VERSION
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

install -d -o root -g root -m 0755 "${INSTALL_ROOT}" "${INSTALL_ROOT}/releases"
install -d -o root -g root -m 0755 "${CONFIG_ROOT}"
install -d -o root -g root -m 0700 "${CONFIG_ROOT}/secrets"

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
    python3 -m pip install \
        --disable-pip-version-check --no-cache-dir \
        --target "${site_packages}" \
        --requirement "${release_staging}/requirements.txt"
    "${release_staging}/.venv/bin/python" -c \
        'from host_helper.protocol import HelperConfig; from host_helper.server import main'
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

socket_gid="$(getent group "${SOCKET_GROUP}" | cut -d: -f3)"
printf '\nFrappe Host Helper %s installed successfully.\n' "${version}"
printf 'Release: %s\n' "${release_path}"
printf 'Socket:  %s\n' "${SOCKET_PATH}"
printf 'Set FRAPPE_HOST_HELPER_GID=%s in the Deploy Agent environment.\n' "${socket_gid}"
