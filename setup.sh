#!/usr/bin/env bash
set -Eeuo pipefail

readonly CONFIG_ROOT="/etc/frappe-deploy-agent"
readonly AGENT_CONFIG_ROOT="/etc/frappe-agent"
readonly HELPER_CONFIG="${CONFIG_ROOT}/host-helper.json"
readonly BENCH_REGISTRY="${AGENT_CONFIG_ROOT}/benches.yaml"
readonly AGENT_COMPOSE="/opt/frappe-deploy-agent/compose.yml"

bench_id=""
compose_file=""
backend_service="backend"
sites_path=""
container_sites_path="/home/frappe/frappe-bench/sites"
staging_path=""
site_suffix=""
traefik_service=""
db_password_file=""
agent_env=""
agent_uid="10001"
start_agent="false"
temporary_dir=""

usage() {
    cat <<'EOF'
Usage: sudo ./setup.sh [options]

Interactive one-bench setup for a managed Frappe server. With no options, the
script asks only for missing values. It generates both internal policy files
and installs the Host Helper.

Options:
  --bench-id ID                 Local bench name, for example production-a
  --compose-file PATH           Existing Frappe Docker Compose file
  --backend-service NAME        Compose backend service (default: backend)
  --sites-path PATH             Existing sites directory on the host
  --container-sites-path PATH   Sites path inside backend (default shown above)
  --staging-path PATH           Shared staging directory (created if missing)
  --site-suffix DOMAIN          Allowed site suffix, for example kaleam.net
  --traefik-service NAME        Traefik service, for example production-a@docker
  --db-password-file PATH       Existing root-owned mode-0600 password file
  --agent-env PATH              Completed Agent environment file (optional)
  --agent-uid UID               Agent container UID (default: 10001)
  --start-agent                 Start Agent, Worker, and Redis after setup
  -h, --help                    Show this help

If --db-password-file is omitted, the script securely asks for the MariaDB root
password and stores it under /etc/frappe-deploy-agent/secrets/.
EOF
}

fail() {
    printf 'frappe managed-server setup: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [[ -n "${temporary_dir}" && "${temporary_dir}" == /run/frappe-setup.* ]]; then
        rm -rf -- "${temporary_dir}"
    fi
}
trap cleanup EXIT

prompt() {
    local variable_name="$1"
    local label="$2"
    local default_value="${3:-}"
    local answer=""
    if [[ -n "${default_value}" ]]; then
        read -r -p "${label} [${default_value}]: " answer </dev/tty
        printf -v "${variable_name}" '%s' "${answer:-${default_value}}"
    else
        while [[ -z "${answer}" ]]; do
            read -r -p "${label}: " answer </dev/tty
        done
        printf -v "${variable_name}" '%s' "${answer}"
    fi
}

while (($#)); do
    case "$1" in
        --bench-id) bench_id="${2-}"; shift 2 ;;
        --compose-file) compose_file="${2-}"; shift 2 ;;
        --backend-service) backend_service="${2-}"; shift 2 ;;
        --sites-path) sites_path="${2-}"; shift 2 ;;
        --container-sites-path) container_sites_path="${2-}"; shift 2 ;;
        --staging-path) staging_path="${2-}"; shift 2 ;;
        --site-suffix) site_suffix="${2-}"; shift 2 ;;
        --traefik-service) traefik_service="${2-}"; shift 2 ;;
        --db-password-file) db_password_file="${2-}"; shift 2 ;;
        --agent-env) agent_env="${2-}"; shift 2 ;;
        --agent-uid) agent_uid="${2-}"; shift 2 ;;
        --start-agent) start_agent="true"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "unknown argument: $1" ;;
    esac
done

[[ ${EUID} -eq 0 ]] || fail "run this command with sudo"
for command in python3 install readlink mktemp rm; do
    command -v "${command}" >/dev/null 2>&1 || fail "required command is missing: ${command}"
done

source_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -x "${source_root}/install.sh" ]] || fail "install.sh is missing or not executable"

[[ -n "${bench_id}" ]] || prompt bench_id "Bench ID" "production-a"
[[ -n "${compose_file}" ]] || prompt compose_file "Frappe Compose file"
[[ -n "${backend_service}" ]] || prompt backend_service "Backend service" "backend"
[[ -n "${sites_path}" ]] || prompt sites_path "Sites directory on host"
[[ -n "${container_sites_path}" ]] || prompt container_sites_path "Sites directory inside backend" "/home/frappe/frappe-bench/sites"
[[ -n "${staging_path}" ]] || prompt staging_path "Shared staging directory" "/var/lib/frappe-agent/staging/${bench_id}"
[[ -n "${site_suffix}" ]] || prompt site_suffix "Allowed site suffix (example: kaleam.net)"
[[ -n "${traefik_service}" ]] || prompt traefik_service "Traefik frontend service" "${bench_id}@docker"

[[ "${bench_id}" =~ ^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$ ]] || fail "bench ID must be lowercase letters, numbers, and hyphens"
[[ "${backend_service}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$ ]] || fail "backend service name is invalid"
[[ "${traefik_service}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}@[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || fail "Traefik service must look like production-a@docker"
[[ "${agent_uid}" =~ ^[0-9]+$ ]] || fail "agent UID must be numeric"
((agent_uid <= 4294967295)) || fail "agent UID is outside the supported range"

python3 - "${site_suffix}" <<'PY' || fail "site suffix is not a valid domain"
import re
import sys

value = sys.argv[1].lower().strip(".")
pattern = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
raise SystemExit(0 if value == sys.argv[1] and "." in value and pattern.fullmatch(value) else 1)
PY

[[ "${compose_file}" == /* && -f "${compose_file}" && ! -L "${compose_file}" ]] || fail "Compose file must be an existing absolute regular file, not a symlink"
[[ "${sites_path}" == /* && -d "${sites_path}" && ! -L "${sites_path}" ]] || fail "sites path must be an existing absolute directory, not a symlink"
[[ "${container_sites_path}" == /* ]] || fail "container sites path must be absolute"
[[ "${staging_path}" == /* ]] || fail "staging path must be absolute"

compose_file="$(readlink -f -- "${compose_file}")"
sites_path="$(readlink -f -- "${sites_path}")"
install -d -o root -g root -m 0755 "${staging_path}"
staging_path="$(readlink -f -- "${staging_path}")"

install -d -o root -g root -m 0755 "${CONFIG_ROOT}" "${AGENT_CONFIG_ROOT}"
install -d -o root -g root -m 0700 "${CONFIG_ROOT}/secrets"

if [[ -z "${db_password_file}" ]]; then
    db_password_file="${CONFIG_ROOT}/secrets/${bench_id}-db-root"
    if [[ ! -e "${db_password_file}" ]]; then
        password=""
        while [[ -z "${password}" ]]; do
            read -r -s -p "MariaDB root password: " password </dev/tty
            printf '\n' >/dev/tty
        done
        password_temporary="${db_password_file}.new.$$"
        umask 077
        printf '%s' "${password}" >"${password_temporary}"
        unset password
        install -o root -g root -m 0600 "${password_temporary}" "${db_password_file}"
        rm -f -- "${password_temporary}"
    fi
fi
[[ "${db_password_file}" == /* && -f "${db_password_file}" && ! -L "${db_password_file}" ]] || fail "database password file must be an existing absolute regular file, not a symlink"
db_password_file="$(readlink -f -- "${db_password_file}")"
[[ "$(stat -c '%u:%a' "${db_password_file}")" == "0:600" ]] || fail "database password file must be owned by root with mode 0600"

if [[ -n "${agent_env}" ]]; then
    [[ "${agent_env}" == /* && -f "${agent_env}" && ! -L "${agent_env}" ]] || fail "Agent environment must be an existing absolute regular file, not a symlink"
    agent_env="$(readlink -f -- "${agent_env}")"
fi
[[ "${start_agent}" != "true" || -n "${agent_env}" ]] || fail "--start-agent requires --agent-env"

temporary_dir="$(mktemp -d /run/frappe-setup.XXXXXXXX)"
chmod 0700 "${temporary_dir}"
helper_temporary="${temporary_dir}/host-helper.json"
registry_temporary="${temporary_dir}/benches.yaml"

python3 - \
    "${helper_temporary}" "${registry_temporary}" "${bench_id}" \
    "${compose_file}" "${backend_service}" "${sites_path}" \
    "${container_sites_path}" "${staging_path}" "${db_password_file}" \
    "${site_suffix}" "${traefik_service}" "${agent_uid}" <<'PY'
import json
import sys
from pathlib import Path

(
    helper_path, registry_path, bench_id, compose_file, backend_service,
    sites_path, container_sites_path, staging_path, password_file,
    suffix, traefik_service, agent_uid,
) = sys.argv[1:]

operations = [
    "site.create", "site.create_blank", "site.create_from_backup",
    "site.backup", "site.restore", "site.reinstall", "site.delete",
    "site.migrate", "site.scheduler.enable", "site.scheduler.disable",
    "site.maintenance.enable", "site.maintenance.disable",
    "site.config.update", "site.verify",
]

helper_bench = {
    "bench_id": bench_id,
    "compose_file": compose_file,
    "backend_service": backend_service,
    "sites_path": sites_path,
    "container_sites_path": container_sites_path,
    "host_staging_path": staging_path,
    "container_staging_path": staging_path,
    "db_root_password_file": password_file,
    "allowed_site_suffixes": [suffix],
    "allowed_operations": operations,
    "allowed_site_config_keys": [],
    "allowed_data_update_policies": [],
    "concurrency_limit": 1,
}
registry_bench = {
    "bench_id": bench_id,
    "compose_file": compose_file,
    "backend_service": backend_service,
    "sites_path": sites_path,
    "host_staging_path": staging_path,
    "container_staging_path": staging_path,
    "db_secret_ref": f"bench-{bench_id}-db-root",
    "traefik_frontend_service": traefik_service,
    "allowed_domain_suffixes": [suffix],
    "allowed_operations": operations,
    "concurrency_limit": 1,
}
helper = {
    "benches": [helper_bench],
    "allowed_uids": [int(agent_uid)],
    "socket_path": "/run/frappe-agent/helper.sock",
    "socket_group": "frappe-agent",
    "timeout_seconds": 1800,
    "output_limit_bytes": 262144,
}
registry = {"benches": [registry_bench]}
Path(helper_path).write_text(json.dumps(helper, indent=2) + "\n", encoding="utf-8")
# JSON is valid YAML and avoids unsafe string interpolation.
Path(registry_path).write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
PY
chmod 0600 "${helper_temporary}" "${registry_temporary}"

install_args=(--config "${helper_temporary}" --agent-uid "${agent_uid}")
if [[ -n "${agent_env}" ]]; then
    install_args+=(--agent-env "${agent_env}")
fi
"${source_root}/install.sh" "${install_args[@]}"

if [[ -e "${BENCH_REGISTRY}" ]] && ! cmp -s "${BENCH_REGISTRY}" "${registry_temporary}"; then
    install -o root -g root -m 0600 "${BENCH_REGISTRY}" "${BENCH_REGISTRY}.previous"
fi
install -o root -g root -m 0600 "${registry_temporary}" "${BENCH_REGISTRY}"

if [[ "${start_agent}" == "true" ]]; then
    docker compose --env-file /etc/frappe-agent/agent.env --file "${AGENT_COMPOSE}" \
        up --detach --wait --wait-timeout 120
fi

printf '\nManaged server setup complete.\n'
printf 'Bench:           %s\n' "${bench_id}"
printf 'Helper policy:   %s\n' "${HELPER_CONFIG}"
printf 'Bench registry:  %s\n' "${BENCH_REGISTRY}"
if [[ "${start_agent}" == "true" ]]; then
    printf 'Agent stack:     running\n'
else
    printf 'Agent stack:     not started (run setup again with --agent-env PATH --start-agent)\n'
fi
