#!/usr/bin/env bash
set -Eeuo pipefail

readonly CONFIG_ROOT="/etc/frappe-deploy-agent"
readonly AGENT_CONFIG_ROOT="/etc/frappe-agent"
readonly HELPER_CONFIG="${CONFIG_ROOT}/host-helper.json"
readonly BENCH_REGISTRY="${AGENT_CONFIG_ROOT}/benches.yaml"
readonly AGENT_COMPOSE="/opt/frappe-deploy-agent/compose.yml"
readonly AGENT_ENV_TARGET="/etc/frappe-agent/agent.env"
readonly AGENT_SIGNING_ROOT="/etc/frappe-agent/signing"

bench_id=""
compose_file=""
backend_service=""
sites_path=""
container_sites_path=""
staging_path=""
site_suffix=""
traefik_service=""
db_password_file=""
agent_env=""
agent_uid="10001"
start_agent="false"
controller_url=""
agent_id=""
enrollment_token_file=""
doctor_mode="false"
doctor_json="false"
doctor_fix="false"
bootstrap_file=""
discovery_file=""
allowed_operations_json=""
allowed_suffixes_json=""
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
  --controller HTTPS_URL        Enroll with the central Controller
  --agent-id ID                 Agent ID from the Controller install command
  --enrollment-token-file PATH  Root-owned mode-0600 token file (otherwise prompt)
  --start-agent                 Start the unified Agent runtime after setup
  doctor                        Run installed-stack diagnostics
  --fix                         Repair safe doctor findings (doctor only)
  --json                        Emit doctor results as JSON
  -h, --help                    Show this help

If --db-password-file is omitted, the script securely asks for the MariaDB root
password and stores it under /etc/frappe-deploy-agent/secrets/.
EOF
}

repair_agent_file_permissions() {
    local signing_key="${AGENT_SIGNING_ROOT}/agent-signing-key.pem"
    [[ -f "${BENCH_REGISTRY}" && ! -L "${BENCH_REGISTRY}" ]] || fail "Bench registry must be a regular file, not a symlink"
    [[ -d "${AGENT_SIGNING_ROOT}" && ! -L "${AGENT_SIGNING_ROOT}" ]] || fail "Agent signing directory must be a directory, not a symlink"
    [[ -f "${signing_key}" && ! -L "${signing_key}" ]] || fail "Agent signing key must be a regular file, not a symlink"
    chgrp frappe-agent "${BENCH_REGISTRY}" "${AGENT_SIGNING_ROOT}" "${signing_key}"
    chmod 0640 "${BENCH_REGISTRY}" "${signing_key}"
    chmod 0750 "${AGENT_SIGNING_ROOT}"
    printf 'FIXED Agent registry and signing permissions\n'
}

repair_traefik_route_directory() {
    local -a configured_paths=()
    local route_directory=""
    [[ -f "${AGENT_ENV_TARGET}" ]] || fail "Agent environment is missing"
    mapfile -t configured_paths < <(sed -n 's/^TRAEFIK_DYNAMIC_CONFIG_PATH=//p' "${AGENT_ENV_TARGET}")
    [[ ${#configured_paths[@]} -eq 1 && -n "${configured_paths[0]}" ]] || fail "Agent environment must define TRAEFIK_DYNAMIC_CONFIG_PATH exactly once"
    [[ "${configured_paths[0]}" == /* && -d "${configured_paths[0]}" && ! -L "${configured_paths[0]}" ]] || fail "TRAEFIK_DYNAMIC_CONFIG_PATH must be an existing absolute directory, not a symlink"
    route_directory="$(readlink -f -- "${configured_paths[0]}")"
    [[ "${route_directory}" != "/" ]] || fail "refusing to change permissions on /"
    getent group frappe-agent >/dev/null || fail "frappe-agent group is missing"
    chgrp frappe-agent "${route_directory}"
    chmod 2775 "${route_directory}"
    printf 'FIXED Traefik route directory permissions: %s\n' "${route_directory}"
}

doctor() {
    local failures=0
    local -a results=()
    check() {
        local label="$1"
        shift
        if "$@" >/dev/null 2>&1; then
            results+=("${label}|ok")
            [[ "${doctor_json}" == "true" ]] || printf 'OK    %s\n' "${label}"
        else
            results+=("${label}|failed")
            [[ "${doctor_json}" == "true" ]] || printf 'FAIL  %s\n' "${label}"
            failures=$((failures + 1))
        fi
    }
    check "Docker service" systemctl is-active --quiet docker.service
    check "Docker Compose" docker compose version
    check "Host Helper service" systemctl is-active --quiet frappe-host-helper.service
    check "Host Helper socket" test -S /run/frappe-agent/helper.sock
    check "Host Helper policy" test -f "${HELPER_CONFIG}"
    check "Bench registry permissions" bash -c \
        'test "$(stat -c "%u:%G:%a" /etc/frappe-agent/benches.yaml 2>/dev/null)" = "0:frappe-agent:640"'
    check "Agent environment" test -f "${AGENT_ENV_TARGET}"
    check "Agent updater timer" systemctl is-active --quiet frappe-agent-updater.timer
    check "Agent signing key permissions" bash -c \
        'test "$(stat -c "%u:%G:%a" /etc/frappe-agent/signing/agent-signing-key.pem 2>/dev/null)" = "0:frappe-agent:640"'
    check "Agent signing directory permissions" bash -c \
        'test "$(stat -c "%u:%G:%a" /etc/frappe-agent/signing 2>/dev/null)" = "0:frappe-agent:750"'
    check "Agent signing key type" openssl pkey -in \
        "${AGENT_SIGNING_ROOT}/agent-signing-key.pem" -text_pub -noout
    if [[ -f "${AGENT_ENV_TARGET}" && -f "${AGENT_COMPOSE}" ]]; then
        traefik_dynamic_config_path="$(sed -n 's/^TRAEFIK_DYNAMIC_CONFIG_PATH=//p' "${AGENT_ENV_TARGET}")"
        if [[ -n "${traefik_dynamic_config_path}" ]]; then
            check "Traefik route directory permissions" bash -c 'test -d "$1" && test ! -L "$1" && test "$(stat -c "%G:%a" "$1")" = "frappe-agent:2775"' _ "${traefik_dynamic_config_path}"
        else
            check "Traefik route directory permissions" false
        fi
        check "Agent Compose configuration" docker compose \
            --env-file "${AGENT_ENV_TARGET}" --file "${AGENT_COMPOSE}" config --quiet
        check "Agent containers" docker compose \
            --env-file "${AGENT_ENV_TARGET}" --file "${AGENT_COMPOSE}" ps --status running --quiet
    fi
    if ((failures)); then
        if [[ "${doctor_json}" == "true" ]]; then
            python3 - "${failures}" "${results[@]}" <<'PY'
import json, sys
checks = [{"component": item.rsplit("|", 1)[0], "status": item.rsplit("|", 1)[1]} for item in sys.argv[2:]]
print(json.dumps({"healthy": int(sys.argv[1]) == 0, "failed": int(sys.argv[1]), "checks": checks}, separators=(",", ":")))
PY
        else
            printf '\nDoctor found %d failed check(s).\n' "${failures}"
        fi
        return 1
    fi
    if [[ "${doctor_json}" == "true" ]]; then
        python3 - "0" "${results[@]}" <<'PY'
import json, sys
checks = [{"component": item.rsplit("|", 1)[0], "status": item.rsplit("|", 1)[1]} for item in sys.argv[2:]]
print(json.dumps({"healthy": True, "failed": 0, "checks": checks}, separators=(",", ":")))
PY
    else
        printf '\nAll Agent checks passed.\n'
    fi
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
        --controller) controller_url="${2-}"; shift 2 ;;
        --agent-id) agent_id="${2-}"; shift 2 ;;
        --enrollment-token-file) enrollment_token_file="${2-}"; shift 2 ;;
        --start-agent) start_agent="true"; shift ;;
        doctor) doctor_mode="true"; shift ;;
        --fix) doctor_fix="true"; shift ;;
        --json) doctor_json="true"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) fail "unknown argument: $1" ;;
    esac
done

[[ "${doctor_json}" != "true" || "${doctor_mode}" == "true" ]] || fail "--json is only valid with doctor"
[[ "${doctor_fix}" != "true" || "${doctor_mode}" == "true" ]] || fail "--fix is only valid with doctor"
[[ ${EUID} -eq 0 ]] || fail "run this command with sudo"
for command in python3 install readlink mktemp rm sed stat getent chgrp chmod; do
    command -v "${command}" >/dev/null 2>&1 || fail "required command is missing: ${command}"
done

source_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
[[ -x "${source_root}/install.sh" ]] || fail "install.sh is missing or not executable"

if [[ "${doctor_mode}" == "true" ]]; then
    if [[ "${doctor_fix}" == "true" ]]; then
        repair_agent_file_permissions
        repair_traefik_route_directory
    fi
    doctor
    exit $?
fi

if [[ -n "${controller_url}" ]]; then
    [[ -n "${agent_id}" ]] || fail "--controller requires --agent-id from the Controller install command"
    for command in openssl docker; do
        command -v "${command}" >/dev/null 2>&1 || fail "required enrollment command is missing: ${command}"
    done
    temporary_dir="$(mktemp -d /run/frappe-setup.XXXXXXXX)"
    chmod 0700 "${temporary_dir}"
    bootstrap_args=(
        --controller "${controller_url}" --agent-id "${agent_id}"
        --output "${temporary_dir}/signing"
    )
    if [[ -n "${enrollment_token_file}" ]]; then
        bootstrap_args+=(--token-file "${enrollment_token_file}")
    fi
    python3 "${source_root}/bootstrap.py" "${bootstrap_args[@]}" >/dev/null
    bootstrap_file="${temporary_dir}/signing/bootstrap.json"
    discovery_file="${temporary_dir}/discovery.json"
    discovery_args=(--output "${discovery_file}")
    [[ -z "${compose_file}" ]] || discovery_args+=(--compose-file "${compose_file}")
    [[ -z "${backend_service}" ]] || discovery_args+=(--backend-service "${backend_service}")
    [[ -z "${sites_path}" ]] || discovery_args+=(--sites-path "${sites_path}")
    [[ -z "${container_sites_path}" ]] || discovery_args+=(--container-sites-path "${container_sites_path}")
    [[ -z "${staging_path}" ]] || discovery_args+=(--staging-path "${staging_path}")
    [[ -z "${traefik_service}" ]] || discovery_args+=(--traefik-service "${traefik_service}")
    python3 "${source_root}/discover.py" "${discovery_args[@]}"
    eval "$(python3 - "${discovery_file}" <<'PY'
import json, shlex, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for key in ("bench_id", "compose_file", "backend_service", "sites_path", "container_sites_path", "staging_path", "traefik_service"):
    print(f"{key}={shlex.quote(str(value[key]))}")
PY
)"
    site_suffix="$(python3 - "${bootstrap_file}" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["policy"]["allowed_site_suffixes"][0])
PY
)"
    allowed_suffixes_json="$(python3 - "${bootstrap_file}" <<'PY'
import json, sys
print(json.dumps(json.load(open(sys.argv[1], encoding="utf-8"))["policy"]["allowed_site_suffixes"], separators=(",", ":")))
PY
)"
    allowed_operations_json="$(python3 - "${bootstrap_file}" <<'PY'
import json, sys
print(json.dumps(json.load(open(sys.argv[1], encoding="utf-8"))["policy"]["allowed_operations"], separators=(",", ":")))
PY
)"
    start_agent="true"
fi

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
[[ "${start_agent}" != "true" || -n "${agent_env}" || -n "${bootstrap_file}" ]] || fail "--start-agent requires --agent-env or Controller enrollment"

if [[ -z "${temporary_dir}" ]]; then
    temporary_dir="$(mktemp -d /run/frappe-setup.XXXXXXXX)"
    chmod 0700 "${temporary_dir}"
fi
helper_temporary="${temporary_dir}/host-helper.json"
registry_temporary="${temporary_dir}/benches.yaml"

python3 - \
    "${helper_temporary}" "${registry_temporary}" "${bench_id}" \
    "${compose_file}" "${backend_service}" "${sites_path}" \
    "${container_sites_path}" "${staging_path}" "${db_password_file}" \
    "${site_suffix}" "${traefik_service}" "${agent_uid}" \
    "${allowed_operations_json}" "${allowed_suffixes_json}" <<'PY'
import json
import sys
from pathlib import Path

(
    helper_path, registry_path, bench_id, compose_file, backend_service,
    sites_path, container_sites_path, staging_path, password_file,
    suffix, traefik_service, agent_uid, allowed_operations_json,
    allowed_suffixes_json,
) = sys.argv[1:]

default_operations = [
    "site.create", "site.create_blank", "site.create_from_backup",
    "site.backup", "site.restore", "site.reinstall", "site.delete",
    "site.migrate", "site.scheduler.enable", "site.scheduler.disable",
    "site.maintenance.enable", "site.maintenance.disable",
    "site.config.update", "site.verify",
]
operations = json.loads(allowed_operations_json) if allowed_operations_json else default_operations
if not isinstance(operations, list) or not operations or any(not isinstance(item, str) for item in operations):
    raise SystemExit("Controller allowed_operations policy is invalid")
suffixes = json.loads(allowed_suffixes_json) if allowed_suffixes_json else [suffix]
if not isinstance(suffixes, list) or not suffixes or any(not isinstance(item, str) for item in suffixes):
    raise SystemExit("Controller allowed_site_suffixes policy is invalid")

helper_bench = {
    "bench_id": bench_id,
    "compose_file": compose_file,
    "backend_service": backend_service,
    "sites_path": sites_path,
    "container_sites_path": container_sites_path,
    "host_staging_path": staging_path,
    "container_staging_path": staging_path,
    "db_root_password_file": password_file,
    "allowed_site_suffixes": suffixes,
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
    "allowed_domain_suffixes": suffixes,
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

if [[ -n "${bootstrap_file}" ]]; then
    agent_env="${temporary_dir}/agent.env"
    python3 - \
        "${bootstrap_file}" "${discovery_file}" "${agent_env}" \
        "${BENCH_REGISTRY}" "${site_suffix}" <<'PY'
import json
import sys
from pathlib import Path

bootstrap = json.load(open(sys.argv[1], encoding="utf-8"))
discovery = json.load(open(sys.argv[2], encoding="utf-8"))
target = Path(sys.argv[3])
registry = sys.argv[4]
suffix = sys.argv[5]

def env(name, value):
    text = str(value)
    if "\n" in text or "\r" in text:
        raise SystemExit(f"invalid newline in {name}")
    return f"{name}={text}"

values = [
    env("FRAPPE_HOST_HELPER_SOCKET", "/run/frappe-agent/helper.sock"),
    env("FRAPPE_HOST_HELPER_GID", "auto"),
    env("BENCH_REGISTRY_FILE", registry),
    env("BENCH_STAGING_ROOT", discovery["staging_path"]),
    env("BENCH_SITES_ROOT", discovery["sites_path"]),
    env("TRAEFIK_DYNAMIC_CONFIG_PATH", "/deploy/proxy/simple-traefik/config/dynamic"),
    env("TRAEFIK_FRONTEND_SERVICE", discovery["traefik_service"]),
    env("STAGING_DIR", discovery["staging_path"]),
    env("AGENT_IMAGE_REPOSITORY", bootstrap["image"]["reference"].rsplit("@sha256:", 1)[0]),
    env("AGENT_IMAGE_DIGEST", bootstrap["image"]["reference"].rsplit("@sha256:", 1)[1]),
    env("AGENT_ID", bootstrap["agent"]["agent_id"]),
    env("CONTROLLER_URL", bootstrap["controller"]["url"]),
    env("CONTROLLER_SITE_NAME", bootstrap["controller"].get("site_name", "")),
    env("CONTROLLER_AUDIENCE", bootstrap["agent"]["audience"]),
    env("CONTROLLER_ALLOWED_OPERATIONS", json.dumps(bootstrap["policy"]["allowed_operations"], separators=(",", ":"))),
    env("CONTROLLER_CA_CERTIFICATE_PATH", ""),
    env("DATA_UPDATE_POLICY_FILE", ""),
    env("DATA_UPDATE_POLICY_PATH", ""),
    env("LOG_LEVEL", "INFO"),
]
target.write_text("\n".join(values) + "\n", encoding="utf-8")
target.chmod(0o600)
PY
fi

install_args=(--config "${helper_temporary}" --agent-uid "${agent_uid}")
if [[ -n "${agent_env}" ]]; then
    install_args+=(--agent-env "${agent_env}")
fi
"${source_root}/install.sh" "${install_args[@]}"

if [[ -e "${BENCH_REGISTRY}" ]] && ! cmp -s "${BENCH_REGISTRY}" "${registry_temporary}"; then
    install -o root -g frappe-agent -m 0640 "${BENCH_REGISTRY}" "${BENCH_REGISTRY}.previous"
fi
install -o root -g frappe-agent -m 0640 "${registry_temporary}" "${BENCH_REGISTRY}"

if [[ -n "${bootstrap_file}" ]]; then
    install -d -o root -g frappe-agent -m 0750 "${AGENT_SIGNING_ROOT}"
    for source_name in agent-signing-key.pem; do
        target_name="${AGENT_SIGNING_ROOT}/${source_name}"
        [[ ! -L "${target_name}" ]] || fail "refusing to replace symlinked signing-key file: ${target_name}"
        if [[ -e "${target_name}" ]]; then
            install -o root -g root -m 0600 "${target_name}" "${target_name}.previous"
        fi
        install -o root -g frappe-agent -m 0640 "${temporary_dir}/signing/${source_name}" "${target_name}"
    done
    systemctl restart frappe-agent-updater.timer
fi

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
