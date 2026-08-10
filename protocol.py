"""Strict, bench-scoped request schema and host-owned helper policy."""

from __future__ import annotations

import json
import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import ValidationError

from .data_update_contract import DataUpdatePayload, MAX_PAYLOAD_BYTES

_REQUEST_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_BENCH_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_OPERATION_RE = re.compile(r"^[a-z][a-z0-9_-]{0,62}(?:\.[a-z][a-z0-9_-]{0,62})+$")
_CONFIG_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_DATA_UPDATE_POLICY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_DATA_UPDATE_HASH_RE = re.compile(r"^[a-f0-9]{64}$")
_DATA_UPDATE_OPERATION_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_DATA_UPDATE_OPERATIONS = frozenset({"data.update", "data.update.break_glass"})
_SENSITIVE_CONFIG_MARKERS = (
    "api_key", "credential", "encryption_key", "password", "private_key",
    "secret", "token",
)
_HELPER_OPERATIONS = frozenset({
    "new_site", "restore_site", "drop_site", "enable_scheduler",
    "restore_companion_assets", "backup_site", "migrate_site",
    "scheduler_set", "maintenance_set", "config_set", "verify_site",
    "data_update",
})
_POLICY_OPERATIONS = {
    "new_site": frozenset({"site.create", "site.create_blank", "site.create_from_backup"}),
    "restore_site": frozenset({"site.create", "site.create_from_backup", "site.restore", "site.reinstall"}),
    "drop_site": frozenset({"site.delete"}),
    "enable_scheduler": frozenset({"site.create", "site.create_blank", "site.create_from_backup", "site.restore", "site.reinstall"}),
    "restore_companion_assets": frozenset({"site.create", "site.create_from_backup", "site.restore", "site.reinstall"}),
    "backup_site": frozenset({"site.backup", "site.restore", "site.reinstall", "site.delete"}),
    "migrate_site": frozenset({"site.migrate", "site.restore", "site.reinstall"}),
    "scheduler_set": frozenset({
        "site.scheduler.enable", "site.scheduler.disable", "site.create",
        "site.create_blank", "site.create_from_backup", "site.restore",
        "site.reinstall", "site.delete", "site.migrate",
    }),
    "maintenance_set": frozenset({
        "site.maintenance.enable", "site.maintenance.disable", "site.restore",
        "site.reinstall", "site.delete", "site.migrate",
    }),
    "config_set": frozenset({"site.config.update", "site.config.set"}),
    "verify_site": frozenset({
        "site.verify", "site.create", "site.create_blank", "site.create_from_backup",
        "site.backup", "site.restore", "site.reinstall", "site.delete",
        "site.migrate", "site.scheduler.enable", "site.scheduler.disable",
        "site.maintenance.enable", "site.maintenance.disable", "site.config.update",
        "site.config.set",
    }),
    "data_update": _DATA_UPDATE_OPERATIONS,
}


class RequestRejected(ValueError):
    """Request failed strict schema or policy validation."""


def _absolute_path(value: Any, name: str, *, must_exist: bool = True) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RequestRejected(f"invalid {name}")
    path = Path(value)
    if not path.is_absolute():
        raise RequestRejected(f"{name} must be absolute")
    try:
        return path.resolve(strict=must_exist)
    except OSError:
        raise RequestRejected(f"invalid {name}") from None


def _suffixes(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise RequestRejected("at least one site suffix is required")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise RequestRejected("invalid site suffix")
        suffix = item.lower().strip(".")
        if not _DOMAIN_RE.fullmatch(f"site.{suffix}"):
            raise RequestRejected("invalid site suffix")
        result.append(suffix)
    return tuple(result)


@dataclass(frozen=True)
class DataUpdatePolicyGrant:
    """Root-owned binding between one policy identity and operation class."""

    policy_id: str
    operation: str


def _data_update_policy_grants(value: Any) -> tuple[DataUpdatePolicyGrant, ...]:
    if not isinstance(value, list):
        raise RequestRejected("invalid data update policy grants")
    grants: list[DataUpdatePolicyGrant] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"policy_id", "operation"}:
            raise RequestRejected("invalid data update policy grant")
        policy_id = item["policy_id"]
        operation = item["operation"]
        if (
            not isinstance(policy_id, str)
            or not _DATA_UPDATE_POLICY_ID_RE.fullmatch(policy_id)
            or operation not in _DATA_UPDATE_OPERATIONS
        ):
            raise RequestRejected("invalid data update policy grant")
        grants.append(DataUpdatePolicyGrant(policy_id=policy_id, operation=operation))
    if len({grant.policy_id for grant in grants}) != len(grants):
        raise RequestRejected("duplicate data update policy grant")
    return tuple(grants)


@dataclass(frozen=True)
class HelperBenchPolicy:
    """Root-owned routing and authorization policy for one local bench."""

    bench_id: str
    compose_file: Path
    backend_service: str
    sites_path: Path
    container_sites_path: Path
    host_staging_path: Path
    container_staging_path: Path
    db_root_password_file: Path
    allowed_site_suffixes: tuple[str, ...]
    allowed_operations: frozenset[str]
    allowed_site_config_keys: frozenset[str] = frozenset()
    allowed_data_update_policies: tuple[DataUpdatePolicyGrant, ...] = ()
    concurrency_limit: int = 1

    @classmethod
    def from_mapping(cls, value: Any) -> "HelperBenchPolicy":
        expected = {
            "bench_id", "compose_file", "backend_service", "sites_path", "container_sites_path",
            "host_staging_path", "container_staging_path", "db_root_password_file",
            "allowed_site_suffixes", "allowed_operations", "allowed_site_config_keys",
            "concurrency_limit", "allowed_data_update_policies",
        }
        required = expected - {
            "allowed_site_config_keys", "allowed_data_update_policies", "concurrency_limit"
        }
        if not isinstance(value, dict) or not required <= value.keys() or value.keys() - expected:
            raise RequestRejected("invalid helper bench configuration keys")
        bench_id = value.get("bench_id")
        if not isinstance(bench_id, str) or not _BENCH_ID_RE.fullmatch(bench_id):
            raise RequestRejected("invalid bench id")
        backend = value.get("backend_service")
        if not isinstance(backend, str) or not _SERVICE_RE.fullmatch(backend):
            raise RequestRejected("invalid backend service")
        compose_file = _absolute_path(value.get("compose_file"), "compose_file")
        sites_path = _absolute_path(value.get("sites_path"), "sites_path")
        container_sites = _absolute_path(value.get("container_sites_path"), "container_sites_path", must_exist=False)
        host_staging = _absolute_path(value.get("host_staging_path"), "host_staging_path")
        container_staging = _absolute_path(value.get("container_staging_path"), "container_staging_path", must_exist=False)
        secret = _absolute_path(value.get("db_root_password_file"), "db_root_password_file")
        if not compose_file.is_file() or not sites_path.is_dir() or not host_staging.is_dir() or not secret.is_file():
            raise RequestRejected("configured bench paths have invalid types")
        raw_operations = value.get("allowed_operations")
        if not isinstance(raw_operations, list) or not raw_operations or any(
            not isinstance(item, str) or not _OPERATION_RE.fullmatch(item)
            for item in raw_operations
        ):
            raise RequestRejected("at least one valid operation is required")
        concurrency = value.get("concurrency_limit", 1)
        if type(concurrency) is not int or not 1 <= concurrency <= 64:
            raise RequestRejected("invalid concurrency limit")
        raw_config_keys = value.get("allowed_site_config_keys", [])
        if not isinstance(raw_config_keys, list) or any(
            not isinstance(item, str)
            or not _CONFIG_KEY_RE.fullmatch(item)
            or any(marker in item.casefold() for marker in _SENSITIVE_CONFIG_MARKERS)
            for item in raw_config_keys
        ):
            raise RequestRejected("invalid allowed site config keys")
        if len(set(raw_config_keys)) != len(raw_config_keys):
            raise RequestRejected("duplicate allowed site config key")
        grants = _data_update_policy_grants(value.get("allowed_data_update_policies", []))
        configured_data_operations = frozenset(raw_operations) & _DATA_UPDATE_OPERATIONS
        granted_operations = frozenset(grant.operation for grant in grants)
        if configured_data_operations != granted_operations:
            raise RequestRejected(
                "data update operations and root-owned policy grants must match"
            )
        return cls(
            bench_id=bench_id, compose_file=compose_file, backend_service=backend,
            sites_path=sites_path, container_sites_path=container_sites,
            host_staging_path=host_staging,
            container_staging_path=container_staging, db_root_password_file=secret,
            allowed_site_suffixes=_suffixes(value.get("allowed_site_suffixes")),
            allowed_operations=frozenset(raw_operations),
            allowed_site_config_keys=frozenset(raw_config_keys),
            allowed_data_update_policies=grants,
            concurrency_limit=concurrency,
        )


@dataclass(frozen=True)
class HelperConfig:
    benches: tuple[HelperBenchPolicy, ...]
    allowed_uids: frozenset[int]
    socket_path: Path = Path("/run/frappe-agent/helper.sock")
    socket_group: str = "frappe-agent"
    timeout_seconds: int = 1800
    output_limit_bytes: int = 256 * 1024

    def bench(self, bench_id: str) -> HelperBenchPolicy:
        for policy in self.benches:
            if policy.bench_id == bench_id:
                return policy
        raise RequestRejected("unknown bench")

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "HelperConfig":
        expected = {"benches", "allowed_uids", "socket_path", "socket_group", "timeout_seconds", "output_limit_bytes"}
        if not isinstance(value, dict) or not {"benches", "allowed_uids"} <= value.keys() or value.keys() - expected:
            raise RequestRejected("invalid helper configuration keys")
        raw_benches = value.get("benches")
        if not isinstance(raw_benches, list) or not raw_benches:
            raise RequestRejected("at least one bench is required")
        benches = tuple(HelperBenchPolicy.from_mapping(item) for item in raw_benches)
        if len({bench.bench_id for bench in benches}) != len(benches):
            raise RequestRejected("duplicate bench id")
        for offset, left in enumerate(benches):
            for right in benches[offset + 1 :]:
                if left.compose_file == right.compose_file:
                    raise RequestRejected("bench compose files must be isolated")
                for left_path, right_path in (
                    (left.sites_path, right.sites_path),
                    (left.host_staging_path, right.host_staging_path),
                ):
                    try:
                        left_path.relative_to(right_path)
                    except ValueError:
                        try:
                            right_path.relative_to(left_path)
                        except ValueError:
                            pass
                        else:
                            raise RequestRejected("bench host paths must be isolated") from None
                    else:
                        raise RequestRejected("bench host paths must be isolated")
                for left_suffix in left.allowed_site_suffixes:
                    for right_suffix in right.allowed_site_suffixes:
                        if (
                            left_suffix == right_suffix
                            or left_suffix.endswith(f".{right_suffix}")
                            or right_suffix.endswith(f".{left_suffix}")
                        ):
                            raise RequestRejected("bench domain policies must be isolated")
        raw_uids = value.get("allowed_uids")
        if not isinstance(raw_uids, list) or not raw_uids or any(type(uid) is not int or uid < 0 for uid in raw_uids):
            raise RequestRejected("at least one valid peer uid is required")
        socket_path = _absolute_path(value["socket_path"], "socket_path", must_exist=False) if "socket_path" in value else Path("/run/frappe-agent/helper.sock")
        socket_group = value.get("socket_group", "frappe-agent")
        timeout = value.get("timeout_seconds", 1800)
        output_limit = value.get("output_limit_bytes", 256 * 1024)
        if not isinstance(socket_group, str) or not _SERVICE_RE.fullmatch(socket_group):
            raise RequestRejected("invalid socket group")
        if type(timeout) is not int or not 1 <= timeout <= 24 * 60 * 60:
            raise RequestRejected("invalid timeout")
        if type(output_limit) is not int or not 1024 <= output_limit <= 16 * 1024 * 1024:
            raise RequestRejected("invalid output limit")
        return cls(benches=benches, allowed_uids=frozenset(raw_uids), socket_path=socket_path,
                   socket_group=socket_group, timeout_seconds=timeout, output_limit_bytes=output_limit)

    @classmethod
    def from_file(cls, path: str | Path) -> "HelperConfig":
        config_path = Path(path).resolve(strict=True)
        if not config_path.is_file():
            raise RequestRejected("helper config is not a file")
        metadata = config_path.stat()
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
            raise RequestRejected("helper config must be owned by the service uid and not writable by group or other")
        raw = config_path.read_bytes()
        if len(raw) > 256 * 1024:
            raise RequestRejected("helper config is too large")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RequestRejected("helper config is not valid JSON") from None
        return cls.from_mapping(value)


@dataclass(frozen=True)
class Operation:
    request_id: str
    bench_id: str
    name: str
    arguments: dict[str, Any]


def _require_exact(arguments: Any, keys: set[str]) -> dict[str, Any]:
    if not isinstance(arguments, dict) or set(arguments) != keys:
        raise RequestRejected("operation arguments do not match schema")
    return arguments


def _domain(value: Any, policy: HelperBenchPolicy) -> str:
    if not isinstance(value, str) or value != value.lower() or not _DOMAIN_RE.fullmatch(value):
        raise RequestRejected("invalid site domain")
    if not any(value.endswith(f".{suffix}") for suffix in policy.allowed_site_suffixes):
        raise RequestRejected("site domain is outside allowed suffixes")
    return value


def _site(value: Any, policy: HelperBenchPolicy, *, must_exist: bool) -> str:
    domain = _domain(value, policy)
    candidate = policy.sites_path / domain
    if must_exist:
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(policy.sites_path)
        except (OSError, ValueError):
            raise RequestRejected("site is not owned by the configured bench") from None
        if not resolved.is_dir() or resolved.is_symlink() or candidate.is_symlink():
            raise RequestRejected("site is not owned by the configured bench")
    elif candidate.exists() or candidate.is_symlink():
        raise RequestRejected("site already exists")
    return domain


def _boolean(value: Any) -> bool:
    if type(value) is not bool:
        raise RequestRejected("expected boolean")
    return value


def _config_value(value: Any) -> str | int | bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if not -(2**31) <= value < 2**31:
            raise RequestRejected("site config integer is out of range")
        return value
    if isinstance(value, str):
        if (
            not value or value != value.strip()
            or len(value.encode("utf-8")) > 2048
            or "\x00" in value or "\n" in value or "\r" in value
        ):
            raise RequestRejected("site config string is invalid")
        return value
    raise RequestRejected("site config value must be a string, integer, or boolean")


def _canonical_data_update_payload(value: Any) -> tuple[dict[str, Any], bytes]:
    if not isinstance(value, dict):
        raise RequestRejected("invalid data update payload")
    try:
        payload = DataUpdatePayload.model_validate(value)
        normalized = payload.model_dump(mode="json")
        canonical = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        supplied = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (ValidationError, TypeError, ValueError, RecursionError):
        raise RequestRejected("invalid data update payload") from None
    if canonical != supplied or len(canonical) > MAX_PAYLOAD_BYTES:
        raise RequestRejected("data update payload is not normalized")
    return normalized, canonical


def _data_update_arguments(
    arguments: Any, policy: HelperBenchPolicy
) -> dict[str, Any]:
    values = _require_exact(
        arguments,
        {
            "domain", "operation_id", "operation", "policy_id",
            "policy_version", "payload_hash", "payload",
        },
    )
    operation = values["operation"]
    policy_id = values["policy_id"]
    if operation not in _DATA_UPDATE_OPERATIONS:
        raise RequestRejected("unsupported data update operation")
    if operation not in policy.allowed_operations:
        raise RequestRejected("data update operation is not allowed for bench")
    if not isinstance(policy_id, str) or not _DATA_UPDATE_POLICY_ID_RE.fullmatch(policy_id):
        raise RequestRejected("invalid data update policy id")
    if not any(
        grant.policy_id == policy_id and grant.operation == operation
        for grant in policy.allowed_data_update_policies
    ):
        raise RequestRejected("data update policy is not allowlisted")
    operation_id = values["operation_id"]
    if not isinstance(operation_id, str) or not _DATA_UPDATE_OPERATION_ID_RE.fullmatch(operation_id):
        raise RequestRejected("invalid data update operation id")
    if values["policy_version"] != "1.0":
        raise RequestRejected("unsupported data update policy version")
    payload_hash = values["payload_hash"]
    if not isinstance(payload_hash, str) or not _DATA_UPDATE_HASH_RE.fullmatch(payload_hash):
        raise RequestRejected("invalid data update payload hash")
    payload, canonical = _canonical_data_update_payload(values["payload"])
    if hashlib.sha256(canonical).hexdigest() != payload_hash:
        raise RequestRejected("data update payload hash mismatch")
    return {
        "domain": _site(values["domain"], policy, must_exist=True),
        "operation_id": operation_id,
        "operation": operation,
        "policy_id": policy_id,
        "policy_version": "1.0",
        "payload_hash": payload_hash,
        "payload": payload,
    }


def _staging_path(value: Any, policy: HelperBenchPolicy, *, kind: str, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RequestRejected("invalid staging path")
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or "." in relative.parts:
        raise RequestRejected("staging path must be a normalized relative path")
    try:
        unresolved = policy.host_staging_path
        for part in relative.parts:
            unresolved = unresolved / part
            if unresolved.is_symlink():
                raise ValueError
        host_path = unresolved.resolve(strict=True)
        host_path.relative_to(policy.host_staging_path)
    except (OSError, ValueError):
        raise RequestRejected("staging path escapes the configured root") from None
    if kind == "file" and not host_path.is_file():
        raise RequestRejected("staging file does not exist")
    if kind == "directory" and not host_path.is_dir():
        raise RequestRejected("staging directory does not exist")
    return str(policy.container_staging_path.joinpath(*relative.parts))


def parse_request(raw: bytes, config: HelperConfig) -> Operation:
    """Parse one request; bench routing is resolved only from host-owned policy."""
    if not raw or len(raw) > 192 * 1024:
        raise RequestRejected("invalid request size")
    try:
        request = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RequestRejected("invalid JSON") from None
    if not isinstance(request, dict) or set(request) != {"version", "request_id", "bench_id", "operation", "arguments"}:
        raise RequestRejected("invalid request envelope")
    if request["version"] != 2:
        raise RequestRejected("unsupported protocol version")
    request_id = request["request_id"]
    if not isinstance(request_id, str) or not _REQUEST_ID_RE.fullmatch(request_id):
        raise RequestRejected("invalid request id")
    bench_id = request["bench_id"]
    if not isinstance(bench_id, str) or not _BENCH_ID_RE.fullmatch(bench_id):
        raise RequestRejected("invalid bench id")
    policy = config.bench(bench_id)
    name = request["operation"]
    if not isinstance(name, str) or name not in _HELPER_OPERATIONS:
        raise RequestRejected("unknown operation")
    if not (_POLICY_OPERATIONS[name] & policy.allowed_operations):
        raise RequestRejected("operation is not allowed for bench")
    arguments = request["arguments"]
    if name == "new_site":
        values = _require_exact(arguments, {"domain"})
        normalized = {"domain": _site(values["domain"], policy, must_exist=False)}
    elif name in {"enable_scheduler", "migrate_site", "verify_site"}:
        values = _require_exact(arguments, {"domain"})
        normalized = {"domain": _site(values["domain"], policy, must_exist=True)}
    elif name == "backup_site":
        values = _require_exact(arguments, {"domain", "with_files"})
        normalized = {
            "domain": _site(values["domain"], policy, must_exist=True),
            "with_files": _boolean(values["with_files"]),
        }
    elif name in {"scheduler_set", "maintenance_set"}:
        values = _require_exact(arguments, {"domain", "enabled"})
        normalized = {
            "domain": _site(values["domain"], policy, must_exist=True),
            "enabled": _boolean(values["enabled"]),
        }
        if name == "scheduler_set":
            direct = (
                "site.scheduler.enable" if normalized["enabled"]
                else "site.scheduler.disable"
            )
            internal = frozenset({
                "site.create", "site.create_blank", "site.create_from_backup",
                "site.restore", "site.reinstall", "site.delete", "site.migrate",
            })
        else:
            direct = (
                "site.maintenance.enable" if normalized["enabled"]
                else "site.maintenance.disable"
            )
            internal = frozenset({"site.restore", "site.reinstall", "site.delete", "site.migrate"})
        if direct not in policy.allowed_operations and not (
            internal & policy.allowed_operations
        ):
            raise RequestRejected("requested state transition is not allowed for bench")
    elif name == "config_set":
        values = _require_exact(arguments, {"domain", "key", "value"})
        key = values["key"]
        if not isinstance(key, str) or not _CONFIG_KEY_RE.fullmatch(key):
            raise RequestRejected("invalid site config key")
        if any(marker in key.casefold() for marker in _SENSITIVE_CONFIG_MARKERS):
            raise RequestRejected("sensitive site config keys are forbidden")
        if key not in policy.allowed_site_config_keys:
            raise RequestRejected("site config key is not allowlisted")
        normalized = {
            "domain": _site(values["domain"], policy, must_exist=True),
            "key": key,
            "value": _config_value(values["value"]),
        }
    elif name == "data_update":
        normalized = _data_update_arguments(arguments, policy)
    elif name == "drop_site":
        values = _require_exact(arguments, {"domain", "force", "no_backup"})
        normalized = {"domain": _site(values["domain"], policy, must_exist=True), "force": _boolean(values["force"]), "no_backup": _boolean(values["no_backup"])}
    elif name == "restore_site":
        values = _require_exact(arguments, {"domain", "backup_path", "force", "public_files_path", "private_files_path"})
        normalized = {
            "domain": _site(values["domain"], policy, must_exist=True),
            "backup_path": _staging_path(values["backup_path"], policy, kind="file"),
            "force": _boolean(values["force"]),
            "public_files_path": _staging_path(values["public_files_path"], policy, kind="file", optional=True),
            "private_files_path": _staging_path(values["private_files_path"], policy, kind="file", optional=True),
        }
    else:
        values = _require_exact(arguments, {"domain", "public_dir", "private_dir", "site_config_path"})
        normalized = {
            "domain": _site(values["domain"], policy, must_exist=True),
            "public_dir": _staging_path(values["public_dir"], policy, kind="directory", optional=True),
            "private_dir": _staging_path(values["private_dir"], policy, kind="directory", optional=True),
            "site_config_path": _staging_path(values["site_config_path"], policy, kind="file", optional=True),
        }
        if all(normalized[key] is None for key in ("public_dir", "private_dir", "site_config_path")):
            raise RequestRejected("at least one companion asset is required")
    return Operation(request_id=request_id, bench_id=bench_id, name=name, arguments=normalized)
