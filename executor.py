"""Privileged operation-to-command mapping and bounded subprocess execution."""

from __future__ import annotations

import json
import logging
import os
import secrets
import signal
import string
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from pydantic import ValidationError

from .data_update_contract import (
    DataUpdateEvidence,
    MAX_EVIDENCE_BYTES,
    MAX_EVIDENCE_RECORDS,
)

from .protocol import HelperBenchPolicy, HelperConfig, Operation

logger = logging.getLogger(__name__)

_SENSITIVE_FLAGS = {"--db-root-password", "--mariadb-root-password", "--admin-password"}
_ADMIN_ALPHABET = string.ascii_letters + string.digits

_COMPANION_SCRIPT = r'''
import json
import os
import shutil
from pathlib import Path

payload = json.load(__import__("sys").stdin)
domain = payload["domain"]
site_dir = Path(payload["sites_path"]) / domain
if not site_dir.is_dir():
    raise RuntimeError("target site directory was not found")

def replace_directory(source_value, target_name):
    if source_value is None:
        return
    source = Path(source_value)
    if not source.is_dir():
        raise RuntimeError("companion source directory was not found")
    target = site_dir / target_name
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(source, target)

replace_directory(payload["public_dir"], "public")
replace_directory(payload["private_dir"], "private")
source_path = payload["site_config_path"]
if source_path is not None:
    source = json.loads(Path(source_path).read_text())
    encryption_key = source.get("encryption_key")
    if not isinstance(encryption_key, str) or not encryption_key:
        raise RuntimeError("source config has no encryption key")
    target_file = site_dir / "site_config.json"
    target = json.loads(target_file.read_text()) if target_file.exists() else {}
    target["encryption_key"] = encryption_key
    temporary = target_file.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(target, indent=1, sort_keys=True) + "\n")
    os.replace(temporary, target_file)
'''


class ExecutionFailed(RuntimeError):
    """A fixed helper operation failed. Output is intentionally not public."""


class ExecutionTimedOut(ExecutionFailed):
    """A fixed helper operation exceeded the configured deadline."""


class ExecutionCancelled(ExecutionFailed):
    """A fixed helper operation was explicitly cancelled."""


@dataclass(frozen=True)
class BoundedResult:
    returncode: int
    stdout: str
    stderr: str


def _mask_command(command: list[str]) -> str:
    rendered: list[str] = []
    redact = False
    config_value_index = len(command) - 1 if "set-config" in command else -1
    for index, token in enumerate(command):
        if redact or index == config_value_index:
            rendered.append("***")
            redact = False
        elif token in _SENSITIVE_FLAGS:
            rendered.append(token)
            redact = True
        elif token == _COMPANION_SCRIPT:
            rendered.append("<fixed-companion-script>")
        else:
            rendered.append(token)
    return " ".join(rendered)


def _drain(stream: BinaryIO, limit: int, destination: bytearray) -> None:
    try:
        while chunk := stream.read(64 * 1024):
            remaining = limit - len(destination)
            if remaining > 0:
                destination.extend(chunk[:remaining])
    finally:
        stream.close()


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def run_fixed(
    command: list[str],
    config: HelperConfig,
    input_data: str | None = None,
    cancellation_event: threading.Event | None = None,
) -> BoundedResult:
    """Run an already allowlisted command with output and time bounds."""
    if cancellation_event is not None and cancellation_event.is_set():
        raise ExecutionCancelled("operation cancelled")
    logger.info("Executing host-helper operation: %s", _mask_command(command))
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    stdout = bytearray()
    stderr = bytearray()
    stdout_thread = threading.Thread(target=_drain, args=(process.stdout, config.output_limit_bytes, stdout), daemon=True)
    stderr_thread = threading.Thread(target=_drain, args=(process.stderr, config.output_limit_bytes, stderr), daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    if input_data is not None and process.stdin is not None:
        try:
            process.stdin.write(input_data.encode("utf-8"))
            process.stdin.flush()
        except BrokenPipeError:
            pass
        finally:
            process.stdin.close()
    deadline = time.monotonic() + config.timeout_seconds
    while True:
        returncode = process.poll()
        if returncode is not None:
            break
        if cancellation_event is not None and cancellation_event.is_set():
            _terminate(process)
            stdout_thread.join()
            stderr_thread.join()
            logger.info("Host-helper operation cancelled: %s", _mask_command(command))
            raise ExecutionCancelled("operation cancelled")
        if time.monotonic() >= deadline:
            _terminate(process)
            stdout_thread.join()
            stderr_thread.join()
            logger.error("Host-helper operation timed out: %s", _mask_command(command))
            raise ExecutionTimedOut("operation timed out")
        time.sleep(0.05)
    stdout_thread.join()
    stderr_thread.join()
    result = BoundedResult(
        returncode=returncode,
        stdout=stdout.decode("utf-8", errors="replace"),
        stderr=stderr.decode("utf-8", errors="replace"),
    )
    if returncode != 0:
        logger.error(
            "Host-helper operation failed (exit=%d stdout_chars=%d stderr_chars=%d): %s",
            returncode,
            len(result.stdout),
            len(result.stderr),
            _mask_command(command),
        )
        raise ExecutionFailed("operation failed")
    return result


def _read_db_password(path: Path) -> str:
    metadata = path.stat()
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise ExecutionFailed("database secret permissions are too broad")
    raw = path.read_bytes()
    if not raw or len(raw) > 4096:
        raise ExecutionFailed("database secret is invalid")
    try:
        password = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ExecutionFailed("database secret is invalid") from None
    if not password or "\x00" in password or "\n" in password:
        raise ExecutionFailed("database secret is invalid")
    return password


def _compose_command(policy: HelperBenchPolicy, bench_arguments: list[str]) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(policy.compose_file),
        "exec",
        "-T",
        policy.backend_service,
        *bench_arguments,
    ]


_DATA_UPDATE_RESULT_KEYS = frozenset({
    "contract_version", "operation_id", "operation", "policy_id",
    "policy_version", "payload_hash", "actor", "reason", "target", "dry_run",
    "maximum_rows", "matched_count", "affected_count", "result", "evidence",
    "evidence_truncated",
})


def _data_update_result(values: dict[str, object], output: str) -> dict[str, object]:
    try:
        result = json.loads(
            output,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (json.JSONDecodeError, TypeError, ValueError):
        raise ExecutionFailed("data update companion returned an invalid result") from None
    if not isinstance(result, dict) or set(result) != _DATA_UPDATE_RESULT_KEYS:
        raise ExecutionFailed("data update companion returned an invalid result")
    target = result["target"]
    if (
        result["contract_version"] != "1.0"
        or result["operation_id"] != values["operation_id"]
        or result["operation"] != values["operation"]
        or result["policy_id"] != values["policy_id"]
        or result["policy_version"] != values["policy_version"]
        or result["payload_hash"] != values["payload_hash"]
        or result["actor"] != "frappe-deploy-agent"
        or result["reason"] != values["payload"]["reason"]
        or target != {"site": values["domain"], "doctype": values["payload"]["doctype"]}
        or result["dry_run"] is not values["payload"]["dry_run"]
        or result["maximum_rows"] != values["payload"]["maximum_rows"]
    ):
        raise ExecutionFailed("data update companion result identity mismatch")
    matched = result["matched_count"]
    affected = result["affected_count"]
    if (
        type(matched) is not int
        or type(affected) is not int
        or not 0 <= affected <= matched <= values["payload"]["maximum_rows"]
    ):
        raise ExecutionFailed("data update companion returned invalid counts")
    result_kind = result["result"]
    dry_run = result["dry_run"]
    if (
        result_kind not in {"would_update", "updated", "no_changes"}
        or (result_kind == "no_changes" and affected != 0)
        or (result_kind == "would_update" and (dry_run is not True or affected == 0))
        or (result_kind == "updated" and (dry_run is not False or affected == 0))
    ):
        raise ExecutionFailed("data update companion returned invalid result semantics")
    evidence = result["evidence"]
    if not isinstance(evidence, list) or len(evidence) > MAX_EVIDENCE_RECORDS:
        raise ExecutionFailed("data update companion returned invalid evidence")
    normalized_evidence: list[dict[str, object]] = []
    changed_fields = set(values["payload"]["changes"])
    try:
        for item in evidence:
            validated = DataUpdateEvidence.model_validate(item)
            normalized = validated.model_dump(mode="json")
            if normalized != item or set(normalized["before"]) != changed_fields:
                raise ValueError
            normalized_evidence.append(normalized)
    except (ValidationError, TypeError, ValueError):
        raise ExecutionFailed("data update companion returned invalid evidence") from None
    names = [item["document_name"].casefold() for item in normalized_evidence]
    truncated = result["evidence_truncated"]
    if (
        len(set(names)) != len(names)
        or len(normalized_evidence) > affected
        or type(truncated) is not bool
        or truncated is not (len(normalized_evidence) < affected)
    ):
        raise ExecutionFailed("data update companion returned invalid evidence attribution")
    try:
        encoded = json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise ExecutionFailed("data update companion returned an invalid result") from None
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise ExecutionFailed("data update companion result exceeded its safety limit")
    result["evidence"] = normalized_evidence
    return result


def execute(
    operation: Operation,
    config: HelperConfig,
    cancellation_event: threading.Event | None = None,
) -> dict[str, object]:
    """Map a validated typed operation to a locally constructed command."""
    policy = config.bench(operation.bench_id)
    values = operation.arguments
    if operation.name == "new_site":
        password = _read_db_password(policy.db_root_password_file)
        admin_password = "".join(secrets.choice(_ADMIN_ALPHABET) for _ in range(16))
        domain = values["domain"]
        command = _compose_command(
            policy,
            [
                "bench",
                "new-site",
                "--mariadb-user-host-login-scope=%",
                "--db-root-password",
                password,
                "--db-name",
                domain.split(".", 1)[0],
                "--admin-password",
                admin_password,
                domain,
            ],
        )
        run_fixed(command, config, cancellation_event=cancellation_event)
        return {"admin_password": admin_password}

    if operation.name == "restore_site":
        password = _read_db_password(policy.db_root_password_file)
        command = _compose_command(
            policy,
            [
                "bench",
                "--site",
                values["domain"],
                "restore",
                "--mariadb-root-password",
                password,
                values["backup_path"],
            ],
        )
        if values["public_files_path"]:
            command.extend(["--with-public-files", values["public_files_path"]])
        if values["private_files_path"]:
            command.extend(["--with-private-files", values["private_files_path"]])
        if values["force"]:
            command.append("--force")
        result = run_fixed(command, config, input_data="y\n", cancellation_event=cancellation_event)
        return {"had_warnings": bool(result.stderr.strip())}

    if operation.name == "drop_site":
        password = _read_db_password(policy.db_root_password_file)
        command = _compose_command(
            policy,
            ["bench", "drop-site", values["domain"], "--mariadb-root-password", password],
        )
        if values["no_backup"]:
            command.append("--no-backup")
        if values["force"]:
            command.append("--force")
        run_fixed(command, config, cancellation_event=cancellation_event)
        return {}

    if operation.name == "enable_scheduler":
        run_fixed(
            _compose_command(policy, ["bench", "--site", values["domain"], "enable-scheduler"]),
            config,
            cancellation_event=cancellation_event,
        )
        return {}

    if operation.name == "backup_site":
        command = _compose_command(
            policy, ["bench", "--site", values["domain"], "backup"]
        )
        if values["with_files"]:
            command.append("--with-files")
        run_fixed(command, config, cancellation_event=cancellation_event)
        return {"completed": True}

    if operation.name == "migrate_site":
        run_fixed(
            _compose_command(policy, ["bench", "--site", values["domain"], "migrate"]),
            config,
            cancellation_event=cancellation_event,
        )
        return {"completed": True}

    if operation.name == "scheduler_set":
        action = "enable-scheduler" if values["enabled"] else "disable-scheduler"
        run_fixed(
            _compose_command(policy, ["bench", "--site", values["domain"], action]),
            config,
            cancellation_event=cancellation_event,
        )
        return {"enabled": values["enabled"]}

    if operation.name == "maintenance_set":
        state = "on" if values["enabled"] else "off"
        run_fixed(
            _compose_command(
                policy,
                ["bench", "--site", values["domain"], "set-maintenance-mode", state],
            ),
            config,
            cancellation_event=cancellation_event,
        )
        return {"enabled": values["enabled"]}

    if operation.name == "config_set":
        serialized = json.dumps(values["value"], separators=(",", ":"), ensure_ascii=False)
        run_fixed(
            _compose_command(
                policy,
                [
                    "bench", "--site", values["domain"], "set-config", "--parse",
                    values["key"], serialized,
                ],
            ),
            config,
            cancellation_event=cancellation_event,
        )
        return {"key": values["key"], "updated": True}

    if operation.name == "verify_site":
        run_fixed(
            _compose_command(
                policy, ["bench", "--site", values["domain"], "list-apps"]
            ),
            config,
            cancellation_event=cancellation_event,
        )
        return {"healthy": True}

    if operation.name == "data_update":
        payload = json.dumps(
            values["payload"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        command = _compose_command(
            policy,
            [
                "bench", "frappe-deploy-data-update",
                "--site", values["domain"],
                "--operation-id", values["operation_id"],
                "--operation", values["operation"],
                "--policy-id", values["policy_id"],
                "--payload-hash", values["payload_hash"],
            ],
        )
        result = run_fixed(
            command,
            config,
            input_data=payload,
            cancellation_event=cancellation_event,
        )
        return _data_update_result(values, result.stdout)

    if operation.name == "restore_companion_assets":
        payload = json.dumps({**values, "sites_path": str(policy.sites_path)}, separators=(",", ":"))
        run_fixed(
            _compose_command(policy, ["python", "-c", _COMPANION_SCRIPT]),
            config,
            input_data=payload,
            cancellation_event=cancellation_event,
        )
        return {}

    # Operation is normally constructed only by parse_request; retain fail-closed
    # behavior if another caller constructs it directly.
    raise ExecutionFailed("unsupported operation")
