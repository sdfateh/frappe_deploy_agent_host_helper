#!/usr/bin/env python3
"""Apply Controller-approved Agent image digests from a root systemd timer."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ENV_FILE = Path("/etc/frappe-agent/agent.env")
COMPOSE_FILE = Path("/opt/frappe-deploy-agent/compose.yml")
SIGNING_KEY = Path("/etc/frappe-agent/signing/agent-signing-key.pem")
LOCK_FILE = Path("/run/frappe-agent-updater.lock")
AGENT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
UPGRADE_PATH = "/api/method/frappe_controller.api.agent_upgrade_routes.upgrade_route"


def fail(message: str) -> None:
    raise RuntimeError(message)


def read_env(path: Path) -> tuple[dict[str, str], list[str]]:
    if path.is_symlink() or not path.is_file():
        fail("Agent environment is missing or unsafe")
    metadata = path.stat()
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077:
        fail("Agent environment must be root-owned with mode 0600")
    values: dict[str, str] = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in line:
            fail("Agent environment contains an invalid line")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in values:
            fail("Agent environment contains an invalid or duplicate key")
        values[key] = value
    return values, lines


def required(values: dict[str, str], key: str) -> str:
    value = values.get(key, "")
    if not value:
        fail(f"{key} is required")
    return value


def identity(values: dict[str, str]) -> tuple[str, str, ssl.SSLContext, Ed25519PrivateKey]:
    controller = required(values, "CONTROLLER_URL").rstrip("/")
    parsed = urlsplit(controller)
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username
        or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
    ):
        fail("CONTROLLER_URL must be a plain trusted HTTPS origin")
    agent_id = required(values, "AGENT_ID")
    if not AGENT_ID.fullmatch(agent_id):
        fail("AGENT_ID is invalid")
    if SIGNING_KEY.is_symlink() or not SIGNING_KEY.is_file():
        fail("Agent signing key is missing or unsafe")
    try:
        key = serialization.load_pem_private_key(SIGNING_KEY.read_bytes(), password=None)
    except (OSError, ValueError):
        fail("Agent signing key could not be loaded")
    if not isinstance(key, Ed25519PrivateKey):
        fail("Agent signing key must be Ed25519")
    context = ssl.create_default_context(
        cafile=values.get("CONTROLLER_CA_CERTIFICATE_PATH") or None
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return controller, agent_id, context, key


def unwrap(raw: bytes) -> dict:
    if len(raw) > 65536:
        fail("Controller upgrade response is too large")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("Controller returned invalid upgrade JSON")
    if isinstance(payload, dict) and set(payload) == {"message"}:
        payload = payload["message"]
    if not isinstance(payload, dict) or payload.get("accepted") is not True:
        fail("Controller rejected upgrade request")
    return payload


def request(values: dict[str, str], action: str, digest: str) -> dict:
    controller, agent_id, context, key = identity(values)
    body = json.dumps(
        {"agent_id": agent_id, "action": action, "observed_image_digest": digest},
        separators=(",", ":"),
    ).encode("utf-8")
    sequence = str(time.time_ns())
    canonical = (
        f"frappe-agent-v1\n{agent_id}\nupgrade\n{sequence}\n"
        f"{hashlib.sha256(body).hexdigest()}"
    ).encode("ascii")
    signature = base64.urlsafe_b64encode(key.sign(canonical)).rstrip(b"=").decode("ascii")
    req = urllib.request.Request(
        f"{controller}{UPGRADE_PATH}", data=body, method="POST",
        headers={
            "Content-Type": "application/json", "Accept": "application/json",
            "X-Frappe-Agent-ID": agent_id,
            "X-Frappe-Agent-Sequence": sequence,
            "X-Frappe-Agent-Signature": signature,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30, context=context) as response:
            raw = response.read(65537)
    except urllib.error.HTTPError as error:
        raw = error.read(65537)
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {}
        code = payload.get("error") or payload.get("message", {}).get("error")
        if error.code == 409 and code == "upgrade_verification_pending":
            return {"accepted": True, "action": "none", "upgrade_state": "verifying"}
        fail(f"Controller rejected upgrade request ({error.code}, {code or 'unknown_error'})")
    except (urllib.error.URLError, TimeoutError) as error:
        fail(f"Controller upgrade endpoint is unavailable: {error}")
    return unwrap(raw)


def replace_digest(lines: list[str], digest: str) -> None:
    if not DIGEST.fullmatch(digest):
        fail("Controller supplied an invalid image digest")
    indexes = [i for i, line in enumerate(lines) if line.startswith("AGENT_IMAGE_DIGEST=")]
    if len(indexes) != 1:
        fail("Agent environment must contain AGENT_IMAGE_DIGEST exactly once")
    updated = list(lines)
    updated[indexes[0]] = f"AGENT_IMAGE_DIGEST={digest}"
    backup = ENV_FILE.with_suffix(".env.previous")
    if backup.is_symlink():
        fail("refusing to replace a symlinked Agent environment backup")
    shutil.copy2(ENV_FILE, backup, follow_symlinks=False)
    descriptor, temporary = tempfile.mkstemp(prefix=".agent.env.", dir=ENV_FILE.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write("\n".join(updated) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.chown(temporary, 0, 0)
        os.replace(temporary, ENV_FILE)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def compose(*arguments: str) -> None:
    subprocess.run(
        ["docker", "compose", "--env-file", str(ENV_FILE), "--file", str(COMPOSE_FILE), *arguments],
        check=True,
        timeout=300,
    )


def deploy(values: dict[str, str], lines: list[str], target: str, action: str) -> None:
    current = required(values, "AGENT_IMAGE_DIGEST")
    if not DIGEST.fullmatch(current) or not DIGEST.fullmatch(target):
        fail("current or desired image digest is invalid")
    if target == current:
        request(values, "deployed", target)
        return
    replace_digest(lines, target)
    try:
        compose("pull")
        compose("up", "--detach", "--wait", "--wait-timeout", "120")
        new_values, _ = read_env(ENV_FILE)
        request(new_values, "deployed", target)
    except Exception:
        if action == "rollback":
            raise
        try:
            request(values, "failed", current)
        finally:
            _, restored_lines = read_env(ENV_FILE)
            replace_digest(restored_lines, current)
            compose("pull")
            compose("up", "--detach", "--wait", "--wait-timeout", "120")
            old_values, _ = read_env(ENV_FILE)
            request(old_values, "deployed", current)
        raise


def main() -> int:
    if os.geteuid() != 0:
        fail("updater must run as root")
    LOCK_FILE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    with LOCK_FILE.open("w", encoding="ascii") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        values, lines = read_env(ENV_FILE)
        current = required(values, "AGENT_IMAGE_DIGEST")
        if not DIGEST.fullmatch(current):
            fail("AGENT_IMAGE_DIGEST is invalid")
        instruction = request(values, "poll", current)
        action = instruction.get("action")
        if action in {None, "none"}:
            return 0
        target = instruction.get("image_digest")
        if action in {"deploy", "rollback"} and isinstance(target, str):
            deploy(values, lines, target, action)
            return 0
        if action == "verify" and target == current:
            request(values, "verify", current)
            return 0
        fail("Controller returned an invalid upgrade instruction")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"frappe-agent updater: {error}", file=sys.stderr)
        raise SystemExit(1)
