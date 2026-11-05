#!/usr/bin/env python3
"""Enroll one Agent signing key without exposing its token or private key."""

from __future__ import annotations

import argparse
import getpass
import base64
import hashlib
import http.client
import json
import os
import re
import ssl
import stat
import subprocess
import tempfile
import time
import urllib.error
from pathlib import Path
from urllib.parse import urlsplit

AGENT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
ENDPOINT = "/api/method/frappe_controller.api.enrollment_routes.bootstrap_agent_route"
STATUS_ENDPOINT = "/api/method/frappe_controller.api.enrollment_routes.installation_status_route"
STATUS_CHECKS = {"agent_ready", "signed_heartbeat", "agent_inventory", "bench_inventory", "required_apps"}


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_json(path: Path, value: dict) -> None:
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=".enrollment-")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
        sync_directory(path.parent)
    finally:
        Path(name).unlink(missing_ok=True)


def protected(path: Path, *, directory: bool = False) -> None:
    metadata = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077:
        fail("enrollment state must be root-owned, private, and contain no symlinks")


def create_key(key: Path) -> None:
    descriptor, pending = tempfile.mkstemp(dir=key.parent, prefix=".key-")
    os.close(descriptor)
    try:
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", pending], check=True, capture_output=True)
        with open(pending, "rb") as source:
            os.fsync(source.fileno())
        os.replace(pending, key)
        sync_directory(key.parent)
    finally:
        Path(pending).unlink(missing_ok=True)


def post(controller: str, endpoint: str, body: bytes, headers: dict) -> bytes:
    parsed = urlsplit(controller)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        fail("Controller must be a plain HTTPS origin")
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=15, context=context)
    try:
        connection.request("POST", endpoint, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(1024 * 1024 + 1)
        # Never forward a token or signature through an HTTP redirect.
        if response.status != 200:
            raise urllib.error.HTTPError(controller + endpoint, response.status, "setup request rejected", {}, None)
    finally:
        connection.close()
    if len(raw) > 1024 * 1024:
        fail("Controller setup response is too large")
    return raw


def signed_status(controller: str, agent_id: str, key: Path, bench_id: str = "") -> dict:
    """Read policy/readiness using the pinned identity; never poll or lease work."""
    body = json.dumps({"agent_id": agent_id, "bench_id": bench_id}, separators=(",", ":")).encode()
    sequence = str(time.time_ns())
    canonical = f"frappe-agent-v1\n{agent_id}\nsetup:status\n{sequence}\n{hashlib.sha256(body).hexdigest()}".encode("ascii")
    # Ed25519 OpenSSL signing needs a regular input file on older OpenSSL releases.
    with tempfile.TemporaryDirectory(prefix="frappe-setup-sign-") as directory:
        source = Path(directory) / "request"
        source.write_bytes(canonical)
        signature = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(source)],
            check=True, capture_output=True,
        ).stdout
    raw = post(controller, STATUS_ENDPOINT, body, {
            "Content-Type": "application/json", "Accept": "application/json",
            "X-Frappe-Agent-ID": agent_id, "X-Frappe-Agent-Sequence": sequence,
            "X-Frappe-Agent-Signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
        })
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("Controller returned invalid setup JSON")
    if not isinstance(value, dict) or set(value) != {"accepted", "bootstrap", "ready", "checks", "bench_required_apps"} or type(value["ready"]) is not bool:
        fail("Controller returned invalid setup status")
    apps = value["bench_required_apps"]
    if (not isinstance(apps, list) or len(apps) > 32
        or any(not isinstance(app, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", app) for app in apps)
        or len(set(apps)) != len(apps) or (apps and apps[0] != "frappe")):
        fail("Controller returned invalid Bench app evidence")
    checks = value["checks"]
    if (not isinstance(checks, dict) or set(checks) != STATUS_CHECKS
        or any(type(item) is not bool for item in checks.values()) or value["ready"] != all(checks.values())):
        fail("Controller returned invalid setup evidence")
    validate_bootstrap({"accepted": value["accepted"], "bootstrap": value["bootstrap"]}, agent_id)
    return value


def fail(message: str) -> None:
    raise SystemExit(f"frappe Agent enrollment: {message}")


def token_from_file(path: Path) -> str:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
        fail("enrollment token file must be a root-owned regular file")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        fail("enrollment token file must use mode 0600")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        fail("enrollment token is empty")
    return value


def validate_bootstrap(value: object, agent_id: str) -> dict:
    if isinstance(value, dict) and set(value) == {"message"}:
        value = value["message"]
    outer_fields = {"accepted", "bootstrap"}
    if not isinstance(value, dict) or set(value) != outer_fields or value.get("accepted") is not True:
        fail("Controller rejected enrollment")
    bootstrap = value.get("bootstrap")
    if (
        not isinstance(bootstrap, dict)
        or set(bootstrap) != {"contract_version", "agent", "controller", "policy", "image"}
        or bootstrap.get("contract_version") not in ("1.0", "1.1")
    ):
        fail("Controller returned an unsupported bootstrap contract")
    agent = bootstrap.get("agent")
    controller = bootstrap.get("controller")
    policy = bootstrap.get("policy")
    image = bootstrap.get("image")
    if not all(isinstance(item, dict) for item in (agent, controller, policy, image)):
        fail("Controller returned an invalid bootstrap profile")
    if (
        set(agent) != {"agent_id", "audience", "protocol_version"}
        or set(controller) != {"url", "site_name"}
        or set(policy) != ({"allowed_site_suffixes", "allowed_operations"} | ({"required_apps"} if bootstrap["contract_version"] == "1.1" else set()))
        or set(image) != {"reference"}
    ):
        fail("Controller returned unknown bootstrap fields")
    if agent.get("agent_id") != agent_id or agent.get("audience") != "frappe-controller" or agent.get("protocol_version") != "1.0":
        fail("Controller returned a mismatched Agent identity")
    controller_url = controller.get("url")
    parsed_controller = urlsplit(controller_url) if isinstance(controller_url, str) else None
    if (
        parsed_controller is None or parsed_controller.scheme != "https"
        or not parsed_controller.hostname or parsed_controller.username
        or parsed_controller.password or parsed_controller.path not in {"", "/"}
        or parsed_controller.query or parsed_controller.fragment
    ):
        fail("Controller bootstrap URL must use HTTPS")
    suffixes = policy.get("allowed_site_suffixes")
    operations = policy.get("allowed_operations")
    domain = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
    if not isinstance(suffixes, list) or not 1 <= len(suffixes) <= 64 or not all(isinstance(x, str) and domain.fullmatch(x) for x in suffixes):
        fail("Controller returned no allowed site suffixes")
    if not isinstance(operations, list) or not 1 <= len(operations) <= 256 or not all(isinstance(x, str) and re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+", x) for x in operations):
        fail("Controller returned no allowed operations")
    apps = policy.get("required_apps", ["frappe"])
    if (not isinstance(apps, list) or not 1 <= len(apps) <= 32 or apps[0] != "frappe"
        or any(not isinstance(app, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", app) for app in apps)
        or len(set(apps)) != len(apps)):
        fail("Controller returned invalid required apps")
    if not isinstance(image.get("reference"), str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}@sha256:[0-9a-f]{64}", image["reference"]
    ):
        fail("Controller returned an invalid image reference")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--controller", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    controller = args.controller.rstrip("/")
    parsed = urlsplit(controller)
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username
        or parsed.password or parsed.path not in {"", "/"}
        or parsed.query or parsed.fragment
    ):
        fail("Controller must be a plain HTTPS origin")
    if not AGENT_ID.fullmatch(args.agent_id):
        fail("Agent ID is invalid")
    if not args.output.is_absolute():
        fail("enrollment state path must be absolute")
    # Check every existing ancestor before creating private durable state.
    for parent in reversed((args.output, *args.output.parents)):
        if parent.exists() or parent.is_symlink():
            metadata = parent.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
                fail("enrollment state ancestors must be root-owned directories without write access for others")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    protected(args.output, directory=True)
    key = args.output / "agent-signing-key.pem"
    public_key = args.output / "agent-signing-public.pem"
    bootstrap_file = args.output / "bootstrap.json"
    identity_file = args.output / "identity.json"
    expected_identity = {"agent_id": args.agent_id, "controller": controller}
    if identity_file.exists() or identity_file.is_symlink():
        protected(identity_file)
        if json.loads(identity_file.read_text()) != expected_identity:
            fail("saved enrollment belongs to another Controller or Agent")
    else:
        if key.exists() or key.is_symlink():
            fail("signing key has no matching enrollment identity")
        atomic_json(identity_file, expected_identity)
    existing = key.exists() or key.is_symlink()
    if args.prepare_only:
        if existing:
            protected(key)
        else:
            create_key(key)
        return 0
    if existing:
        protected(key)
        try:
            value = signed_status(controller, args.agent_id, key)
            if value["bootstrap"]["controller"]["url"].rstrip("/") != controller:
                fail("Controller returned a different HTTPS origin")
            atomic_json(bootstrap_file, value["bootstrap"])
            print(str(bootstrap_file))
            return 0
        except urllib.error.HTTPError as error:
            if bootstrap_file.exists() or error.code not in {401, 403}:
                fail(f"signed setup status rejected with HTTP {error.code}; saved identity retained")
        except (OSError, http.client.HTTPException):
            fail("could not reach Controller setup status; saved identity retained, rerun setup")
    else:
        # Never truncate a saved key, even after an interrupted setup.
        create_key(key)
    token = token_from_file(args.token_file) if args.token_file else getpass.getpass("One-time enrollment token: ")
    if not token:
        fail("enrollment token is empty")
    subprocess.run(
        ["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public_key)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    key.chmod(0o600)
    payload = json.dumps(
        {
            "protocol_version": "1.0",
            "bootstrap_contract_version": "1.1",
            "agent_id": args.agent_id,
            "enrollment_token": token,
            "signing_public_key_pem": public_key.read_text(encoding="ascii"),
        },
        separators=(",", ":"),
    ).encode("utf-8")
    del token
    raw = b""
    for attempt in range(3):
        try:
            raw = post(controller, ENDPOINT, payload, {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "frappe-agent/1.0"})
            break
        except urllib.error.HTTPError as error:
            fail(f"Controller rejected enrollment with HTTP {error.code}")
        except (OSError, http.client.HTTPException):
            if attempt == 2:
                fail("could not reach the Controller over trusted HTTPS")
            time.sleep(1)
    if len(raw) > 1024 * 1024:
        fail("Controller bootstrap response is too large")
    try:
        value = validate_bootstrap(json.loads(raw), args.agent_id)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("Controller returned invalid JSON")
    if value["bootstrap"]["controller"]["url"].rstrip("/") != controller:
        fail("Controller returned a different HTTPS origin; saved identity retained")
    atomic_json(bootstrap_file, value["bootstrap"])
    public_key.unlink()
    print(str(bootstrap_file))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
