#!/usr/bin/env python3
"""Enroll one Agent signing key without exposing its token or private key."""

from __future__ import annotations

import argparse
import getpass
import json
import re
import ssl
import stat
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

AGENT_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
ENDPOINT = "/api/method/frappe_controller.api.enrollment_routes.bootstrap_agent_route"


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
        or bootstrap.get("contract_version") != "1.0"
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
        or set(policy) != {"allowed_site_suffixes", "allowed_operations"}
        or set(image) != {"reference"}
    ):
        fail("Controller returned unknown bootstrap fields")
    if agent.get("agent_id") != agent_id or agent.get("audience") != "frappe-controller":
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
    if not isinstance(suffixes, list) or not suffixes or not all(isinstance(x, str) for x in suffixes):
        fail("Controller returned no allowed site suffixes")
    if not isinstance(operations, list) or not operations or not all(isinstance(x, str) for x in operations):
        fail("Controller returned no allowed operations")
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
    token = token_from_file(args.token_file) if args.token_file else getpass.getpass("One-time enrollment token: ")
    if not token:
        fail("enrollment token is empty")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = args.output / "agent-signing-key.pem"
    public_key = args.output / "agent-signing-public.pem"
    bootstrap_file = args.output / "bootstrap.json"
    subprocess.run(
        [
            "openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(key),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
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
            "agent_id": args.agent_id,
            "enrollment_token": token,
            "signing_public_key_pem": public_key.read_text(encoding="ascii"),
        },
        separators=(",", ":"),
    ).encode("utf-8")
    del token
    request = urllib.request.Request(
        f"{controller}{ENDPOINT}",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    raw = b""
    for attempt in range(3):
        try:
            with urllib.request.urlopen(
                request, timeout=30, context=ssl.create_default_context()
            ) as response:
                raw = response.read(1024 * 1024 + 1)
            break
        except urllib.error.HTTPError as error:
            fail(f"Controller rejected enrollment with HTTP {error.code}")
        except (urllib.error.URLError, TimeoutError):
            if attempt == 2:
                fail("could not reach the Controller over trusted HTTPS")
            time.sleep(1)
    if len(raw) > 1024 * 1024:
        fail("Controller bootstrap response is too large")
    try:
        value = validate_bootstrap(json.loads(raw), args.agent_id)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("Controller returned invalid JSON")
    bootstrap_file.write_text(json.dumps(value["bootstrap"], indent=2) + "\n", encoding="utf-8")
    bootstrap_file.chmod(0o600)
    public_key.unlink()
    print(str(bootstrap_file))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
