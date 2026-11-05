#!/usr/bin/env python3
"""Bounded, read-only installation checks. Never leases or executes operations."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time

try:
    from .bootstrap import signed_status
except ImportError:
    from bootstrap import signed_status


def environment(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file() or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
        raise ValueError("unsafe Agent environment")
    values = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or name in values:
            raise ValueError("invalid Agent environment")
        values[name] = value
    return values


def output(*argv: str) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=20).stdout.strip()


def runtime_check(values: dict[str, str], *, env: Path, compose: Path) -> bool:
    ids = output("docker", "compose", "--env-file", str(env), "--file", str(compose), "ps", "--all", "--quiet", "frappe-deploy-agent").split()
    if len(ids) != 1:
        return False
    containers = json.loads(output("docker", "inspect", ids[0]))
    container = containers[0]
    reference = values["AGENT_IMAGE_REPOSITORY"] + "@sha256:" + values["AGENT_IMAGE_DIGEST"]
    image = output("docker", "image", "inspect", "--format", "{{.Id}}", reference)
    state = container.get("State", {})
    return (state.get("Running") is True and state.get("Health", {}).get("Status") == "healthy"
            and container.get("Config", {}).get("Image") == reference and container.get("Image") == image)


def controller_check(values: dict[str, str], *, policy: Path, signing_key: Path) -> bool:
    if policy.is_symlink() or signing_key.is_symlink():
        return False
    benches = json.loads(policy.read_text())["benches"]
    if not benches:
        return False
    for bench in benches:
        result = signed_status(values["CONTROLLER_URL"], values["AGENT_ID"], signing_key, bench["bench_id"])
        bootstrap = result["bootstrap"]
        remote = bootstrap["policy"]
        if (not result["ready"] or bootstrap["controller"]["url"].rstrip("/") != values["CONTROLLER_URL"].rstrip("/")
            or result["bench_required_apps"] != bench.get("required_apps", ["frappe"])
            or not set(bench["allowed_operations"]).issubset(remote["allowed_operations"])
            or not all(any(suffix == allowed or suffix.endswith("." + allowed) for allowed in remote["allowed_site_suffixes"]) for suffix in bench["allowed_site_suffixes"])):
            return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("check", choices=["runtime", "controller"])
    parser.add_argument("--env", type=Path, default=Path("/etc/frappe-agent/agent.env"))
    parser.add_argument("--compose", type=Path, default=Path("/opt/frappe-deploy-agent/compose.yml"))
    parser.add_argument("--policy", type=Path, default=Path("/etc/frappe-deploy-agent/host-helper.json"))
    parser.add_argument("--signing-key", type=Path, default=Path("/etc/frappe-agent/signing/agent-signing-key.pem"))
    parser.add_argument("--timeout", type=int, default=0)
    args = parser.parse_args()
    if not 0 <= args.timeout <= 600:
        parser.error("timeout must be between 0 and 600")
    deadline = time.monotonic() + args.timeout
    while True:
        try:
            values = environment(args.env)
            healthy = runtime_check(values, env=args.env, compose=args.compose) if args.check == "runtime" else controller_check(values, policy=args.policy, signing_key=args.signing_key)
            if healthy:
                return 0
        except (Exception, SystemExit):
            # Do not echo provider bodies, signatures, env contents, or secret paths.
            pass
        if time.monotonic() >= deadline:
            print("Agent check failed: " + args.check + "; inspect service health, inventory feature/policy and Controller connectivity", file=sys.stderr)
            return 1
        time.sleep(min(5, max(0, deadline - time.monotonic())))


if __name__ == "__main__":
    raise SystemExit(main())
