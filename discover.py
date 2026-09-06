#!/usr/bin/env python3
"""Read-only discovery of one local Docker Compose Frappe Bench."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def run(*argv: str) -> str:
    result = subprocess.run(argv, check=True, text=True, capture_output=True)
    return result.stdout


def compose_document(path: Path) -> dict:
    return json.loads(run("docker", "compose", "-f", str(path), "config", "--format", "json"))


def is_frappe(document: dict) -> bool:
    services = document.get("services") or {}
    return "backend" in services or len([name for name in services if "backend" in name.lower()]) == 1


def choose_compose(explicit: str | None) -> tuple[Path, str]:
    if explicit:
        return Path(explicit).resolve(), ""
    projects = json.loads(run("docker", "compose", "ls", "--format", "json"))
    candidates = []
    for project in projects:
        files = str(project.get("ConfigFiles") or "").split(",")
        if files and files[0]:
            path = Path(files[0]).resolve()
            try:
                if is_frappe(compose_document(path)):
                    candidates.append((path, str(project.get("Name") or "")))
            except (subprocess.CalledProcessError, json.JSONDecodeError):
                continue
    if not candidates:
        raise SystemExit("no Docker Compose projects were found")
    if len(candidates) == 1:
        return candidates[0]
    print("Detected Docker Compose projects:")
    for number, (path, name) in enumerate(candidates, 1):
        print(f"  {number}. {name or path.parent.name}: {path}")
    with open("/dev/tty", "r+", encoding="utf-8") as terminal:
        terminal.write("Select the Frappe project: ")
        terminal.flush()
        selected = terminal.readline().strip()
    if not selected.isdigit() or not 1 <= int(selected) <= len(candidates):
        raise SystemExit("invalid project selection")
    return candidates[int(selected) - 1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose-file")
    parser.add_argument("--backend-service")
    parser.add_argument("--sites-path")
    parser.add_argument("--container-sites-path")
    parser.add_argument("--staging-path")
    parser.add_argument("--traefik-service")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    compose_file, project_name = choose_compose(args.compose_file)
    if not compose_file.is_file() or compose_file.is_symlink():
        raise SystemExit("Compose file must be an existing regular file")
    document = compose_document(compose_file)
    services = document.get("services") or {}
    if args.backend_service:
        if args.backend_service not in services:
            raise SystemExit("explicit backend service does not exist in the Compose project")
        backend = args.backend_service
    elif "backend" in services:
        backend = "backend"
    else:
        names = [name for name in services if "backend" in name.lower()]
        if len(names) != 1:
            raise SystemExit("could not uniquely identify the Frappe backend service")
        backend = names[0]
    mounts = services[backend].get("volumes") or []
    sites_mounts = [item for item in mounts if str(item.get("target", "")).rstrip("/").endswith("/sites")]
    if args.sites_path and args.container_sites_path:
        sites_path = args.sites_path
        container_sites_path = args.container_sites_path
    else:
        if len(sites_mounts) != 1:
            raise SystemExit("could not uniquely identify the backend sites mount")
        mount = sites_mounts[0]
        source = str(mount.get("source") or "")
        container_sites_path = args.container_sites_path or str(mount["target"])
        if args.sites_path:
            sites_path = args.sites_path
        elif mount.get("type") == "volume":
            volume = (document.get("volumes") or {}).get(source) or {}
            volume_name = str(volume.get("name") or source)
            values = json.loads(run("docker", "volume", "inspect", volume_name))
            sites_path = values[0]["Mountpoint"]
        elif mount.get("type") == "bind":
            sites_path = source
        else:
            raise SystemExit("unsupported sites mount type")
    project_name = project_name or str(document.get("name") or compose_file.parent.name)
    result = {
        "bench_id": project_name.lower().replace("_", "-")[:64],
        "compose_file": str(compose_file),
        "backend_service": backend,
        "sites_path": str(Path(sites_path).resolve()),
        "container_sites_path": container_sites_path,
        "staging_path": args.staging_path or f"/var/lib/frappe-agent/staging/{project_name}",
        "traefik_service": args.traefik_service or f"{project_name}@docker",
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    args.output.chmod(0o600)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
