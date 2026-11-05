#!/usr/bin/env python3
"""Read-only discovery of one local Docker Compose Frappe Bench."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


def run(*argv: str) -> str:
    result = subprocess.run(argv, check=True, text=True, capture_output=True)
    return result.stdout


def compose_document(path: Path) -> dict:
    return json.loads(run("docker", "compose", "-f", str(path), "config", "--format", "json"))


def is_frappe(document: dict) -> bool:
    services = document.get("services") or {}
    backends = [name for name in services if name == "backend" or "backend" in name.lower()]
    return any(any(str(mount.get("target", "")).rstrip("/").endswith("/sites") for mount in services[name].get("volumes", [])) for name in backends)


def route_directory(explicit: str | None) -> str:
    if explicit:
        path = Path(explicit)
    else:
        ids = run("docker", "ps", "--quiet").split()
        containers = json.loads(run("docker", "inspect", *ids)) if ids else []
        candidates = set()
        for container in containers:
            config = container.get("Config") or {}
            entrypoint, command = config.get("Entrypoint") or [], config.get("Cmd") or []
            if not isinstance(entrypoint, list) or not isinstance(command, list):
                continue
            args = entrypoint + command
            directories = []
            for index, arg in enumerate(args):
                if arg.lower().startswith("--providers.file.directory="):
                    directories.append(arg.split("=", 1)[1])
                elif arg.lower() == "--providers.file.directory" and index + 1 < len(args):
                    directories.append(args[index + 1])
            directories.extend(item.split("=", 1)[1] for item in config.get("Env", []) if item.startswith("TRAEFIK_PROVIDERS_FILE_DIRECTORY="))
            for directory in directories:
                for mount in container.get("Mounts", []):
                    destination = Path(mount.get("Destination", ""))
                    if mount.get("Type") != "bind" or not destination.is_absolute():
                        continue
                    try:
                        relative = Path(directory).relative_to(destination)
                    except ValueError:
                        continue
                    candidates.add(str(Path(mount["Source"]) / relative))
        if len(candidates) != 1:
            raise SystemExit("could not uniquely discover the Traefik file-provider directory; pass --traefik-dynamic-config-path /absolute/host/directory")
        path = Path(candidates.pop())
    if not path.is_absolute() or not path.is_dir() or path.is_symlink() or path.resolve() == Path("/"):
        raise SystemExit("Traefik route directory must be an existing absolute directory, not / or a symlink")
    return str(path.resolve())


def frontend_service(document: dict, explicit: str | None) -> str:
    if explicit:
        return explicit
    labels = (document.get("services", {}).get("frontend", {}) or {}).get("labels", {})
    if isinstance(labels, list):
        labels = dict(item.split("=", 1) for item in labels if "=" in item)
    names = {key[len("traefik.http.services."):-len(".loadbalancer.server.port")] for key in labels
             if key.startswith("traefik.http.services.") and key.endswith(".loadbalancer.server.port")}
    if len(names) != 1:
        raise SystemExit("could not uniquely discover the Traefik frontend service; pass --traefik-service NAME@docker")
    return names.pop() + "@docker"


def choose_compose(explicit: str | None) -> tuple[Path, str]:
    if explicit:
        path = Path(explicit)
        if not path.is_absolute() or path.is_symlink():
            raise SystemExit("Compose file must be absolute and not a symlink")
        return path.resolve(), ""
    projects = json.loads(run("docker", "compose", "ls", "--format", "json"))
    candidates = []
    for project in projects:
        files = str(project.get("ConfigFiles") or "").split(",")
        if files and files[0]:
            path = Path(files[0])
            if path.is_symlink():
                continue
            try:
                if is_frappe(compose_document(path)):
                    candidates.append((path.resolve(), str(project.get("Name") or ""), len(files)))
            except (subprocess.CalledProcessError, json.JSONDecodeError):
                continue
    if not candidates:
        raise SystemExit("no Docker Compose projects were found")
    if len(candidates) == 1:
        selected = candidates[0]
        if selected[2] != 1:
            raise SystemExit("selected project uses Compose overlays; provide a reviewed complete Compose file with --compose-file (overlays cannot be silently omitted)")
        return selected[:2]
    print("Detected Docker Compose projects:")
    for number, (path, name, count) in enumerate(candidates, 1):
        print(f"  {number}. {name or path.parent.name}: {path}")
    with open("/dev/tty", "r+", encoding="utf-8") as terminal:
        terminal.write("Select the Frappe project: ")
        terminal.flush()
        selected = terminal.readline().strip()
    if not selected.isdigit() or not 1 <= int(selected) <= len(candidates):
        raise SystemExit("invalid project selection")
    candidate = candidates[int(selected) - 1]
    if candidate[2] != 1:
        raise SystemExit("selected project uses Compose overlays; provide a reviewed complete Compose file with --compose-file (overlays cannot be silently omitted)")
    return candidate[:2]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose-file")
    parser.add_argument("--bench-id")
    parser.add_argument("--backend-service")
    parser.add_argument("--sites-path")
    parser.add_argument("--container-sites-path")
    parser.add_argument("--staging-path")
    parser.add_argument("--traefik-service")
    parser.add_argument("--traefik-dynamic-config-path")
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
    bench_id = args.bench_id or project_name.lower().replace("_", "-")[:64]
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?", bench_id):
        raise SystemExit("discovered Bench ID is invalid; pass --bench-id explicitly")
    host_sites = Path(sites_path)
    if not host_sites.is_absolute() or not host_sites.is_dir() or host_sites.is_symlink():
        raise SystemExit("sites mount must be an existing absolute host directory, not a symlink")
    staging = Path(args.staging_path or f"/var/lib/frappe-agent/staging/{project_name}")
    if not staging.is_absolute() or staging.is_symlink() or (staging.exists() and not staging.is_dir()):
        raise SystemExit("staging must be an absolute directory, not a symlink")
    frontend = frontend_service(document, args.traefik_service)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}@[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", frontend):
        raise SystemExit("Traefik service name is invalid")
    result = {
        "bench_id": bench_id,
        "compose_file": str(compose_file),
        "backend_service": backend,
        "sites_path": str(Path(sites_path).resolve()),
        "container_sites_path": container_sites_path,
        "staging_path": str(staging),
        "traefik_service": frontend,
        "traefik_dynamic_config_path": route_directory(args.traefik_dynamic_config_path),
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    args.output.chmod(0o600)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
