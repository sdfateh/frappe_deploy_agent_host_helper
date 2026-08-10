"""Root-owned Unix-domain-socket server for typed Frappe operations."""

from __future__ import annotations

import argparse
import grp
import json
import logging
import os
import signal
import socket
import stat
import struct
import threading
from pathlib import Path
from types import FrameType

from .observability import configure_json_logging
from .executor import ExecutionCancelled, ExecutionFailed, ExecutionTimedOut, execute
from .protocol import HelperConfig, RequestRejected, parse_request

logger = logging.getLogger(__name__)
_MAX_REQUEST_BYTES = 192 * 1024
_MAX_RESPONSE_BYTES = 192 * 1024


def _peer_uid(connection: socket.socket) -> int | None:
    """Return the authenticated Unix peer uid on platforms supporting SO_PEERCRED."""
    if not hasattr(socket, "SO_PEERCRED"):
        return None
    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", credentials)
    return uid


def _read_request(connection: socket.socket) -> bytes:
    buffer = bytearray()
    while True:
        chunk = connection.recv(min(16 * 1024, _MAX_REQUEST_BYTES + 1 - len(buffer)))
        if not chunk:
            raise RequestRejected("incomplete request")
        buffer.extend(chunk)
        if len(buffer) > _MAX_REQUEST_BYTES:
            raise RequestRejected("request too large")
        newline = buffer.find(b"\n")
        if newline >= 0:
            if buffer[newline + 1 :].strip():
                raise RequestRejected("multiple requests per connection are not allowed")
            return bytes(buffer[:newline])


def _send(connection: socket.socket, response: dict[str, object]) -> None:
    encoded = json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n"
    # Responses contain only small typed results, never captured process output.
    if len(encoded) > _MAX_RESPONSE_BYTES:
        encoded = b'{"request_id":null,"ok":false,"error_code":"internal"}\n'
    try:
        connection.sendall(encoded)
    except OSError:
        # Cancellation is represented by a client disconnect; there may be no
        # peer left to receive the final typed response.
        logger.debug("Host-helper peer disconnected before response delivery")


def _best_effort_request_id(raw: bytes) -> str | None:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    request_id = value.get("request_id") if isinstance(value, dict) else None
    if isinstance(request_id, str) and len(request_id) == 32 and all(c in "0123456789abcdef" for c in request_id):
        return request_id
    return None


def _watch_disconnect(
    connection: socket.socket,
    cancellation_event: threading.Event,
    completed_event: threading.Event,
) -> None:
    """Cancel an active subprocess if the authenticated client goes away."""
    connection.settimeout(0.1)
    while not completed_event.is_set():
        try:
            if connection.recv(1, socket.MSG_PEEK) == b"":
                cancellation_event.set()
                return
        except socket.timeout:
            continue
        except OSError:
            cancellation_event.set()
            return


def handle_connection(connection: socket.socket, config: HelperConfig) -> None:
    request_id: str | None = None
    try:
        uid = _peer_uid(connection)
        if uid is not None and uid not in config.allowed_uids:
            logger.warning("Rejected host-helper peer uid=%d", uid)
            raise RequestRejected("peer uid is not allowed")
        raw = _read_request(connection)
        request_id = _best_effort_request_id(raw)
        operation = parse_request(raw, config)
        request_id = operation.request_id
        cancellation_event = threading.Event()
        completed_event = threading.Event()
        watcher = threading.Thread(
            target=_watch_disconnect,
            args=(connection, cancellation_event, completed_event),
            daemon=True,
        )
        watcher.start()
        try:
            result = execute(operation, config, cancellation_event=cancellation_event)
        finally:
            completed_event.set()
            watcher.join(timeout=0.2)
        _send(connection, {"request_id": request_id, "ok": True, "result": result})
    except RequestRejected:
        _send(connection, {"request_id": request_id, "ok": False, "error_code": "rejected"})
    except ExecutionTimedOut:
        _send(connection, {"request_id": request_id, "ok": False, "error_code": "timeout"})
    except ExecutionCancelled:
        _send(connection, {"request_id": request_id, "ok": False, "error_code": "cancelled"})
    except ExecutionFailed:
        _send(connection, {"request_id": request_id, "ok": False, "error_code": "execution"})
    except Exception:
        logger.exception("Unexpected host-helper failure")
        _send(connection, {"request_id": request_id, "ok": False, "error_code": "internal"})


def _prepare_socket(config: HelperConfig) -> socket.socket:
    if os.geteuid() != 0:
        raise RuntimeError("host helper must run as root")
    parent = config.socket_path.parent
    parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    parent_mode = stat.S_IMODE(parent.stat().st_mode)
    if parent_mode & 0o002:
        raise RuntimeError("socket parent directory must not be world-writable")
    if config.socket_path.exists() or config.socket_path.is_symlink():
        metadata = config.socket_path.lstat()
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != 0:
            raise RuntimeError("refusing to replace a non-root-owned socket path")
        config.socket_path.unlink()

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_umask = os.umask(0o117)
    try:
        listener.bind(str(config.socket_path))
    finally:
        os.umask(old_umask)
    group_id = grp.getgrnam(config.socket_group).gr_gid
    os.chown(config.socket_path, 0, group_id)
    os.chmod(config.socket_path, 0o660)
    listener.listen(16)
    listener.settimeout(1.0)
    return listener


def serve(config: HelperConfig) -> None:
    listener = _prepare_socket(config)
    stopping = False

    def stop(_signum: int, _frame: FrameType | None) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    logger.info("Host helper listening on %s", config.socket_path)
    try:
        while not stopping:
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(config.timeout_seconds + 10)
                handle_connection(connection, config)
    finally:
        listener.close()
        try:
            metadata = config.socket_path.lstat()
            if stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == 0:
                config.socket_path.unlink()
        except FileNotFoundError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Typed root-owned Frappe host helper")
    parser.add_argument("--config", required=True, help="Absolute path to the root-owned JSON config")
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    arguments = parser.parse_args()
    configure_json_logging(
        getattr(logging, arguments.log_level), component="host-helper"
    )
    config = HelperConfig.from_file(arguments.config)
    serve(config)


if __name__ == "__main__":
    main()
