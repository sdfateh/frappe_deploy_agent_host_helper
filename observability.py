"""Bounded structured logging primitives for privileged agent processes."""

# Vendored into this standalone repository from the agent logging primitives.
# Security fixes to either copy must be applied to both in the same release.

from __future__ import annotations

import contextvars
import json
import logging
import re
import sys
import threading
import unicodedata
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, TextIO


MAX_MESSAGE_BYTES = 2048
MAX_FIELD_BYTES = 256
MAX_RECORD_BYTES = 8192
MAX_COLLECTION_ITEMS = 32
MAX_NESTING_DEPTH = 5

ALLOWED_CONTEXT_FIELDS = frozenset(
    {"component", "event", "agent_id", "operation_id", "bench_id"}
)
_SECRET_KEY_PARTS = frozenset(
    {
        "api_key",
        "api_secret",
        "authorization",
        "client_secret",
        "credential",
        "credentials",
        "db_password",
        "password",
        "private_key",
        "secret",
        "token",
    }
)
_PROHIBITED_DATA_KEYS = frozenset(
    {
        "command",
        "domain",
        "domains",
        "exception",
        "file",
        "filename",
        "output",
        "path",
        "payload",
        "site",
        "site_id",
        "site_ids",
        "stderr",
        "stdout",
        "traceback",
    }
)
_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,63}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_UUID_ANYWHERE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_LOGGER_ROOTS = frozenset(
    {
        "asyncio",
        "boto3",
        "botocore",
        "cloudflare",
        "core",
        "fastapi",
        "host_helper",
        "main",
        "redis",
        "routers",
        "services",
        "tests",
        "uvicorn",
        "worker",
    }
)
_STANDARD_LEVEL_NAMES = frozenset(
    {"CRITICAL", "DEBUG", "ERROR", "INFO", "NOTSET", "WARNING"}
)
_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s]+")
_WINDOWS_PATH = re.compile(r"(?i)(?<![A-Za-z0-9])[A-Z]:\\(?:[^\s\\]+\\)*[^\s\\]+")
_UNIX_PATH = re.compile(r"(?<![A-Za-z0-9:])/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+")
_DOMAIN = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9_-])"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passphrase|secret|token|authorization|credential|api[_-]?key|"
    r"api[_-]?secret|client[_-]?secret|db[_-]?password|private[_-]?key|domain|"
    r"site[_-]?id|path|filename|payload|command|stdout|stderr|output)"
    r"([\"']?\s*[:=]\s*[\"']?)([^\s,;\]\}]+)"
)
_PRIVATE_KEY_BLOCK = re.compile(
    r"(?is)-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----"
)

_context: contextvars.ContextVar[Mapping[str, str]] = contextvars.ContextVar(
    "frappe_agent_log_context", default={}
)
_configuration_lock = threading.Lock()


def _normalized_key(key: object) -> str:
    if not isinstance(key, str):
        return ""
    return re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")


def _is_redacted_key(key: object) -> bool:
    normalized = _normalized_key(key)
    if not normalized:
        return True
    padded = f"_{normalized}_"
    if any(f"_{part}_" in padded for part in _PROHIBITED_DATA_KEYS):
        return True
    return any(f"_{part}_" in padded for part in _SECRET_KEY_PARTS)


def _bounded_utf8(value: str, maximum: int) -> str:
    encoded = value.encode("utf-8", "replace")
    if len(encoded) <= maximum:
        return value
    suffix = "...<truncated>"
    remaining = max(0, maximum - len(suffix.encode("utf-8")))
    prefix = encoded[:remaining]
    while prefix:
        try:
            return prefix.decode("utf-8") + suffix
        except UnicodeDecodeError:
            prefix = prefix[:-1]
    return suffix[:maximum]


def _sanitize_text(value: str, *, maximum: int) -> str:
    visible = "".join(
        " " if unicodedata.category(character) in {"Cc", "Cf", "Cs"} else character
        for character in value
    )
    visible = _PRIVATE_KEY_BLOCK.sub("<redacted-private-key>", visible)
    visible = _BEARER.sub("Bearer <redacted>", visible)
    visible = _SECRET_ASSIGNMENT.sub(r"\1\2<redacted>", visible)
    visible = _URL.sub("<url>", visible)
    visible = _WINDOWS_PATH.sub("<path>", visible)
    visible = _UNIX_PATH.sub("<path>", visible)
    visible = _DOMAIN.sub("<domain>", visible)
    return _bounded_utf8(visible, maximum)


class _SanitizeBudget:
    def __init__(self) -> None:
        self.items = 0
        self.seen: set[int] = set()

    def claim(self) -> bool:
        self.items += 1
        return self.items <= MAX_COLLECTION_ITEMS


def _sanitize_value(value: Any, budget: _SanitizeBudget, depth: int = 0) -> Any:
    if depth > MAX_NESTING_DEPTH:
        return "<max-depth>"
    if value is None or type(value) in {bool, int}:
        return value
    if isinstance(value, float):
        return value if value == value and abs(value) != float("inf") else "<non-finite>"
    if isinstance(value, str):
        return _sanitize_text(value, maximum=MAX_FIELD_BYTES)
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"
    if isinstance(value, BaseException):
        return f"<{type(value).__name__}>"

    identity = id(value)
    if identity in budget.seen:
        return "<cycle>"
    if isinstance(value, Mapping):
        budget.seen.add(identity)
        output: dict[str, Any] = {}
        try:
            for raw_key, child in value.items():
                if not budget.claim():
                    output["_omitted"] = "<item-limit>"
                    break
                key = _sanitize_text(str(raw_key), maximum=64)
                if _is_redacted_key(raw_key):
                    output[key or "_redacted"] = "<redacted>"
                else:
                    output[key] = _sanitize_value(child, budget, depth + 1)
        finally:
            budget.seen.remove(identity)
        return output
    if isinstance(value, (list, tuple, set, frozenset)):
        budget.seen.add(identity)
        output_list: list[Any] = []
        try:
            for child in value:
                if not budget.claim():
                    output_list.append("<item-limit>")
                    break
                output_list.append(_sanitize_value(child, budget, depth + 1))
        finally:
            budget.seen.remove(identity)
        return output_list
    return f"<{type(value).__name__}>"


def sanitize_for_logging(value: Any) -> Any:
    """Return a bounded, cycle-safe value with prohibited keys removed."""

    return _sanitize_value(value, _SanitizeBudget())


def _context_value(key: str, value: object) -> str:
    if not isinstance(value, str):
        return "invalid"
    sanitized = _sanitize_text(value, maximum=128)
    if key in {"component", "event"}:
        if not _TOKEN.fullmatch(sanitized) or _UUID_ANYWHERE.search(sanitized):
            return "invalid"
    elif key == "operation_id":
        if not _UUID.fullmatch(sanitized):
            return "invalid"
    elif not _IDENTIFIER.fullmatch(sanitized):
        return "invalid"
    return sanitized


def _logger_name(value: str) -> str:
    sanitized = "".join(
        " " if unicodedata.category(character) in {"Cc", "Cf", "Cs"} else character
        for character in value
    )
    if (
        not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", sanitized)
        or sanitized.split(".", 1)[0] not in _LOGGER_ROOTS
    ):
        return "invalid"
    return sanitized


@contextmanager
def log_context(**fields: object) -> Iterator[None]:
    """Temporarily add only reviewed correlation fields to this context."""

    unknown = set(fields) - ALLOWED_CONTEXT_FIELDS
    if unknown:
        raise ValueError("unsupported logging context field")
    merged = dict(_context.get())
    for key, value in fields.items():
        merged[key] = _context_value(key, value)
    token = _context.set(merged)
    try:
        yield
    finally:
        _context.reset(token)


def _safe_message(record: logging.LogRecord) -> str:
    if isinstance(record.msg, str):
        if record.args:
            safe_arguments = sanitize_for_logging(record.args)
            try:
                if isinstance(record.args, Mapping):
                    rendered = record.msg % safe_arguments
                elif isinstance(safe_arguments, list):
                    rendered = record.msg % tuple(safe_arguments)
                else:
                    rendered = record.msg % safe_arguments
            except (TypeError, ValueError, KeyError):
                rendered = record.msg
        else:
            rendered = record.msg
        return _sanitize_text(rendered, maximum=MAX_MESSAGE_BYTES)
    sanitized = sanitize_for_logging(record.msg)
    try:
        rendered = json.dumps(
            sanitized, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    except (TypeError, ValueError, RecursionError):
        rendered = "<unrenderable-message>"
    return _sanitize_text(rendered, maximum=MAX_MESSAGE_BYTES)


class BoundedJSONFormatter(logging.Formatter):
    """Render one single-line JSON object with a strict maximum size."""

    def __init__(self, *, component: str) -> None:
        super().__init__()
        self.component = _context_value("component", component)

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )
        body: dict[str, Any] = {
            "timestamp": timestamp,
            "level": record.levelname if record.levelname in _STANDARD_LEVEL_NAMES else "INFO",
            "logger": _logger_name(record.name),
            "component": self.component,
            "message": _safe_message(record),
        }
        combined = dict(_context.get())
        for key in ALLOWED_CONTEXT_FIELDS:
            if key in record.__dict__:
                combined[key] = _context_value(key, record.__dict__[key])
        for key, value in combined.items():
            if key in ALLOWED_CONTEXT_FIELDS:
                body[key] = _context_value(key, value)
        if record.exc_info and record.exc_info[0] is not None:
            body["exception_class"] = _sanitize_text(
                record.exc_info[0].__name__, maximum=128
            )

        encoded = json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        if len(encoded.encode("utf-8")) > MAX_RECORD_BYTES:
            body["message"] = "<record-omitted-size-limit>"
            encoded = json.dumps(
                body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            )
        if len(encoded.encode("utf-8")) > MAX_RECORD_BYTES:
            encoded = json.dumps(
                {
                    "timestamp": timestamp,
                    "level": body["level"],
                    "component": self.component,
                    "message": "<record-omitted-size-limit>",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        return encoded


def configure_json_logging(
    level: str | int,
    *,
    component: str,
    stream: TextIO | None = None,
) -> logging.Handler:
    """Install one JSON handler on the root logger and return it."""

    if isinstance(level, str):
        resolved_level = logging.getLevelNamesMapping().get(level.upper())
    elif isinstance(level, int) and not isinstance(level, bool):
        resolved_level = level
    else:
        resolved_level = None
    if not isinstance(resolved_level, int):
        raise ValueError("invalid logging level")
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(BoundedJSONFormatter(component=component))
    with _configuration_lock:
        root = logging.getLogger()
        for existing in tuple(root.handlers):
            root.removeHandler(existing)
        root.addHandler(handler)
        root.setLevel(resolved_level)
    return handler
