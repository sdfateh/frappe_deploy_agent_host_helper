"""Strict, execution-free contract for allowlisted Frappe data updates.

This module deliberately contains no database, Frappe, shell, helper, or worker
integration.  It turns untrusted JSON into a normalized payload and authorizes
that payload against one administrator-owned local policy before producing a
hash suitable for approval and durable submission.
"""

# Vendored into this standalone repository from the agent data-update contract.
# Protocol changes must update and test both copies in the same release.

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, date, datetime
from enum import Enum
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


CONTRACT_VERSION = "1.0"
MAXIMUM_ROWS = 100
MAX_DOCUMENT_NAMES = 100
MAX_FILTERS = 20
MAX_FILTER_VALUES = 100
MAX_CHANGED_FIELDS = 32
MAX_REASON_BYTES = 500
MAX_JSON_VALUE_BYTES = 32 * 1024
MAX_PAYLOAD_BYTES = 128 * 1024
MAX_EVIDENCE_RECORDS = 20
MAX_EVIDENCE_BYTES = 128 * 1024

_STRICT = ConfigDict(extra="forbid", strict=True, frozen=True)
_FIELD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,139}$")
_DOCTYPE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9 _-]{0,139}$")
_POLICY_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_AGENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_BENCH_ID = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)

_SECRET_WORDS = frozenset(
    {
        "api_key",
        "api_secret",
        "auth",
        "authorization",
        "credential",
        "credentials",
        "encryption_key",
        "otp_secret",
        "passwd",
        "password",
        "private_key",
        "secret",
        "token",
    }
)
_SYSTEM_FIELDS = frozenset(
    {
        "_assign",
        "_comments",
        "_liked_by",
        "_seen",
        "_user_tags",
        "creation",
        "docstatus",
        "doctype",
        "idx",
        "modified",
        "modified_by",
        "name",
        "owner",
        "parent",
        "parentfield",
        "parenttype",
    }
)
_SCHEMA_FIELDS = frozenset(
    {
        "allow_on_submit",
        "autoname",
        "collapsible",
        "depends_on",
        "fetch_from",
        "fieldname",
        "fieldtype",
        "hidden",
        "in_list_view",
        "in_standard_filter",
        "mandatory_depends_on",
        "options",
        "permlevel",
        "read_only",
        "read_only_depends_on",
        "reqd",
        "unique",
    }
)
_AUTH_FIELDS = frozenset(
    {
        "api_key",
        "api_secret",
        "bypass_restrict_ip_check",
        "csrf_token",
        "last_active",
        "last_login",
        "login_after",
        "login_before",
        "reset_password_key",
        "role_profile_name",
        "roles",
        "simultaneous_sessions",
        "two_factor_auth",
        "username",
        "user_type",
    }
)
_FORBIDDEN_DOCTYPES = frozenset(
    {
        "agent certificate",
        "authentication log",
        "client script",
        "custom docperm",
        "custom field",
        "connected app",
        "docfield",
        "docperm",
        "doctype",
        "has role",
        "installed applications",
        "module def",
        "oauth bearer token",
        "oauth client",
        "oauth scope",
        "operation approval",
        "property setter",
        "role",
        "role profile",
        "role permission for page and report",
        "server script",
        "singles",
        "system settings",
        "user permission",
        "user",
    }
)

FilterOperator = Literal["eq", "ne", "in", "not_in", "lt", "lte", "gt", "gte"]
FieldValueType = Literal[
    "data",
    "small_text",
    "text",
    "long_text",
    "check",
    "int",
    "float",
    "currency",
    "percent",
    "date",
    "datetime",
    "select",
    "link",
    "dynamic_link",
    "json",
]


class DataUpdateOperation(str, Enum):
    STANDARD = "data.update"
    BREAK_GLASS = "data.update.break_glass"


def _utf8_size(value: str) -> int:
    return len(value.encode("utf-8"))


def _normalized_name(value: Any, *, kind: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{kind} must be a string")
    normalized = unicodedata.normalize("NFC", value)
    if value != normalized or value != value.strip() or not pattern.fullmatch(value):
        raise ValueError(f"invalid {kind}")
    return value


def _name_words(value: str) -> tuple[str, ...]:
    snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    normalized = re.sub(r"[^a-z0-9]+", "_", snake.casefold()).strip("_")
    words = tuple(part for part in normalized.split("_") if part)
    return words


def _secret_shaped(value: str) -> bool:
    normalized = "_".join(_name_words(value))
    words = set(_name_words(value))
    return normalized in _SECRET_WORDS or bool(
        words & {"password", "passwd", "secret", "token", "credential", "credentials", "authorization", "auth"}
    ) or normalized in {"api_key", "api_secret", "private_key", "encryption_key", "otp_secret"}


def _mutation_field(value: Any) -> str:
    field = _normalized_name(value, kind="field name", pattern=_FIELD_NAME)
    normalized = field.casefold()
    if (
        field.startswith("_")
        or normalized in _SYSTEM_FIELDS
        or normalized in _SCHEMA_FIELDS
        or normalized in _AUTH_FIELDS
        or _secret_shaped(field)
    ):
        raise ValueError("sensitive, authentication, schema, and system fields are forbidden")
    return field


def _doctype(value: Any) -> str:
    doctype = _normalized_name(value, kind="DocType", pattern=_DOCTYPE_NAME)
    normalized = doctype.casefold()
    if normalized in _FORBIDDEN_DOCTYPES or normalized.startswith(("oauth ", "integration request")) or _secret_shaped(doctype):
        raise ValueError("authentication, schema, and system DocTypes are forbidden")
    return doctype


def _bounded_text(value: Any, name: str, limit: int, *, allow_newlines: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    normalized = unicodedata.normalize("NFC", value)
    if normalized != value or value != value.strip() or not value or _utf8_size(value) > limit:
        raise ValueError(f"invalid or oversized {name}")
    if "\x00" in value or (not allow_newlines and any(mark in value for mark in ("\r", "\n"))):
        raise ValueError(f"invalid {name}")
    return value


def _json_value(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> Any:
    """Validate and NFC-normalize bounded JSON without coercing Python types."""

    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > 1000 or depth > 8:
        raise ValueError("JSON value is too complex")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if abs(value) > 10**38 - 1:
            raise ValueError("integer value is oversized")
        return value
    if type(value) is float:
        if not math.isfinite(value) or abs(value) > 1e100:
            raise ValueError("numeric value must be finite and bounded")
        return value
    if isinstance(value, str):
        normalized = unicodedata.normalize("NFC", value)
        if "\x00" in normalized or _utf8_size(normalized) > MAX_JSON_VALUE_BYTES:
            raise ValueError("string value is oversized or invalid")
        return normalized
    if isinstance(value, list):
        if len(value) > MAX_FILTER_VALUES:
            raise ValueError("JSON array exceeds its item limit")
        return [_json_value(item, depth=depth + 1, budget=budget) for item in value]
    if isinstance(value, Mapping):
        if len(value) > MAX_CHANGED_FIELDS:
            raise ValueError("JSON object exceeds its field limit")
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or key != key.strip() or _utf8_size(key) > 140:
                raise ValueError("invalid nested JSON field name")
            safe_key = unicodedata.normalize("NFC", key)
            if safe_key != key or _secret_shaped(safe_key):
                raise ValueError("secret-shaped nested JSON field names are forbidden")
            normalized[safe_key] = _json_value(item, depth=depth + 1, budget=budget)
        return normalized
    raise ValueError("value must be strict JSON data")


def _bounded_json(value: Any, limit: int, name: str) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError(f"{name} must be canonical JSON") from exc
    if len(encoded) > limit:
        raise ValueError(f"{name} exceeds its size limit")
    return encoded


def _timestamp(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 64:
        raise ValueError(f"invalid {name}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{name} must be an RFC3339 timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a timezone")
    return parsed.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


class DataUpdateFilter(BaseModel):
    model_config = _STRICT

    field: str
    operator: FilterOperator
    value: Any

    @field_validator("field")
    @classmethod
    def validate_field(cls, value: str) -> str:
        return _mutation_field(value)

    @field_validator("value", mode="before")
    @classmethod
    def validate_value(cls, value: Any) -> Any:
        normalized = _json_value(value)
        _bounded_json(normalized, MAX_JSON_VALUE_BYTES, "filter value")
        return normalized

    @model_validator(mode="after")
    def validate_operator_value(self) -> "DataUpdateFilter":
        if self.operator in {"in", "not_in"}:
            if not isinstance(self.value, list) or not self.value or len(self.value) > MAX_FILTER_VALUES:
                raise ValueError("in/not_in filters require a non-empty bounded array")
            if any(isinstance(item, (list, Mapping)) for item in self.value):
                raise ValueError("filter arrays may contain only scalar values")
        elif isinstance(self.value, (list, Mapping)):
            raise ValueError("scalar filter operator requires a scalar value")
        if self.operator in {"lt", "lte", "gt", "gte"} and self.value is None:
            raise ValueError("ordering filters cannot compare null")
        return self


class DataUpdatePayload(BaseModel):
    """Untrusted protocol payload; local policy authorization is still required."""

    model_config = _STRICT

    contract_version: Literal["1.0"]
    doctype: str
    document_names: list[str] | None = Field(default=None, max_length=MAX_DOCUMENT_NAMES)
    filters: list[DataUpdateFilter] | None = Field(default=None, max_length=MAX_FILTERS)
    changes: dict[str, Any] = Field(min_length=1, max_length=MAX_CHANGED_FIELDS)
    expected_modified: str | None = None
    dry_run: bool
    maximum_rows: int = Field(ge=1, le=MAXIMUM_ROWS)
    reason: str

    @field_validator("doctype")
    @classmethod
    def validate_doctype(cls, value: str) -> str:
        return _doctype(value)

    @field_validator("document_names", mode="before")
    @classmethod
    def validate_document_names(cls, value: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, list):
            raise ValueError("document_names must be an array")
        names = [_bounded_text(item, "document name", 140) for item in value]
        if len({item.casefold() for item in names}) != len(names):
            raise ValueError("duplicate document names are forbidden")
        return names

    @field_validator("changes", mode="before")
    @classmethod
    def validate_changes(cls, value: Any) -> Any:
        if not isinstance(value, Mapping) or not value:
            raise ValueError("changes must be a non-empty object")
        if len(value) > MAX_CHANGED_FIELDS:
            raise ValueError("changes exceeds its field limit")
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            field = _mutation_field(key)
            if field in normalized:
                raise ValueError("duplicate changed fields are forbidden")
            normalized[field] = _json_value(item)
        _bounded_json(normalized, MAX_PAYLOAD_BYTES, "changes")
        return normalized

    @field_validator("expected_modified")
    @classmethod
    def validate_expected_modified(cls, value: str | None) -> str | None:
        return None if value is None else _timestamp(value, "expected_modified")

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        return _bounded_text(value, "reason", MAX_REASON_BYTES)

    @model_validator(mode="after")
    def validate_selector(self) -> "DataUpdatePayload":
        has_names = bool(self.document_names)
        has_filters = bool(self.filters)
        if has_names == has_filters:
            raise ValueError("exactly one of document_names or filters is required")
        if self.expected_modified is not None and self.maximum_rows != 1:
            raise ValueError("expected_modified requires maximum_rows=1")
        if self.expected_modified is not None and self.document_names is not None and len(self.document_names) != 1:
            raise ValueError("expected_modified requires one document name")
        return self


class DataUpdateCommandPayload(BaseModel):
    """Exact controller command wrapper around one locally authorized mutation."""

    model_config = _STRICT

    policy_id: str
    payload: DataUpdatePayload

    @field_validator("policy_id")
    @classmethod
    def validate_policy_id(cls, value: str) -> str:
        if not isinstance(value, str) or not _POLICY_ID.fullmatch(value):
            raise ValueError("invalid local policy id")
        return value


class DataUpdateFieldPolicy(BaseModel):
    """Administrator-owned metadata for one explicitly usable Frappe field.

    Table, Password, Code, HTML, Attach, and other executable/sensitive Frappe
    field types are intentionally absent from ``FieldValueType``.
    """

    model_config = _STRICT

    fieldname: str
    field_type: FieldValueType
    mutable: bool = True
    filterable: bool = True
    nullable: bool = False
    maximum_string_bytes: int = Field(default=4096, ge=1, le=MAX_JSON_VALUE_BYTES)
    allowed_operators: tuple[FilterOperator, ...] = Field(default=("eq",), min_length=1, max_length=8)
    allowed_values: tuple[Any, ...] = Field(default=(), max_length=MAX_FILTER_VALUES)

    @field_validator("fieldname")
    @classmethod
    def validate_fieldname(cls, value: str) -> str:
        return _mutation_field(value)

    @field_validator("allowed_operators", mode="before")
    @classmethod
    def validate_operators(cls, value: Any) -> Any:
        if not isinstance(value, (list, tuple)):
            raise ValueError("allowed_operators must be an array")
        result = tuple(value)
        if len(set(result)) != len(result):
            raise ValueError("duplicate filter operators are forbidden")
        return result

    @field_validator("allowed_values", mode="before")
    @classmethod
    def validate_allowed_values(cls, value: Any) -> Any:
        if not isinstance(value, (list, tuple)):
            raise ValueError("allowed_values must be an array")
        return tuple(_json_value(item) for item in value)

    @model_validator(mode="after")
    def validate_field_policy(self) -> "DataUpdateFieldPolicy":
        if not self.mutable and not self.filterable:
            raise ValueError("an allowlisted field must be mutable or filterable")
        if self.field_type == "select" and not self.allowed_values:
            raise ValueError("select fields require explicit allowed_values")
        ordered_types = {"int", "float", "currency", "percent", "date", "datetime"}
        if self.field_type not in ordered_types and any(
            operator in {"lt", "lte", "gt", "gte"}
            for operator in self.allowed_operators
        ):
            raise ValueError("ordering operators require a numeric or temporal field")
        if self.field_type == "json" and any(
            operator not in {"eq", "ne"} for operator in self.allowed_operators
        ):
            raise ValueError("JSON fields support only eq/ne filters")
        if self.field_type == "json" and self.allowed_values:
            raise ValueError("JSON fields cannot use scalar allowed_values")
        for value in self.allowed_values:
            self.normalize_value(value)
        return self

    def normalize_value(self, value: Any) -> Any:
        if value is None:
            if self.nullable:
                return None
            raise ValueError(f"field {self.fieldname} is not nullable")

        kind = self.field_type
        if kind in {"data", "small_text", "text", "long_text", "select", "link", "dynamic_link"}:
            if not isinstance(value, str):
                raise ValueError(f"field {self.fieldname} requires a string")
            normalized: Any = unicodedata.normalize("NFC", value)
            if "\x00" in normalized or _utf8_size(normalized) > self.maximum_string_bytes:
                raise ValueError(f"field {self.fieldname} contains an oversized string")
        elif kind == "check":
            if type(value) is not bool:
                raise ValueError(f"field {self.fieldname} requires a boolean")
            normalized = value
        elif kind == "int":
            if type(value) is not int or abs(value) > 10**38 - 1:
                raise ValueError(f"field {self.fieldname} requires a bounded integer")
            normalized = value
        elif kind in {"float", "currency", "percent"}:
            if type(value) not in {int, float} or not math.isfinite(value) or abs(value) > 1e100:
                raise ValueError(f"field {self.fieldname} requires a finite bounded number")
            normalized = value
        elif kind == "date":
            if not isinstance(value, str):
                raise ValueError(f"field {self.fieldname} requires an ISO date")
            try:
                normalized = date.fromisoformat(value).isoformat()
            except ValueError:
                raise ValueError(f"field {self.fieldname} requires an ISO date") from None
        elif kind == "datetime":
            normalized = _timestamp(value, self.fieldname)
        elif kind == "json":
            normalized = _json_value(value)
        else:  # Literal validation makes this defensive only.
            raise ValueError("unsupported field type")

        if self.allowed_values and normalized not in self.allowed_values:
            raise ValueError(f"field {self.fieldname} value is outside local policy")
        return normalized


class DataUpdateDocTypePolicy(BaseModel):
    model_config = _STRICT

    doctype: str
    maximum_rows: int = Field(ge=1, le=MAXIMUM_ROWS)
    fields: tuple[DataUpdateFieldPolicy, ...] = Field(min_length=1, max_length=128)

    @field_validator("doctype")
    @classmethod
    def validate_doctype(cls, value: str) -> str:
        return _doctype(value)

    @field_validator("fields", mode="before")
    @classmethod
    def freeze_fields(cls, value: Any) -> Any:
        if not isinstance(value, (list, tuple)):
            raise ValueError("fields must be an array")
        return tuple(value)

    @model_validator(mode="after")
    def validate_unique_fields(self) -> "DataUpdateDocTypePolicy":
        names = [field.fieldname for field in self.fields]
        if len(set(names)) != len(names):
            raise ValueError("duplicate field policies are forbidden")
        return self


@dataclass(frozen=True, slots=True)
class AuthorizedDataUpdate:
    """Immutable authorization artifact; execute only its canonical JSON."""

    operation: DataUpdateOperation
    policy_id: str
    policy_version: str
    payload: DataUpdatePayload
    canonical_payload_json: bytes
    payload_hash: str

    def execution_payload(self) -> DataUpdatePayload:
        return DataUpdatePayload.model_validate_json(self.canonical_payload_json)


class LocalDataUpdatePolicy(BaseModel):
    """One frozen, administrator-owned standard or break-glass allowlist."""

    model_config = _STRICT

    policy_version: Literal["1.0"]
    policy_id: str
    operation: Literal["data.update", "data.update.break_glass"]
    maximum_rows: int = Field(ge=1, le=MAXIMUM_ROWS)
    doctypes: tuple[DataUpdateDocTypePolicy, ...] = Field(min_length=1, max_length=64)

    @field_validator("policy_id")
    @classmethod
    def validate_policy_id(cls, value: str) -> str:
        if not isinstance(value, str) or not _POLICY_ID.fullmatch(value):
            raise ValueError("invalid local policy id")
        return value

    @field_validator("doctypes", mode="before")
    @classmethod
    def freeze_doctypes(cls, value: Any) -> Any:
        if not isinstance(value, (list, tuple)):
            raise ValueError("doctypes must be an array")
        return tuple(value)

    @model_validator(mode="after")
    def validate_unique_doctypes(self) -> "LocalDataUpdatePolicy":
        names = [item.doctype for item in self.doctypes]
        if len(set(names)) != len(names):
            raise ValueError("duplicate DocType policies are forbidden")
        return self

    def authorize(
        self,
        value: DataUpdatePayload | Mapping[str, Any],
        *,
        operation: DataUpdateOperation | str,
    ) -> AuthorizedDataUpdate:
        try:
            selected_operation = DataUpdateOperation(operation)
        except (ValueError, TypeError):
            raise ValueError("unsupported data update operation") from None
        if selected_operation.value != self.operation:
            raise ValueError("standard and break-glass policies are not interchangeable")

        raw = value.model_dump(mode="json") if isinstance(value, DataUpdatePayload) else value
        payload = DataUpdatePayload.model_validate(raw)
        doctype_policy = next((item for item in self.doctypes if item.doctype == payload.doctype), None)
        if doctype_policy is None:
            raise ValueError("DocType is not approved by local policy")
        if payload.maximum_rows > min(self.maximum_rows, doctype_policy.maximum_rows):
            raise ValueError("maximum_rows exceeds local policy")

        field_policies = {item.fieldname: item for item in doctype_policy.fields}
        normalized_changes: dict[str, Any] = {}
        for name, value_item in payload.changes.items():
            field_policy = field_policies.get(name)
            if field_policy is None or not field_policy.mutable:
                raise ValueError("changed field is not approved by local policy")
            normalized_changes[name] = field_policy.normalize_value(value_item)

        normalized_filters: list[DataUpdateFilter] | None = None
        if payload.filters:
            normalized_filters = []
            for filter_item in payload.filters:
                field_policy = field_policies.get(filter_item.field)
                if field_policy is None or not field_policy.filterable:
                    raise ValueError("filter field is not approved by local policy")
                if filter_item.operator not in field_policy.allowed_operators:
                    raise ValueError("filter operator is not approved by local policy")
                if filter_item.operator in {"in", "not_in"}:
                    normalized_value = [field_policy.normalize_value(item) for item in filter_item.value]
                else:
                    normalized_value = field_policy.normalize_value(filter_item.value)
                normalized_filters.append(
                    DataUpdateFilter(field=filter_item.field, operator=filter_item.operator, value=normalized_value)
                )

        normalized_payload = DataUpdatePayload(
            **{
                **payload.model_dump(mode="python"),
                "changes": normalized_changes,
                "filters": normalized_filters,
            }
        )
        canonical = _bounded_json(
            normalized_payload.model_dump(mode="json"), MAX_PAYLOAD_BYTES, "data update payload"
        )
        return AuthorizedDataUpdate(
            operation=selected_operation,
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            payload=normalized_payload,
            canonical_payload_json=canonical,
            payload_hash=hashlib.sha256(canonical).hexdigest(),
        )


def authorize_data_update(
    value: DataUpdatePayload | Mapping[str, Any],
    *,
    operation: DataUpdateOperation | str,
    policy: LocalDataUpdatePolicy,
) -> AuthorizedDataUpdate:
    if not isinstance(policy, LocalDataUpdatePolicy):
        raise TypeError("a validated local data update policy is required")
    return policy.authorize(value, operation=operation)


def canonical_payload_hash(
    value: DataUpdatePayload | Mapping[str, Any],
    *,
    operation: DataUpdateOperation | str,
    policy: LocalDataUpdatePolicy,
) -> str:
    """Authorize first, then hash every normalized payload field without omission."""

    return authorize_data_update(value, operation=operation, policy=policy).payload_hash


class DataUpdateTarget(BaseModel):
    model_config = _STRICT

    agent_id: str
    bench_id: str
    site_id: str
    site_domain: str
    doctype: str

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, value: str) -> str:
        value = _bounded_text(value, "agent_id", 128)
        if not _AGENT_ID.fullmatch(value):
            raise ValueError("invalid agent_id")
        return value

    @field_validator("bench_id")
    @classmethod
    def validate_bench_id(cls, value: str) -> str:
        value = _bounded_text(value, "bench_id", 64)
        if not _BENCH_ID.fullmatch(value):
            raise ValueError("invalid bench_id")
        return value

    @field_validator("site_id")
    @classmethod
    def validate_site_id(cls, value: str) -> str:
        return _bounded_text(value, "site_id", 253)

    @field_validator("site_domain")
    @classmethod
    def validate_site_domain(cls, value: str) -> str:
        value = _bounded_text(value, "site_domain", 253)
        if value != value.casefold() or not _DOMAIN.fullmatch(value):
            raise ValueError("invalid site_domain")
        return value

    @field_validator("doctype")
    @classmethod
    def validate_doctype(cls, value: str) -> str:
        return _doctype(value)


class DataUpdateEvidence(BaseModel):
    model_config = _STRICT

    document_name: str
    before_modified: str
    after_modified: str | None = None
    before: dict[str, Any] = Field(min_length=1, max_length=MAX_CHANGED_FIELDS)
    after: dict[str, Any] = Field(min_length=1, max_length=MAX_CHANGED_FIELDS)

    @field_validator("document_name")
    @classmethod
    def validate_document_name(cls, value: str) -> str:
        return _bounded_text(value, "document name", 140)

    @field_validator("before_modified")
    @classmethod
    def validate_before_modified(cls, value: str) -> str:
        return _timestamp(value, "before_modified")

    @field_validator("after_modified")
    @classmethod
    def validate_after_modified(cls, value: str | None) -> str | None:
        return None if value is None else _timestamp(value, "after_modified")

    @field_validator("before", "after", mode="before")
    @classmethod
    def validate_values(cls, value: Any) -> Any:
        if not isinstance(value, Mapping) or not value:
            raise ValueError("evidence must contain a non-empty field map")
        normalized = {_mutation_field(key): _json_value(item) for key, item in value.items()}
        _bounded_json(normalized, MAX_JSON_VALUE_BYTES, "evidence record")
        return normalized

    @model_validator(mode="after")
    def validate_matching_fields(self) -> "DataUpdateEvidence":
        if set(self.before) != set(self.after):
            raise ValueError("before and after evidence fields must match")
        return self


class DataUpdateResult(BaseModel):
    """Bounded terminal result suitable for the existing durable result spool."""

    model_config = _STRICT

    contract_version: Literal["1.0"]
    operation_id: str
    operation: Literal["data.update", "data.update.break_glass"]
    policy_id: str
    policy_version: Literal["1.0"]
    payload_hash: str
    actor: str
    reason: str
    target: DataUpdateTarget
    dry_run: bool
    maximum_rows: int = Field(ge=1, le=MAXIMUM_ROWS)
    matched_count: int = Field(ge=0, le=MAXIMUM_ROWS)
    affected_count: int = Field(ge=0, le=MAXIMUM_ROWS)
    result: Literal["would_update", "updated", "no_changes"]
    evidence: list[DataUpdateEvidence] = Field(default_factory=list, max_length=MAX_EVIDENCE_RECORDS)
    evidence_truncated: bool = False

    @field_validator("operation_id")
    @classmethod
    def validate_operation_id(cls, value: str) -> str:
        if not isinstance(value, str) or not _UUID.fullmatch(value):
            raise ValueError("operation_id must be a canonical UUID")
        return value

    @field_validator("policy_id")
    @classmethod
    def validate_policy_id(cls, value: str) -> str:
        if not _POLICY_ID.fullmatch(value):
            raise ValueError("invalid policy_id")
        return value

    @field_validator("payload_hash")
    @classmethod
    def validate_payload_hash(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("payload_hash must be a SHA-256 digest")
        return value

    @field_validator("actor")
    @classmethod
    def validate_actor(cls, value: str) -> str:
        return _bounded_text(value, "actor", 253)

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        return _bounded_text(value, "reason", MAX_REASON_BYTES)

    @model_validator(mode="after")
    def validate_result_semantics(self) -> "DataUpdateResult":
        if self.matched_count > self.maximum_rows or self.affected_count > self.matched_count:
            raise ValueError("result counts exceed the approved bounds")
        if self.result == "no_changes" and self.affected_count != 0:
            raise ValueError("no_changes requires affected_count=0")
        if self.result == "would_update" and (not self.dry_run or self.affected_count == 0):
            raise ValueError("would_update requires a non-empty dry-run")
        if self.result == "updated" and (self.dry_run or self.affected_count == 0):
            raise ValueError("updated requires a non-empty actual mutation")
        if self.dry_run and any(item.after_modified is not None for item in self.evidence):
            raise ValueError("dry-run evidence cannot claim a persisted modified timestamp")
        if self.result == "updated" and any(item.after_modified is None for item in self.evidence):
            raise ValueError("updated evidence requires a persisted modified timestamp")
        names = [item.document_name.casefold() for item in self.evidence]
        if len(set(names)) != len(names):
            raise ValueError("duplicate evidence records are forbidden")
        if len(self.evidence) > self.affected_count:
            raise ValueError("evidence cannot exceed affected records")
        if self.evidence_truncated != (len(self.evidence) < self.affected_count):
            raise ValueError("evidence_truncated does not match evidence count")
        _bounded_json(self.model_dump(mode="json"), MAX_EVIDENCE_BYTES, "data update result")
        return self


__all__ = [
    "AuthorizedDataUpdate",
    "CONTRACT_VERSION",
    "DataUpdateDocTypePolicy",
    "DataUpdateCommandPayload",
    "DataUpdateEvidence",
    "DataUpdateFieldPolicy",
    "DataUpdateFilter",
    "DataUpdateOperation",
    "DataUpdatePayload",
    "DataUpdateResult",
    "DataUpdateTarget",
    "LocalDataUpdatePolicy",
    "authorize_data_update",
    "canonical_payload_hash",
]
