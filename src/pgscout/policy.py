"""Authorisation policy and audit log.

The policy is pure data plus pure checks; :class:`pgscout.gate.Gate` is the
single place that applies it to every tool call and resource read.
"""

from __future__ import annotations

import fnmatch
import json
import sys
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, TextIO

from .sqlguard import GuardedSql

DEFAULT_DENIED_COLUMNS = (
    "*password*",
    "passwd",
    "ssn",
    "*secret*",
    "*api_key*",
    "*token*",
    "card_number",
    "cvv",
)

SYSTEM_SCHEMAS = frozenset({"pg_catalog", "information_schema", "pg_toast"})
REDACTED = "[REDACTED]"


class PolicyDenied(PermissionError):
    """Raised when a call is outside what the policy allows."""


@dataclass(frozen=True)
class Policy:
    allowed_schemas: tuple[str, ...] = ("public",)
    denied_columns: tuple[str, ...] = DEFAULT_DENIED_COLUMNS
    max_rows: int = 200
    statement_timeout_ms: int = 5_000
    allow_explain_analyze: bool = False

    def __post_init__(self) -> None:
        if not self.allowed_schemas:
            raise ValueError("at least one schema must be allowed")
        if self.max_rows < 1 or self.statement_timeout_ms < 1:
            raise ValueError("max_rows and statement_timeout_ms must be positive")

    @property
    def default_schema(self) -> str:
        return self.allowed_schemas[0]

    def schema_allowed(self, schema: str) -> bool:
        return schema in self.allowed_schemas

    def check_schema(self, schema: str) -> None:
        if not self.schema_allowed(schema):
            raise PolicyDenied(f"schema {schema!r} is not in the allowlist")

    def column_denied(self, name: str) -> bool:
        lowered = name.lower()
        return any(fnmatch.fnmatchcase(lowered, pattern.lower()) for pattern in self.denied_columns)

    def check_sql(self, guarded: GuardedSql, known_schemas: Iterable[str]) -> None:
        """Reject statements that reach outside the allowlist or name denied columns."""
        schemas = set(known_schemas) | SYSTEM_SCHEMAS
        for qualifier in sorted(guarded.qualifiers):
            if qualifier in schemas and not self.schema_allowed(qualifier):
                raise PolicyDenied(f"schema {qualifier!r} is not in the allowlist")
        denied = sorted(name for name in guarded.identifiers if self.column_denied(name))
        if denied:
            raise PolicyDenied(f"query references denied column(s): {', '.join(denied)}")

    def max_rows_for(self, requested: Optional[int]) -> int:
        return self.max_rows if requested is None else max(1, min(requested, self.max_rows))

    def redact_rows(self, columns: list[str], rows: list[list[Any]]) -> tuple[list[list[Any]], list[str]]:
        """Replace values of denied columns. Returns new rows and the redacted column names."""
        hits = [i for i, name in enumerate(columns) if self.column_denied(name)]
        if not hits:
            return rows, []
        redacted_rows = []
        for row in rows:
            new_row = list(row)
            for i in hits:
                new_row[i] = REDACTED
            redacted_rows.append(new_row)
        return redacted_rows, [columns[i] for i in hits]

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed_schemas": list(self.allowed_schemas),
            "denied_columns": list(self.denied_columns),
            "max_rows": self.max_rows,
            "statement_timeout_ms": self.statement_timeout_ms,
            "allow_explain_analyze": self.allow_explain_analyze,
            "read_only": True,
        }


class AuditLog:
    """Append-only JSON lines audit log. Never writes to stdout (that is the protocol channel)."""

    def __init__(self, stream: Optional[TextIO] = None) -> None:
        self._stream = stream
        self._lock = threading.Lock()

    @classmethod
    def to_file(cls, path: str) -> AuditLog:
        return cls(open(path, "a", encoding="utf-8", buffering=1))

    @classmethod
    def to_stderr(cls) -> AuditLog:
        return cls(sys.stderr)

    def record(self, **fields: Any) -> dict[str, Any]:
        entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **fields}
        if self._stream is not None:
            line = json.dumps(entry, default=str, sort_keys=True)
            with self._lock:
                self._stream.write(line + "\n")
                self._stream.flush()
        return entry


@dataclass
class MemoryAuditLog(AuditLog):
    """Audit log that keeps entries in memory; used in tests."""

    entries: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        super().__init__(None)

    def record(self, **fields: Any) -> dict[str, Any]:
        entry = super().record(**fields)
        self.entries.append(entry)
        return entry
