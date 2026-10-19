"""The single authorisation choke point.

Every tool call and resource read goes through :class:`Gate`, in this order:

1. validate arguments against the tool's input schema
2. check any ``schema`` argument against the allowlist
3. guard any ``sql`` argument (single read-only statement) and apply the
   policy to it (allowlisted schemas, denied columns)
4. run the handler
5. redact denied columns in tabular results
6. write one audit record, whatever the outcome
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Optional

from .db import Database, DatabaseError
from .policy import AuditLog, Policy, PolicyDenied
from .sqlguard import SqlRejected, guard
from .tools import TOOLS, ToolContext, ToolError, ToolSpec
from .validation import ValidationError, validate

log = logging.getLogger(__name__)

RESOURCE_PREFIX = "pgscout://"
POLICY_URI = "pgscout://policy"
SCHEMA_URI_PREFIX = "pgscout://schema/"
_AUDIT_SQL_CHARS = 2_000


class UnknownTool(KeyError):
    pass


class UnknownResource(KeyError):
    pass


@dataclass
class Outcome:
    ok: bool
    payload: dict[str, Any]

    @property
    def text(self) -> str:
        return json.dumps(self.payload, default=to_jsonable, ensure_ascii=False)


def to_jsonable(value: Any) -> Any:
    """``json.dumps`` default for values that come back from PostgreSQL."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "\\x" + bytes(value).hex()
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, (set, frozenset, tuple)):
        return list(value)
    return str(value)  # Decimal, UUID, ranges, inet ...


class Gate:
    def __init__(
        self,
        db: Database,
        policy: Policy,
        audit: Optional[AuditLog] = None,
        tools: Iterable[ToolSpec] = TOOLS,
    ) -> None:
        self.db = db
        self.policy = policy
        self.audit = audit or AuditLog()
        self.tools = {t.name: t for t in tools}

    # -- tools -----------------------------------------------------------

    def list_tools(self) -> list[dict[str, Any]]:
        return [t.describe() for t in self.tools.values()]

    def call_tool(self, name: str, arguments: Optional[dict[str, Any]]) -> Outcome:
        spec = self.tools.get(name)
        if spec is None:
            raise UnknownTool(name)
        started = time.monotonic()
        decision, reason, outcome = "allowed", None, None
        try:
            args = validate(arguments if arguments is not None else {}, spec.input_schema)
            if "schema" in args:
                self.policy.check_schema(args["schema"])
            ctx = ToolContext(self.db, self.policy)
            if spec.sql_mode is not None:
                ctx.guarded = guard(
                    args["sql"],
                    allow_explain=spec.sql_mode == "query",
                    allow_explain_analyze=self.policy.allow_explain_analyze,
                )
                self.policy.check_sql(ctx.guarded, self.db.list_schemas())
            if args.get("analyze") and not self.policy.allow_explain_analyze:
                raise PolicyDenied("EXPLAIN ANALYZE executes the query and is disabled by policy")
            payload = self._redact(spec.handler(ctx, args))
            outcome = Outcome(True, payload)
        except (ValidationError, SqlRejected, PolicyDenied) as exc:
            decision, reason = "denied", str(exc)
            outcome = Outcome(False, {"error": reason, "type": type(exc).__name__})
        except (ToolError, DatabaseError) as exc:
            decision, reason = "error", str(exc)
            outcome = Outcome(False, {"error": reason, "type": type(exc).__name__})
        except Exception:
            log.exception("tool %s failed", name)
            decision, reason = "error", "internal error"
            outcome = Outcome(False, {"error": "internal error", "type": "InternalError"})
        finally:
            self._audit(
                "tool",
                name,
                arguments,
                decision,
                reason,
                started,
                rows=outcome.payload.get("row_count") if outcome else None,
            )
        return outcome

    def _redact(self, payload: dict[str, Any]) -> dict[str, Any]:
        columns, rows = payload.get("columns"), payload.get("rows")
        if isinstance(rows, list) and isinstance(columns, list) and all(isinstance(c, str) for c in columns):
            payload["rows"], redacted = self.policy.redact_rows(columns, rows)
            payload["redacted_columns"] = redacted
        return payload

    # -- resources -------------------------------------------------------

    def list_resources(self) -> list[dict[str, Any]]:
        resources = [
            {
                "uri": POLICY_URI,
                "name": "policy",
                "title": "Effective access policy",
                "mimeType": "application/json",
            }
        ]
        existing = set(self.db.list_schemas())
        for schema in self.policy.allowed_schemas:
            if schema in existing:
                resources.append(
                    {
                        "uri": SCHEMA_URI_PREFIX + schema,
                        "name": f"schema-{schema}",
                        "title": f"Tables in schema {schema}",
                        "mimeType": "application/json",
                    }
                )
        return resources

    def read_resource(self, uri: str) -> str:
        started = time.monotonic()
        decision, reason = "allowed", None
        try:
            if uri == POLICY_URI:
                return json.dumps(self.policy.as_dict())
            if uri.startswith(SCHEMA_URI_PREFIX):
                schema = uri[len(SCHEMA_URI_PREFIX) :]
                try:
                    self.policy.check_schema(schema)
                except PolicyDenied as exc:
                    decision, reason = "denied", str(exc)
                    raise UnknownResource(uri) from exc
                tables = [
                    {"name": t.name, "kind": t.kind, "estimated_rows": t.estimated_rows}
                    for t in self.db.list_tables(schema)
                ]
                return json.dumps({"schema": schema, "tables": tables})
            decision, reason = "denied", "unknown resource"
            raise UnknownResource(uri)
        except DatabaseError as exc:
            decision, reason = "error", str(exc)
            raise
        finally:
            self._audit("resource", uri, None, decision, reason, started)

    # -- audit -----------------------------------------------------------

    def _audit(
        self,
        kind: str,
        target: str,
        arguments: Optional[dict[str, Any]],
        decision: str,
        reason: Optional[str],
        started: float,
        rows: Optional[int] = None,
    ) -> None:
        args = dict(arguments) if isinstance(arguments, dict) else arguments
        if isinstance(args, dict) and isinstance(args.get("sql"), str):
            args["sql"] = args["sql"][:_AUDIT_SQL_CHARS]
        fields: dict[str, Any] = {
            "kind": kind,
            "target": target,
            "arguments": args,
            "decision": decision,
            "duration_ms": round((time.monotonic() - started) * 1000, 2),
        }
        if reason:
            fields["reason"] = reason
        if rows is not None:
            fields["rows"] = rows
        try:
            self.audit.record(**fields)
        except Exception:  # an audit failure must be loud but must not crash the server
            log.exception("failed to write audit record")
