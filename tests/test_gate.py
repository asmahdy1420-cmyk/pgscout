from __future__ import annotations

import io
import json

import pytest

from pgscout.fake import FakeDatabase
from pgscout.gate import Gate, UnknownTool
from pgscout.policy import REDACTED, AuditLog, MemoryAuditLog, Policy


def test_list_schemas_only_shows_allowlisted(gate: Gate) -> None:
    out = gate.call_tool("list_schemas", {})
    assert out.ok
    assert out.payload == {"schemas": ["public"]}


def test_schema_outside_allowlist_is_denied_and_audited(gate: Gate, audit: MemoryAuditLog) -> None:
    out = gate.call_tool("list_tables", {"schema": "internal"})
    assert not out.ok
    assert "not in the allowlist" in out.payload["error"]
    assert audit.entries[-1]["decision"] == "denied"
    assert audit.entries[-1]["target"] == "list_tables"


def test_query_redacts_denied_columns_from_star(gate: Gate) -> None:
    out = gate.call_tool("run_readonly_query", {"sql": "SELECT * FROM customers"})
    assert out.ok, out.payload
    cols = out.payload["columns"]
    idx = cols.index("password_hash")
    assert all(row[idx] == REDACTED for row in out.payload["rows"])
    assert out.payload["redacted_columns"] == ["password_hash"]
    assert out.payload["rows"][0][cols.index("email")] == "lina@example.com"


def test_query_naming_a_denied_column_is_refused(gate: Gate, db: FakeDatabase) -> None:
    # Aliasing would defeat name-based redaction, so the reference itself is refused.
    out = gate.call_tool("run_readonly_query", {"sql": "SELECT password_hash AS p FROM customers"})
    assert not out.ok
    assert "denied column" in out.payload["error"]
    assert db.executed == []


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM internal.api_keys",
        'SELECT * FROM "internal".api_keys',
        "SELECT * FROM pg_catalog.pg_authid",
        "SELECT * FROM information_schema.tables",
    ],
)
def test_schema_qualified_references_outside_allowlist_are_refused(gate: Gate, db: FakeDatabase, sql: str) -> None:
    out = gate.call_tool("run_readonly_query", {"sql": sql})
    assert not out.ok
    assert "not in the allowlist" in out.payload["error"]
    assert db.executed == []


def test_write_attempt_never_reaches_the_database(gate: Gate, db: FakeDatabase, audit: MemoryAuditLog) -> None:
    out = gate.call_tool("run_readonly_query", {"sql": "SELECT 1; DELETE FROM orders"})
    assert not out.ok
    assert out.payload["type"] == "SqlRejected"
    assert db.executed == []
    assert audit.entries[-1]["arguments"]["sql"] == "SELECT 1; DELETE FROM orders"


def test_row_cap_is_enforced_by_policy(db: FakeDatabase, audit: MemoryAuditLog) -> None:
    gate = Gate(db, Policy(max_rows=2), audit)
    out = gate.call_tool("run_readonly_query", {"sql": "SELECT id FROM orders", "max_rows": 500})
    assert out.ok
    assert out.payload["row_count"] == 2
    assert out.payload["truncated"] is True
    assert out.payload["max_rows"] == 2
    assert audit.entries[-1]["rows"] == 2


def test_invalid_arguments_are_denied(gate: Gate) -> None:
    out = gate.call_tool("run_readonly_query", {"sql": "SELECT 1", "max_rows": "ten"})
    assert not out.ok
    assert out.payload["type"] == "ValidationError"
    out = gate.call_tool("describe_table", {"table": "orders", "drop": True})
    assert "unexpected argument" in out.payload["error"]


def test_describe_table_flags_denied_columns(gate: Gate) -> None:
    out = gate.call_tool("describe_table", {"table": "customers"})
    assert out.ok
    flagged = [c["name"] for c in out.payload["columns"] if c.get("denied")]
    assert flagged == ["password_hash"]
    assert {ix["name"] for ix in out.payload["indexes"]} == {"customers_pkey", "customers_email_key"}


def test_missing_table_is_a_tool_error(gate: Gate, audit: MemoryAuditLog) -> None:
    out = gate.call_tool("describe_table", {"table": "nope"})
    assert not out.ok
    assert audit.entries[-1]["decision"] == "error"


def test_explain_analyze_requires_policy(gate: Gate) -> None:
    out = gate.call_tool("explain_query", {"sql": "SELECT * FROM orders", "analyze": True})
    assert not out.ok
    assert "disabled by policy" in out.payload["error"]


def test_unknown_tool_raises(gate: Gate) -> None:
    with pytest.raises(UnknownTool):
        gate.call_tool("drop_everything", {})


def test_audit_log_writes_json_lines(db: FakeDatabase) -> None:
    stream = io.StringIO()
    gate = Gate(db, Policy(), AuditLog(stream))
    gate.call_tool("list_tables", {})
    gate.call_tool("run_readonly_query", {"sql": "DROP TABLE orders"})
    lines = [json.loads(line) for line in stream.getvalue().splitlines()]
    assert [entry["decision"] for entry in lines] == ["allowed", "denied"]
    assert all({"ts", "kind", "target", "duration_ms"} <= set(entry) for entry in lines)


def test_policy_resource_and_schema_resource(gate: Gate) -> None:
    uris = [r["uri"] for r in gate.list_resources()]
    assert uris == ["pgscout://policy", "pgscout://schema/public"]
    assert json.loads(gate.read_resource("pgscout://policy"))["read_only"] is True
    tables = json.loads(gate.read_resource("pgscout://schema/public"))["tables"]
    assert {t["name"] for t in tables} == {"customers", "orders"}
