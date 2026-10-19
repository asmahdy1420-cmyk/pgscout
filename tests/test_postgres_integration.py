"""Runs against a real PostgreSQL when PGSCOUT_TEST_DSN is set (CI does this)."""

from __future__ import annotations

import os

import pytest

DSN = os.environ.get("PGSCOUT_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="PGSCOUT_TEST_DSN not set")

SETUP = """
DROP SCHEMA IF EXISTS scout_it CASCADE;
CREATE SCHEMA scout_it;
CREATE TABLE scout_it.customers (id bigserial PRIMARY KEY, email text NOT NULL UNIQUE, password_hash text);
CREATE TABLE scout_it.orders (
    id bigserial PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES scout_it.customers (id),
    status text NOT NULL DEFAULT 'pending'
);
INSERT INTO scout_it.customers (email, password_hash) VALUES ('a@example.com', 'x'), ('b@example.com', 'y');
INSERT INTO scout_it.orders (customer_id, status) SELECT 1 + (g % 2), 'paid' FROM generate_series(1, 50) g;
ANALYZE scout_it.customers;
ANALYZE scout_it.orders;
"""


@pytest.fixture(scope="module")
def pg():
    import psycopg

    from pgscout.db import PsycopgDatabase

    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(SETUP)
    yield PsycopgDatabase(DSN)
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS scout_it CASCADE")


def test_catalog_introspection(pg) -> None:
    assert "scout_it" in pg.list_schemas()
    assert [t.name for t in pg.list_tables("scout_it")] == ["customers", "orders"]
    desc = pg.describe_table("scout_it", "orders")
    assert [c.name for c in desc.columns] == ["id", "customer_id", "status"]
    assert {ix.name for ix in desc.indexes} == {"orders_pkey"}
    fk = desc.foreign_keys[0]
    assert (fk.columns, fk.ref_table, fk.ref_columns) == (["customer_id"], "customers", ["id"])
    assert pg.describe_table("scout_it", "missing") is None


def test_query_row_cap_and_search_path(pg) -> None:
    result = pg.run_query("SELECT id FROM orders ORDER BY id", max_rows=5, timeout_ms=2000, search_path=["scout_it"])
    assert result.columns == ["id"]
    assert len(result.rows) == 5
    assert result.truncated is True


def test_database_enforces_read_only_even_without_the_guard(pg) -> None:
    from pgscout.db import DatabaseError

    with pytest.raises(DatabaseError, match="read-only"):
        pg.run_query("DELETE FROM scout_it.orders", max_rows=1, timeout_ms=2000, search_path=["scout_it"])
    count = pg.run_query("SELECT count(*) FROM scout_it.orders", max_rows=1, timeout_ms=2000, search_path=[])
    assert count.rows == [[50]]


def test_statement_timeout(pg) -> None:
    from pgscout.db import DatabaseError

    with pytest.raises(DatabaseError, match="57014"):
        pg.run_query("SELECT pg_sleep(2)", max_rows=1, timeout_ms=100, search_path=["scout_it"])


def test_explain_and_suggestions_end_to_end(pg) -> None:
    from pgscout.gate import Gate
    from pgscout.policy import MemoryAuditLog, Policy

    gate = Gate(pg, Policy(allowed_schemas=("scout_it",)), MemoryAuditLog())
    out = gate.call_tool("suggest_indexes", {"sql": "SELECT * FROM orders WHERE status = 'paid'"})
    assert out.ok, out.payload
    cols = [s["columns"] for s in out.payload["suggestions"]]
    assert ["customer_id"] in cols
    explained = gate.call_tool("explain_query", {"sql": "SELECT * FROM orders WHERE id = 3"})
    assert explained.ok, explained.payload
    assert explained.payload["summary"]["total_cost"] > 0
