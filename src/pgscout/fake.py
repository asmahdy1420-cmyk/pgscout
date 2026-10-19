"""In-memory :class:`~pgscout.db.Database` for tests and ``--demo`` mode.

It understands catalog calls fully. For SQL it returns canned results
registered with :meth:`FakeDatabase.add_query` / :meth:`FakeDatabase.add_plan`
and otherwise evaluates a tiny subset (``SELECT cols FROM table [WHERE col =
'v'] [LIMIT n]``) and synthesises a sequential-scan plan, which is enough to
exercise every tool end to end without PostgreSQL.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Optional

from .db import (
    ColumnInfo,
    DatabaseError,
    ForeignKeyInfo,
    IndexInfo,
    QueryResult,
    TableDescription,
    TableInfo,
)

_SELECT = re.compile(
    r"^\s*select\s+(?P<cols>.+?)\s+from\s+(?P<table>[\w.]+)(?:\s+(?:as\s+)?(?!where\b|limit\b)\w+)?"
    r"(?:\s+where\s+(?P<col>\w+)\s*=\s*'(?P<val>[^']*)')?(?:\s+limit\s+(?P<limit>\d+))?\s*$",
    re.IGNORECASE | re.DOTALL,
)
_FROM = re.compile(
    r"\bfrom\s+(?P<table>[\w.]+)(?:\s+(?:as\s+)?(?P<alias>(?!where\b|limit\b|order\b|group\b)\w+))?", re.IGNORECASE
)
_WHERE = re.compile(r"\bwhere\s+(?P<cond>.+?)(?:\s+order\s+by|\s+group\s+by|\s+limit|$)", re.IGNORECASE | re.DOTALL)


def _normalize(sql: str) -> str:
    return " ".join(sql.split()).rstrip(";").strip().lower()


@dataclass
class FakeTable:
    description: TableDescription
    kind: str = "table"
    estimated_rows: int = 0
    rows: list[dict[str, Any]] = field(default_factory=list)


class FakeDatabase:
    def __init__(self, tables: Iterable[FakeTable] = (), schemas: Iterable[str] = ()) -> None:
        self.tables = {(t.description.schema, t.description.name): t for t in tables}
        self.schemas = sorted(set(schemas) | {schema for schema, _ in self.tables})
        self.queries: dict[str, QueryResult] = {}
        self.plans: dict[str, dict[str, Any]] = {}
        self.executed: list[str] = []

    def add_query(self, sql: str, columns: list[str], rows: list[list[Any]]) -> None:
        self.queries[_normalize(sql)] = QueryResult(columns=columns, rows=rows)

    def add_plan(self, sql: str, plan_doc: dict[str, Any]) -> None:
        self.plans[_normalize(sql)] = plan_doc

    # -- catalog ---------------------------------------------------------

    def list_schemas(self) -> list[str]:
        return list(self.schemas)

    def list_tables(self, schema: str) -> list[TableInfo]:
        return [
            TableInfo(schema=s, name=n, kind=t.kind, estimated_rows=t.estimated_rows)
            for (s, n), t in sorted(self.tables.items())
            if s == schema
        ]

    def describe_table(self, schema: str, table: str) -> Optional[TableDescription]:
        found = self.tables.get((schema, table))
        return found.description if found else None

    # -- SQL -------------------------------------------------------------

    def _resolve(self, name: str, search_path: Sequence[str]) -> FakeTable:
        if "." in name:
            schema, table = name.split(".", 1)
            candidates = [(schema, table)]
        else:
            candidates = [(s, name) for s in search_path]
        for key in candidates:
            if key in self.tables:
                return self.tables[key]
        raise DatabaseError(f'relation "{name}" does not exist (SQLSTATE 42P01)')

    def run_query(self, sql: str, *, max_rows: int, timeout_ms: int, search_path: Sequence[str]) -> QueryResult:
        self.executed.append(sql)
        canned = self.queries.get(_normalize(sql))
        if canned is None:
            canned = self._evaluate(sql, search_path)
        rows = canned.rows[:max_rows]
        return QueryResult(
            columns=list(canned.columns), rows=[list(r) for r in rows], truncated=len(canned.rows) > max_rows
        )

    def _evaluate(self, sql: str, search_path: Sequence[str]) -> QueryResult:
        match = _SELECT.match(sql)
        if match is None:
            raise DatabaseError("the fake database only evaluates simple SELECT ... FROM ... queries")
        table = self._resolve(match.group("table"), search_path)
        known = [c.name for c in table.description.columns]
        cols_text = match.group("cols").strip()
        columns = known if cols_text == "*" else [c.strip() for c in cols_text.split(",")]
        for col in columns:
            if col not in known:
                raise DatabaseError(f'column "{col}" does not exist (SQLSTATE 42703)')
        rows = table.rows
        if match.group("col"):
            rows = [r for r in rows if str(r.get(match.group("col"))) == match.group("val")]
        if match.group("limit"):
            rows = rows[: int(match.group("limit"))]
        return QueryResult(columns=columns, rows=[[r.get(c) for c in columns] for r in rows])

    def explain(self, sql: str, *, analyze: bool, timeout_ms: int, search_path: Sequence[str]) -> dict[str, Any]:
        self.executed.append(f"EXPLAIN {sql}")
        canned = self.plans.get(_normalize(sql))
        if canned is not None:
            return canned
        found = _FROM.search(sql)
        if found is None:
            return {"Plan": {"Node Type": "Result", "Startup Cost": 0.0, "Total Cost": 0.01, "Plan Rows": 1}}
        table = self._resolve(found.group("table"), search_path)
        node: dict[str, Any] = {
            "Node Type": "Seq Scan",
            "Relation Name": table.description.name,
            "Alias": found.group("alias") or table.description.name,
            "Startup Cost": 0.0,
            "Total Cost": round(table.estimated_rows * 0.0125 + 1, 2),
            "Plan Rows": table.estimated_rows,
        }
        where = _WHERE.search(sql)
        if where:
            node["Filter"] = f"({where.group('cond').strip()})"
            node["Plan Rows"] = max(1, table.estimated_rows // 100)
        return {"Plan": node}


def demo_database() -> FakeDatabase:
    """A small shop schema used by ``pgscout --demo`` and the tests."""
    customers = TableDescription(
        schema="public",
        name="customers",
        columns=[
            ColumnInfo("id", "bigint", False, "nextval('customers_id_seq'::regclass)"),
            ColumnInfo("email", "text", False),
            ColumnInfo("full_name", "text", True),
            ColumnInfo("password_hash", "text", False),
            ColumnInfo("created_at", "timestamp with time zone", False, "now()"),
        ],
        indexes=[
            IndexInfo(
                "customers_pkey",
                ["id"],
                "CREATE UNIQUE INDEX customers_pkey ON public.customers USING btree (id)",
                True,
                True,
            ),
            IndexInfo(
                "customers_email_key",
                ["email"],
                "CREATE UNIQUE INDEX customers_email_key ON public.customers USING btree (email)",
                True,
            ),
        ],
    )
    orders = TableDescription(
        schema="public",
        name="orders",
        columns=[
            ColumnInfo("id", "bigint", False, "nextval('orders_id_seq'::regclass)"),
            ColumnInfo("customer_id", "bigint", False),
            ColumnInfo("status", "text", False, "'pending'::text"),
            ColumnInfo("total_cents", "bigint", False),
            ColumnInfo("created_at", "timestamp with time zone", False, "now()"),
        ],
        indexes=[
            IndexInfo(
                "orders_pkey", ["id"], "CREATE UNIQUE INDEX orders_pkey ON public.orders USING btree (id)", True, True
            ),
        ],
        foreign_keys=[ForeignKeyInfo("orders_customer_id_fkey", ["customer_id"], "public", "customers", ["id"])],
    )
    api_keys = TableDescription(
        schema="internal",
        name="api_keys",
        columns=[
            ColumnInfo("id", "bigint", False),
            ColumnInfo("key", "text", False),
            ColumnInfo("owner", "text", False),
        ],
        indexes=[
            IndexInfo(
                "api_keys_pkey",
                ["id"],
                "CREATE UNIQUE INDEX api_keys_pkey ON internal.api_keys USING btree (id)",
                True,
                True,
            )
        ],
    )
    return FakeDatabase(
        [
            FakeTable(
                customers,
                estimated_rows=120_000,
                rows=[
                    {
                        "id": 1,
                        "email": "lina@example.com",
                        "full_name": "Lina Haddad",
                        "password_hash": "$2b$12$abc",
                        "created_at": "2026-01-04T10:00:00+00:00",
                    },
                    {
                        "id": 2,
                        "email": "omar@example.com",
                        "full_name": "Omar Saleh",
                        "password_hash": "$2b$12$def",
                        "created_at": "2026-02-11T08:30:00+00:00",
                    },
                ],
            ),
            FakeTable(
                orders,
                estimated_rows=2_400_000,
                rows=[
                    {
                        "id": 10,
                        "customer_id": 1,
                        "status": "paid",
                        "total_cents": 4599,
                        "created_at": "2026-03-01T12:00:00+00:00",
                    },
                    {
                        "id": 11,
                        "customer_id": 2,
                        "status": "pending",
                        "total_cents": 1250,
                        "created_at": "2026-03-02T09:15:00+00:00",
                    },
                    {
                        "id": 12,
                        "customer_id": 1,
                        "status": "paid",
                        "total_cents": 9900,
                        "created_at": "2026-03-05T17:45:00+00:00",
                    },
                ],
            ),
            FakeTable(api_keys, estimated_rows=12, rows=[{"id": 1, "key": "k_live_123", "owner": "billing"}]),
        ]
    )
