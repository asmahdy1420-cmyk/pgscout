from __future__ import annotations

from pgscout.db import ColumnInfo, IndexInfo, TableDescription
from pgscout.explain import filter_columns, suggest_indexes, summarize
from pgscout.gate import Gate

PLAN = {
    "Plan": {
        "Node Type": "Hash Join",
        "Startup Cost": 10.0,
        "Total Cost": 48210.5,
        "Plan Rows": 1200,
        "Hash Cond": "(o.customer_id = c.id)",
        "Plans": [
            {
                "Node Type": "Seq Scan",
                "Relation Name": "orders",
                "Alias": "o",
                "Total Cost": 45000.0,
                "Plan Rows": 1200,
                "Filter": "((created_at > '2026-01-01 00:00:00+00'::timestamp with time zone) AND ((status)::text = 'paid'::text))",
            },
            {
                "Node Type": "Hash",
                "Total Cost": 30.0,
                "Plan Rows": 100,
                "Plans": [
                    {
                        "Node Type": "Index Scan",
                        "Relation Name": "customers",
                        "Index Name": "customers_pkey",
                        "Total Cost": 30.0,
                        "Plan Rows": 100,
                    }
                ],
            },
        ],
    },
    "Planning Time": 0.4,
}


def test_filter_columns_orders_equality_before_range() -> None:
    eq, rng = filter_columns(PLAN["Plan"]["Plans"][0]["Filter"])
    assert eq == ["status"]
    assert rng == ["created_at"]


def test_filter_columns_ignores_text_inside_literals_and_inequality() -> None:
    eq, rng = filter_columns("((note = 'a = b'::text) AND (kind <> 'x'::text) AND (region IS NULL))")
    assert eq == ["note", "region"]
    assert rng == []


def test_summarize_reports_seq_scans_and_warnings() -> None:
    summary = summarize(PLAN)
    assert summary["total_cost"] == 48210.5
    assert summary["node_counts"]["Seq Scan"] == 1
    assert summary["seq_scans"][0]["relation"] == "orders"
    assert summary["index_scans"] == [{"relation": "customers", "index": "customers_pkey", "type": "Index Scan"}]
    assert summary["planning_time_ms"] == 0.4
    assert any("Sequential scan on orders" in w for w in summary["warnings"])


def test_suggest_indexes_from_plan_and_fk(gate: Gate) -> None:
    resolve = lambda schema, table: gate.db.describe_table(schema or "public", table)  # noqa: E731
    result = suggest_indexes(PLAN, resolve)
    by_cols = {tuple(s["columns"]): s for s in result["suggestions"]}
    assert ("status", "created_at") in by_cols
    assert by_cols[("status", "created_at")]["confidence"] == "high"
    assert by_cols[("status", "created_at")]["ddl"] == (
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_orders_status_created_at ON public.orders (status, created_at);"
    )
    assert ("customer_id",) in by_cols  # unindexed foreign key


def test_existing_leading_index_yields_note_not_duplicate() -> None:
    desc = TableDescription(
        schema="public",
        name="events",
        columns=[ColumnInfo("kind", "text")],
        indexes=[IndexInfo("events_kind_idx", ["kind"], "CREATE INDEX ...")],
    )
    plan = {
        "Plan": {"Node Type": "Seq Scan", "Relation Name": "events", "Total Cost": 5.0, "Filter": "(kind = 'a'::text)"}
    }
    result = suggest_indexes(plan, lambda schema, table: desc)
    assert result["suggestions"] == []
    assert "events_kind_idx" in result["notes"][0]


def test_suggest_indexes_tool_end_to_end(gate: Gate) -> None:
    out = gate.call_tool("suggest_indexes", {"sql": "SELECT id FROM orders WHERE status = 'paid'"})
    assert out.ok, out.payload
    cols = [s["columns"] for s in out.payload["suggestions"]]
    assert ["status"] in cols
    assert ["customer_id"] in cols
    assert out.payload["plan_summary"]["seq_scans"][0]["relation"] == "orders"
