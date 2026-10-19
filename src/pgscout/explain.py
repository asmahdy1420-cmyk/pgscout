"""Read EXPLAIN (FORMAT JSON) plans: summaries and index heuristics."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from typing import Any, Callable, Optional

from .db import TableDescription, quote_ident

Resolver = Callable[[Optional[str], str], Optional[TableDescription]]

_STRING_LITERAL = re.compile(r"'(?:[^']|'')*'")
_PREDICATE = re.compile(
    r"\(*\s*(?:[A-Za-z_][\w$]*\.)?\"?([A-Za-z_][\w$]*)\"?\s*\)?"  # column, maybe wrapped
    r"(?:::[A-Za-z_][\w ]*(?:\[\])?\)?)*\s*"  # optional casts
    r"(=\s*ANY|<>|!=|<=|>=|=|<|>|~~\*|~~|IS\s+NOT\s+NULL|IS\s+NULL)",
    re.IGNORECASE,
)
_SIMPLE_IDENT = re.compile(r"^[a-z_][a-z0-9_]*$")

SCAN_TYPES = {"Seq Scan", "Index Scan", "Index Only Scan", "Bitmap Heap Scan", "Bitmap Index Scan"}
HIGH_COST = 1_000.0


def walk(node: dict[str, Any], depth: int = 0) -> Iterator[tuple[dict[str, Any], int]]:
    yield node, depth
    for child in node.get("Plans", []) or []:
        yield from walk(child, depth + 1)


def summarize(plan_doc: dict[str, Any]) -> dict[str, Any]:
    root = plan_doc["Plan"]
    counts: Counter[str] = Counter()
    seq_scans: list[dict[str, Any]] = []
    index_scans: list[dict[str, Any]] = []
    warnings: list[str] = []

    for node, _depth in walk(root):
        node_type = node.get("Node Type", "?")
        counts[node_type] += 1
        relation = node.get("Relation Name")
        if node_type == "Seq Scan":
            scan = {
                "relation": relation,
                "alias": node.get("Alias"),
                "filter": node.get("Filter"),
                "estimated_rows": node.get("Plan Rows"),
                "total_cost": node.get("Total Cost"),
            }
            if "Rows Removed by Filter" in node:
                scan["rows_removed_by_filter"] = node["Rows Removed by Filter"]
            seq_scans.append(scan)
            if node.get("Filter"):
                warnings.append(f"Sequential scan on {relation} with filter {node['Filter']}")
        elif node_type in {"Index Scan", "Index Only Scan", "Bitmap Index Scan"}:
            index_scans.append({"relation": relation, "index": node.get("Index Name"), "type": node_type})
        if node.get("Sort Space Type") == "Disk":
            warnings.append(f"Sort spilled to disk ({node.get('Sort Space Used')} kB)")
        if node_type == "Nested Loop":
            children = node.get("Plans", []) or []
            if len(children) == 2 and children[1].get("Node Type") == "Seq Scan":
                warnings.append(f"Nested loop re-scans {children[1].get('Relation Name')} sequentially")

    summary: dict[str, Any] = {
        "total_cost": root.get("Total Cost"),
        "startup_cost": root.get("Startup Cost"),
        "estimated_rows": root.get("Plan Rows"),
        "node_counts": dict(counts),
        "seq_scans": seq_scans,
        "index_scans": index_scans,
        "warnings": warnings,
    }
    if "Planning Time" in plan_doc:
        summary["planning_time_ms"] = plan_doc["Planning Time"]
    if "Execution Time" in plan_doc:
        summary["execution_time_ms"] = plan_doc["Execution Time"]
    return summary


def filter_columns(filter_text: str) -> tuple[list[str], list[str]]:
    """Return (equality columns, range columns) referenced by a plan Filter, in order."""
    text = _STRING_LITERAL.sub("''", filter_text)
    equality: list[str] = []
    ranges: list[str] = []
    for match in _PREDICATE.finditer(text):
        column, op = match.group(1), re.sub(r"\s+", " ", match.group(2).upper())
        if op in {"=", "= ANY", "IS NULL"}:
            bucket = equality
        elif op in {"<", ">", "<=", ">=", "~~"}:
            bucket = ranges
        else:
            continue  # <>, !=, ILIKE and IS NOT NULL rarely benefit from a b-tree
        if column not in equality and column not in ranges:
            bucket.append(column)
    return equality, ranges


def _ident(name: str) -> str:
    return name if _SIMPLE_IDENT.match(name) else quote_ident(name)


def _index_ddl(desc: TableDescription, columns: list[str]) -> str:
    name = f"idx_{desc.name}_{'_'.join(columns)}"[:63]
    cols = ", ".join(_ident(c) for c in columns)
    return (
        f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {_ident(name)} ON {_ident(desc.schema)}.{_ident(desc.name)} ({cols});"
    )


def _has_prefix_index(desc: TableDescription, columns: list[str]) -> bool:
    return any(ix.columns[: len(columns)] == columns for ix in desc.indexes)


def suggest_indexes(plan_doc: dict[str, Any], resolve: Resolver) -> dict[str, Any]:
    """Heuristic index suggestions from a plan.

    1. Seq Scan with a Filter: index the equality columns first, then at most
       one range column (a b-tree stops being selective after a range).
    2. Foreign keys on scanned tables with no index starting with the FK
       columns: joins and ``ON DELETE`` checks on the parent must scan them.
    """
    suggestions: list[dict[str, Any]] = []
    notes: list[str] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    described: dict[str, TableDescription] = {}

    def add(desc: TableDescription, columns: list[str], reason: str, confidence: str, cost: Any = None) -> None:
        key = (desc.schema, desc.name, tuple(columns))
        if key in seen:
            return
        seen.add(key)
        item = {
            "table": f"{desc.schema}.{desc.name}",
            "columns": columns,
            "reason": reason,
            "confidence": confidence,
            "ddl": _index_ddl(desc, columns),
        }
        if cost is not None:
            item["scan_cost"] = cost
        suggestions.append(item)

    for node, _depth in walk(plan_doc["Plan"]):
        relation = node.get("Relation Name")
        if not relation or node.get("Node Type") not in SCAN_TYPES:
            continue
        desc = resolve(node.get("Schema"), relation)
        if desc is None:
            continue
        described[f"{desc.schema}.{desc.name}"] = desc
        if node.get("Node Type") != "Seq Scan" or not node.get("Filter"):
            continue
        known = {c.name for c in desc.columns}
        equality, ranges = filter_columns(node["Filter"])
        columns = [c for c in equality if c in known] + [c for c in ranges if c in known][:1]
        if not columns:
            continue
        existing = [ix.name for ix in desc.indexes if ix.columns and ix.columns[0] == columns[0]]
        if existing:
            notes.append(
                f"{desc.schema}.{desc.name}: index {existing[0]} already starts with {columns[0]} but the "
                "planner chose a sequential scan; check selectivity and run ANALYZE before adding more"
            )
            continue
        cost = node.get("Total Cost")
        confidence = "high" if isinstance(cost, (int, float)) and cost >= HIGH_COST else "low"
        add(desc, columns, f"sequential scan filtered on {', '.join(columns)}", confidence, cost)

    for desc in described.values():
        for fk in desc.foreign_keys:
            if fk.columns and not _has_prefix_index(desc, fk.columns):
                add(
                    desc,
                    list(fk.columns),
                    f"foreign key {fk.name} -> {fk.ref_schema}.{fk.ref_table} has no supporting index",
                    "medium",
                )

    if not suggestions and not notes:
        notes.append("no sequential scans on filtered columns and no unindexed foreign keys found")
    return {"suggestions": suggestions, "notes": notes}
