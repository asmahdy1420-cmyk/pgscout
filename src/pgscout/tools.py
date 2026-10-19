"""Tool definitions: input schemas and handlers.

Handlers assume the gate has already validated arguments, checked the schema
allowlist and guarded any SQL. They never touch the policy's redaction rules
for result rows; the gate applies those to every payload on the way out.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable, Optional

from . import explain as plans
from .db import Database, TableDescription
from .policy import Policy
from .sqlguard import MAX_SQL_LENGTH, GuardedSql


class ToolError(Exception):
    """A tool-level failure reported to the client as ``isError: true``."""


@dataclass
class ToolContext:
    db: Database
    policy: Policy
    guarded: Optional[GuardedSql] = None


Handler = Callable[[ToolContext, dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    title: str
    description: str
    input_schema: dict[str, Any]
    handler: Handler
    sql_mode: Optional[str] = None  # "query" allows EXPLAIN, "plan" expects a bare SELECT/WITH

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {
                "title": self.title,
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
        }


_SCHEMA_PROP = {
    "type": "string",
    "minLength": 1,
    "maxLength": 63,
    "description": "Schema name; defaults to the first allowed schema.",
}
_SQL_PROP = {"type": "string", "minLength": 1, "maxLength": MAX_SQL_LENGTH}


def _object(properties: dict[str, Any], required: tuple[str, ...] = ()) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}


def _list_schemas(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    existing = set(ctx.db.list_schemas())
    return {"schemas": [s for s in ctx.policy.allowed_schemas if s in existing]}


def _list_tables(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    schema = args.get("schema", ctx.policy.default_schema)
    tables = ctx.db.list_tables(schema)
    return {
        "schema": schema,
        "tables": [
            {"name": t.name, "kind": t.kind, "estimated_rows": t.estimated_rows, "comment": t.comment} for t in tables
        ],
    }


def _describe_table(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    schema = args.get("schema", ctx.policy.default_schema)
    desc = ctx.db.describe_table(schema, args["table"])
    if desc is None:
        raise ToolError(f"table {schema}.{args['table']} not found")
    columns = []
    for col in desc.columns:
        item = asdict(col)
        if ctx.policy.column_denied(col.name):
            item["denied"] = True
        columns.append(item)
    return {
        "schema": desc.schema,
        "table": desc.name,
        "columns": columns,
        "indexes": [asdict(ix) for ix in desc.indexes],
        "foreign_keys": [asdict(fk) for fk in desc.foreign_keys],
    }


def _run_readonly_query(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    assert ctx.guarded is not None
    limit = ctx.policy.max_rows_for(args.get("max_rows"))
    result = ctx.db.run_query(
        ctx.guarded.sql,
        max_rows=limit,
        timeout_ms=ctx.policy.statement_timeout_ms,
        search_path=ctx.policy.allowed_schemas,
    )
    return {
        "statement": ctx.guarded.statement,
        "columns": result.columns,
        "rows": result.rows,
        "row_count": len(result.rows),
        "truncated": result.truncated,
        "max_rows": limit,
    }


def _plan(ctx: ToolContext, analyze: bool = False) -> dict[str, Any]:
    assert ctx.guarded is not None
    return ctx.db.explain(
        ctx.guarded.sql,
        analyze=analyze,
        timeout_ms=ctx.policy.statement_timeout_ms,
        search_path=ctx.policy.allowed_schemas,
    )


def _explain_query(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    doc = _plan(ctx, analyze=bool(args.get("analyze")))
    payload = {"summary": plans.summarize(doc)}
    if args.get("include_plan"):
        payload["plan"] = doc
    return payload


def _resolver(ctx: ToolContext) -> plans.Resolver:
    cache: dict[tuple[str, str], Optional[TableDescription]] = {}

    def resolve(schema: Optional[str], table: str) -> Optional[TableDescription]:
        candidates = [schema] if schema else list(ctx.policy.allowed_schemas)
        for name in candidates:
            if not ctx.policy.schema_allowed(name):
                continue
            key = (name, table)
            if key not in cache:
                cache[key] = ctx.db.describe_table(name, table)
            if cache[key] is not None:
                return cache[key]
        return None

    return resolve


def _suggest_indexes(ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
    doc = _plan(ctx)
    result = plans.suggest_indexes(doc, _resolver(ctx))
    result["plan_summary"] = plans.summarize(doc)
    return result


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="list_schemas",
        title="List schemas",
        description="List the database schemas this server is allowed to inspect.",
        input_schema=_object({}),
        handler=_list_schemas,
    ),
    ToolSpec(
        name="list_tables",
        title="List tables",
        description="List tables, views and materialized views in a schema with estimated row counts.",
        input_schema=_object({"schema": _SCHEMA_PROP}),
        handler=_list_tables,
    ),
    ToolSpec(
        name="describe_table",
        title="Describe table",
        description="Columns (type, nullability, default), indexes and foreign keys of one table.",
        input_schema=_object(
            {"schema": _SCHEMA_PROP, "table": {"type": "string", "minLength": 1, "maxLength": 63}},
            required=("table",),
        ),
        handler=_describe_table,
    ),
    ToolSpec(
        name="run_readonly_query",
        title="Run read-only query",
        description=(
            "Run one SELECT, WITH or EXPLAIN statement in a read-only transaction with a statement "
            "timeout. Results are capped at max_rows and denied columns are redacted."
        ),
        input_schema=_object(
            {
                "sql": _SQL_PROP,
                "max_rows": {"type": "integer", "minimum": 1, "maximum": 10_000},
            },
            required=("sql",),
        ),
        handler=_run_readonly_query,
        sql_mode="query",
    ),
    ToolSpec(
        name="explain_query",
        title="Explain query",
        description=(
            "EXPLAIN (FORMAT JSON) a SELECT or WITH query and summarise it: total cost, node types, "
            "sequential scans and warnings. Pass the bare query, not EXPLAIN."
        ),
        input_schema=_object(
            {
                "sql": _SQL_PROP,
                "analyze": {
                    "type": "boolean",
                    "default": False,
                    "description": "Execute the query (if allowed by policy).",
                },
                "include_plan": {"type": "boolean", "default": False, "description": "Include the raw plan JSON."},
            },
            required=("sql",),
        ),
        handler=_explain_query,
        sql_mode="plan",
    ),
    ToolSpec(
        name="suggest_indexes",
        title="Suggest indexes",
        description=(
            "Heuristic index suggestions for a SELECT or WITH query, from its plan: sequential scans "
            "on filtered columns and foreign keys without a supporting index. Never creates anything."
        ),
        input_schema=_object({"sql": _SQL_PROP}, required=("sql",)),
        handler=_suggest_indexes,
        sql_mode="plan",
    ),
)
