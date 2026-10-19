"""Database access behind a small protocol.

``PsycopgDatabase`` talks to PostgreSQL through psycopg 3. ``FakeDatabase``
(in :mod:`pgscout.fake`) implements the same protocol in memory for tests and
the ``--demo`` mode.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

log = logging.getLogger(__name__)


class DatabaseError(Exception):
    """A database-side failure that is safe to report to the client."""


@dataclass
class QueryResult:
    columns: list[str]
    rows: list[list[Any]]
    truncated: bool = False


@dataclass
class TableInfo:
    schema: str
    name: str
    kind: str
    estimated_rows: int = 0
    comment: Optional[str] = None


@dataclass
class ColumnInfo:
    name: str
    data_type: str
    nullable: bool = True
    default: Optional[str] = None


@dataclass
class IndexInfo:
    name: str
    columns: list[str]
    definition: str
    unique: bool = False
    primary: bool = False


@dataclass
class ForeignKeyInfo:
    name: str
    columns: list[str]
    ref_schema: str
    ref_table: str
    ref_columns: list[str]


@dataclass
class TableDescription:
    schema: str
    name: str
    columns: list[ColumnInfo] = field(default_factory=list)
    indexes: list[IndexInfo] = field(default_factory=list)
    foreign_keys: list[ForeignKeyInfo] = field(default_factory=list)


class Database(Protocol):
    def list_schemas(self) -> list[str]: ...

    def list_tables(self, schema: str) -> list[TableInfo]: ...

    def describe_table(self, schema: str, table: str) -> Optional[TableDescription]: ...

    def run_query(self, sql: str, *, max_rows: int, timeout_ms: int, search_path: Sequence[str]) -> QueryResult: ...

    def explain(self, sql: str, *, analyze: bool, timeout_ms: int, search_path: Sequence[str]) -> dict[str, Any]: ...


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


_LIST_SCHEMAS = """
SELECT nspname
FROM pg_catalog.pg_namespace
WHERE nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema'
ORDER BY nspname
"""

_LIST_TABLES = """
SELECT c.relname,
       CASE c.relkind
         WHEN 'r' THEN 'table'
         WHEN 'p' THEN 'partitioned table'
         WHEN 'v' THEN 'view'
         WHEN 'm' THEN 'materialized view'
         WHEN 'f' THEN 'foreign table'
       END,
       GREATEST(c.reltuples, 0)::bigint,
       pg_catalog.obj_description(c.oid, 'pg_class')
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = %s AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
ORDER BY c.relname
"""

_TABLE_OID = """
SELECT c.oid
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = %s AND c.relname = %s AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
"""

_COLUMNS = """
SELECT a.attname,
       pg_catalog.format_type(a.atttypid, a.atttypmod),
       NOT a.attnotnull,
       pg_catalog.pg_get_expr(d.adbin, d.adrelid)
FROM pg_catalog.pg_attribute a
LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
WHERE a.attrelid = %s AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY a.attnum
"""

_INDEXES = """
SELECT i.relname,
       ARRAY(
         SELECT a.attname
         FROM unnest(x.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
         JOIN pg_catalog.pg_attribute a ON a.attrelid = x.indrelid AND a.attnum = k.attnum
         ORDER BY k.ord
       ),
       pg_catalog.pg_get_indexdef(x.indexrelid),
       x.indisunique,
       x.indisprimary
FROM pg_catalog.pg_index x
JOIN pg_catalog.pg_class i ON i.oid = x.indexrelid
WHERE x.indrelid = %s
ORDER BY i.relname
"""

_FOREIGN_KEYS = """
SELECT con.conname,
       ARRAY(
         SELECT a.attname
         FROM unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord)
         JOIN pg_catalog.pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum
         ORDER BY k.ord
       ),
       nf.nspname,
       cf.relname,
       ARRAY(
         SELECT a.attname
         FROM unnest(con.confkey) WITH ORDINALITY AS k(attnum, ord)
         JOIN pg_catalog.pg_attribute a ON a.attrelid = con.confrelid AND a.attnum = k.attnum
         ORDER BY k.ord
       )
FROM pg_catalog.pg_constraint con
JOIN pg_catalog.pg_class cf ON cf.oid = con.confrelid
JOIN pg_catalog.pg_namespace nf ON nf.oid = cf.relnamespace
WHERE con.conrelid = %s AND con.contype = 'f'
ORDER BY con.conname
"""

CATALOG_TIMEOUT_MS = 5_000


class PsycopgDatabase:
    """PostgreSQL access through psycopg 3.

    Every call runs in its own transaction that is marked ``READ ONLY``, gets
    a local ``statement_timeout`` and ``search_path``, and is always rolled
    back. The session default is also set to read-only on connect.
    """

    def __init__(self, dsn: str, *, application_name: str = "pgscout") -> None:
        self._dsn = dsn
        self._application_name = application_name
        self._conn: Any = None
        self._lock = threading.Lock()

    def _connect(self) -> Any:
        import psycopg  # imported lazily so tests and --demo need no driver

        conn = psycopg.connect(self._dsn, autocommit=False, application_name=self._application_name)
        conn.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
        conn.commit()
        return conn

    @contextmanager
    def _transaction(self, timeout_ms: int, search_path: Sequence[str] = ()) -> Iterator[Any]:
        import psycopg

        with self._lock:
            if self._conn is None or self._conn.closed:
                self._conn = self._connect()
            conn = self._conn
            try:
                with conn.cursor() as cur:
                    cur.execute("SET TRANSACTION READ ONLY")
                    cur.execute("SELECT set_config('statement_timeout', %s, true)", (str(int(timeout_ms)),))
                    cur.execute(
                        "SELECT set_config('idle_in_transaction_session_timeout', %s, true)",
                        (str(int(timeout_ms) * 2),),
                    )
                    if search_path:
                        path = ", ".join(quote_ident(s) for s in search_path)
                        cur.execute("SELECT set_config('search_path', %s, true)", (path,))
                    yield cur
            except psycopg.Error as exc:
                raise DatabaseError(_describe_pg_error(exc)) from exc
            finally:
                try:
                    conn.rollback()
                except Exception:  # connection is broken; drop it and reconnect next time
                    log.warning("rollback failed; reconnecting on next call", exc_info=True)
                    self._conn = None

    def _fetchall(self, sql: str, params: Optional[Sequence[Any]] = None) -> list[tuple[Any, ...]]:
        with self._transaction(CATALOG_TIMEOUT_MS) as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())

    def list_schemas(self) -> list[str]:
        return [row[0] for row in self._fetchall(_LIST_SCHEMAS)]

    def list_tables(self, schema: str) -> list[TableInfo]:
        return [
            TableInfo(schema=schema, name=r[0], kind=r[1], estimated_rows=int(r[2]), comment=r[3])
            for r in self._fetchall(_LIST_TABLES, (schema,))
        ]

    def describe_table(self, schema: str, table: str) -> Optional[TableDescription]:
        with self._transaction(CATALOG_TIMEOUT_MS) as cur:
            cur.execute(_TABLE_OID, (schema, table))
            found = cur.fetchone()
            if found is None:
                return None
            oid = found[0]
            cur.execute(_COLUMNS, (oid,))
            columns = [ColumnInfo(name=r[0], data_type=r[1], nullable=r[2], default=r[3]) for r in cur.fetchall()]
            cur.execute(_INDEXES, (oid,))
            indexes = [
                IndexInfo(name=r[0], columns=list(r[1]), definition=r[2], unique=r[3], primary=r[4])
                for r in cur.fetchall()
            ]
            cur.execute(_FOREIGN_KEYS, (oid,))
            fks = [
                ForeignKeyInfo(name=r[0], columns=list(r[1]), ref_schema=r[2], ref_table=r[3], ref_columns=list(r[4]))
                for r in cur.fetchall()
            ]
        return TableDescription(schema=schema, name=table, columns=columns, indexes=indexes, foreign_keys=fks)

    def run_query(self, sql: str, *, max_rows: int, timeout_ms: int, search_path: Sequence[str]) -> QueryResult:
        with self._transaction(timeout_ms, search_path) as cur:
            cur.execute(sql, prepare=False)
            if cur.description is None:
                return QueryResult(columns=[], rows=[])
            columns = [d.name for d in cur.description]
            fetched = cur.fetchmany(max_rows + 1)
        rows = [list(r) for r in fetched[:max_rows]]
        return QueryResult(columns=columns, rows=rows, truncated=len(fetched) > max_rows)

    def explain(self, sql: str, *, analyze: bool, timeout_ms: int, search_path: Sequence[str]) -> dict[str, Any]:
        options = "FORMAT JSON, ANALYZE, BUFFERS" if analyze else "FORMAT JSON"
        with self._transaction(timeout_ms, search_path) as cur:
            cur.execute(f"EXPLAIN ({options}) {sql}", prepare=False)
            row = cur.fetchone()
        doc = row[0] if row else None
        if isinstance(doc, str):
            doc = json.loads(doc)
        if not isinstance(doc, list) or not doc or "Plan" not in doc[0]:
            raise DatabaseError("unexpected EXPLAIN output")
        return doc[0]


def _describe_pg_error(exc: Exception) -> str:
    diag = getattr(exc, "diag", None)
    primary = getattr(diag, "message_primary", None) if diag is not None else None
    sqlstate = getattr(exc, "sqlstate", None)
    text = str(exc).strip()
    message = primary or (text.splitlines()[0] if text else type(exc).__name__)
    return f"{message} (SQLSTATE {sqlstate})" if sqlstate else message
