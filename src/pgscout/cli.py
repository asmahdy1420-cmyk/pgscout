"""Command line entry point: ``pgscout`` / ``python -m pgscout``."""

from __future__ import annotations

import argparse
import contextlib
import io
import logging
import os
import sys
from typing import Optional

from . import __version__
from .db import Database, PsycopgDatabase
from .fake import demo_database
from .gate import Gate
from .policy import DEFAULT_DENIED_COLUMNS, AuditLog, Policy
from .server import McpServer


def _csv(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def build_parser() -> argparse.ArgumentParser:
    env = os.environ.get
    parser = argparse.ArgumentParser(
        prog="pgscout",
        description="Read-only PostgreSQL inspection server speaking MCP over stdio.",
    )
    parser.add_argument(
        "--dsn",
        default=env("PGSCOUT_DSN") or env("DATABASE_URL"),
        help="libpq connection string (env PGSCOUT_DSN or DATABASE_URL)",
    )
    parser.add_argument(
        "--schemas",
        default=env("PGSCOUT_SCHEMAS", "public"),
        help="comma-separated schema allowlist (env PGSCOUT_SCHEMAS, default: public)",
    )
    parser.add_argument(
        "--deny-columns",
        default=env("PGSCOUT_DENY_COLUMNS", ",".join(DEFAULT_DENIED_COLUMNS)),
        help="comma-separated glob patterns of column names to redact and refuse (env PGSCOUT_DENY_COLUMNS)",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=int(env("PGSCOUT_MAX_ROWS", "200")),
        help="row cap per query (env PGSCOUT_MAX_ROWS, default: 200)",
    )
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=int(env("PGSCOUT_TIMEOUT_MS", "5000")),
        help="statement_timeout in ms (env PGSCOUT_TIMEOUT_MS, default: 5000)",
    )
    parser.add_argument(
        "--audit-log",
        default=env("PGSCOUT_AUDIT_LOG"),
        help="JSON lines audit file (env PGSCOUT_AUDIT_LOG, default: stderr)",
    )
    parser.add_argument(
        "--allow-explain-analyze", action="store_true", help="allow EXPLAIN ANALYZE, which executes the query"
    )
    parser.add_argument(
        "--demo", action="store_true", help="serve a built-in in-memory sample database instead of PostgreSQL"
    )
    parser.add_argument("--log-level", default=env("PGSCOUT_LOG_LEVEL", "WARNING"))
    parser.add_argument("--version", action="version", version=f"pgscout {__version__}")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        stream=sys.stderr, level=args.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    try:
        policy = Policy(
            allowed_schemas=_csv(args.schemas),
            denied_columns=_csv(args.deny_columns),
            max_rows=args.max_rows,
            statement_timeout_ms=args.timeout_ms,
            allow_explain_analyze=args.allow_explain_analyze,
        )
    except ValueError as exc:
        print(f"pgscout: {exc}", file=sys.stderr)
        return 2

    db: Database
    if args.demo:
        db = demo_database()
    elif args.dsn:
        db = PsycopgDatabase(args.dsn)
    else:
        print("pgscout: set --dsn / PGSCOUT_DSN, or use --demo", file=sys.stderr)
        return 2

    audit = AuditLog.to_file(args.audit_log) if args.audit_log else AuditLog.to_stderr()
    server = McpServer(Gate(db, policy, audit))

    # Protocol messages are UTF-8 regardless of the platform locale.
    stdin = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")
    stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n", write_through=True)
    with contextlib.suppress(KeyboardInterrupt):
        server.serve(stdin, stdout)
    return 0
