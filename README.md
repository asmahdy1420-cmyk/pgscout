# pgscout

A Model Context Protocol (MCP) server that gives agents **safe, read-only insight into a PostgreSQL database**: schema discovery, guarded queries, `EXPLAIN` summaries and index suggestions, all behind one policy layer with an audit trail.

The MCP stdio transport (JSON-RPC 2.0, newline-delimited) is implemented directly in under 200 lines, so the server has a single runtime dependency (`psycopg`) and no SDK to track.

## Why

Agents are useful at the "why is this query slow / what does this table look like" stage of database work, but handing one a connection string is handing it `DROP TABLE`. pgscout narrows the surface to what inspection actually needs and makes every call explainable after the fact:

- the agent can only read, and only from the schemas you allow;
- sensitive columns are refused in SQL and redacted in results;
- every call, allowed or denied, lands in a JSON lines audit log.

## Tools

| Tool | What it returns |
| --- | --- |
| `list_schemas` | Allowlisted schemas that exist in the database |
| `list_tables` | Tables, views and materialized views with estimated row counts |
| `describe_table` | Columns (type, nullability, default), indexes, foreign keys; denied columns are flagged |
| `run_readonly_query` | Rows from one `SELECT` / `WITH` / `EXPLAIN` statement, capped at `max_rows`, denied columns redacted |
| `explain_query` | `EXPLAIN (FORMAT JSON)` summary: total cost, node counts, sequential scans, warnings (optionally the raw plan) |
| `suggest_indexes` | Heuristic suggestions with ready `CREATE INDEX CONCURRENTLY` DDL; never executes them |

Resources: `pgscout://policy` (the effective policy) and `pgscout://schema/<name>` (table list per allowed schema).

## Security model

Defence in depth. No single layer is trusted on its own.

1. **Database role (the real boundary).** Run pgscout as a dedicated role with `SELECT` grants only, and use column privileges for anything truly secret. Everything below is there to make mistakes in that setup survivable.
2. **Read-only session and transaction.** The session default is `READ ONLY`; every call additionally runs `SET TRANSACTION READ ONLY`, sets a local `statement_timeout` and `search_path` (the allowlisted schemas), and is always rolled back.
3. **SQL guard.** A tokenizer that understands string literals (`'...'`, `E'...'`, `$tag$...$tag$`), quoted identifiers and nested block comments. It accepts exactly one statement starting with `SELECT`, `WITH` or `EXPLAIN` and rejects:
   - a second statement after `;` (trailing semicolons and comments are fine);
   - write and DDL keywords anywhere, including data-modifying CTEs and `SELECT ... INTO`;
   - row-locking clauses (`FOR UPDATE`, `FOR SHARE` ...);
   - functions that sleep, read files, signal backends, take advisory locks, change settings (`set_config` could lift the timeout) or bump sequences;
   - `EXPLAIN ANALYZE` unless the policy allows it, because it executes the query.
4. **Policy (one choke point).** Every tool call and resource read passes through `Gate`: argument validation against the tool's JSON Schema, schema allowlist (both `schema` arguments and schema-qualified names in SQL, including `pg_catalog` and `information_schema`), denied-column checks, row cap, result redaction, audit.
5. **Denied columns.** Glob patterns such as `*password*`, `ssn`, `*token*`. A query that *names* a denied column is refused (an alias would otherwise defeat redaction); `SELECT *` results have those columns replaced with `[REDACTED]`.

Known limits, stated plainly: name-based redaction cannot see through whole-row expressions such as `row_to_json(t)`, and unqualified references to `pg_catalog` views resolve implicitly. Both are why layer 1 matters.

## Architecture

```mermaid
flowchart LR
  C["MCP client / agent"] -->|"JSON-RPC over stdio"| S["McpServer<br>initialize, tools, resources"]
  S --> G["Gate<br>single choke point"]
  G --> V["validate args<br>JSON Schema subset"]
  G --> Q["sqlguard<br>one read-only statement"]
  G --> P["Policy<br>schemas, denied columns, row cap"]
  G --> T["tool handlers"]
  T --> D[("Database protocol")]
  D --> PG["PsycopgDatabase<br>READ ONLY tx, statement_timeout"]
  D --> F["FakeDatabase<br>tests and --demo"]
  T --> E["explain<br>plan summary, index heuristics"]
  G --> A["AuditLog<br>JSON lines"]
```

```
src/pgscout/
  server.py      JSON-RPC 2.0 framing and MCP methods
  gate.py        authorisation choke point and audit
  policy.py      Policy, PolicyDenied, AuditLog
  sqlguard.py    tokenizer and read-only statement guard
  validation.py  JSON Schema subset for tool arguments
  tools.py       tool specs and handlers
  explain.py     plan summaries and index suggestions
  db.py          Database protocol and psycopg implementation
  fake.py        in-memory Database and demo data
  cli.py         argument / environment configuration
```

## Quick start

```bash
pip install .                         # Python 3.11+
pgscout --demo                        # in-memory sample shop database, no PostgreSQL needed
PGSCOUT_DSN="postgresql://scout@localhost/app" pgscout --schemas public,reporting
```

Talk to it by hand:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"suggest_indexes","arguments":{"sql":"SELECT * FROM orders WHERE status = '\''paid'\''"}}}' \
  | pgscout --demo --audit-log audit.jsonl
```

A minimal role for production use:

```sql
CREATE ROLE scout LOGIN PASSWORD '...';
GRANT USAGE ON SCHEMA public TO scout;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO scout;
REVOKE SELECT (password_hash) ON public.customers FROM scout;  -- column-level, if needed
```

### Client configuration

Most MCP clients accept a JSON block like this:

```json
{
  "mcpServers": {
    "pgscout": {
      "command": "pgscout",
      "args": ["--schemas", "public", "--max-rows", "200"],
      "env": {
        "PGSCOUT_DSN": "postgresql://scout:secret@localhost:5432/app",
        "PGSCOUT_AUDIT_LOG": "/var/log/pgscout/audit.jsonl"
      }
    }
  }
}
```

With Docker: `"command": "docker", "args": ["run", "-i", "--rm", "-e", "PGSCOUT_DSN", "pgscout"]`.

### Configuration

| Flag | Environment | Default |
| --- | --- | --- |
| `--dsn` | `PGSCOUT_DSN` or `DATABASE_URL` | none (required unless `--demo`) |
| `--schemas` | `PGSCOUT_SCHEMAS` | `public` |
| `--deny-columns` | `PGSCOUT_DENY_COLUMNS` | `*password*,passwd,ssn,*secret*,*api_key*,*token*,card_number,cvv` |
| `--max-rows` | `PGSCOUT_MAX_ROWS` | `200` |
| `--timeout-ms` | `PGSCOUT_TIMEOUT_MS` | `5000` |
| `--audit-log` | `PGSCOUT_AUDIT_LOG` | stderr |
| `--allow-explain-analyze` | | off |

Audit records look like:

```json
{"arguments": {"sql": "SELECT 1; DELETE FROM orders"}, "decision": "denied", "duration_ms": 0.11, "kind": "tool", "reason": "only a single statement is allowed", "target": "run_readonly_query", "ts": "2026-10-19T09:12:03.418+00:00"}
```

## Design decisions

- **Protocol implemented by hand.** Newline-delimited JSON-RPC with six methods is small enough to own. It keeps the dependency list to the database driver and makes the wire behaviour easy to test in-process.
- **Tool errors are results, protocol errors are errors.** A denied query returns `isError: true` with the reason, so the agent can correct itself; an unknown method or tool returns a JSON-RPC error.
- **A tokenizer, not regexes, guards SQL.** Every bypass trick lives in the lexical layer (a `;` in a comment, a quote inside a dollar body, an escaped quote in `E''`). Getting the lexer right closes that whole class; the read-only transaction catches what a lexer cannot.
- **Refuse, then redact.** Naming a denied column fails the call; redaction is the second net for `SELECT *`.
- **Row cap by fetch, not by rewriting SQL.** pgscout fetches `max_rows + 1` and reports `truncated`, so the statement the agent wrote is the statement that runs.
- **`Database` is a protocol.** The psycopg implementation and the in-memory fake share it, so the whole server, including the stdio transport, is tested without PostgreSQL. A separate integration suite runs against a real server in CI.
- **Index suggestions are heuristics and say so.** Equality columns first, then one range column; unindexed foreign keys; an existing index on the leading column produces a note about statistics instead of a duplicate index.

What it deliberately does not do: write, run DDL, create the indexes it suggests, hold connections open in a transaction, or manage credentials.

## Running tests

```bash
python3 -m venv .venv
.venv/bin/pip install pytest ruff "psycopg[binary]>=3.1"
.venv/bin/python -m pytest          # unit and protocol tests, no database needed
.venv/bin/ruff check . && .venv/bin/ruff format --check .

# integration tests against a real PostgreSQL (creates and drops schema scout_it)
PGSCOUT_TEST_DSN=postgresql://postgres:postgres@localhost:5432/postgres .venv/bin/python -m pytest
```

The code is written to run on Python 3.9+ even though the package targets 3.11+, so the test suite runs on older system interpreters too.

## License

MIT, see [LICENSE](LICENSE). Author: Ahmed Mahdy.
