from __future__ import annotations

import pytest

from pgscout.sqlguard import SqlRejected, guard, tokenize


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1",
        "select id, email from customers where id = 1",
        "WITH recent AS (SELECT * FROM orders) SELECT count(*) FROM recent",
        "(SELECT 1) UNION ALL (SELECT 2)",
        "EXPLAIN SELECT * FROM orders",
        "EXPLAIN (FORMAT JSON, COSTS true) SELECT * FROM orders",
        "SELECT 1;",
        "SELECT 1; -- trailing comment",
        "SELECT ';' AS semicolon_in_string",
        "SELECT 'it''s; DROP TABLE t' AS doubled_quote",
        "SELECT E'it\\'s; DROP TABLE t' AS escape_string",
        "SELECT $$; DROP TABLE t$$ AS dollar_body",
        "SELECT $tag$ $$ ; DELETE FROM t $tag$",
        'SELECT "delete", "update" FROM audit_events',
        "SELECT 1 /* ; DROP TABLE t; */",
        "SELECT /* outer /* nested ; DELETE */ still comment */ 1",
        "SELECT for_update, share FROM flags WHERE created_at > now() - interval '1 day'",
    ],
)
def test_accepts_single_read_only_statements(sql: str) -> None:
    result = guard(sql)
    assert result.statement in {"SELECT", "WITH", "EXPLAIN"}
    assert not result.sql.rstrip().endswith(";")


@pytest.mark.parametrize(
    ("sql", "reason"),
    [
        ("INSERT INTO t VALUES (1)", "INSERT"),
        ("update t set a = 1", "UPDATE"),
        ("DeLeTe FROM t", "DELETE"),
        ("DROP TABLE customers", "DROP"),
        ("TRUNCATE orders", "TRUNCATE"),
        ("SET statement_timeout = 0", "SET"),
        ("COPY customers TO '/tmp/x'", "COPY"),
        ("SELECT 1; DROP TABLE t", "single statement"),
        ("SELECT 1;; SELECT 2", "single statement"),
        ("SELECT 1 /* */; DELETE FROM t", "single statement"),
        ("SELECT 1 -- comment\n; DELETE FROM t", "single statement"),
        ("SELECT 'a'';' ; DELETE FROM t", "single statement"),
        ("WITH gone AS (DELETE FROM t RETURNING *) SELECT * FROM gone", "DELETE"),
        ("SELECT * INTO new_table FROM t", "INTO"),
        ("SELECT * FROM t FOR UPDATE", "FOR UPDATE"),
        ("SELECT * FROM t FOR NO KEY UPDATE", "FOR UPDATE"),
        ("SELECT * FROM t FOR SHARE", "FOR UPDATE"),
        ("SELECT pg_sleep(10)", "pg_sleep"),
        ('SELECT "pg_sleep"(10)', "pg_sleep"),
        ("SELECT pg_catalog.pg_terminate_backend(123)", "pg_terminate_backend"),
        ("SELECT set_config('statement_timeout', '0', false)", "set_config"),
        ("SELECT nextval('orders_id_seq')", "nextval"),
        ("EXPLAIN ANALYZE DELETE FROM t", "EXPLAIN may only wrap"),
        ("EXPLAIN ANALYZE SELECT * FROM t", "EXPLAIN ANALYZE"),
        ("EXPLAIN (ANALYZE) SELECT * FROM t", "EXPLAIN ANALYZE"),
        ("SELECT 1 /* unterminated", "unterminated"),
        ("SELECT 'unterminated", "unterminated"),
        ("SELECT $x$ never closed", "unterminated"),
        ("", "empty"),
        ("  ;  ", "empty"),
        ("SELECT 1\x00", "NUL"),
    ],
)
def test_rejects_writes_and_tricks(sql: str, reason: str) -> None:
    with pytest.raises(SqlRejected, match=reason):
        guard(sql)


def test_explain_analyze_only_when_allowed() -> None:
    result = guard("EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM t", allow_explain_analyze=True)
    assert result.explain_analyze is True
    assert guard("EXPLAIN (ANALYZE false) SELECT 1").explain_analyze is False


def test_plan_tools_refuse_explain_prefix() -> None:
    with pytest.raises(SqlRejected, match="pass the bare query"):
        guard("EXPLAIN SELECT 1", allow_explain=False)


def test_strips_trailing_semicolons_but_keeps_body() -> None:
    assert guard("SELECT ';' ;  ; -- done").sql == "SELECT ';'"


def test_collects_identifiers_and_schema_qualifiers() -> None:
    result = guard('SELECT c.email, "Full Name" FROM internal.customers c')
    assert {"email", "Full Name", "customers"} <= result.identifiers
    assert {"c", "internal"} <= result.qualifiers


def test_tokenizer_hides_strings_and_comments() -> None:
    kinds = [(t.kind, t.value) for t in tokenize("SELECT 'a;b' -- x;\n, $$c;d$$ /* ; */")]
    assert kinds == [("word", "SELECT"), ("string", "'a;b'"), ("punct", ","), ("string", "$$c;d$$")]
