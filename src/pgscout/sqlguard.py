"""Lexical guard that only lets a single read-only statement through.

The guard is a real tokenizer for the parts of PostgreSQL's lexical grammar
that matter for safety: string literals (standard, ``E''`` escape strings and
dollar-quoted bodies), quoted identifiers, and line / nested block comments.
Everything inside those constructs is opaque, so a semicolon or keyword hidden
in a string or comment can never be mistaken for code, and code can never be
hidden from the guard by pretending to be a string or comment.

The guard is one layer of defence. The statement is still executed inside a
``READ ONLY`` transaction with a ``statement_timeout`` and should run under a
database role that only has ``SELECT`` grants.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MAX_SQL_LENGTH = 20_000

# Keywords that may only appear in a statement that writes, locks or changes
# server state. Everything else that is statement-level (VACUUM, SET, COPY ...)
# is excluded by the "must start with SELECT / WITH / EXPLAIN" rule, but the
# common ones are listed too so a mistake in that rule does not open a hole.
FORBIDDEN_KEYWORDS = frozenset(
    {
        "INSERT",
        "UPDATE",
        "DELETE",
        "MERGE",
        "INTO",
        "DROP",
        "ALTER",
        "CREATE",
        "TRUNCATE",
        "GRANT",
        "REVOKE",
        "COPY",
        "VACUUM",
        "REINDEX",
        "CLUSTER",
        "LISTEN",
        "NOTIFY",
        "CHECKPOINT",
    }
)

# Functions that sleep, touch the filesystem, signal other backends, take
# locks, change settings (set_config could lift statement_timeout) or write.
FORBIDDEN_FUNCTIONS = frozenset(
    {
        "pg_sleep",
        "pg_sleep_for",
        "pg_sleep_until",
        "pg_terminate_backend",
        "pg_cancel_backend",
        "pg_reload_conf",
        "pg_rotate_logfile",
        "pg_read_file",
        "pg_read_binary_file",
        "pg_ls_dir",
        "pg_stat_file",
        "pg_ls_logdir",
        "pg_ls_waldir",
        "lo_import",
        "lo_export",
        "lo_unlink",
        "lo_from_bytea",
        "lo_put",
        "set_config",
        "nextval",
        "setval",
        "pg_advisory_lock",
        "pg_advisory_lock_shared",
        "pg_advisory_xact_lock",
        "pg_advisory_xact_lock_shared",
        "pg_try_advisory_lock",
        "pg_try_advisory_lock_shared",
        "pg_try_advisory_xact_lock",
        "pg_try_advisory_xact_lock_shared",
        "dblink",
        "dblink_exec",
        "dblink_connect",
        "pg_notify",
        "query_to_xml",
        "pg_switch_wal",
        "pg_create_restore_point",
    }
)

LOCKING_STRENGTHS = frozenset({"UPDATE", "SHARE", "NO", "KEY"})
EXPLAIN_FLAGS = frozenset({"ANALYZE", "ANALYSE", "VERBOSE"})


class SqlRejected(ValueError):
    """Raised when a statement is not a single read-only query."""


@dataclass(frozen=True)
class Token:
    kind: str  # word | qident | string | number | param | punct
    value: str
    pos: int

    @property
    def upper(self) -> str:
        return self.value.upper()


@dataclass(frozen=True)
class GuardedSql:
    """A statement that passed the guard."""

    sql: str
    statement: str  # SELECT | WITH | EXPLAIN
    explain_analyze: bool = False
    identifiers: frozenset[str] = field(default_factory=frozenset)
    qualifiers: frozenset[str] = field(default_factory=frozenset)


def _is_ident_start(ch: str) -> bool:
    return ch.isalpha() or ch == "_" or ord(ch) > 127


def _is_ident_char(ch: str) -> bool:
    return ch.isalnum() or ch in "_$" or ord(ch) > 127


def tokenize(sql: str) -> list[Token]:
    """Split SQL into tokens, dropping comments and whitespace."""
    tokens: list[Token] = []
    i, n = 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch.isspace():
            i += 1
        elif sql.startswith("--", i):
            end = sql.find("\n", i)
            i = n if end == -1 else end + 1
        elif sql.startswith("/*", i):
            i = _skip_block_comment(sql, i)
        elif ch == "'":
            i = _read_string(sql, i, tokens, backslash_escapes=False)
        elif ch == '"':
            i = _read_quoted_ident(sql, i, tokens)
        elif ch == "$":
            i = _read_dollar(sql, i, tokens)
        elif _is_ident_start(ch):
            start = i
            while i < n and _is_ident_char(sql[i]):
                i += 1
            word = sql[start:i]
            if i < n and sql[i] == "'" and word.upper() in {"E", "X", "B", "N"}:
                # Prefixed literal: E'..' honours backslash escapes.
                i = _read_string(sql, i, tokens, backslash_escapes=word.upper() == "E")
            else:
                tokens.append(Token("word", word, start))
        elif ch.isdigit():
            start = i
            while i < n and (sql[i].isalnum() or sql[i] in "._"):
                i += 1
            tokens.append(Token("number", sql[start:i], start))
        else:
            tokens.append(Token("punct", ch, i))
            i += 1
    return tokens


def _skip_block_comment(sql: str, i: int) -> int:
    # PostgreSQL block comments nest.
    depth, i, n = 0, i, len(sql)
    while i < n:
        if sql.startswith("/*", i):
            depth += 1
            i += 2
        elif sql.startswith("*/", i):
            depth -= 1
            i += 2
            if depth == 0:
                return i
        else:
            i += 1
    raise SqlRejected("unterminated block comment")


def _read_string(sql: str, i: int, tokens: list[Token], *, backslash_escapes: bool) -> int:
    start, i, n = i, i + 1, len(sql)
    while i < n:
        ch = sql[i]
        if backslash_escapes and ch == "\\":
            i += 2
            continue
        if ch == "'":
            if i + 1 < n and sql[i + 1] == "'":
                i += 2
                continue
            tokens.append(Token("string", sql[start : i + 1], start))
            return i + 1
        i += 1
    raise SqlRejected("unterminated string literal")


def _read_quoted_ident(sql: str, i: int, tokens: list[Token]) -> int:
    start, i, n = i, i + 1, len(sql)
    buf: list[str] = []
    while i < n:
        if sql[i] == '"':
            if i + 1 < n and sql[i + 1] == '"':
                buf.append('"')
                i += 2
                continue
            tokens.append(Token("qident", "".join(buf), start))
            return i + 1
        buf.append(sql[i])
        i += 1
    raise SqlRejected("unterminated quoted identifier")


def _read_dollar(sql: str, i: int, tokens: list[Token]) -> int:
    n = len(sql)
    j = i + 1
    if j < n and sql[j].isdigit():
        while j < n and sql[j].isdigit():
            j += 1
        tokens.append(Token("param", sql[i:j], i))
        return j
    while j < n and _is_ident_char(sql[j]) and sql[j] != "$":
        j += 1
    if j < n and sql[j] == "$":
        tag = sql[i : j + 1]
        close = sql.find(tag, j + 1)
        if close == -1:
            raise SqlRejected("unterminated dollar-quoted string")
        end = close + len(tag)
        tokens.append(Token("string", sql[i:end], i))
        return end
    tokens.append(Token("punct", "$", i))
    return i + 1


def guard(sql: str, *, allow_explain: bool = True, allow_explain_analyze: bool = False) -> GuardedSql:
    """Return the statement if it is a single read-only query, else raise."""
    if not isinstance(sql, str) or not sql.strip():
        raise SqlRejected("empty statement")
    if len(sql) > MAX_SQL_LENGTH:
        raise SqlRejected(f"statement longer than {MAX_SQL_LENGTH} characters")
    if "\x00" in sql:
        raise SqlRejected("NUL byte in statement")

    tokens = tokenize(sql)

    # Allow trailing semicolons only; anything after a semicolon is a second statement.
    while tokens and tokens[-1].value == ";" and tokens[-1].kind == "punct":
        tokens.pop()
    if any(t.kind == "punct" and t.value == ";" for t in tokens):
        raise SqlRejected("only a single statement is allowed")
    if not tokens:
        raise SqlRejected("empty statement")

    first = next((t for t in tokens if not (t.kind == "punct" and t.value == "(")), None)
    if first is None or first.kind != "word":
        raise SqlRejected("statement must start with SELECT, WITH or EXPLAIN")
    statement = first.upper
    explain_analyze = False
    if statement == "EXPLAIN":
        if not allow_explain:
            raise SqlRejected("EXPLAIN is added by this tool; pass the bare query")
        explain_analyze = _check_explain(tokens, tokens.index(first))
        if explain_analyze and not allow_explain_analyze:
            raise SqlRejected("EXPLAIN ANALYZE executes the query and is disabled by policy")
    elif statement not in {"SELECT", "WITH"}:
        raise SqlRejected(f"{statement} statements are not allowed; use SELECT, WITH or EXPLAIN")

    identifiers: set[str] = set()
    qualifiers: set[str] = set()
    for idx, tok in enumerate(tokens):
        nxt = tokens[idx + 1] if idx + 1 < len(tokens) else None
        if tok.kind == "word":
            word = tok.upper
            if word in FORBIDDEN_KEYWORDS:
                raise SqlRejected(f"keyword {word} is not allowed in a read-only query")
            if word == "FOR" and nxt is not None and nxt.kind == "word" and nxt.upper in LOCKING_STRENGTHS:
                raise SqlRejected("row-locking clauses (FOR UPDATE / FOR SHARE) are not allowed")
        if tok.kind in {"word", "qident"}:
            name = tok.value.lower() if tok.kind == "word" else tok.value
            if nxt is not None and nxt.kind == "punct" and nxt.value == "(" and name in FORBIDDEN_FUNCTIONS:
                raise SqlRejected(f"function {name}() is not allowed")
            identifiers.add(name)
            if nxt is not None and nxt.kind == "punct" and nxt.value == ".":
                qualifiers.add(name)

    return GuardedSql(
        sql=_strip_trailing_semicolons(sql),
        statement=statement,
        explain_analyze=explain_analyze,
        identifiers=frozenset(identifiers),
        qualifiers=frozenset(qualifiers),
    )


def _check_explain(tokens: list[Token], start: int) -> bool:
    """Validate ``EXPLAIN [options] <SELECT|WITH ...>``; return True for ANALYZE."""
    i = start + 1
    analyze = False
    if i < len(tokens) and tokens[i].value == "(":
        depth = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok.value == "(":
                depth += 1
            elif tok.value == ")":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            elif tok.kind == "word" and tok.upper in {"ANALYZE", "ANALYSE"}:
                nxt = tokens[i + 1] if i + 1 < len(tokens) else None
                analyze = not (nxt is not None and nxt.upper in {"FALSE", "OFF", "0"})
            i += 1
    while i < len(tokens) and tokens[i].kind == "word" and tokens[i].upper in EXPLAIN_FLAGS:
        analyze = analyze or tokens[i].upper in {"ANALYZE", "ANALYSE"}
        i += 1
    inner = next((t for t in tokens[i:] if not (t.kind == "punct" and t.value == "(")), None)
    if inner is None or inner.kind != "word" or inner.upper not in {"SELECT", "WITH"}:
        raise SqlRejected("EXPLAIN may only wrap a SELECT or WITH query")
    return analyze


def _strip_trailing_semicolons(sql: str) -> str:
    """Remove trailing semicolons. Called only after the guard has accepted the SQL."""
    stripped = sql.rstrip()
    tokens = tokenize(stripped)
    while tokens and tokens[-1].kind == "punct" and tokens[-1].value == ";":
        stripped = stripped[: tokens[-1].pos].rstrip()
        tokens.pop()
    return stripped
