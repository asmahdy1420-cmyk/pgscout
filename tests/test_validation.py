from __future__ import annotations

import pytest

from pgscout.tools import TOOLS
from pgscout.validation import ValidationError, validate

SCHEMAS = {t.name: t.input_schema for t in TOOLS}


def test_applies_defaults() -> None:
    args = validate({"sql": "SELECT 1"}, SCHEMAS["explain_query"])
    assert args == {"sql": "SELECT 1", "analyze": False, "include_plan": False}


@pytest.mark.parametrize(
    ("tool", "args", "message"),
    [
        ("run_readonly_query", {}, "$.sql: is required"),
        ("run_readonly_query", {"sql": 42}, "expected string"),
        ("run_readonly_query", {"sql": ""}, "at least 1"),
        ("run_readonly_query", {"sql": "SELECT 1", "max_rows": True}, "expected integer, got boolean"),
        ("run_readonly_query", {"sql": "SELECT 1", "max_rows": 0}, ">= 1"),
        ("run_readonly_query", {"sql": "SELECT 1", "max_rows": 10**6}, "<= 10000"),
        ("list_tables", {"schema": "public", "extra": 1}, "unexpected argument"),
        ("list_tables", [], "expected object"),
    ],
)
def test_rejects_bad_arguments(tool: str, args: object, message: str) -> None:
    with pytest.raises(ValidationError, match=message.replace("$", r"\$")):
        validate(args, SCHEMAS[tool])
