from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

from pgscout.gate import Gate
from pgscout.server import INVALID_PARAMS, METHOD_NOT_FOUND, PARSE_ERROR, RESOURCE_NOT_FOUND, McpServer

SRC = Path(__file__).resolve().parents[1] / "src"


def call(server: McpServer, method: str, params: dict | None = None, id_: int = 1) -> dict:
    msg = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        msg["params"] = params
    response = server.handle(msg)
    assert response is not None
    assert response["id"] == id_
    return response


def test_initialize_negotiates_version(gate: Gate) -> None:
    server = McpServer(gate)
    result = call(server, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {}})["result"]
    assert result["protocolVersion"] == "2025-03-26"
    assert result["serverInfo"]["name"] == "pgscout"
    assert set(result["capabilities"]) == {"tools", "resources"}
    unknown = call(McpServer(gate), "initialize", {"protocolVersion": "1999-01-01"})["result"]
    assert unknown["protocolVersion"] == "2025-06-18"


def test_requests_before_initialize_are_rejected(gate: Gate) -> None:
    server = McpServer(gate)
    assert "error" in call(server, "tools/list")
    assert call(server, "ping")["result"] == {}


def test_tools_list_exposes_all_tools_as_read_only(server: McpServer) -> None:
    tools = call(server, "tools/list")["result"]["tools"]
    names = {t["name"] for t in tools}
    assert names == {
        "list_schemas",
        "list_tables",
        "describe_table",
        "run_readonly_query",
        "explain_query",
        "suggest_indexes",
    }
    assert all(t["annotations"]["readOnlyHint"] is True for t in tools)
    assert all(t["inputSchema"]["type"] == "object" for t in tools)


def test_tools_call_success_and_tool_error(server: McpServer) -> None:
    ok = call(
        server, "tools/call", {"name": "run_readonly_query", "arguments": {"sql": "SELECT id, status FROM orders"}}
    )
    result = ok["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["row_count"] == 3
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]

    bad = call(server, "tools/call", {"name": "run_readonly_query", "arguments": {"sql": "DROP TABLE orders"}})
    assert bad["result"]["isError"] is True
    assert "DROP" in bad["result"]["content"][0]["text"]


def test_protocol_errors(server: McpServer) -> None:
    assert call(server, "does/not/exist")["error"]["code"] == METHOD_NOT_FOUND
    assert call(server, "tools/call", {"name": "nope"})["error"]["code"] == INVALID_PARAMS
    assert call(server, "tools/call", {"name": "list_tables", "arguments": []})["error"]["code"] == INVALID_PARAMS
    assert call(server, "resources/read", {"uri": "pgscout://schema/internal"})["error"]["code"] == RESOURCE_NOT_FOUND
    parse = server.handle_line("{not json")
    assert parse is not None and parse["error"]["code"] == PARSE_ERROR and parse["id"] is None
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {}}) is None


def test_serve_over_streams(gate: Gate) -> None:
    lines = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "resources/list"},
        {"jsonrpc": "2.0", "id": "r3", "method": "resources/read", "params": {"uri": "pgscout://policy"}},
    ]
    instream = io.StringIO("\n".join(json.dumps(m) for m in lines) + "\n\n")
    outstream = io.StringIO()
    McpServer(gate).serve(instream, outstream)
    responses = [json.loads(line) for line in outstream.getvalue().splitlines()]
    assert [r["id"] for r in responses] == [1, 2, "r3"]
    policy = json.loads(responses[2]["result"]["contents"][0]["text"])
    assert policy["allowed_schemas"] == ["public"]


def test_stdio_subprocess_round_trip(tmp_path: Path) -> None:
    audit_file = tmp_path / "audit.jsonl"
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_tables", "arguments": {}}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "run_readonly_query", "arguments": {"sql": "SELECT * FROM customers LIMIT 1"}},
        },
    ]
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    proc = subprocess.run(
        [sys.executable, "-m", "pgscout", "--demo", "--audit-log", str(audit_file)],
        input="".join(json.dumps(r) + "\n" for r in requests),
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=True,
    )
    responses = [json.loads(line) for line in proc.stdout.splitlines()]
    assert [r["id"] for r in responses] == [1, 2, 3]
    tables = responses[1]["result"]["structuredContent"]["tables"]
    assert [t["name"] for t in tables] == ["customers", "orders"]
    query = responses[2]["result"]["structuredContent"]
    assert query["rows"][0][query["columns"].index("password_hash")] == "[REDACTED]"
    audit = [json.loads(line) for line in audit_file.read_text().splitlines()]
    assert [a["target"] for a in audit] == ["list_tables", "run_readonly_query"]
