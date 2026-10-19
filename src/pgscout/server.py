"""MCP over stdio: newline-delimited JSON-RPC 2.0.

Implements the subset of the Model Context Protocol a tool server needs:
``initialize``, ``ping``, ``tools/list``, ``tools/call``, ``resources/list``
and ``resources/read``, plus the ``notifications/*`` a client may send.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Optional, TextIO

from . import __version__
from .db import DatabaseError
from .gate import Gate, UnknownResource, UnknownTool

log = logging.getLogger(__name__)

SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
RESOURCE_NOT_FOUND = -32002

INSTRUCTIONS = (
    "Read-only PostgreSQL inspection. Start with list_schemas and list_tables, use describe_table "
    "before writing queries, and prefer explain_query over running expensive statements. Only a "
    "single SELECT, WITH or EXPLAIN statement is accepted; results are capped and sensitive "
    "columns are redacted."
)


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _error(id_: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": id_, "error": err}


class McpServer:
    def __init__(self, gate: Gate, *, name: str = "pgscout", version: str = __version__) -> None:
        self.gate = gate
        self.name = name
        self.version = version
        self.initialized = False
        self.protocol_version: Optional[str] = None
        self._methods: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "initialize": self._initialize,
            "ping": lambda params: {},
            "tools/list": self._tools_list,
            "tools/call": self._tools_call,
            "resources/list": self._resources_list,
            "resources/read": self._resources_read,
        }

    # -- dispatch --------------------------------------------------------

    def handle_line(self, line: str) -> Optional[dict[str, Any]]:
        """Handle one raw line; return the response object, or None for notifications."""
        try:
            message = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return _error(None, PARSE_ERROR, "parse error", str(exc))
        return self.handle(message)

    def handle(self, message: Any) -> Optional[dict[str, Any]]:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error(None, INVALID_REQUEST, "invalid request: expected a JSON-RPC 2.0 object")
        if "method" not in message:
            return None  # a response to a request we never send; ignore
        method = message["method"]
        is_notification = "id" not in message
        id_ = message.get("id")
        if not isinstance(method, str) or (not is_notification and not isinstance(id_, (str, int))):
            return None if is_notification else _error(id_, INVALID_REQUEST, "invalid request")

        if is_notification:
            if method == "notifications/initialized":
                self.initialized = True
            return None

        params = message.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return _error(id_, INVALID_PARAMS, "params must be an object")

        handler = self._methods.get(method)
        if handler is None:
            return _error(id_, METHOD_NOT_FOUND, f"method not found: {method}")
        if method not in {"initialize", "ping"} and self.protocol_version is None:
            return _error(id_, INVALID_REQUEST, "server not initialized")
        try:
            result = handler(params)
        except RpcError as exc:
            return _error(id_, exc.code, exc.message, exc.data)
        except Exception:
            log.exception("unhandled error in %s", method)
            return _error(id_, INTERNAL_ERROR, "internal error")
        return {"jsonrpc": "2.0", "id": id_, "result": result}

    # -- methods ---------------------------------------------------------

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else LATEST_PROTOCOL_VERSION
        self.protocol_version = version
        return {
            "protocolVersion": version,
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"listChanged": False, "subscribe": False},
            },
            "serverInfo": {"name": self.name, "title": "pgscout", "version": self.version},
            "instructions": INSTRUCTIONS,
        }

    def _tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"tools": self.gate.list_tools()}

    def _tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments")
        if not isinstance(name, str):
            raise RpcError(INVALID_PARAMS, "tools/call requires a tool name")
        if arguments is not None and not isinstance(arguments, dict):
            raise RpcError(INVALID_PARAMS, "arguments must be an object")
        try:
            outcome = self.gate.call_tool(name, arguments)
        except UnknownTool as exc:
            raise RpcError(INVALID_PARAMS, f"unknown tool: {name}") from exc
        result: dict[str, Any] = {
            "content": [{"type": "text", "text": outcome.text}],
            "isError": not outcome.ok,
        }
        if outcome.ok:
            # Round-trip through JSON so structured content matches the text exactly.
            result["structuredContent"] = json.loads(outcome.text)
        return result

    def _resources_list(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"resources": self.gate.list_resources()}

    def _resources_read(self, params: dict[str, Any]) -> dict[str, Any]:
        uri = params.get("uri")
        if not isinstance(uri, str):
            raise RpcError(INVALID_PARAMS, "resources/read requires a uri")
        try:
            text = self.gate.read_resource(uri)
        except UnknownResource as exc:
            raise RpcError(RESOURCE_NOT_FOUND, "resource not found", {"uri": uri}) from exc
        except DatabaseError as exc:
            raise RpcError(INTERNAL_ERROR, str(exc)) from exc
        return {"contents": [{"uri": uri, "mimeType": "application/json", "text": text}]}

    # -- transport -------------------------------------------------------

    def serve(self, instream: TextIO, outstream: TextIO) -> None:
        """Read requests line by line until EOF, writing one response line per request."""
        for line in instream:
            if not line.strip():
                continue
            response = self.handle_line(line)
            if response is not None:
                outstream.write(json.dumps(response, ensure_ascii=False) + "\n")
                outstream.flush()
