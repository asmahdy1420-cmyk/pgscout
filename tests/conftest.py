from __future__ import annotations

import pytest

from pgscout.fake import FakeDatabase, demo_database
from pgscout.gate import Gate
from pgscout.policy import MemoryAuditLog, Policy
from pgscout.server import McpServer


@pytest.fixture
def db() -> FakeDatabase:
    return demo_database()


@pytest.fixture
def audit() -> MemoryAuditLog:
    return MemoryAuditLog()


@pytest.fixture
def policy() -> Policy:
    return Policy(allowed_schemas=("public",), max_rows=50)


@pytest.fixture
def gate(db: FakeDatabase, policy: Policy, audit: MemoryAuditLog) -> Gate:
    return Gate(db, policy, audit)


@pytest.fixture
def server(gate: Gate) -> McpServer:
    srv = McpServer(gate)
    srv.handle({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
    srv.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
    return srv
