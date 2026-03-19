from __future__ import annotations

"""
FastAPI REST API tests using TestClient.
Tests all three routes: /health, /v1/identity/verify, /v1/policy/evaluate.
"""

import pytest
from fastapi.testclient import TestClient

from agentmesh.api.server import create_app, set_policy_engine
from agentmesh.identity.agent_identity import AgentIdentity
from agentmesh.policy.engine import PolicyEngine

SIMPLE_POLICY = {
    "version": "1.0",
    "agents": {
        "orchestrator": {"allowed_tools": [], "allowed_callers": []},
        "researcher": {
            "allowed_tools": ["web_search", "read_file"],
            "denied_tools": ["execute_shell"],
            "allowed_callers": ["orchestrator"],
            "rate_limits": {"web_search": "100/minute"},
        },
    },
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_policy():
    """Reset the global policy engine before each test."""
    set_policy_engine(None)
    yield
    set_policy_engine(None)


@pytest.fixture
def app_no_policy():
    return TestClient(create_app())


@pytest.fixture
def app_with_policy():
    engine = PolicyEngine.from_dict(SIMPLE_POLICY)
    set_policy_engine(engine)
    return TestClient(create_app())


@pytest.fixture
def identity():
    return AgentIdentity("researcher", ["web_search"], mesh_id="test-mesh")


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health_returns_ok(self, app_no_policy):
        r = app_no_policy.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_health_returns_version(self, app_no_policy):
        r = app_no_policy.get("/health")
        assert r.json()["version"] == "0.1.0"

    def test_health_policy_not_loaded(self, app_no_policy):
        r = app_no_policy.get("/health")
        assert r.json()["policy_loaded"] is False
        assert r.json()["registered_agents"] == []

    def test_health_policy_loaded(self, app_with_policy):
        r = app_with_policy.get("/health")
        assert r.json()["policy_loaded"] is True
        assert "researcher" in r.json()["registered_agents"]

    def test_health_is_fast(self, app_no_policy):
        """Health endpoint must respond quickly — used by SDK keep-alive."""
        import time
        start = time.monotonic()
        app_no_policy.get("/health")
        assert time.monotonic() - start < 1.0


# ---------------------------------------------------------------------------
# POST /v1/identity/verify
# ---------------------------------------------------------------------------

class TestIdentityVerifyEndpoint:
    def test_valid_token_returns_valid_true(self, app_no_policy, identity):
        token = identity.issue_token()
        r = app_no_policy.post("/v1/identity/verify", json={"token": token})
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is True
        assert data["agent_id"] == "researcher"
        assert data["mesh_id"] == "test-mesh"
        assert "web_search" in data["capabilities"]

    def test_invalid_token_returns_valid_false(self, app_no_policy):
        r = app_no_policy.post("/v1/identity/verify", json={"token": "bad.token.here"})
        assert r.status_code == 200
        assert r.json()["valid"] is False
        assert r.json()["error"] is not None

    def test_malformed_token_returns_valid_false(self, app_no_policy):
        r = app_no_policy.post("/v1/identity/verify", json={"token": "notavalidtoken"})
        assert r.status_code == 200
        assert r.json()["valid"] is False

    def test_revoked_token_returns_valid_false(self, app_no_policy, identity):
        token = identity.issue_token()
        identity.revoke_all()
        r = app_no_policy.post("/v1/identity/verify", json={"token": token})
        assert r.status_code == 200
        assert r.json()["valid"] is False
        assert r.json()["error"] == "token_revoked"

    def test_missing_token_field_returns_422(self, app_no_policy):
        r = app_no_policy.post("/v1/identity/verify", json={})
        assert r.status_code == 422

    def test_raw_token_not_in_response(self, app_no_policy, identity):
        """The raw token must NEVER appear in the response body."""
        token = identity.issue_token()
        r = app_no_policy.post("/v1/identity/verify", json={"token": token})
        assert token not in r.text


# ---------------------------------------------------------------------------
# POST /v1/policy/evaluate
# ---------------------------------------------------------------------------

class TestPolicyEvaluateEndpoint:
    def test_no_policy_returns_deny(self, app_no_policy):
        r = app_no_policy.post("/v1/policy/evaluate", json={
            "agent_id": "researcher",
            "tool_name": "web_search",
        })
        assert r.status_code == 200
        assert r.json()["decision"] == "deny"
        assert "No policy" in r.json()["reason"]

    def test_allowed_call_returns_allow(self, app_with_policy):
        r = app_with_policy.post("/v1/policy/evaluate", json={
            "agent_id": "researcher",
            "tool_name": "web_search",
            "caller_id": "orchestrator",
        })
        assert r.status_code == 200
        assert r.json()["decision"] == "allow"

    def test_denied_tool_returns_deny(self, app_with_policy):
        r = app_with_policy.post("/v1/policy/evaluate", json={
            "agent_id": "researcher",
            "tool_name": "execute_shell",
            "caller_id": "orchestrator",
        })
        assert r.status_code == 200
        assert r.json()["decision"] == "deny"

    def test_wrong_caller_returns_deny(self, app_with_policy):
        r = app_with_policy.post("/v1/policy/evaluate", json={
            "agent_id": "researcher",
            "tool_name": "web_search",
            "caller_id": "rogue_agent",
        })
        assert r.status_code == 200
        assert r.json()["decision"] == "deny"

    def test_unknown_agent_returns_deny(self, app_with_policy):
        r = app_with_policy.post("/v1/policy/evaluate", json={
            "agent_id": "unknown_agent",
            "tool_name": "web_search",
        })
        assert r.status_code == 200
        assert r.json()["decision"] == "deny"

    def test_response_contains_agent_and_tool(self, app_with_policy):
        r = app_with_policy.post("/v1/policy/evaluate", json={
            "agent_id": "researcher",
            "tool_name": "web_search",
            "caller_id": "orchestrator",
        })
        data = r.json()
        assert data["agent_id"] == "researcher"
        assert data["tool_name"] == "web_search"

    def test_missing_required_fields_returns_422(self, app_with_policy):
        r = app_with_policy.post("/v1/policy/evaluate", json={"agent_id": "a"})
        assert r.status_code == 422

    def test_caller_id_optional(self, app_with_policy):
        """caller_id is optional — omitting it should not raise a 422."""
        r = app_with_policy.post("/v1/policy/evaluate", json={
            "agent_id": "orchestrator",
            "tool_name": "some_tool",
        })
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Global error handler
# ---------------------------------------------------------------------------

class TestErrorHandler:
    def test_404_returns_json(self, app_no_policy):
        r = app_no_policy.get("/nonexistent_endpoint")
        assert r.status_code == 404

    def test_method_not_allowed(self, app_no_policy):
        r = app_no_policy.get("/v1/identity/verify")
        assert r.status_code == 405