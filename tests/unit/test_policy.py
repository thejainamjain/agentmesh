from __future__ import annotations

import time
import tempfile
from pathlib import Path

import pytest

from agentmesh.policy.engine import Decision, PolicyDecision, PolicyEngine, _parse_rate_limit
from agentmesh.policy.exceptions import (
    PolicyDenied,
    PolicyLoadError,
    PolicyValidationError,
    RateLimitExceeded,
)
from agentmesh.policy.schema import validate_policy


# ---------------------------------------------------------------------------
# Fixtures — reusable policy dicts
# ---------------------------------------------------------------------------

@pytest.fixture
def simple_policy() -> dict:
    return {
        "version": "1.0",
        "agents": {
            "orchestrator": {
                "allowed_tools": [],
                "allowed_callers": [],
            },
            "researcher": {
                "allowed_tools": ["web_search", "read_file"],
                "denied_tools": ["write_file", "execute_shell"],
                "allowed_callers": ["orchestrator"],
                "rate_limits": {
                    "web_search": "10/minute",
                },
            },
        },
    }


@pytest.fixture
def engine(simple_policy) -> PolicyEngine:
    return PolicyEngine.from_dict(simple_policy)


def make_policy_file(policy_dict: dict, tmp_path: Path) -> Path:
    """Write a policy dict to a temp YAML file and return the path."""
    import yaml
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.dump(policy_dict))
    return p


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

class TestSchemaValidation:
    def test_valid_policy_passes(self, simple_policy):
        validate_policy(simple_policy)  # should not raise

    def test_missing_version_raises(self):
        with pytest.raises(PolicyValidationError):
            validate_policy({"agents": {"a": {}}})

    def test_wrong_version_raises(self):
        with pytest.raises(PolicyValidationError):
            validate_policy({"version": "2.0", "agents": {"a": {}}})

    def test_missing_agents_raises(self):
        with pytest.raises(PolicyValidationError):
            validate_policy({"version": "1.0"})

    def test_empty_agents_raises(self):
        with pytest.raises(PolicyValidationError):
            validate_policy({"version": "1.0", "agents": {}})

    def test_unknown_top_level_field_raises(self):
        with pytest.raises(PolicyValidationError):
            validate_policy({
                "version": "1.0",
                "agents": {"a": {}},
                "unknown_field": True,
            })

    def test_unknown_agent_field_raises(self):
        with pytest.raises(PolicyValidationError):
            validate_policy({
                "version": "1.0",
                "agents": {
                    "a": {"allowed_tools": [], "typo_field": True}
                },
            })

    def test_deny_on_missing_rule_false_raises(self):
        with pytest.raises(PolicyValidationError, match="deny_on_missing_rule"):
            validate_policy({
                "version": "1.0",
                "defaults": {"deny_on_missing_rule": False},
                "agents": {"a": {}},
            })

    def test_deny_on_engine_error_false_raises(self):
        with pytest.raises(PolicyValidationError, match="deny_on_engine_error"):
            validate_policy({
                "version": "1.0",
                "defaults": {"deny_on_engine_error": False},
                "agents": {"a": {}},
            })

    def test_invalid_rate_limit_format_raises(self):
        with pytest.raises(PolicyValidationError):
            validate_policy({
                "version": "1.0",
                "agents": {
                    "a": {
                        "allowed_tools": ["web_search"],
                        "rate_limits": {"web_search": "10perminute"},  # wrong format
                    }
                },
            })

    def test_valid_rate_limit_formats_pass(self):
        for fmt in ["1/second", "10/minute", "100/hour"]:
            validate_policy({
                "version": "1.0",
                "agents": {
                    "a": {
                        "allowed_tools": ["t"],
                        "rate_limits": {"t": fmt},
                    }
                },
            })


# ---------------------------------------------------------------------------
# PolicyEngine construction
# ---------------------------------------------------------------------------

class TestPolicyEngineConstruction:
    def test_from_dict_succeeds(self, simple_policy):
        engine = PolicyEngine.from_dict(simple_policy)
        assert "researcher" in engine.registered_agents()
        assert "orchestrator" in engine.registered_agents()

    def test_from_file_succeeds(self, simple_policy, tmp_path):
        path = make_policy_file(simple_policy, tmp_path)
        engine = PolicyEngine.from_file(path)
        assert "researcher" in engine.registered_agents()

    def test_from_file_missing_raises(self, tmp_path):
        with pytest.raises(PolicyLoadError, match="not found"):
            PolicyEngine.from_file(tmp_path / "nonexistent.yaml")

    def test_from_file_invalid_yaml_raises(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("{ invalid: yaml: content: [")
        with pytest.raises(PolicyLoadError, match="invalid YAML"):
            PolicyEngine.from_file(bad)

    def test_from_file_not_a_mapping_raises(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("- just\n- a\n- list\n")
        with pytest.raises(PolicyLoadError, match="must be a YAML mapping"):
            PolicyEngine.from_file(bad)

    def test_invalid_policy_dict_raises_validation_error(self):
        with pytest.raises(PolicyValidationError):
            PolicyEngine.from_dict({"version": "1.0", "agents": {}})

    def test_repr_contains_agents(self, engine):
        r = repr(engine)
        assert "researcher" in r
        assert "orchestrator" in r


# ---------------------------------------------------------------------------
# Policy evaluation — ALLOW cases
# ---------------------------------------------------------------------------

class TestEvaluateAllow:
    def test_allowed_tool_with_correct_caller(self, engine):
        d = engine.evaluate("researcher", "web_search", caller_id="orchestrator")
        assert d.allowed is True
        assert d.decision == Decision.ALLOW

    def test_allowed_tool_top_level_agent(self, engine):
        # orchestrator has no allowed_callers — can be called directly
        d = engine.evaluate("orchestrator", "read_task_queue", caller_id=None)
        # orchestrator has no allowed_tools so this will deny — but let's test a proper allow
        engine2 = PolicyEngine.from_dict({
            "version": "1.0",
            "agents": {
                "top_agent": {
                    "allowed_tools": ["ping"],
                    "allowed_callers": [],
                }
            },
        })
        d = engine2.evaluate("top_agent", "ping", caller_id=None)
        assert d.allowed is True

    def test_decision_contains_correct_fields(self, engine):
        d = engine.evaluate("researcher", "web_search", caller_id="orchestrator")
        assert d.agent_id == "researcher"
        assert d.tool_name == "web_search"
        assert d.caller_id == "orchestrator"

    def test_multiple_allowed_tools(self, engine):
        d1 = engine.evaluate("researcher", "web_search", caller_id="orchestrator")
        d2 = engine.evaluate("researcher", "read_file", caller_id="orchestrator")
        assert d1.allowed and d2.allowed


# ---------------------------------------------------------------------------
# Policy evaluation — DENY cases
# ---------------------------------------------------------------------------

class TestEvaluateDeny:
    def test_unknown_agent_is_denied(self, engine):
        d = engine.evaluate("ghost_agent", "web_search")
        assert d.allowed is False
        assert d.decision == Decision.DENY
        assert "not registered" in d.reason

    def test_tool_not_in_allowed_list_is_denied(self, engine):
        d = engine.evaluate("researcher", "execute_shell", caller_id="orchestrator")
        assert d.allowed is False
        assert "execute_shell" in d.reason

    def test_explicitly_denied_tool_is_denied(self, engine):
        # write_file is in denied_tools — blocked even before allowed_tools check
        d = engine.evaluate("researcher", "write_file", caller_id="orchestrator")
        assert d.allowed is False
        assert "explicitly denied" in d.reason

    def test_wrong_caller_is_denied(self, engine):
        # researcher only allows orchestrator as caller
        d = engine.evaluate("researcher", "web_search", caller_id="rogue_agent")
        assert d.allowed is False
        assert "allowed_callers" in d.reason

    def test_no_caller_when_caller_required_is_denied(self, engine):
        # researcher requires a caller — calling directly should be denied
        d = engine.evaluate("researcher", "web_search", caller_id=None)
        assert d.allowed is False
        assert "requires a caller" in d.reason

    def test_policy_decision_str(self, engine):
        d = engine.evaluate("ghost", "tool")
        assert "deny" in str(d)

    def test_denied_tool_blocked_before_allowed_check(self):
        """denied_tools takes priority over allowed_tools — belt and suspenders."""
        engine = PolicyEngine.from_dict({
            "version": "1.0",
            "agents": {
                "agent": {
                    "allowed_tools": ["dangerous_tool"],
                    "denied_tools": ["dangerous_tool"],  # both lists — deny wins
                    "allowed_callers": [],
                }
            },
        })
        d = engine.evaluate("agent", "dangerous_tool")
        assert d.allowed is False
        assert "explicitly denied" in d.reason


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimiting:
    def test_within_rate_limit_is_allowed(self, engine):
        for _ in range(5):
            d = engine.evaluate("researcher", "web_search", caller_id="orchestrator")
            assert d.allowed is True

    def test_exceeding_rate_limit_is_denied(self):
        engine = PolicyEngine.from_dict({
            "version": "1.0",
            "agents": {
                "agent": {
                    "allowed_tools": ["fast_tool"],
                    "allowed_callers": [],
                    "rate_limits": {"fast_tool": "3/minute"},
                }
            },
        })
        # First 3 calls should pass
        for _ in range(3):
            d = engine.evaluate("agent", "fast_tool")
            assert d.allowed is True
        # 4th call should be rate limited
        d = engine.evaluate("agent", "fast_tool")
        assert d.allowed is False
        assert d.decision == Decision.RATE_LIMITED
        assert "Rate limit" in d.reason

    def test_rate_limit_has_registered(self, engine):
        assert engine.has_rate_limit("researcher", "web_search") is True
        assert engine.has_rate_limit("researcher", "read_file") is False

    def test_parse_rate_limit_second(self):
        count, window = _parse_rate_limit("5/second")
        assert count == 5 and window == 1

    def test_parse_rate_limit_minute(self):
        count, window = _parse_rate_limit("10/minute")
        assert count == 10 and window == 60

    def test_parse_rate_limit_hour(self):
        count, window = _parse_rate_limit("100/hour")
        assert count == 100 and window == 3600

    def test_parse_rate_limit_invalid_raises(self):
        with pytest.raises(PolicyLoadError, match="Invalid rate limit"):
            _parse_rate_limit("10_per_minute")


# ---------------------------------------------------------------------------
# Introspection helpers
# ---------------------------------------------------------------------------

class TestIntrospection:
    def test_registered_agents(self, engine):
        agents = engine.registered_agents()
        assert "researcher" in agents
        assert "orchestrator" in agents

    def test_allowed_tools_for(self, engine):
        tools = engine.allowed_tools_for("researcher")
        assert "web_search" in tools
        assert "read_file" in tools

    def test_allowed_tools_for_unknown_agent(self, engine):
        assert engine.allowed_tools_for("nobody") == []

    def test_allowed_callers_for(self, engine):
        callers = engine.allowed_callers_for("researcher")
        assert "orchestrator" in callers

    def test_allowed_callers_for_unknown_agent(self, engine):
        assert engine.allowed_callers_for("nobody") == []


# ---------------------------------------------------------------------------
# Interceptor integration with PolicyEngine
# ---------------------------------------------------------------------------

class TestInterceptorWithPolicy:
    def test_allowed_call_executes(self, engine):
        from agentmesh.identity.agent_identity import AgentIdentity
        from agentmesh.monitor.interceptor import intercept_tools

        identity = AgentIdentity("researcher", ["web_search"], mesh_id="test")

        @intercept_tools(identity=identity, policy=engine, caller_id="orchestrator")
        def web_search(query: str) -> str:
            return f"results: {query}"

        assert web_search("AI") == "results: AI"

    def test_denied_call_raises_policy_denied(self, engine):
        from agentmesh.identity.agent_identity import AgentIdentity
        from agentmesh.monitor.interceptor import intercept_tools
        from agentmesh.monitor.exceptions import PolicyDenied

        identity = AgentIdentity("researcher", ["web_search"], mesh_id="test")

        @intercept_tools(identity=identity, policy=engine, caller_id="rogue")
        def web_search(query: str) -> str:
            return "should not reach"

        with pytest.raises(PolicyDenied):
            web_search("test")

    def test_no_policy_still_works(self):
        from agentmesh.identity.agent_identity import AgentIdentity
        from agentmesh.monitor.interceptor import intercept_tools

        identity = AgentIdentity("any-agent", [], mesh_id="test")

        @intercept_tools(identity=identity)
        def ping() -> str:
            return "pong"

        assert ping() == "pong"

    def test_policy_from_file(self, simple_policy, tmp_path):
        from agentmesh.identity.agent_identity import AgentIdentity
        from agentmesh.monitor.interceptor import intercept_tools

        path = make_policy_file(simple_policy, tmp_path)
        identity = AgentIdentity("researcher", ["web_search"], mesh_id="test")

        @intercept_tools(identity=identity, policy=str(path), caller_id="orchestrator")
        def web_search(query: str) -> str:
            return f"results: {query}"

        assert "results" in web_search("security")

    def test_engine_attached_to_wrapper(self, engine):
        from agentmesh.identity.agent_identity import AgentIdentity
        from agentmesh.monitor.interceptor import intercept_tools

        identity = AgentIdentity("researcher", [], mesh_id="test")

        @intercept_tools(identity=identity, policy=engine)
        def tool() -> str:
            return "ok"

        assert tool._agentmesh_engine is engine

    def test_invalid_policy_type_raises(self):
        from agentmesh.identity.agent_identity import AgentIdentity
        from agentmesh.monitor.interceptor import intercept_tools, InterceptorError

        identity = AgentIdentity("agent", [], mesh_id="test")
        with pytest.raises(InterceptorError):
            @intercept_tools(identity=identity, policy=12345)
            def tool(): pass