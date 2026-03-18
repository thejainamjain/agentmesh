from __future__ import annotations

import pytest
from datetime import timezone

from agentmesh.identity.agent_identity import AgentIdentity
from agentmesh.monitor import intercept_tools, CapturedCall
from agentmesh.monitor.exceptions import InterceptorError, PolicyDenied
from agentmesh.monitor.interceptor import _bind_arguments, _USE_CPP


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def researcher():
    return AgentIdentity("researcher", ["web_search", "read_file"], mesh_id="test-mesh")

@pytest.fixture
def orchestrator():
    return AgentIdentity("orchestrator", ["delegate"], mesh_id="test-mesh")


# ---------------------------------------------------------------------------
# Basic interception
# ---------------------------------------------------------------------------

class TestBasicInterception:
    def test_tool_executes_and_returns(self, researcher):
        @intercept_tools(identity=researcher)
        def web_search(query: str) -> str:
            return f"results for: {query}"
        assert web_search("AI security") == "results for: AI security"

    def test_intercepted_flag_set(self, researcher):
        @intercept_tools(identity=researcher)
        def web_search(query: str) -> str:
            return "results"
        assert web_search._agentmesh_intercepted is True

    def test_tool_name_attached(self, researcher):
        @intercept_tools(identity=researcher)
        def web_search(query: str) -> str:
            return "results"
        assert web_search._agentmesh_tool_name == "web_search"

    def test_identity_attached(self, researcher):
        @intercept_tools(identity=researcher)
        def web_search(query: str) -> str:
            return "results"
        assert web_search._agentmesh_identity is researcher

    def test_functools_wraps_preserves_name(self, researcher):
        @intercept_tools(identity=researcher)
        def web_search(query: str) -> str:
            return "results"
        assert web_search.__name__ == "web_search"

    def test_functools_wraps_preserves_docstring(self, researcher):
        @intercept_tools(identity=researcher)
        def web_search(query: str) -> str:
            """Search the web."""
            return "results"
        assert "Search the web" in web_search.__doc__

    def test_multiple_args(self, researcher):
        @intercept_tools(identity=researcher)
        def read_file(path: str, encoding: str = "utf-8") -> str:
            return f"{path}:{encoding}"
        assert read_file("/tmp/f.txt", encoding="ascii") == "/tmp/f.txt:ascii"

    def test_no_args_tool(self, researcher):
        @intercept_tools(identity=researcher)
        def ping() -> str:
            return "pong"
        assert ping() == "pong"

    def test_tool_exception_propagates(self, researcher):
        @intercept_tools(identity=researcher)
        def bad_tool(x: str) -> str:
            raise RuntimeError("tool failed")
        with pytest.raises(RuntimeError, match="tool failed"):
            bad_tool("test")

    def test_wrong_identity_type_raises(self):
        with pytest.raises(InterceptorError):
            @intercept_tools(identity="not-an-identity")
            def tool(): pass

    def test_sequential_calls_all_succeed(self, researcher):
        @intercept_tools(identity=researcher)
        def web_search(query: str) -> str:
            return f"r:{query}"
        results = [web_search(f"q{i}") for i in range(5)]
        assert len(results) == 5
        assert all(r.startswith("r:") for r in results)


# ---------------------------------------------------------------------------
# Argument binding
# ---------------------------------------------------------------------------

class TestBindArguments:
    def test_positional(self):
        def f(a: str, b: int): pass
        assert _bind_arguments(f, ("hello", 42), {}) == {"a": "hello", "b": 42}

    def test_keyword(self):
        def f(a: str, b: int = 10): pass
        assert _bind_arguments(f, (), {"a": "hi"}) == {"a": "hi", "b": 10}

    def test_defaults_applied(self):
        def f(a: str, b: int = 99): pass
        result = _bind_arguments(f, ("x",), {})
        assert result["b"] == 99

    def test_varargs_fallback(self):
        def f(*args): pass
        result = _bind_arguments(f, ("x", "y"), {})
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# CapturedCall
# ---------------------------------------------------------------------------

class TestCapturedCall:
    def test_capture_fields(self):
        c = CapturedCall.capture("agent-1", "mesh-1", "tok", "web_search", {"q": "ai"})
        assert c.agent_id == "agent-1"
        assert c.tool_name == "web_search"
        assert c.arguments == {"q": "ai"}
        assert len(c.arguments_hash) == 64
        assert c.allowed is True
        assert c.result is None

    def test_hash_deterministic(self):
        args = {"query": "test", "n": 10}
        c1 = CapturedCall.capture("a", "m", "t", "s", args)
        c2 = CapturedCall.capture("a", "m", "t", "s", args)
        assert c1.arguments_hash == c2.arguments_hash

    def test_hash_differs_for_different_args(self):
        c1 = CapturedCall.capture("a", "m", "t", "s", {"q": "foo"})
        c2 = CapturedCall.capture("a", "m", "t", "s", {"q": "bar"})
        assert c1.arguments_hash != c2.arguments_hash

    def test_record_result(self):
        c = CapturedCall.capture("a", "m", "t", "s", {})
        c.record_result({"status": "ok"})
        assert c.result == {"status": "ok"}
        assert len(c.result_hash) == 64

    def test_block(self):
        c = CapturedCall.capture("a", "m", "t", "s", {})
        c.block("rate limit")
        assert c.allowed is False
        assert c.block_reason == "rate limit"

    def test_to_audit_dict_allowed(self):
        c = CapturedCall.capture("agent-1", "mesh-1", "tok", "web_search", {"q": "t"})
        c.record_result("results")
        d = c.to_audit_dict()
        assert d["action_type"] == "tool_call"
        assert d["policy_decision"] == "allow"
        assert d["tool_name"] == "web_search"

    def test_to_audit_dict_denied(self):
        c = CapturedCall.capture("a", "m", "t", "s", {})
        c.block("policy violation")
        d = c.to_audit_dict()
        assert d["policy_decision"] == "deny"
        assert d["block_reason"] == "policy violation"

    def test_repr_allowed(self):
        c = CapturedCall.capture("a", "m", "t", "web_search", {})
        assert "ALLOWED" in repr(c) and "web_search" in repr(c)

    def test_repr_blocked(self):
        c = CapturedCall.capture("a", "m", "t", "web_search", {})
        c.block("policy")
        assert "BLOCKED" in repr(c)

    def test_timestamp_utc(self):
        c = CapturedCall.capture("a", "m", "t", "s", {})
        assert c.timestamp.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# Mock LangChain agent
# ---------------------------------------------------------------------------

class MockLangChainTool:
    """Simulates a LangChain BaseTool — has a _run method, wrapped by interceptor."""
    def __init__(self, identity: AgentIdentity, name: str = "web_search"):
        self.name = name
        self.identity = identity
        self._run = intercept_tools(identity=identity)(self._run_impl)

    def _run_impl(self, query: str) -> str:
        return f"LangChain result: {query}"

    def run(self, query: str) -> str:
        return self._run(query)


class MockLangChainAgent:
    """Simulates a LangChain AgentExecutor with a tool registry."""
    def __init__(self, agent_id: str, capabilities: list):
        self.identity = AgentIdentity(agent_id, capabilities, mesh_id="lc-mesh")
        self.tools: dict = {}

    def register_tool(self, tool: MockLangChainTool) -> None:
        self.tools[tool.name] = tool

    def run(self, tool_name: str, **kwargs) -> str:
        if tool_name not in self.tools:
            raise ValueError(f"Tool {tool_name!r} not registered")
        return self.tools[tool_name].run(**kwargs)


class TestMockLangChainIntegration:
    def test_langchain_tool_intercepted(self):
        identity = AgentIdentity("lc-researcher", ["web_search"], mesh_id="lc-mesh")
        tool = MockLangChainTool(identity=identity)
        assert "pybind11" in tool.run(query="pybind11")

    def test_langchain_agent_with_tool(self):
        agent = MockLangChainAgent("lc-orchestrator", ["web_search"])
        tool = MockLangChainTool(identity=agent.identity)
        agent.register_tool(tool)
        result = agent.run("web_search", query="AgentMesh")
        assert "AgentMesh" in result

    def test_two_agents_independent(self):
        id_a = AgentIdentity("alpha", ["web_search"])
        id_b = AgentIdentity("beta", ["read_file"])

        @intercept_tools(identity=id_a)
        def web_search(query: str) -> str:
            return f"alpha:{query}"

        @intercept_tools(identity=id_b)
        def read_file(path: str) -> str:
            return f"beta:{path}"

        assert "alpha" in web_search("test")
        assert "beta" in read_file("/tmp/f")

    def test_intercepted_method_return_type(self):
        identity = AgentIdentity("type-agent", ["web_search"])
        tool = MockLangChainTool(identity=identity)
        assert isinstance(tool.run(query="test"), str)


# ---------------------------------------------------------------------------
# C++ path
# ---------------------------------------------------------------------------

class TestCppPath:
    def test_cpp_flag_is_bool(self):
        assert isinstance(_USE_CPP, bool)

    def test_works_regardless_of_cpp_flag(self):
        identity = AgentIdentity("cpp-flag-agent", ["web_search"])

        @intercept_tools(identity=identity)
        def web_search(query: str) -> str:
            return f"r:{query}"

        assert web_search("test") == "r:test"