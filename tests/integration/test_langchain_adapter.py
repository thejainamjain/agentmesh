from __future__ import annotations

"""
LangChain Adapter Integration Tests

These tests mock langchain-core's BaseTool so they run in CI
without requiring langchain-core to be installed.

Real integration tests (with actual LangChain agents) are in
examples/langchain_secured/ and require: pip install langchain-core
"""

import sys
import types
import pytest
from unittest.mock import MagicMock

from agentmesh.identity.agent_identity import AgentIdentity
from agentmesh.policy.engine import PolicyEngine
from agentmesh.monitor.exceptions import PolicyDenied as PolicyDeniedError


# ---------------------------------------------------------------------------
# Mock langchain_core so tests run without the real package
# ---------------------------------------------------------------------------

def _make_mock_langchain():
    """Create a minimal mock of langchain_core.tools.BaseTool."""

    class BaseTool:
        """Minimal BaseTool mock — matches the real langchain_core.tools.BaseTool interface."""
        name: str = ""
        description: str = ""
        _agentmesh_secured: bool = False

        def run(self, tool_input: str, **kwargs) -> str:
            return self._run(tool_input, **kwargs)

        async def arun(self, tool_input: str, **kwargs) -> str:
            return await self._arun(tool_input, **kwargs)

        def _run(self, *args, **kwargs) -> str:
            raise NotImplementedError

        async def _arun(self, *args, **kwargs) -> str:
            return self._run(*args, **kwargs)

    # Build the mock module tree
    mock_lc_core = types.ModuleType("langchain_core")
    mock_lc_tools = types.ModuleType("langchain_core.tools")
    mock_lc_tools.BaseTool = BaseTool
    mock_lc_core.tools = mock_lc_tools

    sys.modules["langchain_core"] = mock_lc_core
    sys.modules["langchain_core.tools"] = mock_lc_tools

    return BaseTool


# Install mock before importing the adapter
BaseTool = _make_mock_langchain()

from integrations.langchain.adapter import secure_langchain_tool, _wrap_tool_class
from integrations.langchain.exceptions import (
    LangChainNotInstalledError,
    LangChainSecurityError,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

POLICY_DICT = {
    "version": "1.0",
    "agents": {
        "researcher": {
            "allowed_tools": ["web_search", "read_file"],
            "denied_tools": ["execute_shell"],
            "allowed_callers": ["orchestrator"],
        },
        "orchestrator": {
            "allowed_tools": [],
            "allowed_callers": [],
        },
    },
}


@pytest.fixture
def identity():
    return AgentIdentity("researcher", ["web_search", "read_file"], mesh_id="test")


@pytest.fixture
def policy():
    return PolicyEngine.from_dict(POLICY_DICT)


@pytest.fixture
def caller_identity():
    return AgentIdentity("orchestrator", [], mesh_id="test")


# ---------------------------------------------------------------------------
# Decorator: @secure_langchain_tool
# ---------------------------------------------------------------------------

class TestSecureLangchainToolDecorator:

    def test_decorator_returns_same_class(self, identity):
        @secure_langchain_tool(identity=identity)
        class MyTool(BaseTool):
            name = "web_search"
            description = "Test tool"
            def _run(self, query: str) -> str:
                return f"result:{query}"

        assert MyTool.__name__ == "MyTool"
        assert issubclass(MyTool, BaseTool)

    def test_decorated_tool_executes(self, identity):
        @secure_langchain_tool(identity=identity)
        class MyTool(BaseTool):
            name = "web_search"
            description = "Test"
            def _run(self, query: str) -> str:
                return f"found:{query}"

        tool = MyTool()
        result = tool._run("AI security")
        assert "found:AI security" in result

    def test_decorated_tool_is_marked_secured(self, identity):
        @secure_langchain_tool(identity=identity)
        class MyTool(BaseTool):
            name = "web_search"
            description = "Test"
            def _run(self, q: str) -> str:
                return q

        assert MyTool._agentmesh_secured is True
        assert MyTool._agentmesh_identity is identity

    def test_decorator_with_policy_allows_valid_call(self, identity, policy):
        @secure_langchain_tool(
            identity=identity,
            policy=policy,
            caller_id="orchestrator",
        )
        class WebSearch(BaseTool):
            name = "web_search"
            description = "Search"
            def _run(self, query: str) -> str:
                return f"results:{query}"

        tool = WebSearch()
        result = tool._run("test query")
        assert "results:test query" in result

    def test_decorator_with_policy_denies_forbidden_tool(self, identity, policy):
        @secure_langchain_tool(
            identity=identity,
            policy=policy,
            caller_id="orchestrator",
        )
        class ShellTool(BaseTool):
            name = "execute_shell"
            description = "Run shell commands"
            def _run(self, cmd: str) -> str:
                return f"output:{cmd}"

        tool = ShellTool()
        with pytest.raises(PolicyDeniedError):
            tool._run("rm -rf /")

    def test_decorator_with_policy_denies_wrong_caller(self, identity, policy):
        @secure_langchain_tool(
            identity=identity,
            policy=policy,
            caller_id="rogue_agent",
        )
        class WebSearch(BaseTool):
            name = "web_search"
            description = "Search"
            def _run(self, query: str) -> str:
                return query

        tool = WebSearch()
        with pytest.raises(PolicyDeniedError):
            tool._run("test")

    def test_decorator_rejects_non_basetool_class(self, identity):
        with pytest.raises(TypeError, match="BaseTool subclass"):
            @secure_langchain_tool(identity=identity)
            class NotATool:
                pass

    def test_decorator_rejects_invalid_identity(self):
        with pytest.raises(LangChainSecurityError, match="AgentIdentity"):
            @secure_langchain_tool(identity="not-an-identity")
            class MyTool(BaseTool):
                name = "t"
                description = "t"
                def _run(self, q: str) -> str:
                    return q

    def test_decorated_tool_preserves_name_and_description(self, identity):
        @secure_langchain_tool(identity=identity)
        class WebSearchTool(BaseTool):
            name = "web_search"
            description = "Searches the internet for current information"
            def _run(self, query: str) -> str:
                return query

        tool = WebSearchTool()
        assert tool.name == "web_search"
        assert "internet" in tool.description

    def test_decorator_attaches_policy(self, identity, policy):
        @secure_langchain_tool(identity=identity, policy=policy)
        class MyTool(BaseTool):
            name = "web_search"
            description = "t"
            def _run(self, q: str) -> str:
                return q

        assert MyTool._agentmesh_policy is policy

    def test_decorated_tool_no_policy_executes(self, identity):
        """No policy = no enforcement — just identity wrapping."""
        @secure_langchain_tool(identity=identity)
        class AnyTool(BaseTool):
            name = "anything"
            description = "t"
            def _run(self, q: str) -> str:
                return f"ran:{q}"

        result = AnyTool()._run("hello")
        assert "ran:hello" in result

    def test_tool_exception_propagates(self, identity):
        @secure_langchain_tool(identity=identity)
        class BrokenTool(BaseTool):
            name = "web_search"
            description = "t"
            def _run(self, q: str) -> str:
                raise ValueError("tool is broken")

        with pytest.raises(ValueError, match="tool is broken"):
            BrokenTool()._run("test")

    def test_multiple_tools_independent(self, identity):
        id_a = AgentIdentity("agent-a", ["tool_a"])
        id_b = AgentIdentity("agent-b", ["tool_b"])

        @secure_langchain_tool(identity=id_a)
        class ToolA(BaseTool):
            name = "tool_a"
            description = "t"
            def _run(self, q: str) -> str:
                return f"a:{q}"

        @secure_langchain_tool(identity=id_b)
        class ToolB(BaseTool):
            name = "tool_b"
            description = "t"
            def _run(self, q: str) -> str:
                return f"b:{q}"

        assert ToolA._agentmesh_identity is id_a
        assert ToolB._agentmesh_identity is id_b
        assert "a:x" in ToolA()._run("x")
        assert "b:x" in ToolB()._run("x")


# ---------------------------------------------------------------------------
# SecureTool base class
# ---------------------------------------------------------------------------

class TestSecureToolBaseClass:

    def test_secure_tool_subclass_executes(self, identity):
        from integrations.langchain.adapter import SecureTool

        class WebSearch(SecureTool):
            name = "web_search"
            description = "Search"
            mesh_identity = identity

            def _run(self, query: str) -> str:
                return f"found:{query}"

        tool = WebSearch()
        result = tool._run("AgentMesh")
        assert "found:AgentMesh" in result

    def test_secure_tool_is_marked_secured(self, identity):
        from integrations.langchain.adapter import SecureTool

        class MyTool(SecureTool):
            name = "web_search"
            description = "t"
            mesh_identity = identity
            def _run(self, q: str) -> str:
                return q

        assert MyTool._agentmesh_secured is True

    def test_secure_tool_with_policy_allows(self, identity, policy):
        from integrations.langchain.adapter import SecureTool

        class WebSearch(SecureTool):
            name = "web_search"
            description = "Search"
            mesh_identity = identity
            mesh_policy = policy
            mesh_caller_id = "orchestrator"

            def _run(self, query: str) -> str:
                return f"results:{query}"

        result = WebSearch()._run("test")
        assert "results:test" in result

    def test_secure_tool_with_policy_denies(self, identity, policy):
        from integrations.langchain.adapter import SecureTool

        class ShellTool(SecureTool):
            name = "execute_shell"
            description = "Shell"
            mesh_identity = identity
            mesh_policy = policy
            mesh_caller_id = "orchestrator"

            def _run(self, cmd: str) -> str:
                return cmd

        with pytest.raises(PolicyDeniedError):
            ShellTool()._run("ls")

    def test_secure_tool_no_identity_logs_warning(self):
        from integrations.langchain.adapter import SecureTool

        # Subclass without mesh_identity — should not raise at class definition
        class LazyTool(SecureTool):
            name = "lazy"
            description = "t"
            # mesh_identity deliberately not set
            def _run(self, q: str) -> str:
                return q

        # Class defined without error — identity check deferred to call time
        assert LazyTool.mesh_identity is None

    def test_secure_tool_is_basetool_subclass(self, identity):
        from integrations.langchain.adapter import SecureTool

        class MyTool(SecureTool):
            name = "web_search"
            description = "t"
            mesh_identity = identity
            def _run(self, q: str) -> str:
                return q

        assert issubclass(MyTool, BaseTool)

    def test_secure_tool_preserves_tool_metadata(self, identity):
        from integrations.langchain.adapter import SecureTool

        class WebSearchTool(SecureTool):
            name = "web_search"
            description = "Searches the internet"
            mesh_identity = identity
            def _run(self, q: str) -> str:
                return q

        t = WebSearchTool()
        assert t.name == "web_search"
        assert "internet" in t.description


# ---------------------------------------------------------------------------
# Async support
# ---------------------------------------------------------------------------

class TestAsyncSupport:

    def test_arun_is_wrapped(self, identity):
        @secure_langchain_tool(identity=identity)
        class AsyncTool(BaseTool):
            name = "web_search"
            description = "t"
            def _run(self, q: str) -> str:
                return f"sync:{q}"
            async def _arun(self, q: str) -> str:
                return f"async:{q}"

        # _arun should exist and be a coroutine function
        import asyncio
        tool = AsyncTool()
        result = asyncio.run(tool._arun("test"))
        assert "async:test" in result

    def test_arun_policy_enforced(self, identity, policy):
        @secure_langchain_tool(
            identity=identity,
            policy=policy,
            caller_id="orchestrator",
        )
        class AsyncShell(BaseTool):
            name = "execute_shell"
            description = "t"
            def _run(self, q: str) -> str:
                return q
            async def _arun(self, q: str) -> str:
                return q

        import asyncio
        with pytest.raises(PolicyDeniedError):
            asyncio.run(AsyncShell()._arun("evil command"))


# ---------------------------------------------------------------------------
# LangChainNotInstalledError
# ---------------------------------------------------------------------------

class TestNotInstalledError:

    def test_error_message_contains_install_instructions(self):
        err = LangChainNotInstalledError()
        assert "pip install langchain-core" in str(err)
        assert "agentmesh[langchain]" in str(err)

    def test_error_is_agentmesh_error(self):
        from agentmesh.identity.exceptions import AgentMeshError
        assert issubclass(LangChainNotInstalledError, AgentMeshError)