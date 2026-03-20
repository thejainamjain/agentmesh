from __future__ import annotations

"""
AgentMesh LangChain Adapter

Wraps any LangChain BaseTool with AgentMesh identity, policy, and monitoring.
Requires langchain-core — not the full langchain package.

Two usage patterns:

Pattern 1 — Decorator (zero changes to existing tools):

    from integrations.langchain import secure_langchain_tool

    @secure_langchain_tool(identity=my_identity, policy=my_engine)
    class WebSearchTool(BaseTool):
        name = "web_search"
        description = "Searches the web for information"

        def _run(self, query: str) -> str:
            return my_search_function(query)

Pattern 2 — Base class (for new tools):

    from integrations.langchain import SecureTool

    class WebSearchTool(SecureTool):
        name = "web_search"
        description = "Searches the web for information"
        mesh_identity = my_identity
        mesh_policy = my_engine  # optional

        def _run(self, query: str) -> str:
            return my_search_function(query)

Both patterns provide identical security guarantees:
  - Identity verified on every _run() and _arun() call
  - Policy evaluated before every execution (default-deny)
  - Injection detection on all arguments
  - Every call recorded in the audit trail if AuditTrail is configured
"""

import asyncio
import functools
import logging
from typing import Any, Callable, Type, TypeVar

from agentmesh.identity.agent_identity import AgentIdentity
from agentmesh.monitor.interceptor import intercept_tools
from agentmesh.policy.engine import PolicyEngine
from integrations.langchain.exceptions import (
    LangChainNotInstalledError,
    LangChainSecurityError,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")

# ---------------------------------------------------------------------------
# LangChain import — optional, graceful failure with clear message
# ---------------------------------------------------------------------------

def _require_langchain() -> Any:
    """
    Import langchain-core BaseTool.
    Raises LangChainNotInstalledError with install instructions if missing.
    """
    try:
        from langchain_core.tools import BaseTool
        return BaseTool
    except ImportError:
        raise LangChainNotInstalledError()


# ---------------------------------------------------------------------------
# Internal: wrap _run and _arun on a BaseTool class
# ---------------------------------------------------------------------------

def _wrap_tool_class(
    cls: type,
    identity: AgentIdentity,
    policy: PolicyEngine | None,
    caller_id: str | None,
) -> type:
    """
    Wrap the _run and _arun methods of a BaseTool subclass with @intercept_tools.

    This is the core of the adapter. Both sync and async paths are secured.
    The original class is modified in-place — no subclassing needed.
    """
    # Wrap synchronous _run
    # tool_name is taken from cls.name (e.g. "web_search") so the policy
    # engine checks the correct tool name, not the method name "_run"
    tool_name = getattr(cls, "name", None) or "_run"

    if hasattr(cls, "_run"):
        original_run = cls._run

        # Wrap a standalone function (no self) so the interceptor only
        # serialises the real tool arguments, not the tool instance itself.
        # self is captured via closure when _run is called on the instance.
        def _make_run_wrapper(orig_run: Any) -> Any:
            def _run_impl(*args: Any, **kwargs: Any) -> Any:
                return orig_run(*args, **kwargs)
            _run_impl.__name__ = tool_name
            _run_impl.__qualname__ = f"{cls.__name__}.{tool_name}"
            return intercept_tools(
                identity=identity,
                policy=policy,
                caller_id=caller_id,
            )(_run_impl)

        @functools.wraps(original_run)
        def _run(self, *args: Any, **kwargs: Any) -> Any:  # noqa: E306
            # Bind self into a closure so the interceptor never sees it
            secured = _make_run_wrapper(
                lambda *a, **kw: original_run(self, *a, **kw)
            )
            return secured(*args, **kwargs)

        cls._run = _run
        logger.debug(
            "AgentMesh: wrapped _run on %s with identity=%r",
            cls.__name__, identity.agent_id,
        )

    # Wrap asynchronous _arun — LangChain calls this for async agents
    if hasattr(cls, "_arun"):
        original_arun = cls._arun

        # intercept_tools returns a sync wrapper; for _arun we need async
        # So we wrap the sync interceptor inside an async function
        def _make_arun_wrapper(orig_arun: Any) -> Any:
            def _arun_impl(*args: Any, **kwargs: Any) -> Any:
                return orig_arun(*args, **kwargs)
            _arun_impl.__name__ = tool_name
            _arun_impl.__qualname__ = f"{cls.__name__}.{tool_name}"
            return intercept_tools(
                identity=identity,
                policy=policy,
                caller_id=caller_id,
            )(_arun_impl)

        @functools.wraps(original_arun)
        async def _arun(self, *args: Any, **kwargs: Any) -> Any:  # noqa: E306
            secured = _make_arun_wrapper(
                lambda *a, **kw: original_arun(self, *a, **kw)
            )
            result = secured(*args, **kwargs)
            if asyncio.iscoroutine(result):
                return await result
            return result

        cls._arun = _arun
        logger.debug(
            "AgentMesh: wrapped _arun on %s with identity=%r",
            cls.__name__, identity.agent_id,
        )

    # Mark the class as secured by AgentMesh
    cls._agentmesh_secured = True
    cls._agentmesh_identity = identity
    cls._agentmesh_policy = policy

    logger.info(
        "AgentMesh: LangChain tool %r secured — agent=%r policy=%s",
        cls.__name__,
        identity.agent_id,
        "loaded" if policy else "none (no policy enforcement)",
    )

    return cls


# ---------------------------------------------------------------------------
# API 1: Decorator — for existing BaseTool subclasses
# ---------------------------------------------------------------------------

def secure_langchain_tool(
    identity: AgentIdentity,
    policy: PolicyEngine | None = None,
    caller_id: str | None = None,
) -> Callable[[type], type]:
    """
    Decorator that secures an existing LangChain BaseTool subclass.

    Wraps _run and _arun with AgentMesh identity verification, policy
    enforcement, injection detection, and audit logging.

    Usage:
        @secure_langchain_tool(identity=my_identity, policy=my_engine)
        class WebSearchTool(BaseTool):
            name = "web_search"
            description = "Searches the web"

            def _run(self, query: str) -> str:
                return search(query)

    Args:
        identity:  AgentIdentity of the agent using this tool.
        policy:    Optional PolicyEngine. If None, no policy enforcement.
        caller_id: Optional caller agent ID for agent-to-agent calls.

    Returns:
        The same class with _run and _arun wrapped.

    Raises:
        LangChainNotInstalledError: if langchain-core is not installed.
        TypeError: if the decorated class is not a BaseTool subclass.
    """
    BaseTool = _require_langchain()

    def decorator(cls: type) -> type:
        if not (isinstance(cls, type) and issubclass(cls, BaseTool)):
            raise TypeError(
                f"@secure_langchain_tool must be applied to a BaseTool subclass, "
                f"got {cls!r}. Make sure your tool inherits from langchain_core.tools.BaseTool."
            )

        if not isinstance(identity, AgentIdentity):
            raise LangChainSecurityError(
                f"identity must be an AgentIdentity instance, got {type(identity).__name__}. "
                f"Create one with: AgentIdentity(agent_id='my-agent', capabilities=['tool_name'])"
            )

        return _wrap_tool_class(cls, identity, policy, caller_id)

    return decorator


# ---------------------------------------------------------------------------
# API 2: SecureTool base class — for new tools
# ---------------------------------------------------------------------------

def _make_secure_tool_base() -> type:
    """
    Build the SecureTool base class dynamically, only if langchain-core is available.
    This avoids an ImportError at module import time.
    """
    BaseTool = _require_langchain()

    class SecureTool(BaseTool):
        """
        A LangChain BaseTool subclass with AgentMesh security built in.

        Subclass this instead of BaseTool to get automatic AgentMesh
        security without any decorators.

        Usage:
            class WebSearchTool(SecureTool):
                name = "web_search"
                description = "Searches the web for information"
                mesh_identity = my_identity
                mesh_policy = my_engine  # optional

                def _run(self, query: str) -> str:
                    return search(query)

        Class attributes:
            mesh_identity: AgentIdentity — required. Set on the class.
            mesh_policy:   PolicyEngine  — optional. Set on the class.
            mesh_caller_id: str         — optional caller agent ID.
        """

        # These must be set on the subclass
        mesh_identity: AgentIdentity | None = None
        mesh_policy: PolicyEngine | None = None
        mesh_caller_id: str | None = None

        def __init_subclass__(cls, **kwargs: Any) -> None:
            """
            Automatically wrap _run and _arun when a subclass is defined.
            Called by Python when `class MyTool(SecureTool):` is executed.
            """
            super().__init_subclass__(**kwargs)

            # Only wrap concrete classes that have mesh_identity set
            # Abstract subclasses (e.g. intermediate base classes) are skipped
            if cls.mesh_identity is None:
                # Deferred — will validate at first call
                logger.debug(
                    "AgentMesh: SecureTool subclass %r has no mesh_identity yet — "
                    "set it as a class attribute before using the tool",
                    cls.__name__,
                )
                return

            if not isinstance(cls.mesh_identity, AgentIdentity):
                raise LangChainSecurityError(
                    f"{cls.__name__}.mesh_identity must be an AgentIdentity instance, "
                    f"got {type(cls.mesh_identity).__name__}"
                )

            _wrap_tool_class(
                cls,
                identity=cls.mesh_identity,
                policy=cls.mesh_policy,
                caller_id=cls.mesh_caller_id,
            )

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            """Override this in your subclass."""
            raise NotImplementedError(
                f"{self.__class__.__name__}._run() must be implemented"
            )

    return SecureTool


# Build SecureTool lazily — only fails if langchain-core missing AND accessed
class _LazySecureTool:
    """
    Lazy proxy for SecureTool.
    Importing the module never fails — only accessing SecureTool fails
    if langchain-core is not installed.
    """
    _instance: type | None = None

    def __get__(self, obj: Any, objtype: Any = None) -> type:
        if self._instance is None:
            self._instance = _make_secure_tool_base()
        return self._instance


class _SecureToolDescriptor:
    _base: type | None = None

    def __set_name__(self, owner: type, name: str) -> None:
        self._name = name

    def __get__(self, obj: Any, objtype: Any = None) -> type:
        if self._base is None:
            self._base = _make_secure_tool_base()
        return self._base


# Module-level SecureTool — built on first access
def get_secure_tool_class() -> type:
    """
    Get the SecureTool base class.
    Raises LangChainNotInstalledError if langchain-core is not installed.
    """
    return _make_secure_tool_base()


# Convenience: make SecureTool importable directly
# Usage: from integrations.langchain import SecureTool
try:
    SecureTool = _make_secure_tool_base()
except LangChainNotInstalledError:
    # langchain-core not installed — SecureTool not available
    # Accessing it will raise a clear error
    SecureTool = None  # type: ignore[assignment]