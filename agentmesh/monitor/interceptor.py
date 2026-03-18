from __future__ import annotations

import functools
import inspect
import logging
from typing import Any, Callable

from agentmesh.identity.agent_identity import AgentIdentity
from agentmesh.identity.exceptions import (
    AgentMeshError,
    IdentityError,
    TokenExpiredError,
    TokenRevokedError,
)
from agentmesh.monitor.captured_call import CapturedCall
from agentmesh.monitor.exceptions import InterceptorError, PolicyDenied

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# C++ fast path — graceful fallback to pure Python if not compiled
# ---------------------------------------------------------------------------

try:
    from agentmesh.monitor._ext import interceptor_core  # type: ignore
    _USE_CPP = True
    logger.debug("AgentMesh: using C++ interceptor core")
except ImportError:
    _USE_CPP = False
    logger.debug("AgentMesh: C++ extension not found, using pure Python path")


def _capture_call(
    agent_id: str,
    mesh_id: str,
    token: str,
    tool_name: str,
    arguments: dict[str, Any],
) -> CapturedCall:
    """
    Dispatch to C++ fast path or Python fallback.
    The C++ path computes the timestamp and arguments hash at native speed.
    The Python fallback is functionally identical — used when the extension
    is not compiled (e.g. fresh clone, contributor environments).
    """
    if _USE_CPP:
        ts_iso, args_hash = interceptor_core.capture(agent_id, tool_name, arguments)
        from datetime import datetime
        return CapturedCall(
            agent_id=agent_id,
            mesh_id=mesh_id,
            token=token,
            tool_name=tool_name,
            arguments=arguments,
            arguments_hash=args_hash,
            timestamp=datetime.fromisoformat(ts_iso),
        )
    return CapturedCall.capture(
        agent_id=agent_id,
        mesh_id=mesh_id,
        token=token,
        tool_name=tool_name,
        arguments=arguments,
    )


def _policy_stub(captured: CapturedCall) -> None:
    """
    Placeholder policy check — always allows in Week 3.

    Week 4 replaces this with:
        from agentmesh.policy import PolicyEngine
        decision = PolicyEngine.evaluate(
            caller_id=captured.agent_id,
            tool_name=captured.tool_name,
        )
        if not decision.allowed:
            captured.block(decision.reason)
            raise PolicyDenied(decision.reason)
    """
    pass  # Week 4 replaces this


# ---------------------------------------------------------------------------
# @intercept_tools decorator
# ---------------------------------------------------------------------------

def intercept_tools(identity: AgentIdentity) -> Callable:
    """
    Decorator that wraps a tool function with the AgentMesh interceptor.

    Every call to the decorated function will:
      1. Verify the agent's JWT identity (uses the token issued at decoration time)
      2. Capture: caller identity, tool name, arguments, timestamp
      3. Pass the capture to the policy engine (stub until Week 4)
      4. Allow or block execution based on policy
      5. Execute the tool
      6. Record the result

    The token is issued once at decoration time and re-verified on every call.
    This is the correct zero-trust pattern:
      - The token is stable (same jti) so revocation works — if you call
        identity.revoke_all(), that jti is on the revocation list and every
        subsequent call is blocked immediately.
      - Issue-per-call would generate a fresh jti each time, making revocation
        impossible to enforce.

    Usage:
        @intercept_tools(identity=my_agent_identity)
        def web_search(query: str) -> str:
            ...

    Raises:
        InterceptorError: If identity is not an AgentIdentity instance.
        IdentityError: If the agent's token is invalid or unregistered.
        TokenExpiredError: If the agent's token has expired.
        TokenRevokedError: If the agent's token has been revoked.
        PolicyDenied: If the policy engine blocks the call (Week 4+).
    """
    if not isinstance(identity, AgentIdentity):
        raise InterceptorError(
            f"intercept_tools requires an AgentIdentity instance, "
            f"got {type(identity).__name__!r}"
        )

    # Issue one token at decoration time.
    # This token's jti is tracked in identity._issued_jtis, so revoke_all()
    # will add it to the revocation list and block all future calls.
    token = identity.issue_token()

    def decorator(func: Callable) -> Callable:
        tool_name = func.__name__

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # ── Step 1: Verify identity ──────────────────────────────────
            # Re-verify the decoration-time token on every call.
            # Raises IdentityError / TokenExpiredError / TokenRevokedError.
            try:
                ctx = AgentIdentity.verify(token)
            except AgentMeshError:
                logger.warning(
                    "AgentMesh: identity check failed — agent=%r tool=%r",
                    identity.agent_id, tool_name,
                )
                raise

            # ── Step 2: Bind arguments ───────────────────────────────────
            bound_args = _bind_arguments(func, args, kwargs)

            # ── Step 3: Capture the call ─────────────────────────────────
            captured = _capture_call(
                agent_id=ctx.agent_id,
                mesh_id=ctx.mesh_id,
                token=token,
                tool_name=tool_name,
                arguments=bound_args,
            )

            logger.debug(
                "AgentMesh: captured — agent=%r tool=%r args_hash=%s",
                ctx.agent_id, tool_name, captured.arguments_hash[:8],
            )

            # ── Step 4: Policy check (stub — Week 4 wires real engine) ───
            _policy_stub(captured)

            if not captured.allowed:
                logger.warning(
                    "AgentMesh: BLOCKED — agent=%r tool=%r reason=%r",
                    ctx.agent_id, tool_name, captured.block_reason,
                )
                raise PolicyDenied(
                    f"Tool call blocked: agent={ctx.agent_id!r} "
                    f"tool={tool_name!r} reason={captured.block_reason!r}"
                )

            # ── Step 5: Execute the tool ─────────────────────────────────
            try:
                result = func(*args, **kwargs)
            except Exception as exc:
                logger.error(
                    "AgentMesh: tool execution failed — agent=%r tool=%r error=%r",
                    ctx.agent_id, tool_name, str(exc),
                )
                raise

            # ── Step 6: Record result ────────────────────────────────────
            captured.record_result(result)

            logger.debug(
                "AgentMesh: completed — agent=%r tool=%r result_hash=%s",
                ctx.agent_id, tool_name, (captured.result_hash or "")[:8],
            )

            return result

        # Attach metadata for introspection, tests, and the audit trail
        wrapper._agentmesh_intercepted = True
        wrapper._agentmesh_identity = identity
        wrapper._agentmesh_tool_name = tool_name

        return wrapper

    return decorator


def _bind_arguments(func: Callable, args: tuple, kwargs: dict) -> dict[str, Any]:
    """
    Map positional and keyword arguments to a named dict using the function signature.

    Example:
        def web_search(query: str, max_results: int = 10): ...
        _bind_arguments(web_search, ("AI security",), {})
        → {"query": "AI security", "max_results": 10}

    Falls back gracefully if binding fails (e.g. *args functions).
    """
    try:
        sig = inspect.signature(func)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except (TypeError, ValueError):
        result = {f"arg_{i}": v for i, v in enumerate(args)}
        result.update(kwargs)
        return result