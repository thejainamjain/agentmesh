from __future__ import annotations

import functools
import inspect
import logging
from pathlib import Path
from typing import Any, Callable

from agentmesh.identity.agent_identity import AgentIdentity
from agentmesh.identity.exceptions import AgentMeshError
from agentmesh.monitor.anomaly_detector import AnomalyDetector
from agentmesh.monitor.captured_call import CapturedCall
from agentmesh.monitor.exceptions import InterceptorError, PolicyDenied
from agentmesh.monitor.injection_detector import InjectionDetector, Severity
from agentmesh.policy.engine import Decision, PolicyEngine
from agentmesh.policy.exceptions import PolicyLoadError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# C++ fast path
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


def _evaluate_policy(
    captured: CapturedCall,
    engine: PolicyEngine | None,
    caller_id: str | None,
) -> None:
    """Evaluate policy — raises PolicyDenied if blocked."""
    if engine is None:
        return
    decision = engine.evaluate(
        agent_id=captured.agent_id,
        tool_name=captured.tool_name,
        caller_id=caller_id,
    )
    if decision.decision in (Decision.DENY, Decision.RATE_LIMITED):
        captured.block(decision.reason)
        raise PolicyDenied(decision.reason)


def _evaluate_behavior(
    captured: CapturedCall,
    injection_detector: InjectionDetector | None,
    anomaly_detector: AnomalyDetector | None,
) -> None:
    """
    Run behavior checks — injection detection and anomaly detection.

    Injection detection runs first (faster, pattern-based).
    Anomaly detection runs second (statistical, needs warm-up period).

    Raises PolicyDenied if either detector blocks the call.
    Adds monitor flags to captured for the audit trail.
    """
    # ── Injection detection ───────────────────────────────────────────────────
    if injection_detector is not None:
        result = injection_detector.inspect(captured.arguments)
        if not result.safe:
            captured.block(result.reason)
            if hasattr(captured, 'monitor_flags'):
                captured.monitor_flags.extend(result.flags)
            logger.warning(
                "AgentMesh: injection detected — agent=%r tool=%r reason=%r",
                captured.agent_id, captured.tool_name, result.reason,
            )
            raise PolicyDenied(f"Injection detected: {result.reason}")
        elif result.matches:
            # Warned but not blocked — add flags for audit trail
            if hasattr(captured, 'monitor_flags'):
                captured.monitor_flags.extend(result.flags)
            logger.warning(
                "AgentMesh: injection warning — agent=%r tool=%r flags=%s",
                captured.agent_id, captured.tool_name, result.flags,
            )

    # ── Anomaly detection ─────────────────────────────────────────────────────
    if anomaly_detector is not None:
        anomaly = anomaly_detector.record_and_check(
            agent_id=captured.agent_id,
            tool_name=captured.tool_name,
            arguments=captured.arguments,
        )
        if anomaly.anomalous:
            flag = f"anomaly:{anomaly.metric}:z={anomaly.z_score:.1f}"
            if hasattr(captured, 'monitor_flags'):
                captured.monitor_flags.append(flag)
            logger.warning(
                "AgentMesh: anomaly detected — agent=%r tool=%r reason=%r",
                captured.agent_id, captured.tool_name, anomaly.reason,
            )
            # Anomalies are HIGH severity — block the call
            captured.block(anomaly.reason)
            raise PolicyDenied(f"Anomaly detected: {anomaly.reason}")


# ---------------------------------------------------------------------------
# @intercept_tools decorator
# ---------------------------------------------------------------------------

def intercept_tools(
    identity: AgentIdentity,
    policy: "PolicyEngine | str | Path | None" = None,
    caller_id: str | None = None,
    injection_detector: InjectionDetector | None = None,
    anomaly_detector: AnomalyDetector | None = None,
) -> Callable:
    """
    Decorator that wraps a tool function with the AgentMesh interceptor.

    Every call to the decorated function will:
      1. Verify the agent JWT identity
      2. Capture: caller identity, tool name, arguments, timestamp
      3. Evaluate the policy engine (if configured)
      4. Run injection detection (if configured)
      5. Run anomaly detection (if configured)
      6. Execute the tool
      7. Record the result

    Args:
        identity:           AgentIdentity for the agent owning this tool.
        policy:             PolicyEngine, path to YAML, or None.
        caller_id:          ID of the agent invoking this one.
        injection_detector: InjectionDetector instance, or None to skip.
        anomaly_detector:   AnomalyDetector instance, or None to skip.

    Raises:
        InterceptorError: Bad identity type or policy file load failure.
        IdentityError / TokenExpiredError / TokenRevokedError: JWT failures.
        PolicyDenied: Policy, injection, or anomaly check blocked the call.
    """
    if not isinstance(identity, AgentIdentity):
        raise InterceptorError(
            f"intercept_tools requires an AgentIdentity instance, "
            f"got {type(identity).__name__!r}"
        )

    # Resolve policy engine at decoration time
    engine: PolicyEngine | None = None
    if policy is not None:
        if isinstance(policy, (str, Path)):
            try:
                engine = PolicyEngine.from_file(policy)
            except Exception as e:
                raise InterceptorError(
                    f"Failed to load policy file {policy!r}: {e}"
                ) from e
        elif isinstance(policy, PolicyEngine):
            engine = policy
        else:
            raise InterceptorError(
                f"policy must be a PolicyEngine or path, got {type(policy).__name__!r}"
            )

    token = identity.issue_token()

    def decorator(func: Callable) -> Callable:
        tool_name = func.__name__

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # 1 — Verify identity
            try:
                ctx = AgentIdentity.verify(token)
            except AgentMeshError:
                logger.warning(
                    "AgentMesh: identity check failed — agent=%r tool=%r",
                    identity.agent_id, tool_name,
                )
                raise

            # 2 — Bind arguments
            bound_args = _bind_arguments(func, args, kwargs)

            # 3 — Capture
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

            # 4 — Policy evaluation
            _evaluate_policy(captured, engine, caller_id)

            # 5 — Behavior checks (injection + anomaly)
            _evaluate_behavior(captured, injection_detector, anomaly_detector)

            # 6 — Execute
            try:
                result = func(*args, **kwargs)
            except Exception as exc:
                logger.error(
                    "AgentMesh: tool execution failed — agent=%r tool=%r error=%r",
                    ctx.agent_id, tool_name, str(exc),
                )
                raise

            # 7 — Record result
            captured.record_result(result)

            logger.debug(
                "AgentMesh: completed — agent=%r tool=%r result_hash=%s",
                ctx.agent_id, tool_name, (captured.result_hash or "")[:8],
            )

            return result

        wrapper._agentmesh_intercepted = True
        wrapper._agentmesh_identity = identity
        wrapper._agentmesh_tool_name = tool_name
        wrapper._agentmesh_engine = engine

        return wrapper

    return decorator


def _bind_arguments(func: Callable, args: tuple, kwargs: dict) -> dict[str, Any]:
    """Map positional and keyword arguments to a named dict."""
    try:
        sig = inspect.signature(func)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except (TypeError, ValueError):
        result = {f"arg_{i}": v for i, v in enumerate(args)}
        result.update(kwargs)
        return result