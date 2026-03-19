from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from agentmesh.api.schemas import PolicyEvaluateRequest, PolicyEvaluateResponse

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/v1/policy/evaluate",
    response_model=PolicyEvaluateResponse,
    tags=["policy"],
    summary="Evaluate whether an agent is permitted to call a tool",
)
async def evaluate_policy(request: PolicyEvaluateRequest) -> PolicyEvaluateResponse:
    """
    Evaluate a policy decision for a tool call.

    Used by the JS SDK before executing any tool call. The SDK must
    check the `decision` field and block execution if it is not "allow".

    Security notes:
    - Default-deny: if no policy is loaded, ALL calls return deny.
    - The policy engine is loaded once at server startup and is
      immutable at runtime. A policy reload requires a server restart.
    - Rate limits are enforced per agent_id + tool_name combination,
      not per HTTP client or IP address.
    """
    from agentmesh.api.server import get_policy_engine

    engine = get_policy_engine()

    if engine is None:
        # Fail secure: no policy = deny everything
        logger.warning(
            "Policy evaluate called but no policy loaded — "
            "denying agent=%r tool=%r",
            request.agent_id, request.tool_name,
        )
        return PolicyEvaluateResponse(
            decision="deny",
            reason="No policy loaded. AgentMesh server requires a policy file to permit any calls.",
            agent_id=request.agent_id,
            tool_name=request.tool_name,
        )

    decision = engine.evaluate(
        agent_id=request.agent_id,
        tool_name=request.tool_name,
        caller_id=request.caller_id,
    )

    logger.info(
        "Policy decision: %s agent=%r tool=%r caller=%r reason=%r",
        decision.decision.value,
        request.agent_id,
        request.tool_name,
        request.caller_id,
        decision.reason,
    )

    return PolicyEvaluateResponse(
        decision=decision.decision.value,
        reason=decision.reason,
        agent_id=request.agent_id,
        tool_name=request.tool_name,
    )