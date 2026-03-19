from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Identity endpoints
# ---------------------------------------------------------------------------

class VerifyTokenRequest(BaseModel):
    """POST /v1/identity/verify"""
    token: str = Field(..., description="JWT token issued by AgentIdentity.issue_token()")


class VerifyTokenResponse(BaseModel):
    """Response from POST /v1/identity/verify"""
    valid: bool
    agent_id: str | None = None
    mesh_id: str | None = None
    capabilities: list[str] = []
    error: str | None = None


# ---------------------------------------------------------------------------
# Policy endpoints
# ---------------------------------------------------------------------------

class PolicyEvaluateRequest(BaseModel):
    """POST /v1/policy/evaluate"""
    agent_id: str = Field(..., description="The agent attempting the tool call")
    tool_name: str = Field(..., description="The tool being called")
    caller_id: str | None = Field(None, description="The agent invoking this one")


class PolicyEvaluateResponse(BaseModel):
    """Response from POST /v1/policy/evaluate"""
    decision: Literal["allow", "deny", "rate_limited"]
    reason: str
    agent_id: str
    tool_name: str


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    """GET /health"""
    status: Literal["ok"] = "ok"
    version: str = "0.1.0"
    policy_loaded: bool = False
    registered_agents: list[str] = []