from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from agentmesh.api.schemas import VerifyTokenRequest, VerifyTokenResponse
from agentmesh.identity.agent_identity import AgentIdentity
from agentmesh.identity.exceptions import (
    IdentityError,
    TokenExpiredError,
    TokenRevokedError,
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/v1/identity/verify",
    response_model=VerifyTokenResponse,
    tags=["identity"],
    summary="Verify a JWT token issued by AgentIdentity",
)
async def verify_token(request: VerifyTokenRequest) -> VerifyTokenResponse:
    """
    Verify a JWT token and return the agent context.

    Used by the JS SDK to verify that a token issued by the Python identity
    layer is valid before allowing tool calls.

    Security notes:
    - The raw token is never logged — only the agent_id on success
    - All three failure modes are returned as valid=False responses,
      not HTTP errors. The SDK must check the `valid` field.
    - Rate limiting on this endpoint is handled by the policy engine
      via the caller's token, not by IP address.
    """
    try:
        ctx = AgentIdentity.verify(request.token)
        logger.info(
            "Identity verified: agent_id=%r mesh_id=%r",
            ctx.agent_id, ctx.mesh_id,
        )
        return VerifyTokenResponse(
            valid=True,
            agent_id=ctx.agent_id,
            mesh_id=ctx.mesh_id,
            capabilities=ctx.capabilities,
        )
    except TokenExpiredError as e:
        logger.warning("Token expired: %s", e)
        return VerifyTokenResponse(valid=False, error="token_expired")
    except TokenRevokedError as e:
        logger.warning("Token revoked: %s", e)
        return VerifyTokenResponse(valid=False, error="token_revoked")
    except IdentityError as e:
        logger.warning("Identity error: %s", e)
        return VerifyTokenResponse(valid=False, error="invalid_token")
    except Exception as e:
        logger.error("Unexpected error in identity verification: %s", e)
        return VerifyTokenResponse(valid=False, error="server_error")