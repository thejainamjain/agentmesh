from fastapi import APIRouter
from agentmesh.api.schemas import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["system"])
async def health(policy_engine=None) -> HealthResponse:
    """
    Health check endpoint.

    Returns server status, version, and whether a policy is loaded.
    Used by the JS SDK to verify the server is reachable before sending calls.
    """
    from agentmesh.api.server import get_policy_engine
    engine = get_policy_engine()
    return HealthResponse(
        status="ok",
        version="0.1.0",
        policy_loaded=engine is not None,
        registered_agents=engine.registered_agents() if engine else [],
    )