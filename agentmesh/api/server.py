from __future__ import annotations

import argparse
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

_policy_engine: Optional[object] = None


def get_policy_engine():
    return _policy_engine


def set_policy_engine(engine) -> None:
    global _policy_engine
    _policy_engine = engine


def create_app(
    policy_path: str | Path | None = None,
    allow_origins: list[str] | None = None,
) -> FastAPI:
    if policy_path is not None:
        _load_policy(policy_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        engine = get_policy_engine()
        if engine:
            logger.info(
                "AgentMesh API started. Policy loaded: %d agents registered.",
                len(engine.registered_agents()),
            )
        else:
            logger.warning(
                "AgentMesh API started WITHOUT a policy file. "
                "All policy evaluations will return DENY."
            )
        yield

    app = FastAPI(
        title="AgentMesh API",
        description="REST API for AgentMesh runtime trust and security layer.",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    origins = allow_origins or [
        "http://localhost:3000",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080",
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization"],
    )

    from agentmesh.api.routes.health import router as health_router
    from agentmesh.api.routes.identity import router as identity_router
    from agentmesh.api.routes.policy import router as policy_router

    app.include_router(health_router)
    app.include_router(identity_router)
    app.include_router(policy_router)

    @app.exception_handler(Exception)
    async def global_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.error("Unhandled error: %s %s — %s", request.method, request.url, exc)
        return JSONResponse(
            status_code=500,
            content={"error": "internal_server_error", "detail": "An unexpected error occurred."},
        )

    return app


def _load_policy(policy_path: str | Path) -> None:
    try:
        from agentmesh.policy.engine import PolicyEngine
        engine = PolicyEngine.from_file(policy_path)
        set_policy_engine(engine)
        logger.info("Policy loaded from %s", policy_path)
    except Exception as e:
        logger.error(
            "CRITICAL: Failed to load policy from %s: %s — ALL calls will be DENIED",
            policy_path, e,
        )


def run(app: FastAPI, host: str = "127.0.0.1", port: int = 8000) -> None:
    try:
        import uvicorn
        uvicorn.run(app, host=host, port=port, log_level="info")
    except ImportError:
        logger.error("uvicorn is not installed. Install with: pip install uvicorn")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AgentMesh REST API Server")
    parser.add_argument("--policy", type=str)
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    app = create_app(policy_path=args.policy)
    run(app, host=args.host, port=args.port)