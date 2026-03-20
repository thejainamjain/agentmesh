from __future__ import annotations

"""
WebSocket endpoint for real-time audit trail streaming.

The dashboard connects here to receive live audit entries as they are written.
Authentication uses a shared secret from the environment — never hardcoded.

Security:
  - Secret is read from AGENTMESH_SECRET_KEY env var only
  - Missing secret = all WebSocket connections are rejected
  - Token is checked in the first message, not in the URL (avoids server logs)
  - Connection is dropped immediately on invalid auth
"""

import asyncio
import json
import logging
import os
from pathlib import Path

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

logger = logging.getLogger(__name__)
router = APIRouter()

# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

def _get_secret() -> str | None:
    """
    Read the WebSocket shared secret from the environment.
    Returns None if not set — all connections will be rejected.
    """
    secret = os.environ.get("AGENTMESH_SECRET_KEY", "").strip()
    return secret if secret else None


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@router.websocket("/ws/audit")
async def audit_websocket(websocket: WebSocket) -> None:  # pragma: no cover
    """
    Real-time audit trail WebSocket.

    Protocol:
      1. Client connects
      2. Client sends: {"auth": "<AGENTMESH_SECRET_KEY>", "audit_path": "<path>"}
      3. Server validates auth — closes with 4001 if invalid
      4. Server sends existing entries (last 50) as JSON lines
      5. Server polls for new entries every second and streams them
      6. Client disconnects gracefully

    Message format (server → client):
      {"type": "entry", "data": {...audit entry dict...}}
      {"type": "error", "message": "..."}
      {"type": "connected", "entry_count": N}
    """
    await websocket.accept()
    logger.info("WebSocket connection accepted from %s", websocket.client)

    # ── Step 1: Authenticate ──────────────────────────────────────────────
    secret = _get_secret()
    if secret is None:
        await websocket.send_json({
            "type": "error",
            "message": "Server not configured for WebSocket auth. Set AGENTMESH_SECRET_KEY."
        })
        await websocket.close(code=4001)
        logger.warning("WebSocket rejected: AGENTMESH_SECRET_KEY not set on server")
        return

    try:
        auth_msg = await asyncio.wait_for(websocket.receive_json(), timeout=10.0)
    except asyncio.TimeoutError:
        await websocket.close(code=4002)
        return
    except Exception:
        await websocket.close(code=4003)
        return

    if auth_msg.get("auth") != secret:
        await websocket.send_json({"type": "error", "message": "Unauthorized"})
        await websocket.close(code=4001)
        logger.warning("WebSocket rejected: invalid auth token from %s", websocket.client)
        return

    # ── Step 2: Resolve audit file path ──────────────────────────────────
    audit_path_str = auth_msg.get("audit_path", "agentmesh-audit.jsonl")
    audit_path = Path(audit_path_str)

    logger.info("WebSocket authenticated. Streaming audit from %s", audit_path)

    # ── Step 3: Send existing entries (last 50) ───────────────────────────
    existing = _read_entries(audit_path)
    last_50 = existing[-50:] if len(existing) > 50 else existing

    await websocket.send_json({
        "type": "connected",
        "entry_count": len(existing),
        "streaming_last": len(last_50),
    })

    for entry in last_50:
        await websocket.send_json({"type": "entry", "data": entry})

    # ── Step 4: Poll for new entries ──────────────────────────────────────
    last_count = len(existing)
    try:
        while True:
            await asyncio.sleep(1.0)
            current = _read_entries(audit_path)
            if len(current) > last_count:
                new_entries = current[last_count:]
                for entry in new_entries:
                    await websocket.send_json({"type": "entry", "data": entry})
                last_count = len(current)
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.error("WebSocket error: %s", e)
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass


def _read_entries(path: Path) -> list[dict]:  # pragma: no cover
    """Read all entries from the audit JSONL file. Returns [] if file missing."""
    if not path.exists():
        return []
    entries = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except OSError:
        pass
    return entries