class AgentMeshError(Exception):
    """Base exception for all AgentMesh errors."""

class IdentityError(AgentMeshError):
    """Raised when JWT signature is invalid or agent is unregistered."""

class TokenExpiredError(AgentMeshError):
    """Raised when JWT token has passed its expiry time."""

class TokenRevokedError(AgentMeshError):
    """Raised when JWT jti is on the revocation list."""