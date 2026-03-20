"""
AgentMesh — Runtime Trust & Security Layer for Multi-Agent AI Systems

Quick start:
    from agentmesh import AgentIdentity, PolicyEngine, intercept_tools, AuditTrail

    identity = AgentIdentity("researcher", ["web_search"])
    engine   = PolicyEngine.from_file("policy.yaml")
    trail    = AuditTrail(identity=identity)

    @intercept_tools(identity=identity, policy=engine)
    def web_search(query: str) -> str:
        ...
"""

# Identity layer
from agentmesh.identity.agent_identity import AgentIdentity, AgentContext
from agentmesh.identity.credential_store import CredentialStore
from agentmesh.identity.exceptions import (
    AgentMeshError,
    IdentityError,
    TokenExpiredError,
    TokenRevokedError,
)

# Policy engine
from agentmesh.policy.engine import PolicyEngine, PolicyDecision
from agentmesh.policy.exceptions import (
    PolicyError,
    PolicyDenied,
    PolicyLoadError,
    PolicyValidationError,
)

# Behavior monitor
from agentmesh.monitor.interceptor import intercept_tools
from agentmesh.monitor.injection_detector import InjectionDetector
from agentmesh.monitor.anomaly_detector import AnomalyDetector

# Audit trail
from agentmesh.audit.trail import AuditTrail, AuditEntry, ActionType, hash_arguments
from agentmesh.audit.storage import AuditBackend, LocalJsonlBackend
from agentmesh.audit.exceptions import AuditError, AuditWriteError, ChainIntegrityError

__version__ = "0.1.0"

__all__ = [
    # Identity
    "AgentIdentity",
    "AgentContext",
    "CredentialStore",
    "AgentMeshError",
    "IdentityError",
    "TokenExpiredError",
    "TokenRevokedError",
    # Policy
    "PolicyEngine",
    "PolicyDecision",
    "PolicyError",
    "PolicyDenied",
    "PolicyLoadError",
    "PolicyValidationError",
    # Monitor
    "intercept_tools",
    "InjectionDetector",
    "AnomalyDetector",
    # Audit
    "AuditTrail",
    "AuditEntry",
    "ActionType",
    "AuditBackend",
    "LocalJsonlBackend",
    "AuditError",
    "AuditWriteError",
    "ChainIntegrityError",
    "hash_arguments",
    # Version
    "__version__",
]