from agentmesh.identity.exceptions import AgentMeshError


class InterceptorError(AgentMeshError):
    """Raised when the interceptor itself fails unexpectedly."""


class PolicyDenied(AgentMeshError):
    """Raised when the policy engine blocks a tool call."""