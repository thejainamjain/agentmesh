from agentmesh.identity.exceptions import AgentMeshError


class PolicyError(AgentMeshError):
    """Base exception for all policy engine errors."""


class PolicyLoadError(PolicyError):
    """
    Raised when the policy file cannot be loaded or parsed.

    Security note: a missing or malformed policy file is treated the same
    as a DENY-all policy. The engine refuses to start rather than fall back
    to allow-all. This is the fail-secure guarantee.
    """


class PolicyValidationError(PolicyError):
    """
    Raised when the policy file fails schema validation.

    Every field in the policy YAML is validated against a strict JSON Schema
    before the engine accepts it. An invalid field is never silently ignored.
    """


class PolicyDenied(PolicyError):
    """
    Raised when the policy engine explicitly denies a tool call.

    Contains the denial reason so the audit trail can record exactly
    which rule was violated.
    """


class RateLimitExceeded(PolicyError):
    """
    Raised when an agent exceeds its configured rate limit for a tool.

    Distinct from PolicyDenied so callers can implement retry logic
    for rate limits while treating hard denials as permanent blocks.
    """