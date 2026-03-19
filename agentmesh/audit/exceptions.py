from agentmesh.identity.exceptions import AgentMeshError


class AuditError(AgentMeshError):
    """Base exception for all audit trail errors."""


class AuditWriteError(AuditError):
    """
    Raised when an audit entry cannot be written to storage.

    Security note: if this is raised, the interceptor MUST block the
    tool call that triggered the write. An action that cannot be
    recorded must not proceed. This is the fail-secure guarantee.
    """


class ChainIntegrityError(AuditError):
    """
    Raised when verify_chain() detects tampering in the audit log.

    Contains the entry_id of the first entry where the chain breaks,
    and the reason (prev_hash mismatch or signature failure).
    """

    def __init__(self, message: str, failed_at: str | None = None) -> None:
        super().__init__(message)
        self.failed_at = failed_at  # entry_id of the first tampered entry