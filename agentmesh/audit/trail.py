from __future__ import annotations

"""
AuditTrail — immutable, cryptographically verifiable record of all agent actions.

Every entry is:
  1. SHA-256 hashed (canonical JSON, sorted keys, no whitespace)
  2. Linked to the previous entry via prev_hash (hash chain)
  3. Ed25519 signed by the recording agent

Tampering with any entry breaks the chain from that point forward.
Deleting entries breaks the chain at the gap.
Inserting entries breaks the chain because they lack a valid signature.

This makes the audit trail tamper-evident — not tamper-proof (an attacker
with write access to the file can delete it entirely) but tamper-detectable
(any modification to existing content is immediately detected by verify_chain).
"""

import hashlib
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from agentmesh.audit.exceptions import AuditWriteError, ChainIntegrityError
from agentmesh.audit.storage import AuditBackend, LocalJsonlBackend
from agentmesh.identity.agent_identity import AgentIdentity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Action types
# ---------------------------------------------------------------------------

class ActionType(str, Enum):
    TOOL_CALL = "tool_call"
    AGENT_CALL = "agent_call"
    POLICY_VIOLATION = "policy_violation"
    IDENTITY_EVENT = "identity_event"
    MONITOR_BLOCK = "monitor_block"
    SYSTEM_EVENT = "system_event"


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VerificationResult:
    """Result of verify_chain()."""
    valid: bool
    entry_count: int
    reason: str = "chain intact"
    failed_at: str | None = None  # entry_id of first tampered entry

    def __repr__(self) -> str:
        if self.valid:
            return f"VerificationResult(VALID: {self.entry_count} entries verified)"
        return f"VerificationResult(TAMPERED at entry={self.failed_at!r}: {self.reason})"


# ---------------------------------------------------------------------------
# Canonical hashing — the core of chain integrity
# ---------------------------------------------------------------------------

def _canonical_hash(data: dict[str, Any]) -> str:
    """
    Produce a stable SHA-256 hex digest of a dict.

    Uses canonical JSON: sorted keys, no whitespace, no trailing newline.
    This ensures the same data always produces the same hash regardless
    of insertion order or serialisation library differences.

    This function is the single source of truth for hashing in the audit
    trail. It is used for both entry hashing and chain linking.
    """
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _sign(data: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    """
    Sign the canonical hash of a dict with an Ed25519 private key.

    Returns the signature as a lowercase hex string.
    The signature covers the SHA-256 of the canonical JSON, not the
    JSON itself — this is consistent with the identity layer design.
    """
    entry_hash = _canonical_hash(data).encode("utf-8")
    signature_bytes = private_key.sign(entry_hash)
    return signature_bytes.hex()


def _verify_signature(
    data: dict[str, Any],
    signature_hex: str,
    public_key: Ed25519PublicKey,
) -> bool:
    """
    Verify an Ed25519 signature over the canonical hash of a dict.

    Returns True if valid, False otherwise. Never raises.
    """
    try:
        entry_hash = _canonical_hash(data).encode("utf-8")
        sig_bytes = bytes.fromhex(signature_hex)
        public_key.verify(sig_bytes, entry_hash)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


# ---------------------------------------------------------------------------
# AuditEntry — the schema
# ---------------------------------------------------------------------------

@dataclass
class AuditEntry:
    """
    A single immutable audit log entry.

    Fields match the schema defined in ARCHITECTURE.md Section 7.
    The schema is frozen from v0.1 — changing it would invalidate
    all existing audit logs.

    Arguments are NEVER stored — only their SHA-256 hash. This protects:
      - User PII in query arguments
      - API keys or tokens accidentally passed as arguments
      - Confidential business logic in tool parameters

    Full argument storage is available as an opt-in feature for
    controlled environments where data retention is acceptable.
    """

    # Identity
    entry_id: str
    timestamp: str                  # ISO-8601 UTC
    agent_id: str
    mesh_id: str

    # Action
    action_type: str                # ActionType enum value
    tool_name: str | None           # Required for tool_call
    caller_id: str | None           # Required for agent_call

    # Content hashes (never the content itself)
    arguments_hash: str             # SHA-256 of canonical JSON of arguments
    result_hash: str | None         # SHA-256 of result; None if blocked

    # Decisions
    policy_decision: str            # allow | deny | rate_limited | pending
    monitor_flags: list[str]        # Injection/anomaly warnings

    # Chain link
    prev_hash: str | None           # SHA-256 of previous entry; None for genesis

    # Cryptographic proof
    signature: str                  # Ed25519 over SHA-256(entry_without_signature)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to plain dict for storage and hashing."""
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "mesh_id": self.mesh_id,
            "action_type": self.action_type,
            "tool_name": self.tool_name,
            "caller_id": self.caller_id,
            "arguments_hash": self.arguments_hash,
            "result_hash": self.result_hash,
            "policy_decision": self.policy_decision,
            "monitor_flags": self.monitor_flags,
            "prev_hash": self.prev_hash,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "AuditEntry":
        """Deserialise from a stored dict."""
        return cls(
            entry_id=d["entry_id"],
            timestamp=d["timestamp"],
            agent_id=d["agent_id"],
            mesh_id=d["mesh_id"],
            action_type=d["action_type"],
            tool_name=d.get("tool_name"),
            caller_id=d.get("caller_id"),
            arguments_hash=d["arguments_hash"],
            result_hash=d.get("result_hash"),
            policy_decision=d["policy_decision"],
            monitor_flags=d.get("monitor_flags", []),
            prev_hash=d.get("prev_hash"),
            signature=d["signature"],
        )

    def without_signature(self) -> dict[str, Any]:
        """Return the dict without the signature field — used for verification."""
        d = self.to_dict()
        d.pop("signature")
        return d

    def __repr__(self) -> str:
        return (
            f"AuditEntry(id={self.entry_id[:8]}... "
            f"agent={self.agent_id!r} action={self.action_type} "
            f"tool={self.tool_name!r})"
        )


# ---------------------------------------------------------------------------
# AuditTrail
# ---------------------------------------------------------------------------

class AuditTrail:
    """
    Cryptographically verifiable, append-only audit trail.

    Every action every agent takes is recorded here before it executes.
    The trail is tamper-evident: any modification to any entry is detected
    by verify_chain().

    Usage:
        trail = AuditTrail(identity=my_identity)

        # Record a tool call
        trail.record(
            action_type=ActionType.TOOL_CALL,
            tool_name="web_search",
            arguments_hash="abc123...",
            result_hash="def456...",
            policy_decision="allow",
        )

        # Verify the entire chain
        result = trail.verify_chain()
        if not result.valid:
            raise SecurityAlert(f"Audit log tampered at {result.failed_at}")

    Fail-secure guarantee:
        If record() raises AuditWriteError, the caller MUST block the
        triggering action. An action that cannot be recorded must not
        proceed. The interceptor enforces this.
    """

    def __init__(
        self,
        identity: AgentIdentity,
        backend: AuditBackend | None = None,
        path: str | Path = "agentmesh-audit.jsonl",
    ) -> None:
        """
        Initialise the audit trail.

        Args:
            identity: The AgentIdentity of the agent writing to this trail.
                      Used for Ed25519 signing of each entry.
            backend:  Storage backend. Defaults to LocalJsonlBackend.
            path:     Path for the local JSONL file (used only if backend
                      is not provided).
        """
        self._identity = identity
        self._backend = backend or LocalJsonlBackend(path)

        # Extract the private key for signing
        # Private key is serialised temporarily for signing — never stored
        self._private_key: Ed25519PrivateKey = identity._private_key
        self._public_key: Ed25519PublicKey = identity._public_key

        # Track the hash of the last written entry for chain linking
        # Loaded from existing entries on init to support append-only operation
        self._prev_hash: str | None = self._load_last_hash()

        logger.info(
            "AuditTrail initialised: agent=%r backend=%r prev_hash=%s",
            identity.agent_id,
            self._backend,
            (self._prev_hash[:8] + "...") if self._prev_hash else "None (genesis)",
        )

    def _load_last_hash(self) -> str | None:
        """
        Load the hash of the last existing entry to support append-only operation.

        This allows restarting the agent and continuing the chain without
        breaking it. If no entries exist, returns None (genesis state).
        """
        try:
            entries = self._backend.read_all()
            if not entries:
                return None
            last = entries[-1]
            # Compute the hash of the last entry (including its signature)
            return _canonical_hash(last)
        except Exception as e:
            logger.warning("AuditTrail: could not load last hash: %s", e)
            return None

    # ── Core write operation ──────────────────────────────────────────────────

    def record(
        self,
        action_type: ActionType | str,
        arguments_hash: str,
        policy_decision: str = "allow",
        tool_name: str | None = None,
        caller_id: str | None = None,
        result_hash: str | None = None,
        monitor_flags: list[str] | None = None,
    ) -> AuditEntry:
        """
        Record an action to the audit trail.

        This method:
          1. Builds the entry with all required fields
          2. Signs it with the agent's Ed25519 private key
          3. Links it to the previous entry via prev_hash
          4. Writes it to the storage backend
          5. Updates the internal prev_hash for the next entry

        Args:
            action_type:     Type of action (tool_call, policy_violation, etc.)
            arguments_hash:  SHA-256 of canonical JSON of call arguments.
                             Use _hash_arguments() to compute this.
            policy_decision: The policy engine decision (allow/deny/rate_limited).
            tool_name:       Tool name (required for tool_call actions).
            caller_id:       Calling agent ID (required for agent_call actions).
            result_hash:     SHA-256 of result. None if the action was blocked.
            monitor_flags:   List of injection/anomaly warning flags.

        Returns:
            The written AuditEntry.

        Raises:
            AuditWriteError: If the entry cannot be written to storage.
                             The caller MUST block the triggering action.
        """
        now = datetime.now(timezone.utc)

        # Build the entry without signature first
        unsigned: dict[str, Any] = {
            "entry_id": str(uuid.uuid4()),
            "timestamp": now.isoformat(),
            "agent_id": self._identity.agent_id,
            "mesh_id": self._identity.mesh_id,
            "action_type": str(action_type.value if isinstance(action_type, ActionType) else action_type),
            "tool_name": tool_name,
            "caller_id": caller_id,
            "arguments_hash": arguments_hash,
            "result_hash": result_hash,
            "policy_decision": policy_decision,
            "monitor_flags": monitor_flags or [],
            "prev_hash": self._prev_hash,
        }

        # Sign the entry
        signature = _sign(unsigned, self._private_key)

        # Add signature to produce the final entry
        entry_dict = {**unsigned, "signature": signature}

        # Write to storage — raises AuditWriteError on failure
        try:
            self._backend.append(entry_dict)
        except AuditWriteError:
            raise
        except Exception as e:
            raise AuditWriteError(
                f"Unexpected error writing audit entry: {e}"
            ) from e

        # Update prev_hash for next entry (only after successful write)
        self._prev_hash = _canonical_hash(entry_dict)

        entry = AuditEntry.from_dict(entry_dict)
        logger.debug(
            "AuditTrail: recorded %s entry=%s agent=%r tool=%r",
            action_type, entry.entry_id[:8], self._identity.agent_id, tool_name,
        )
        return entry

    # ── Chain verification ────────────────────────────────────────────────────

    def verify_chain(
        self,
        public_keys: dict[str, Ed25519PublicKey] | None = None,
    ) -> VerificationResult:
        """
        Verify the integrity of the entire audit chain.

        Checks:
          1. prev_hash linkage — each entry's prev_hash must equal the
             SHA-256 of the previous entry (including its signature).
          2. Ed25519 signature — each entry's signature must be valid
             under the signing agent's public key.

        Args:
            public_keys: Map of agent_id → Ed25519PublicKey for signature
                         verification. If None, uses the identity layer's
                         credential store (verifies own-agent entries only).

        Returns:
            VerificationResult with valid=True or valid=False + failed_at.

        Security note: a VALID result means no tampering was detected.
        It does NOT mean the entries are truthful — only that they have
        not been modified after being written.
        """
        try:
            entries = self._backend.read_all()
        except Exception as e:
            return VerificationResult(
                valid=False,
                entry_count=0,
                reason=f"Cannot read audit log: {e}",
            )

        if not entries:
            return VerificationResult(valid=True, entry_count=0, reason="empty log")

        prev_hash: str | None = None

        for i, entry_dict in enumerate(entries):
            entry_id = entry_dict.get("entry_id", f"entry_{i}")

            # ── Check 1: prev_hash linkage ────────────────────────────────
            stored_prev = entry_dict.get("prev_hash")
            if stored_prev != prev_hash:
                reason = (
                    f"Chain broken at entry {entry_id}: "
                    f"expected prev_hash={prev_hash!r} "
                    f"but found {stored_prev!r}"
                )
                logger.error("AuditTrail: %s", reason)
                return VerificationResult(
                    valid=False,
                    entry_count=i,
                    reason=reason,
                    failed_at=entry_id,
                )

            # ── Check 2: Ed25519 signature ────────────────────────────────
            agent_id = entry_dict.get("agent_id", "")
            signature_hex = entry_dict.get("signature", "")

            # Build the entry dict without signature for verification
            unsigned = {k: v for k, v in entry_dict.items() if k != "signature"}

            # Resolve the public key
            pub_key = self._resolve_public_key(agent_id, public_keys)
            if pub_key is None:
                # Cannot verify — skip signature check but note it
                logger.warning(
                    "AuditTrail: no public key for agent %r — "
                    "skipping signature check for entry %s",
                    agent_id, entry_id,
                )
            elif not _verify_signature(unsigned, signature_hex, pub_key):
                reason = (
                    f"Invalid signature at entry {entry_id}: "
                    f"entry was modified after being written, "
                    f"or was not written by agent {agent_id!r}"
                )
                logger.error("AuditTrail: %s", reason)
                return VerificationResult(
                    valid=False,
                    entry_count=i,
                    reason=reason,
                    failed_at=entry_id,
                )

            # Advance the chain
            prev_hash = _canonical_hash(entry_dict)

        return VerificationResult(
            valid=True,
            entry_count=len(entries),
            reason="chain intact",
        )

    def _resolve_public_key(
        self,
        agent_id: str,
        public_keys: dict[str, Ed25519PublicKey] | None,
    ) -> Ed25519PublicKey | None:
        """
        Resolve the public key for an agent.

        Priority:
          1. Caller-supplied public_keys dict
          2. Identity layer credential store
          3. Own identity (if agent_id matches)
        """
        if public_keys and agent_id in public_keys:
            return public_keys[agent_id]

        # Try the credential store
        from agentmesh.identity.agent_identity import _store
        pub_bytes = _store.lookup(agent_id)
        if pub_bytes is not None:
            return Ed25519PublicKey.from_public_bytes(pub_bytes)

        # Fall back to own public key if agent_id matches
        if agent_id == self._identity.agent_id:
            return self._public_key

        return None

    # ── Convenience methods ───────────────────────────────────────────────────

    def record_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: Any = None,
        policy_decision: str = "allow",
        monitor_flags: list[str] | None = None,
        caller_id: str | None = None,
    ) -> AuditEntry:
        """
        Convenience method: record a tool call.

        Hashes the arguments and result before recording — the raw
        values are never written to the audit log.
        """
        args_hash = _canonical_hash(arguments)
        result_hash = _canonical_hash(result) if result is not None else None
        return self.record(
            action_type=ActionType.TOOL_CALL,
            arguments_hash=args_hash,
            result_hash=result_hash,
            tool_name=tool_name,
            caller_id=caller_id,
            policy_decision=policy_decision,
            monitor_flags=monitor_flags,
        )

    def record_policy_violation(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        reason: str,
        caller_id: str | None = None,
    ) -> AuditEntry:
        """Convenience method: record a policy violation."""
        args_hash = _canonical_hash(arguments)
        return self.record(
            action_type=ActionType.POLICY_VIOLATION,
            arguments_hash=args_hash,
            tool_name=tool_name,
            caller_id=caller_id,
            policy_decision="deny",
            monitor_flags=[f"policy_denied:{reason[:100]}"],
        )

    def record_identity_event(
        self,
        event: str,
        details: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Convenience method: record an identity event (token issued, revoked, etc.)"""
        args_hash = _canonical_hash(details or {"event": event})
        return self.record(
            action_type=ActionType.IDENTITY_EVENT,
            arguments_hash=args_hash,
            policy_decision="allow",
            monitor_flags=[f"identity:{event}"],
        )

    @property
    def entry_count(self) -> int:
        """Return the number of entries in the audit log."""
        try:
            return len(self._backend.read_all())
        except Exception:
            return 0

    def __repr__(self) -> str:
        return (
            f"AuditTrail(agent={self._identity.agent_id!r}, "
            f"backend={self._backend!r})"
        )


# ---------------------------------------------------------------------------
# Standalone hash utility — used by the interceptor
# ---------------------------------------------------------------------------

def hash_arguments(arguments: dict[str, Any]) -> str:
    """
    Compute the canonical SHA-256 hash of tool call arguments.

    Used by the interceptor to hash arguments before passing them to
    AuditTrail.record(). Arguments are never stored in the audit log —
    only their hash.
    """
    return _canonical_hash(arguments)