from __future__ import annotations

from agentmesh.identity.exceptions import IdentityError


class CredentialStore:
    """
    In-memory store mapping agent_id → raw Ed25519 public key bytes.

    This is the single source of truth for registered agent public keys.
    On agent init, the public key is registered here.
    On verify, the public key is looked up here.

    Thread safety: not thread-safe in v0.1 (single-process, single-thread assumed).
    A Redis-backed implementation is planned for v0.3 multi-process deployments.
    """

    def __init__(self) -> None:
        # Maps agent_id (str) → raw public key bytes (32 bytes for Ed25519)
        self._keys: dict[str, bytes] = {}

    def register(self, agent_id: str, public_key_bytes: bytes) -> None:
        """
        Register an agent's public key.

        Args:
            agent_id: Unique identifier for the agent.
            public_key_bytes: Raw Ed25519 public key (32 bytes).

        Raises:
            IdentityError: If agent_id is empty or public_key_bytes is not 32 bytes.
        """
        if not agent_id:
            raise IdentityError("agent_id must not be empty")
        if len(public_key_bytes) != 32:
            raise IdentityError(
                f"Ed25519 public key must be 32 bytes, got {len(public_key_bytes)}"
            )
        self._keys[agent_id] = public_key_bytes

    def lookup(self, agent_id: str) -> bytes | None:
        """
        Look up the public key for an agent.

        Args:
            agent_id: The agent to look up.

        Returns:
            Raw public key bytes, or None if the agent is not registered.
        """
        return self._keys.get(agent_id)

    def deregister(self, agent_id: str) -> None:
        """
        Remove an agent from the credential store (called on graceful shutdown).

        Args:
            agent_id: The agent to remove. No-op if not registered.
        """
        self._keys.pop(agent_id, None)

    def is_registered(self, agent_id: str) -> bool:
        """Return True if the agent has a registered public key."""
        return agent_id in self._keys

    def registered_agents(self) -> list[str]:
        """Return a list of all registered agent IDs."""
        return list(self._keys.keys())

    def __len__(self) -> int:
        return len(self._keys)

    def __repr__(self) -> str:
        return f"CredentialStore(agents={self.registered_agents()})"