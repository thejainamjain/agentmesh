from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

from agentmesh.identity.credential_store import CredentialStore
from agentmesh.identity.exceptions import (
    IdentityError,
    TokenExpiredError,
    TokenRevokedError,
)


# Module-level shared store and revocation list
_store = CredentialStore()
_revocation_list: set[str] = set()

# Expose _credential_store as a dict-like alias for test compatibility
_credential_store = _store._keys


class AgentContext:
    """Holds verified agent identity after successful token verification."""

    def __init__(self, agent_id: str, capabilities: list[str], mesh_id: str, jti: str) -> None:
        self.agent_id = agent_id
        self.capabilities = capabilities
        self.mesh_id = mesh_id
        self.jti = jti

    def __repr__(self) -> str:
        return f"AgentContext(agent_id={self.agent_id!r}, capabilities={self.capabilities})"


class AgentIdentity:
    """
    Manages cryptographic identity for an AgentMesh agent.

    Generates an Ed25519 keypair on initialization, issues signed JWTs,
    and provides class-level token verification.
    """

    def __init__(
        self,
        agent_id: str,
        capabilities: list[str],
        mesh_id: str = "default",
        ttl_hours: int = 24,
    ) -> None:
        self.agent_id = agent_id
        self.capabilities = capabilities
        self.mesh_id = mesh_id
        self.ttl_hours = ttl_hours

        # Generate Ed25519 keypair — private key stays in memory only
        self._private_key: Ed25519PrivateKey = Ed25519PrivateKey.generate()
        self._public_key: Ed25519PublicKey = self._private_key.public_key()

        # Register public key in credential store
        pub_bytes = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        _store.register(agent_id, pub_bytes)

        # Track issued tokens for revocation
        self._issued_jtis: set[str] = set()

    def issue_token(self) -> str:
        """Issue a signed JWT for this agent."""
        now = datetime.now(timezone.utc)
        jti = str(uuid.uuid4())
        self._issued_jtis.add(jti)

        payload = {
            "agent_id": self.agent_id,
            "capabilities": self.capabilities,
            "mesh_id": self.mesh_id,
            "iat": now,
            "exp": now + timedelta(hours=self.ttl_hours),
            "jti": jti,
        }

        private_bytes = self._private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        token: str = jwt.encode(payload, private_bytes, algorithm="EdDSA")
        return token

    def revoke(self, token: str) -> None:
        """Add a token's jti to the revocation list."""
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            jti = unverified.get("jti")
            if jti:
                _revocation_list.add(jti)
        except Exception:
            pass

    def revoke_all(self) -> None:
        """Revoke all tokens issued by this identity — called on shutdown."""
        for jti in self._issued_jtis:
            _revocation_list.add(jti)

    @classmethod
    def verify(cls, token: str) -> AgentContext:
        """
        Verify a JWT token and return the agent context.

        Raises:
            IdentityError: If signature is invalid or agent is unregistered.
            TokenExpiredError: If token has expired.
            TokenRevokedError: If token jti is on the revocation list.
        """
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.DecodeError as e:
            raise IdentityError(f"Malformed token: {e}") from e

        agent_id = unverified.get("agent_id")
        if not agent_id:
            raise IdentityError("Token missing agent_id claim")

        pub_bytes = _store.lookup(agent_id)
        if pub_bytes is None:
            raise IdentityError(f"Unknown agent: {agent_id!r} — not registered in credential store")

        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        try:
            payload = jwt.decode(token, pub_pem, algorithms=["EdDSA"])
        except jwt.ExpiredSignatureError as e:
            raise TokenExpiredError(f"Token expired for agent {agent_id!r}") from e
        except jwt.InvalidSignatureError as e:
            raise IdentityError(f"Invalid signature for agent {agent_id!r}") from e
        except jwt.PyJWTError as e:
            raise IdentityError(f"Token verification failed: {e}") from e

        jti = payload.get("jti", "")
        if jti in _revocation_list:
            raise TokenRevokedError(f"Token {jti!r} has been revoked")

        return AgentContext(
            agent_id=payload["agent_id"],
            capabilities=payload.get("capabilities", []),
            mesh_id=payload.get("mesh_id", "default"),
            jti=jti,
        )