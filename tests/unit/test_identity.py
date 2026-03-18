from __future__ import annotations

import uuid
import pytest
from datetime import datetime, timezone, timedelta

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from agentmesh.identity.agent_identity import AgentIdentity, _revocation_list, _store
from agentmesh.identity.credential_store import CredentialStore
from agentmesh.identity.exceptions import (
    AgentMeshError,
    IdentityError,
    TokenExpiredError,
    TokenRevokedError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_identity(**kwargs) -> AgentIdentity:
    return AgentIdentity(
        agent_id=kwargs.get("agent_id", "test-agent"),
        capabilities=kwargs.get("capabilities", ["web_search"]),
        mesh_id=kwargs.get("mesh_id", "test-mesh"),
        ttl_hours=kwargs.get("ttl_hours", 24),
    )


def forge_token(agent_id: str = "ghost-agent", hours: int = 1) -> str:
    """Create a token signed with a fresh unknown key — simulates an impostor."""
    fake_key = Ed25519PrivateKey.generate()
    fake_bytes = fake_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    payload = {
        "agent_id": agent_id,
        "capabilities": [],
        "mesh_id": "test",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=hours),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, fake_bytes, algorithm="EdDSA")


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

class TestExceptionHierarchy:
    def test_identity_error_is_agentmesh_error(self):
        assert issubclass(IdentityError, AgentMeshError)

    def test_token_expired_error_is_agentmesh_error(self):
        assert issubclass(TokenExpiredError, AgentMeshError)

    def test_token_revoked_error_is_agentmesh_error(self):
        assert issubclass(TokenRevokedError, AgentMeshError)

    def test_all_errors_are_exceptions(self):
        assert issubclass(AgentMeshError, Exception)


# ---------------------------------------------------------------------------
# CredentialStore unit tests
# ---------------------------------------------------------------------------

class TestCredentialStore:
    def setup_method(self):
        self.store = CredentialStore()
        self.valid_key = bytes(32)  # 32 zero bytes — valid length for Ed25519

    def test_register_and_lookup(self):
        self.store.register("agent-x", self.valid_key)
        assert self.store.lookup("agent-x") == self.valid_key

    def test_lookup_unknown_returns_none(self):
        assert self.store.lookup("nobody") is None

    def test_is_registered_true(self):
        self.store.register("agent-x", self.valid_key)
        assert self.store.is_registered("agent-x") is True

    def test_is_registered_false(self):
        assert self.store.is_registered("nobody") is False

    def test_deregister_removes_agent(self):
        self.store.register("agent-x", self.valid_key)
        self.store.deregister("agent-x")
        assert self.store.lookup("agent-x") is None

    def test_deregister_noop_if_not_registered(self):
        # Should not raise
        self.store.deregister("nobody")

    def test_registered_agents_list(self):
        self.store.register("a1", self.valid_key)
        self.store.register("a2", self.valid_key)
        agents = self.store.registered_agents()
        assert "a1" in agents
        assert "a2" in agents

    def test_len(self):
        assert len(self.store) == 0
        self.store.register("a1", self.valid_key)
        assert len(self.store) == 1

    def test_repr_contains_agent_id(self):
        self.store.register("my-agent", self.valid_key)
        assert "my-agent" in repr(self.store)

    def test_register_empty_agent_id_raises(self):
        with pytest.raises(IdentityError, match="agent_id must not be empty"):
            self.store.register("", self.valid_key)

    def test_register_wrong_key_length_raises(self):
        with pytest.raises(IdentityError, match="32 bytes"):
            self.store.register("agent-x", b"tooshort")

    def test_overwrite_existing_agent(self):
        key1 = bytes(32)
        key2 = bytes([1] * 32)
        self.store.register("agent-x", key1)
        self.store.register("agent-x", key2)
        assert self.store.lookup("agent-x") == key2


# ---------------------------------------------------------------------------
# AgentIdentity — issue and verify
# ---------------------------------------------------------------------------

class TestIssueAndVerify:
    def test_valid_token_passes(self):
        identity = make_identity()
        token = identity.issue_token()
        ctx = AgentIdentity.verify(token)
        assert ctx.agent_id == "test-agent"
        assert ctx.capabilities == ["web_search"]
        assert ctx.mesh_id == "test-mesh"

    def test_context_contains_correct_fields(self):
        identity = make_identity(agent_id="researcher", capabilities=["read_file", "web_search"])
        token = identity.issue_token()
        ctx = AgentIdentity.verify(token)
        assert ctx.agent_id == "researcher"
        assert "read_file" in ctx.capabilities
        assert "web_search" in ctx.capabilities
        assert ctx.jti != ""

    def test_agent_context_repr(self):
        identity = make_identity(agent_id="repr-agent")
        token = identity.issue_token()
        ctx = AgentIdentity.verify(token)
        assert "repr-agent" in repr(ctx)

    def test_multiple_tokens_from_same_identity_all_valid(self):
        identity = make_identity(agent_id="multi-token-agent")
        tokens = [identity.issue_token() for _ in range(5)]
        for token in tokens:
            ctx = AgentIdentity.verify(token)
            assert ctx.agent_id == "multi-token-agent"

    def test_unknown_agent_raises_identity_error(self):
        with pytest.raises(IdentityError, match="Unknown agent"):
            AgentIdentity.verify(forge_token("nonexistent-agent"))

    def test_tampered_signature_raises_identity_error(self):
        identity = make_identity(agent_id="tamper-test")
        token = identity.issue_token()
        parts = token.split(".")
        parts[2] = parts[2][:-4] + "XXXX"
        with pytest.raises(IdentityError):
            AgentIdentity.verify(".".join(parts))

    def test_malformed_token_raises_identity_error(self):
        with pytest.raises(IdentityError):
            AgentIdentity.verify("not.a.valid.jwt.at.all")

    def test_token_missing_agent_id_raises_identity_error(self):
        # Build a token with no agent_id claim using a registered agent's key
        identity = make_identity(agent_id="missing-claim-agent")
        private_bytes = identity._private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        payload = {
            "capabilities": ["web_search"],
            "mesh_id": "test",
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "jti": str(uuid.uuid4()),
        }
        token = jwt.encode(payload, private_bytes, algorithm="EdDSA")
        with pytest.raises(IdentityError, match="missing agent_id"):
            AgentIdentity.verify(token)

    def test_expired_token_raises_token_expired_error(self):
        identity = make_identity(agent_id="expired-agent", ttl_hours=0)
        # Issue token that expires immediately
        private_bytes = identity._private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        payload = {
            "agent_id": "expired-agent",
            "capabilities": [],
            "mesh_id": "test",
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) - timedelta(seconds=1),  # already expired
            "jti": str(uuid.uuid4()),
        }
        token = jwt.encode(payload, private_bytes, algorithm="EdDSA")
        with pytest.raises(TokenExpiredError):
            AgentIdentity.verify(token)

    def test_default_mesh_id(self):
        identity = AgentIdentity(agent_id="default-mesh-agent", capabilities=[])
        token = identity.issue_token()
        ctx = AgentIdentity.verify(token)
        assert ctx.mesh_id == "default"

    def test_empty_capabilities_allowed(self):
        identity = AgentIdentity(agent_id="no-cap-agent", capabilities=[])
        token = identity.issue_token()
        ctx = AgentIdentity.verify(token)
        assert ctx.capabilities == []


# ---------------------------------------------------------------------------
# AgentIdentity — revocation
# ---------------------------------------------------------------------------

class TestRevocation:
    def test_revoked_token_raises_token_revoked_error(self):
        identity = make_identity(agent_id="revoke-test")
        token = identity.issue_token()
        AgentIdentity.verify(token)  # passes first
        identity.revoke(token)
        with pytest.raises(TokenRevokedError):
            AgentIdentity.verify(token)

    def test_revoke_all_blocks_all_tokens(self):
        identity = make_identity(agent_id="revoke-all-test")
        token1 = identity.issue_token()
        token2 = identity.issue_token()
        identity.revoke_all()
        with pytest.raises(TokenRevokedError):
            AgentIdentity.verify(token1)
        with pytest.raises(TokenRevokedError):
            AgentIdentity.verify(token2)

    def test_different_token_still_valid_after_single_revocation(self):
        identity = make_identity(agent_id="partial-revoke-test")
        token1 = identity.issue_token()
        token2 = identity.issue_token()
        identity.revoke(token1)
        with pytest.raises(TokenRevokedError):
            AgentIdentity.verify(token1)
        ctx = AgentIdentity.verify(token2)
        assert ctx.agent_id == "partial-revoke-test"

    def test_revoke_garbage_token_does_not_raise(self):
        identity = make_identity(agent_id="revoke-garbage-test")
        # Should silently no-op, not crash
        identity.revoke("this.is.garbage")

    def test_revoke_adds_jti_to_global_revocation_list(self):
        identity = make_identity(agent_id="jti-list-test")
        token = identity.issue_token()
        decoded = jwt.decode(token, options={"verify_signature": False})
        jti = decoded["jti"]
        identity.revoke(token)
        assert jti in _revocation_list