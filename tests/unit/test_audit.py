from __future__ import annotations

"""
Audit Trail Test Suite — Week 6

Tests:
  - Entry schema correctness (all required fields present)
  - Hash chain integrity (each entry links to previous)
  - Ed25519 signature verification
  - Tamper detection: modify one entry → chain breaks
  - Tamper detection: delete one entry → chain breaks
  - Tamper detection: insert an entry → chain breaks
  - Storage backend: LocalJsonlBackend append + read
  - Convenience methods: record_tool_call, record_policy_violation
  - verify_chain() on empty, single, and multi-entry logs
  - Fail-secure: AuditWriteError propagated correctly
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from agentmesh.audit.trail import (
    AuditTrail,
    AuditEntry,
    ActionType,
    VerificationResult,
    _canonical_hash,
    _sign,
    _verify_signature,
    hash_arguments,
)
from agentmesh.audit.storage import LocalJsonlBackend
from agentmesh.audit.exceptions import AuditWriteError, ChainIntegrityError
from agentmesh.identity.agent_identity import AgentIdentity


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def identity():
    return AgentIdentity("audit-agent", ["web_search"], mesh_id="test-mesh")


@pytest.fixture
def tmp_audit_path(tmp_path):
    return tmp_path / "test-audit.jsonl"


@pytest.fixture
def trail(identity, tmp_audit_path):
    return AuditTrail(identity=identity, path=tmp_audit_path)


@pytest.fixture
def trail_with_entries(trail):
    """A trail with 5 recorded tool calls."""
    for i in range(5):
        trail.record_tool_call(
            tool_name="web_search",
            arguments={"query": f"query {i}"},
            result={"result": f"result {i}"},
            policy_decision="allow",
        )
    return trail


# ---------------------------------------------------------------------------
# Canonical hashing
# ---------------------------------------------------------------------------

class TestCanonicalHash:
    def test_same_dict_same_hash(self):
        d = {"b": 2, "a": 1}
        assert _canonical_hash(d) == _canonical_hash(d)

    def test_key_order_independent(self):
        d1 = {"a": 1, "b": 2}
        d2 = {"b": 2, "a": 1}
        assert _canonical_hash(d1) == _canonical_hash(d2)

    def test_different_values_different_hash(self):
        assert _canonical_hash({"a": 1}) != _canonical_hash({"a": 2})

    def test_hash_is_64_char_hex(self):
        h = _canonical_hash({"x": "test"})
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_empty_dict_has_stable_hash(self):
        h1 = _canonical_hash({})
        h2 = _canonical_hash({})
        assert h1 == h2

    def test_nested_dict_hashed(self):
        h = _canonical_hash({"a": {"b": {"c": 1}}})
        assert len(h) == 64


# ---------------------------------------------------------------------------
# Ed25519 signing
# ---------------------------------------------------------------------------

class TestSignAndVerify:
    def test_sign_and_verify_succeeds(self, identity):
        data = {"action": "tool_call", "agent": "test"}
        sig = _sign(data, identity._private_key)
        assert _verify_signature(data, sig, identity._public_key)

    def test_tampered_data_fails_verification(self, identity):
        data = {"action": "tool_call", "agent": "test"}
        sig = _sign(data, identity._private_key)
        tampered = {**data, "agent": "evil"}
        assert not _verify_signature(tampered, sig, identity._public_key)

    def test_wrong_key_fails_verification(self, identity):
        other = AgentIdentity("other-agent", [])
        data = {"x": 1}
        sig = _sign(data, identity._private_key)
        assert not _verify_signature(data, sig, other._public_key)

    def test_signature_is_hex_string(self, identity):
        sig = _sign({"x": 1}, identity._private_key)
        assert isinstance(sig, str)
        assert all(c in "0123456789abcdef" for c in sig)

    def test_invalid_hex_signature_fails_gracefully(self, identity):
        assert not _verify_signature({"x": 1}, "not_hex!!!", identity._public_key)


# ---------------------------------------------------------------------------
# AuditEntry schema
# ---------------------------------------------------------------------------

class TestAuditEntrySchema:
    def test_record_returns_audit_entry(self, trail):
        entry = trail.record_tool_call(
            tool_name="web_search",
            arguments={"query": "AI security"},
            result={"status": "ok"},
            policy_decision="allow",
        )
        assert isinstance(entry, AuditEntry)

    def test_entry_has_all_required_fields(self, trail):
        entry = trail.record_tool_call(
            tool_name="web_search",
            arguments={"query": "test"},
        )
        d = entry.to_dict()
        required = [
            "entry_id", "timestamp", "agent_id", "mesh_id",
            "action_type", "tool_name", "caller_id",
            "arguments_hash", "result_hash", "policy_decision",
            "monitor_flags", "prev_hash", "signature",
        ]
        for field in required:
            assert field in d, f"Missing required field: {field}"

    def test_entry_id_is_uuid(self, trail):
        import uuid
        entry = trail.record_tool_call(tool_name="t", arguments={})
        uuid.UUID(entry.entry_id)  # raises if not valid UUID

    def test_timestamp_is_iso_utc(self, trail):
        from datetime import datetime
        entry = trail.record_tool_call(tool_name="t", arguments={})
        dt = datetime.fromisoformat(entry.timestamp)
        assert dt.tzinfo is not None

    def test_agent_id_matches_identity(self, trail, identity):
        entry = trail.record_tool_call(tool_name="t", arguments={})
        assert entry.agent_id == identity.agent_id

    def test_mesh_id_matches_identity(self, trail, identity):
        entry = trail.record_tool_call(tool_name="t", arguments={})
        assert entry.mesh_id == identity.mesh_id

    def test_arguments_never_stored_only_hash(self, trail):
        secret_args = {"api_key": "super_secret_key_12345", "query": "test"}
        entry = trail.record_tool_call(tool_name="t", arguments=secret_args)
        d = entry.to_dict()
        # The raw arguments must NEVER appear in the entry
        entry_str = json.dumps(d)
        assert "super_secret_key_12345" not in entry_str
        assert len(entry.arguments_hash) == 64

    def test_result_none_when_blocked(self, trail):
        entry = trail.record(
            action_type=ActionType.POLICY_VIOLATION,
            arguments_hash="abc" * 21 + "d",
            policy_decision="deny",
            tool_name="dangerous_tool",
        )
        assert entry.result_hash is None

    def test_genesis_entry_has_null_prev_hash(self, trail):
        entry = trail.record_tool_call(tool_name="t", arguments={})
        assert entry.prev_hash is None

    def test_second_entry_links_to_first(self, trail):
        e1 = trail.record_tool_call(tool_name="t1", arguments={"a": 1})
        e2 = trail.record_tool_call(tool_name="t2", arguments={"b": 2})
        expected_prev = _canonical_hash(e1.to_dict())
        assert e2.prev_hash == expected_prev

    def test_from_dict_roundtrip(self, trail):
        entry = trail.record_tool_call(tool_name="t", arguments={"q": "test"})
        restored = AuditEntry.from_dict(entry.to_dict())
        assert restored.entry_id == entry.entry_id
        assert restored.arguments_hash == entry.arguments_hash
        assert restored.signature == entry.signature

    def test_repr_contains_agent_and_action(self, trail):
        entry = trail.record_tool_call(tool_name="web_search", arguments={})
        assert "audit-agent" in repr(entry) or "tool_call" in repr(entry)


# ---------------------------------------------------------------------------
# Chain integrity — valid chains
# ---------------------------------------------------------------------------

class TestChainIntegrityValid:
    def test_empty_log_is_valid(self, trail):
        result = trail.verify_chain()
        assert result.valid
        assert result.entry_count == 0

    def test_single_entry_chain_is_valid(self, trail):
        trail.record_tool_call(tool_name="t", arguments={})
        result = trail.verify_chain()
        assert result.valid
        assert result.entry_count == 1

    def test_five_entry_chain_is_valid(self, trail_with_entries):
        result = trail_with_entries.verify_chain()
        assert result.valid
        assert result.entry_count == 5

    def test_verification_result_repr_valid(self, trail_with_entries):
        result = trail_with_entries.verify_chain()
        assert "VALID" in repr(result)
        assert "5" in repr(result)

    def test_chain_intact_after_restart(self, identity, tmp_audit_path):
        """Simulates restarting the agent and continuing the chain."""
        trail1 = AuditTrail(identity=identity, path=tmp_audit_path)
        trail1.record_tool_call(tool_name="t1", arguments={"n": 1})
        trail1.record_tool_call(tool_name="t2", arguments={"n": 2})

        # Restart — new AuditTrail instance, same file
        trail2 = AuditTrail(identity=identity, path=tmp_audit_path)
        trail2.record_tool_call(tool_name="t3", arguments={"n": 3})

        result = trail2.verify_chain()
        assert result.valid
        assert result.entry_count == 3


# ---------------------------------------------------------------------------
# Tamper detection — the Bible explicitly requires these tests
# ---------------------------------------------------------------------------

class TestTamperDetection:
    def test_modify_entry_field_breaks_chain(self, trail_with_entries, tmp_audit_path):
        """
        THE critical test from the Bible:
        'Write tamper detection tests: modify one entry, verify chain breaks.'

        We modify the agent_id of entry 2 (index 1) and verify the chain
        reports a failure at that entry.
        """
        # Read raw entries
        entries = []
        with open(tmp_audit_path, "r") as f:
            for line in f:
                entries.append(json.loads(line.strip()))

        # Tamper with the second entry — change agent_id
        entries[1]["agent_id"] = "evil-agent"

        # Write tampered entries back
        with open(tmp_audit_path, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")

        result = trail_with_entries.verify_chain()
        assert not result.valid
        assert result.failed_at is not None
        assert "TAMPERED" in repr(result)

    def test_modify_arguments_hash_breaks_chain(self, trail_with_entries, tmp_audit_path):
        """Changing the arguments_hash invalidates the signature."""
        entries = []
        with open(tmp_audit_path, "r") as f:
            for line in f:
                entries.append(json.loads(line.strip()))

        # Tamper: change arguments_hash to suggest different arguments were used
        entries[0]["arguments_hash"] = "a" * 64

        with open(tmp_audit_path, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")

        result = trail_with_entries.verify_chain()
        assert not result.valid

    def test_delete_middle_entry_breaks_chain(self, trail_with_entries, tmp_audit_path):
        """Deleting entry 2 of 5 breaks the chain at entry 3."""
        entries = []
        with open(tmp_audit_path, "r") as f:
            for line in f:
                entries.append(json.loads(line.strip()))

        # Remove entry at index 1 (the second entry)
        del entries[1]

        with open(tmp_audit_path, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")

        result = trail_with_entries.verify_chain()
        assert not result.valid
        assert result.failed_at is not None

    def test_modify_signature_breaks_verification(self, trail_with_entries, tmp_audit_path):
        """Changing the signature field directly fails signature verification."""
        entries = []
        with open(tmp_audit_path, "r") as f:
            for line in f:
                entries.append(json.loads(line.strip()))

        # Forge the signature of the first entry
        entries[0]["signature"] = "00" * 64  # 64 zero bytes in hex

        with open(tmp_audit_path, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")

        result = trail_with_entries.verify_chain()
        assert not result.valid

    def test_insert_fake_entry_breaks_chain(self, trail_with_entries, tmp_audit_path):
        """
        Inserting a fake entry without a valid signature breaks the chain.
        An attacker cannot forge entries without the agent's private key.
        """
        entries = []
        with open(tmp_audit_path, "r") as f:
            for line in f:
                entries.append(json.loads(line.strip()))

        # Create a fake entry between entries 0 and 1
        fake = {
            "entry_id": "fake-entry-id",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "agent_id": "evil-agent",
            "mesh_id": "test-mesh",
            "action_type": "tool_call",
            "tool_name": "steal_data",
            "caller_id": None,
            "arguments_hash": "b" * 64,
            "result_hash": None,
            "policy_decision": "allow",
            "monitor_flags": [],
            "prev_hash": entries[0].get("prev_hash"),  # copy prev_hash from entry 0
            "signature": "ff" * 64,  # fake signature
        }
        entries.insert(1, fake)

        with open(tmp_audit_path, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")

        result = trail_with_entries.verify_chain()
        assert not result.valid

    def test_modify_prev_hash_breaks_chain(self, trail_with_entries, tmp_audit_path):
        """Changing prev_hash of any entry breaks the linkage."""
        entries = []
        with open(tmp_audit_path, "r") as f:
            for line in f:
                entries.append(json.loads(line.strip()))

        entries[2]["prev_hash"] = "c" * 64

        with open(tmp_audit_path, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")

        result = trail_with_entries.verify_chain()
        assert not result.valid
        assert result.failed_at == entries[2]["entry_id"]


# ---------------------------------------------------------------------------
# LocalJsonlBackend
# ---------------------------------------------------------------------------

class TestLocalJsonlBackend:
    def test_file_created_on_init(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        backend = LocalJsonlBackend(path)
        assert path.exists()

    def test_append_and_read_single_entry(self, tmp_path):
        backend = LocalJsonlBackend(tmp_path / "audit.jsonl")
        entry = {"entry_id": "abc", "data": "test"}
        backend.append(entry)
        entries = backend.read_all()
        assert len(entries) == 1
        assert entries[0]["entry_id"] == "abc"

    def test_append_multiple_entries_in_order(self, tmp_path):
        backend = LocalJsonlBackend(tmp_path / "audit.jsonl")
        for i in range(5):
            backend.append({"n": i})
        entries = backend.read_all()
        assert len(entries) == 5
        for i, e in enumerate(entries):
            assert e["n"] == i

    def test_read_empty_file_returns_empty_list(self, tmp_path):
        backend = LocalJsonlBackend(tmp_path / "audit.jsonl")
        assert backend.read_all() == []

    def test_repr_contains_path(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        backend = LocalJsonlBackend(path)
        assert str(path) in repr(backend)

    def test_write_error_raises_audit_write_error(self, tmp_path):
        backend = LocalJsonlBackend(tmp_path / "audit.jsonl")
        # Make file read-only so write fails
        (tmp_path / "audit.jsonl").chmod(0o444)
        with pytest.raises(AuditWriteError):
            backend.append({"x": 1})
        # Restore permissions for cleanup
        (tmp_path / "audit.jsonl").chmod(0o644)


# ---------------------------------------------------------------------------
# Convenience methods
# ---------------------------------------------------------------------------

class TestConvenienceMethods:
    def test_record_tool_call_sets_action_type(self, trail):
        entry = trail.record_tool_call(tool_name="web_search", arguments={"q": "test"})
        assert entry.action_type == ActionType.TOOL_CALL.value

    def test_record_tool_call_hashes_arguments(self, trail):
        args = {"api_key": "secret", "query": "test"}
        entry = trail.record_tool_call(tool_name="t", arguments=args)
        assert entry.arguments_hash == _canonical_hash(args)
        assert "secret" not in json.dumps(entry.to_dict())

    def test_record_tool_call_with_result(self, trail):
        result = {"status": "ok", "data": [1, 2, 3]}
        entry = trail.record_tool_call(tool_name="t", arguments={}, result=result)
        assert entry.result_hash == _canonical_hash(result)

    def test_record_tool_call_without_result(self, trail):
        entry = trail.record_tool_call(tool_name="t", arguments={})
        assert entry.result_hash is None

    def test_record_policy_violation(self, trail):
        entry = trail.record_policy_violation(
            tool_name="forbidden_tool",
            arguments={"q": "test"},
            reason="tool not in allowed_tools",
        )
        assert entry.action_type == ActionType.POLICY_VIOLATION.value
        assert entry.policy_decision == "deny"
        assert any("policy_denied" in f for f in entry.monitor_flags)

    def test_record_identity_event(self, trail):
        entry = trail.record_identity_event("token_issued", {"agent_id": "test"})
        assert entry.action_type == ActionType.IDENTITY_EVENT.value
        assert any("identity:" in f for f in entry.monitor_flags)

    def test_entry_count_property(self, trail):
        assert trail.entry_count == 0
        trail.record_tool_call(tool_name="t", arguments={})
        assert trail.entry_count == 1
        trail.record_tool_call(tool_name="t", arguments={})
        assert trail.entry_count == 2

    def test_repr_contains_agent_and_backend(self, trail):
        r = repr(trail)
        assert "audit-agent" in r


# ---------------------------------------------------------------------------
# hash_arguments utility
# ---------------------------------------------------------------------------

class TestHashArguments:
    def test_same_args_same_hash(self):
        args = {"query": "test", "limit": 10}
        assert hash_arguments(args) == hash_arguments(args)

    def test_different_args_different_hash(self):
        assert hash_arguments({"q": "a"}) != hash_arguments({"q": "b"})

    def test_result_is_64_char_hex(self):
        h = hash_arguments({"x": 1})
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_empty_args_stable(self):
        assert hash_arguments({}) == hash_arguments({})