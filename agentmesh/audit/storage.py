from __future__ import annotations

"""
Audit storage backends.

v0.1 ships with LocalJsonlBackend only.
v0.2 will add PostgresBackend and S3Backend.

All backends implement AuditBackend — callers never depend on a
specific backend, so swapping backends requires zero application changes.
"""

import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from agentmesh.audit.exceptions import AuditWriteError

logger = logging.getLogger(__name__)


class AuditBackend(ABC):
    """
    Abstract interface for audit trail storage.

    Every backend must implement append() and read_all().
    The AuditTrail class uses only these two methods.

    To implement a new backend (PostgreSQL, S3, etc.):
      1. Subclass AuditBackend
      2. Implement append() and read_all()
      3. Pass an instance to AuditTrail.__init__()

    No other changes are needed anywhere in the codebase.
    """

    @abstractmethod
    def append(self, entry: dict[str, Any]) -> None:
        """
        Persist a single audit entry.

        Args:
            entry: The fully-formed audit entry dict (already signed).

        Raises:
            AuditWriteError: If the entry cannot be persisted.
                             The caller must block the triggering action.
        """

    @abstractmethod
    def read_all(self) -> list[dict[str, Any]]:
        """
        Read all audit entries in insertion order.

        Returns:
            List of entry dicts, oldest first.

        Raises:
            AuditWriteError: If the storage cannot be read.
        """


class LocalJsonlBackend(AuditBackend):
    """
    Local newline-delimited JSON (JSONL) file backend.

    Each line in the file is one complete audit entry serialised as JSON.
    This format is:
      - Human-readable with any text editor or `jq`
      - Appendable without reading the full file
      - Streamable for large audit logs
      - Compatible with log aggregation tools (Splunk, Datadog, etc.)

    File location: configured at construction time.
    Default: ./agentmesh-audit.jsonl

    Security notes:
      - File is opened in append mode — existing entries are never
        overwritten by the writer. Deletion is still possible at the OS
        level, which is why the hash chain exists.
      - File permissions should be set to 0o600 (owner read/write only)
        in production. We set this on creation.
      - The file must be kept outside agent-writable paths.
    """

    def __init__(self, path: str | Path = "agentmesh-audit.jsonl") -> None:
        self.path = Path(path)
        self._ensure_file()
        logger.info("AuditTrail: LocalJsonlBackend initialised at %s", self.path)

    def _ensure_file(self) -> None:
        """Create the file if it doesn't exist, with secure permissions."""
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.touch(mode=0o600)
            logger.info("AuditTrail: created new audit log at %s", self.path)

    def append(self, entry: dict[str, Any]) -> None:
        """Append one entry as a JSON line. Atomic at the OS write level."""
        try:
            line = json.dumps(entry, separators=(",", ":"), sort_keys=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()  # ensure write reaches OS buffer
        except OSError as e:
            raise AuditWriteError(
                f"Failed to write audit entry to {self.path}: {e}. "
                f"The triggering tool call has been blocked."
            ) from e

    def read_all(self) -> list[dict[str, Any]]:
        """Read all entries from the JSONL file, oldest first."""
        if not self.path.exists():
            return []
        entries = []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        raise AuditWriteError(
                            f"Corrupt entry at line {line_num} in {self.path}: {e}"
                        ) from e
        except OSError as e:
            raise AuditWriteError(
                f"Cannot read audit log {self.path}: {e}"
            ) from e
        return entries

    def __repr__(self) -> str:
        return f"LocalJsonlBackend(path={self.path})"