from __future__ import annotations

import base64
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def numeric(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    def __ge__(self, other: "Severity") -> bool:
        return self.numeric() >= other.numeric()

    def __gt__(self, other: "Severity") -> bool:
        return self.numeric() > other.numeric()


@dataclass(frozen=True)
class PatternMatch:
    """A single pattern that fired during inspection."""
    pattern_id: str
    severity: Severity
    category: str
    description: str
    matched_text: str
    argument_key: str


@dataclass
class InspectionResult:
    """
    The result of inspecting tool call arguments for injection.

    safe=False means the interceptor must block the call.
    safe=True with flags means warn but allow.
    """
    safe: bool
    severity: Severity | None
    reason: str
    matches: list[PatternMatch] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)

    @classmethod
    def clean(cls) -> "InspectionResult":
        return cls(safe=True, severity=None, reason="no injection patterns detected")

    @classmethod
    def blocked(cls, reason: str, matches: list[PatternMatch]) -> "InspectionResult":
        worst = max(m.severity for m in matches) if matches else Severity.HIGH
        flags = [f"{m.pattern_id}:{m.severity.value}" for m in matches]
        return cls(safe=False, severity=worst, reason=reason, matches=matches, flags=flags)

    @classmethod
    def warned(cls, reason: str, matches: list[PatternMatch]) -> "InspectionResult":
        worst = max(m.severity for m in matches) if matches else Severity.LOW
        flags = [f"{m.pattern_id}:{m.severity.value}" for m in matches]
        return cls(safe=True, severity=worst, reason=reason, matches=matches, flags=flags)

    def __repr__(self) -> str:
        status = "BLOCKED" if not self.safe else "WARNED" if self.matches else "CLEAN"
        return f"InspectionResult({status}: {self.reason})"


# ---------------------------------------------------------------------------
# Compiled pattern entry
# ---------------------------------------------------------------------------

@dataclass
class _CompiledPattern:
    pattern_id: str
    regex: re.Pattern
    severity: Severity
    category: str
    description: str


# ---------------------------------------------------------------------------
# InjectionDetector
# ---------------------------------------------------------------------------

class InjectionDetector:
    """
    Scans tool call arguments for prompt injection patterns.

    Detection method: multi-layer pattern matching with severity scoring.
    We deliberately do NOT use an LLM classifier because:
      1. It would be too slow on the hot path (every tool call)
      2. It creates a recursive trust problem (using AI to protect AI)
      3. Pattern matching is auditable, explainable, and community-contributable

    Blocking rules:
      - Any single CRITICAL match → block immediately
      - Any single HIGH match → block immediately
      - Two or more matches of any severity → block
      - One MEDIUM match alone → warn + log, allow
      - One LOW match alone → log only, allow

    Additionally performs:
      - Base64 decode + re-scan (catches encoded payloads)
      - Typo-tolerance scan (catches typoglycemia attacks)
      - Recursive JSON/nested string scanning
    """

    _DEFAULT_PATTERNS_PATH = (
        Path(__file__).parent / "patterns" / "injection_patterns.yaml"
    )

    def __init__(
        self,
        patterns_path: str | Path | None = None,
        extra_patterns: list[dict] | None = None,
    ) -> None:
        """
        Initialise the detector, loading patterns from YAML.

        Args:
            patterns_path: Path to a custom patterns YAML file.
                           Defaults to the built-in injection_patterns.yaml.
            extra_patterns: Additional pattern dicts to merge in at runtime.
                            Useful for testing and custom deployments.
        """
        path = Path(patterns_path) if patterns_path else self._DEFAULT_PATTERNS_PATH
        self._patterns: list[_CompiledPattern] = []
        self._load_patterns(path)

        if extra_patterns:
            for p in extra_patterns:
                self._compile_and_add(p)

        logger.info(
            "InjectionDetector loaded %d patterns from %s",
            len(self._patterns), path,
        )

    def _load_patterns(self, path: Path) -> None:
        if not path.exists():
            logger.warning(
                "Injection patterns file not found at %s — "
                "running with zero patterns (unsafe for production)",
                path,
            )
            return
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        for p in raw.get("patterns", []):
            self._compile_and_add(p)

    def _compile_and_add(self, p: dict) -> None:
        try:
            compiled = _CompiledPattern(
                pattern_id=p["id"],
                regex=re.compile(p["pattern"], re.IGNORECASE | re.DOTALL),
                severity=Severity(p["severity"]),
                category=p["category"],
                description=p["description"],
            )
            self._patterns.append(compiled)
        except Exception as e:
            logger.error("Failed to compile pattern %r: %s", p.get("id"), e)

    # ── Public API ────────────────────────────────────────────────────────────

    def inspect(self, arguments: dict[str, Any]) -> InspectionResult:
        """
        Inspect tool call arguments for injection patterns.

        Scans all string values in the arguments dict, including:
          - Direct string values
          - Nested dicts and lists (recursive)
          - Base64-decoded versions of strings (catches encoded attacks)
          - Typo-tolerant versions (catches typoglycemia attacks)

        Args:
            arguments: The tool call arguments dict from the interceptor.

        Returns:
            InspectionResult with safe=True (allow) or safe=False (block).
        """
        all_matches: list[PatternMatch] = []

        for key, value in arguments.items():
            strings_to_scan = self._extract_strings(value)
            for text in strings_to_scan:
                matches = self._scan_text(text, arg_key=key)
                all_matches.extend(matches)

                # Layer 2: base64 decode + re-scan
                decoded = self._try_base64_decode(text)
                if decoded:
                    base64_matches = self._scan_text(decoded, arg_key=f"{key}[base64]")
                    all_matches.extend(base64_matches)

                # Layer 3: typo-tolerance scan
                normalised = self._normalise_typos(text)
                if normalised != text.lower():
                    typo_matches = self._scan_text(normalised, arg_key=f"{key}[typo]")
                    all_matches.extend(typo_matches)

        return self._score(all_matches)

    # ── Internal scanning ─────────────────────────────────────────────────────

    def _extract_strings(self, value: Any, depth: int = 0) -> list[str]:
        """Recursively extract all string values from nested structures."""
        if depth > 5:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            result = []
            for v in value.values():
                result.extend(self._extract_strings(v, depth + 1))
            return result
        if isinstance(value, (list, tuple)):
            result = []
            for item in value:
                result.extend(self._extract_strings(item, depth + 1))
            return result
        return []

    def _scan_text(self, text: str, arg_key: str) -> list[PatternMatch]:
        """Scan a single string against all compiled patterns."""
        matches = []
        for pattern in self._patterns:
            m = pattern.regex.search(text)
            if m:
                matches.append(PatternMatch(
                    pattern_id=pattern.pattern_id,
                    severity=pattern.severity,
                    category=pattern.category,
                    description=pattern.description,
                    matched_text=m.group(0)[:200],  # cap length for safety
                    argument_key=arg_key,
                ))
        return matches

    def _try_base64_decode(self, text: str) -> str | None:
        """
        Try to find and base64-decode substrings within text.

        Scans for base64-like substrings (20+ chars from the base64 alphabet)
        and attempts to decode each one. Returns the decoded content of the
        first successful decode, or None if no valid base64 found.

        This catches payloads like:
          "decode this: aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw=="
        where the base64 is embedded in a larger string.
        """
        if len(text) < 20:
            return None

        # First try the whole string (most common case)
        stripped = text.strip()
        try:
            padded = stripped + "=" * (-len(stripped) % 4)
            decoded = base64.b64decode(padded, validate=True).decode("utf-8")
            if len(decoded) >= 10:
                return decoded
        except Exception:
            pass

        # Then scan for base64 substrings embedded in larger text
        import re as _re
        b64_candidates = _re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
        for candidate in b64_candidates:
            try:
                padded = candidate + "=" * (-len(candidate) % 4)
                decoded = base64.b64decode(padded, validate=True).decode("utf-8")
                if len(decoded) >= 10:
                    return decoded
            except Exception:
                continue
        return None

    def _normalise_typos(self, text: str) -> str:
        """
        Normalise common typoglycemia patterns.

        Typoglycemia attacks scramble the middle letters of words
        (e.g. 'ignroe' instead of 'ignore') to bypass keyword matching.
        We normalise by sorting the middle characters of each word,
        which makes scrambled words match their sorted equivalents.

        This is a best-effort heuristic — it does not decode all possible
        scrambles but catches the most common variants seen in the wild.
        """
        words = text.lower().split()
        normalised = []
        for word in words:
            # Strip punctuation for matching
            clean = re.sub(r"[^a-z]", "", word)
            if len(clean) > 3:
                # Sort middle characters — makes 'ignroe' → 'iegonr' same as 'iegnor'
                middle_sorted = clean[0] + "".join(sorted(clean[1:-1])) + clean[-1]
                normalised.append(middle_sorted)
            else:
                normalised.append(clean)
        return " ".join(normalised)

    def _score(self, matches: list[PatternMatch]) -> InspectionResult:
        """
        Apply the severity scoring rules to a list of matches.

        Rules (in order):
          1. Any CRITICAL match → block immediately
          2. Any HIGH match → block immediately
          3. Two or more matches of any severity → block
          4. One MEDIUM match → warn, allow
          5. One LOW match → log only, allow
          6. No matches → clean
        """
        if not matches:
            return InspectionResult.clean()

        # Deduplicate by pattern_id (same pattern on multiple args = one match)
        seen_ids: set[str] = set()
        unique_matches = []
        for m in matches:
            if m.pattern_id not in seen_ids:
                seen_ids.add(m.pattern_id)
                unique_matches.append(m)

        # Rule 1 & 2: any critical or high = immediate block
        critical_or_high = [
            m for m in unique_matches
            if m.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        if critical_or_high:
            worst = max(m.severity for m in critical_or_high)
            reason = (
                f"Injection pattern detected [{worst.value.upper()}]: "
                f"{critical_or_high[0].pattern_id} "
                f"in argument '{critical_or_high[0].argument_key}'"
            )
            logger.warning(
                "InjectionDetector BLOCKED: %s (pattern=%s category=%s)",
                reason, critical_or_high[0].pattern_id, critical_or_high[0].category,
            )
            return InspectionResult.blocked(reason, unique_matches)

        # Rule 3: two or more matches of any severity = block
        if len(unique_matches) >= 2:
            reason = (
                f"Multiple injection patterns detected: "
                f"{', '.join(m.pattern_id for m in unique_matches[:3])}"
            )
            logger.warning("InjectionDetector BLOCKED (multi-match): %s", reason)
            return InspectionResult.blocked(reason, unique_matches)

        # Rule 4: one medium = warn
        if unique_matches[0].severity == Severity.MEDIUM:
            reason = (
                f"Suspicious pattern detected [{Severity.MEDIUM.value.upper()}]: "
                f"{unique_matches[0].pattern_id} "
                f"in argument '{unique_matches[0].argument_key}'"
            )
            logger.warning("InjectionDetector WARN: %s", reason)
            return InspectionResult.warned(reason, unique_matches)

        # Rule 5: one low = log only
        reason = (
            f"Low-confidence pattern: {unique_matches[0].pattern_id}"
        )
        logger.info("InjectionDetector INFO: %s", reason)
        return InspectionResult.warned(reason, unique_matches)

    @property
    def pattern_count(self) -> int:
        return len(self._patterns)