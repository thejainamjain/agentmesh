from __future__ import annotations

import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AnomalyResult:
    """Result of anomaly detection for a single tool call."""
    anomalous: bool
    reason: str
    metric: str | None = None
    z_score: float | None = None

    @classmethod
    def normal(cls) -> "AnomalyResult":
        return cls(anomalous=False, reason="within normal baseline")

    @classmethod
    def flagged(cls, reason: str, metric: str, z_score: float) -> "AnomalyResult":
        return cls(anomalous=True, reason=reason, metric=metric, z_score=z_score)

    def __repr__(self) -> str:
        if self.anomalous:
            return f"AnomalyResult(ANOMALOUS: {self.reason} z={self.z_score:.2f})"
        return "AnomalyResult(NORMAL)"


# ---------------------------------------------------------------------------
# Rolling window statistics
# ---------------------------------------------------------------------------

class _RollingStats:
    """
    Maintains a rolling window of observations for a single metric.

    Uses Welford's online algorithm for numerically stable mean and variance.
    The window is time-based (sliding) not count-based.
    """

    def __init__(self, window_seconds: int = 300, min_samples: int = 10) -> None:
        self.window_seconds = window_seconds
        self.min_samples = min_samples
        self._observations: deque[tuple[float, float]] = deque()  # (timestamp, value)
        self._count = 0
        self._mean = 0.0
        self._m2 = 0.0  # sum of squared deviations (Welford)

    def record(self, value: float) -> None:
        """Record a new observation."""
        now = time.monotonic()
        self._evict(now)
        self._observations.append((now, value))
        # Welford online update
        self._count += 1
        delta = value - self._mean
        self._mean += delta / self._count
        delta2 = value - self._mean
        self._m2 += delta * delta2

    def _evict(self, now: float) -> None:
        """Remove observations older than the window."""
        cutoff = now - self.window_seconds
        while self._observations and self._observations[0][0] < cutoff:
            _, old_value = self._observations.popleft()
            # Welford downdate (remove old observation)
            if self._count > 1:
                self._count -= 1
                delta = old_value - self._mean
                self._mean -= delta / self._count
                delta2 = old_value - self._mean
                self._m2 -= delta * delta2
                self._m2 = max(0.0, self._m2)  # guard against float errors
            else:
                self._count = 0
                self._mean = 0.0
                self._m2 = 0.0

    @property
    def mean(self) -> float:
        return self._mean

    @property
    def std(self) -> float:
        if self._count < 2:
            return 0.0
        return math.sqrt(self._m2 / (self._count - 1))

    @property
    def count(self) -> int:
        return self._count

    def z_score(self, value: float) -> float | None:
        """
        Compute the Z-score of a value against the current rolling baseline.
        Returns None if there are not enough samples to compute a baseline.
        """
        if self._count < self.min_samples:
            return None
        s = self.std
        if s < 1e-9:
            return 0.0
        return (value - self._mean) / s


# ---------------------------------------------------------------------------
# AnomalyDetector
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """
    Detects statistically unusual tool call patterns per agent.

    Uses Z-score based anomaly detection against a rolling baseline.
    A call is flagged anomalous if any tracked metric deviates more than
    Z_THRESHOLD standard deviations from the rolling mean.

    Tracked metrics (v0.1):
      - Call frequency: calls per minute for each agent+tool pair
      - Argument length: character length of serialised arguments

    Planned metrics (v0.2):
      - Tool call sequence patterns
      - Time-of-day usage patterns
      - Argument entropy (detect high-entropy/encrypted payloads)

    Design note: the detector needs MIN_SAMPLES observations before it
    will flag anything. During the warm-up period all calls are allowed.
    This prevents false positives when an agent first starts up.
    """

    Z_THRESHOLD = 3.0       # Flag if metric is 3+ std deviations from mean
    WINDOW_SECONDS = 300    # 5-minute rolling window
    MIN_SAMPLES = 10        # Minimum observations before flagging

    def __init__(
        self,
        z_threshold: float = Z_THRESHOLD,
        window_seconds: int = WINDOW_SECONDS,
        min_samples: int = MIN_SAMPLES,
    ) -> None:
        self.z_threshold = z_threshold
        self.window_seconds = window_seconds
        self.min_samples = min_samples

        # Per-agent-tool call frequency tracking
        # Key: (agent_id, tool_name) → list of call timestamps
        self._call_times: dict[tuple[str, str], deque[float]] = defaultdict(deque)

        # Per-agent-tool argument length baseline
        # Key: (agent_id, tool_name) → _RollingStats
        self._arg_length_stats: dict[tuple[str, str], _RollingStats] = defaultdict(
            lambda: _RollingStats(self.window_seconds, self.min_samples)
        )

        # Per-agent-tool call frequency baseline (calls per minute)
        self._freq_stats: dict[tuple[str, str], _RollingStats] = defaultdict(
            lambda: _RollingStats(self.window_seconds, self.min_samples)
        )

    def record_and_check(
        self,
        agent_id: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> AnomalyResult:
        """
        Record a tool call and check it against the rolling baseline.

        Args:
            agent_id:  The agent making the call.
            tool_name: The tool being called.
            arguments: The tool arguments (used to measure argument length).

        Returns:
            AnomalyResult with anomalous=False (normal) or True (flagged).
        """
        key = (agent_id, tool_name)
        now = time.monotonic()

        # ── Metric 1: Argument length ─────────────────────────────────────────
        arg_length = len(str(arguments))
        length_stats = self._arg_length_stats[key]
        length_z = length_stats.z_score(arg_length)
        length_stats.record(arg_length)  # record after checking

        if length_z is not None and length_z > self.z_threshold:
            reason = (
                f"Argument length anomaly for agent={agent_id!r} tool={tool_name!r}: "
                f"length={arg_length} is {length_z:.1f} std deviations above baseline "
                f"(mean={length_stats.mean:.0f} std={length_stats.std:.0f})"
            )
            logger.warning("AnomalyDetector: %s", reason)
            return AnomalyResult.flagged(reason, "arg_length", length_z)

        # ── Metric 2: Call frequency ──────────────────────────────────────────
        timestamps = self._call_times[key]
        timestamps.append(now)

        # Evict old timestamps outside the window
        cutoff = now - 60.0  # calls per minute
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

        calls_per_minute = len(timestamps)
        freq_stats = self._freq_stats[key]
        freq_z = freq_stats.z_score(float(calls_per_minute))
        freq_stats.record(float(calls_per_minute))

        if freq_z is not None and freq_z > self.z_threshold:
            reason = (
                f"Call frequency anomaly for agent={agent_id!r} tool={tool_name!r}: "
                f"{calls_per_minute} calls/min is {freq_z:.1f} std deviations above "
                f"baseline (mean={freq_stats.mean:.1f} std={freq_stats.std:.1f})"
            )
            logger.warning("AnomalyDetector: %s", reason)
            return AnomalyResult.flagged(reason, "call_frequency", freq_z)

        return AnomalyResult.normal()

    def baseline_size(self, agent_id: str, tool_name: str) -> int:
        """Return the number of observations in the current baseline."""
        return self._arg_length_stats[(agent_id, tool_name)].count

    def is_warmed_up(self, agent_id: str, tool_name: str) -> bool:
        """Return True if the detector has enough data to flag anomalies."""
        return self.baseline_size(agent_id, tool_name) >= self.min_samples