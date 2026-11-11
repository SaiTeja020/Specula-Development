"""
Log Analysis Agent — Statistical Anomaly Detector.

Implements per-key frequency baseline and z-score computation per
resolved-decisions items #11/#12.

Key design points:
  - Baseline key: (host_id, event_class_uid, hour_bucket)
    → counts occurrences of a given event type per host per UTC hour.
  - Returns None (not 0.0) before ANOMALY_BASELINE_MIN_EVENTS are
    observed for a key. Callers MUST treat None as "no signal yet",
    never as "z=0" (plan §4a, item #12 explicit requirement).
  - Exposed as a standalone callable tool so the LLM orchestrator can
    invoke detect_anomaly() directly (plan §4a).
  - The baseline dict is intentionally kept in-process for simplicity.
    Production wiring to Redis/external store is a separate concern
    handled by agent.py.

IMPORTANT: This module is stateful (baseline dict mutates on each call
to update_baseline). Tests must create a fresh BaselineStore per test
to avoid cross-test contamination.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.agents.log_analysis import config
from src.schemas.ocsf_base import OCSFBaseEvent

logger = logging.getLogger(__name__)


# ─── Baseline data structure ──────────────────────────────────────────────────


@dataclass
class _KeyStats:
    """Running statistics for a single (host, event_type, hour) key."""
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0   # Welford's online variance accumulator

    @property
    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.m2 / (self.count - 1)

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)


class BaselineStore:
    """
    In-process baseline store.

    Maintains Welford online mean/variance per (host_id, class_uid, hour_bucket)
    key. Thread-safety is NOT guaranteed — wrap with a lock if shared across
    threads.
    """

    def __init__(self) -> None:
        # key → _KeyStats
        self._stats: dict[tuple, _KeyStats] = defaultdict(_KeyStats)
        # key → total events seen (for warm-up threshold check)
        self._event_counts: dict[tuple, int] = defaultdict(int)

    def _make_key(self, event: OCSFBaseEvent) -> tuple:
        """
        Build the baseline key from an event.
        Falls back to "unknown_host" / 0 for missing fields.
        """
        host_id: str = (
            getattr(event, "canonical_host_id", None)
            or getattr(event, "host_name", None)
            or "unknown_host"
        )
        class_uid: int = getattr(event, "class_uid", 0)

        event_time: datetime | None = getattr(event, "time", None)
        if event_time is None:
            hour_bucket = "unknown_hour"
        else:
            if event_time.tzinfo is None:
                event_time = event_time.replace(tzinfo=timezone.utc)
            hour_bucket = event_time.strftime("%Y-%m-%dT%H")

        return (host_id, class_uid, hour_bucket)

    def update(self, event: OCSFBaseEvent, observation: float = 1.0) -> None:
        """
        Add an observation (default: 1.0 = one event occurrence) to the
        baseline for the event's key using Welford's online algorithm.
        """
        key = self._make_key(event)
        stats = self._stats[key]
        self._event_counts[key] += 1

        # Welford online update.
        stats.count += 1
        delta = observation - stats.mean
        stats.mean += delta / stats.count
        delta2 = observation - stats.mean
        stats.m2 += delta * delta2

    def is_warm(self, event: OCSFBaseEvent) -> bool:
        """Return True only if we have >= ANOMALY_BASELINE_MIN_EVENTS for this key."""
        key = self._make_key(event)
        return self._event_counts[key] >= config.ANOMALY_BASELINE_MIN_EVENTS

    def zscore(self, event: OCSFBaseEvent, observation: float = 1.0) -> float | None:
        """
        Compute z-score for the given observation against the stored baseline.

        Returns:
            float: z-score if baseline is warm.
            None:  if baseline is not yet warm (< ANOMALY_BASELINE_MIN_EVENTS).

        Callers must treat None as "no signal yet", NOT as z=0.
        """
        key = self._make_key(event)
        if not self.is_warm(event):
            return None

        stats = self._stats[key]
        if stats.std == 0.0:
            # Zero variance: every prior observation was identical. Any
            # deviation is infinitely anomalous; return a capped sentinel.
            return 0.0 if observation == stats.mean else float("inf")

        return (observation - stats.mean) / stats.std


# ─── Public tool functions ────────────────────────────────────────────────────


def compute_zscore(
    baseline_store: BaselineStore,
    event: OCSFBaseEvent,
    observation: float = 1.0,
) -> float | None:
    """
    Compute the z-score for `observation` against the stored baseline for
    this event's (host, class_uid, hour) key.

    This is the standalone callable tool exposed to the LLM orchestrator
    (plan §4a — detect_anomaly). Agent.py calls update_baseline() first,
    then this function.

    Returns:
        float | None — None means baseline is not yet warm. Callers MUST
        NOT treat None as z=0.
    """
    return baseline_store.zscore(event, observation)


def update_baseline(
    baseline_store: BaselineStore,
    event: OCSFBaseEvent,
    observation: float = 1.0,
) -> None:
    """
    Update the baseline with a new observation. Call this on every event
    processed (including non-suspicious ones) to keep the baseline current.
    """
    baseline_store.update(event, observation)


def detect_anomaly(
    baseline_store: BaselineStore,
    event: OCSFBaseEvent,
    observation: float = 1.0,
    threshold: float | None = None,
) -> dict[str, Any] | None:
    """
    High-level anomaly detection tool callable by the LLM orchestrator.

    Updates the baseline, then returns an anomaly signal dict if the
    z-score exceeds the threshold, or None if no anomaly is detected.

    Args:
        baseline_store: The in-process BaselineStore for this agent instance.
        event:          The OCSF event to evaluate.
        observation:    The numeric value to test (default 1.0 = event count).
        threshold:      Z-score threshold; defaults to config.ANOMALY_Z_SCORE_THRESHOLD.

    Returns:
        dict: {"pattern": "anomalous_frequency", "weight": float, "detail": str,
               "zscore": float}
        None: baseline not warm, or z-score below threshold.
    """
    threshold = threshold if threshold is not None else config.ANOMALY_Z_SCORE_THRESHOLD

    # Update baseline BEFORE computing z-score (this event is part of history).
    update_baseline(baseline_store, event, observation)

    z = compute_zscore(baseline_store, event, observation)

    if z is None:
        # Baseline not yet warm — no signal.
        return None

    if abs(z) <= threshold:
        return None

    host_id: str = (
        getattr(event, "canonical_host_id", None)
        or getattr(event, "host_name", None)
        or "unknown_host"
    )

    return {
        "pattern": "anomalous_frequency",
        "weight": min(1.0, abs(z) / (threshold * 2)),  # normalised weight
        "detail": (
            f"Anomalous event frequency detected for host={host_id!r}, "
            f"class_uid={getattr(event, 'class_uid', '?')}: "
            f"z={z:.2f} (threshold={threshold})."
        ),
        "zscore": z,
    }
