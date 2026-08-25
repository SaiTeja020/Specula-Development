"""
Tests for anomaly_detector.py — Implementation Plan §9 test 3.

Covers:
  - Below ANOMALY_BASELINE_MIN_EVENTS → returns None, NOT 0.0.
  - Above threshold with z > 3 → flagged.
  - z <= 3 → not flagged.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.agents.log_analysis import config
from src.agents.log_analysis.anomaly_detector import (
    BaselineStore,
    compute_zscore,
    detect_anomaly,
    update_baseline,
)
from src.schemas.ocsf_phase2_events import ProcessActivityEvent


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _make_event(
    class_uid: int = 1007,
    host_name: str = "host-a",
    hour: int = 10,
) -> ProcessActivityEvent:
    t = datetime(2026, 8, 22, hour, 0, 0, tzinfo=timezone.utc)
    return ProcessActivityEvent(
        trace_id="t",
        activity_id=1,
        class_uid=class_uid,
        category_uid=1,
        severity_id=2,
        time=t,
        raw_source_timestamp=t.isoformat(),
        uid=f"uid-{host_name}-{hour}",
        process_name="test.exe",
        process_pid=1,
        host_name=host_name,
    )


def _warm_up_store(
    store: BaselineStore,
    event: ProcessActivityEvent,
    n: int,
    value: float = 1.0,
) -> None:
    """Feed n identical observations to warm up the baseline store."""
    for _ in range(n):
        update_baseline(store, event, value)


# ─── Test 3a: cold baseline returns None (not 0.0) ────────────────────────────


def test_cold_baseline_returns_none():
    """
    Below ANOMALY_BASELINE_MIN_EVENTS the z-score MUST be None, not 0.0.
    This is an explicit contract from implementation plan item #12.
    """
    store = BaselineStore()
    evt = _make_event()

    # Feed fewer observations than the warm-up threshold.
    for _ in range(config.ANOMALY_BASELINE_MIN_EVENTS - 1):
        update_baseline(store, evt, 1.0)

    result = compute_zscore(store, evt, 1.0)
    assert result is None, (
        f"Expected None (cold baseline), got {result!r}. "
        "compute_zscore must return None, not 0.0, before warm-up."
    )


def test_cold_baseline_detect_anomaly_returns_none():
    """detect_anomaly() also returns None when baseline is cold."""
    store = BaselineStore()
    evt = _make_event()
    # No warm-up → should return None.
    result = detect_anomaly(store, evt, observation=100.0)
    assert result is None


# ─── Test 3b: warm baseline, z > threshold → flagged ─────────────────────────


def test_warm_high_zscore_is_flagged():
    """
    After warming up with consistent low-value observations, a large
    observation should produce z > ANOMALY_Z_SCORE_THRESHOLD and be flagged.
    """
    store = BaselineStore()
    evt = _make_event()

    # Warm up: all observations = 1.0 (consistent baseline, low variance).
    _warm_up_store(store, evt, config.ANOMALY_BASELINE_MIN_EVENTS, value=1.0)

    # Inject a massive outlier.
    result = detect_anomaly(store, evt, observation=10_000.0)
    assert result is not None, "Expected anomaly signal for extreme outlier."
    assert result["pattern"] == "anomalous_frequency"
    assert result["zscore"] > config.ANOMALY_Z_SCORE_THRESHOLD


def test_warm_high_zscore_compute_zscore():
    """compute_zscore directly should return a float > threshold for outlier."""
    store = BaselineStore()
    evt = _make_event()
    _warm_up_store(store, evt, config.ANOMALY_BASELINE_MIN_EVENTS, value=1.0)

    z = compute_zscore(store, evt, observation=50_000.0)
    assert z is not None
    assert abs(z) > config.ANOMALY_Z_SCORE_THRESHOLD


# ─── Test 3c: warm baseline, z <= threshold → not flagged ────────────────────


def test_warm_low_zscore_not_flagged():
    """
    Within-range observation on a warm baseline should NOT produce an
    anomaly signal.
    """
    store = BaselineStore()
    evt = _make_event()

    # Warm up with values around 100 with some variance.
    import random
    rng = random.Random(42)
    for _ in range(config.ANOMALY_BASELINE_MIN_EVENTS):
        update_baseline(store, evt, 100.0 + rng.gauss(0, 5.0))

    # Test with an observation close to the mean — should not flag.
    result = detect_anomaly(store, evt, observation=102.0)
    assert result is None, (
        f"Expected None for near-mean observation, got {result!r}."
    )


# ─── Test 3d: different hosts are tracked independently ──────────────────────


def test_different_hosts_are_independent():
    """Baseline for host-a must not affect scoring for host-b."""
    store = BaselineStore()
    evt_a = _make_event(host_name="host-a")
    evt_b = _make_event(host_name="host-b")

    # Only warm up host-a.
    _warm_up_store(store, evt_a, config.ANOMALY_BASELINE_MIN_EVENTS, value=1.0)

    # host-b is cold — must still return None.
    result_b = compute_zscore(store, evt_b, 1.0)
    assert result_b is None


# ─── Test 3e: warm baseline, exactly at threshold → not flagged ───────────────


def test_exactly_at_threshold_not_flagged():
    """
    A z-score of exactly ANOMALY_Z_SCORE_THRESHOLD should NOT be flagged
    (rule is >threshold, not >=).
    """
    store = BaselineStore()
    evt = _make_event()

    # Build a perfectly uniform baseline (std=0 → infinity z for any deviation).
    # Use mean=0, variance≈1 by seeding with Normal(0,1) values.
    import random
    rng = random.Random(99)
    observations = [rng.gauss(0, 1) for _ in range(config.ANOMALY_BASELINE_MIN_EVENTS)]
    for obs in observations:
        update_baseline(store, evt, obs)

    mean = sum(observations) / len(observations)
    std = (sum((x - mean) ** 2 for x in observations) / len(observations)) ** 0.5

    # Construct an observation that lands at exactly the threshold z.
    target_obs = mean + config.ANOMALY_Z_SCORE_THRESHOLD * std
    result = detect_anomaly(store, evt, observation=target_obs)
    # At exactly threshold: abs(z) == threshold, not strictly greater → no signal.
    assert result is None
