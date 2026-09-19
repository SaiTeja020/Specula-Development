"""
Ground Truth Benchmark Test Suite for Log Analysis Agent.

Executes the SHA-256 locked 50-event ground truth evaluation runner
to verify that all 4 pre-committed SLA thresholds pass under pytest.
"""

from __future__ import annotations

import pytest
from scripts.evaluate_log_analysis_ground_truth import run_benchmark, verify_fixture_hashes


def test_fixture_integrity_hashes():
    """Verify SHA-256 hashes of ground-truth fixtures match pre-committed constants."""
    verify_fixture_hashes()


def test_log_analysis_ground_truth_benchmark_sla():
    """Verify all 4 SLA thresholds (FP rate, rule recall, pipeline recall, precision)."""
    run_benchmark()
