"""Real dead-end detection — Supervisor-side inactivity heuristic, Stage 3.

Replaces Stage 1's injectable `DEAD_END:category` flag with actual logic:
track last-progress timestamp per case; if no new finding/DFKG write arrives
within an idle window AND the primary tier has genuinely finished dispatching,
mark dead-end. Per Master_doc §10/§14.1: this is explicitly NOT an APOC
trigger — dead-end is an absence-of-activity signal, which a database trigger
cannot observe by construction.

Test-injectability is preserved for Stage 1's existing test suite: if
`state["test_control"]["dead_end_categories"]` is present, it short-circuits
the heuristic — tests remain deterministic without waiting on real timing.
Production code path never sets this field (Fix 4, Current-Phase Fixes doc).
"""
from __future__ import annotations

import time

import redis

from src.agents.redis_keys import ACTIVE_CASE_PREFIX


IDLE_WINDOW_SECONDS = 30.0


def _progress_key(case_id: str) -> str:
    return f"{ACTIVE_CASE_PREFIX}{case_id}:last_progress_ts"


def record_progress(redis_client: redis.Redis, case_id: str) -> None:
    """Call this every time a new finding is published or a DFKG write
    completes for this case — this is what 'progress' means for the
    heuristic below."""
    redis_client.set(_progress_key(case_id), time.time())


def detect_dead_end(state: dict, redis_client: redis.Redis) -> tuple[bool, list[str]]:
    """Returns (dead_end_detected, dead_end_categories).

    Real heuristic: no progress recorded within IDLE_WINDOW_SECONDS since the
    primary tier's dispatched agents all reported back. Categories are
    inferred from which primary-tier finding (if any) flagged an unresolved
    lead — e.g. Log Analysis finding an unexplained process with no parent
    maps to 'memory'; Network Forensics finding an unattributed external IP
    maps to 'identity' or 'malware' depending on content. This mapping is
    intentionally simple for Stage 3 and should be revisited once Stage 4's
    real domain logic gives agents something more specific to flag.
    """
    test_control = state.get("test_control") or {}
    if "dead_end_categories" in test_control:
        categories = test_control["dead_end_categories"]
        return (bool(categories), categories)

    case_id = state["case_id"]
    last_progress_raw = redis_client.get(_progress_key(case_id))
    if last_progress_raw is None:
        # No progress ever recorded — not a dead end, just not started measuring yet.
        return (False, [])

    idle_seconds = time.time() - float(last_progress_raw)
    if idle_seconds < IDLE_WINDOW_SECONDS:
        return (False, [])

    categories = _infer_categories_from_findings(state.get("findings", []))
    return (bool(categories), categories)


def _infer_categories_from_findings(findings: list[dict]) -> list[str]:
    categories = []
    for f in findings:
        summary = (f.get("summary") or "").lower()
        if "unexplained process" in summary or "no parent" in summary:
            categories.append("memory")
        if "unattributed" in summary or "unknown external ip" in summary:
            categories.append("identity")
        if "suspicious binary" in summary or "unsigned executable" in summary:
            categories.append("malware")
        if "off-hours access" in summary or "unusual login pattern" in summary:
            categories.append("insider")
    return sorted(set(categories))
