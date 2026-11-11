"""Real dead-end detection — primary-tier-join inactivity heuristic, Stage 3.

Replaces Stage 1's injectable `DEAD_END:category` flag in supervisor_node with
actual logic called from primary_tier_join_node (the correct evaluation point —
after primary agents have run and reported findings, NOT at Supervisor entry).

Test-injectability is preserved: if `state["test_control"]["dead_end_categories"]`
is present, the heuristic is short-circuited — tests remain deterministic without
waiting on real timing. Production code never sets this field (Fix 4, Current-Phase
Fixes doc).

D1 note: redis_client=None is handled gracefully — if None and no test_control,
returns (False, []) so unit tests that don't supply a Redis client still work
for the no-dead-end path.
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


def detect_dead_end(state: dict, redis_client) -> tuple[bool, list[str]]:
    """Returns (dead_end_detected, dead_end_categories).

    Test-injection path (checked first, production never hits this):
      state["test_control"]["dead_end_categories"] -> short-circuit with that value.

    Real heuristic: no progress recorded within IDLE_WINDOW_SECONDS since the
    primary tier's dispatched agents all reported back. Categories are inferred
    from which primary-tier finding (if any) flagged an unresolved lead.

    redis_client=None: skips real heuristic and returns (False, []) — safe for
    unit tests that inject dead-end via test_control and don't need real Redis.
    """
    # Test-injection path — deterministic, never touches redis
    test_control = state.get("test_control") or {}
    if "dead_end_categories" in test_control:
        categories = test_control["dead_end_categories"]
        return (bool(categories), categories)

    # No redis client — gracefully degrade (unit-test path without Redis infra)
    if redis_client is None:
        return (False, [])

    case_id = state.get("case_id", "")
    if not case_id:
        return (False, [])

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
