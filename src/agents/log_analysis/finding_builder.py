"""
Log Analysis Agent — Finding Builder.

Pure module: no I/O, no side effects. Constructs the canonical finding
dict that this agent publishes to Kafka.

Schema authority: Implementation Plan §3 / resolved-decisions item #19.
This dict shape is the merged LangGraph Skeleton findings-entry + Log-
Analysis-specific fields. It is NOT a DetectionFindingEvent Pydantic
subclass (class_uid 2004). If a downstream consumer needs an OCSF-
enveloped finding, that translation is out of scope for this module.

HARD REQUIREMENT [RESOLVED item #20]:
    dfkg_refs must be non-empty. An empty list raises ValueError here
    AND is re-checked at the publish boundary in agent.py (belt-and-
    braces). Do not catch this error and continue — let it surface.
"""

from __future__ import annotations

from datetime import timezone
from typing import Any

from src.agents.log_analysis import config
from src.schemas.ocsf_base import OCSFBaseEvent


# Canonical key set for a Log Analysis finding (item #19).
# Tests assert that build_finding output contains EXACTLY these keys —
# no extra, no missing.
_REQUIRED_FINDING_KEYS: frozenset[str] = frozenset({
    "agent_role",
    "summary",
    "severity",
    "pattern",
    "affected_count",
    "timeline_range",
    "dfkg_refs",
    "timestamp",
    "kafka_offset",
})


def build_finding(
    source_event: OCSFBaseEvent,
    agent_role: str,
    summary: str,
    severity: str,
    pattern: str,
    affected_count: int,
    timeline_range: tuple[str, str],
    dfkg_refs: list[str],
    kafka_offset: int,
    confidence: float,
) -> dict[str, Any]:
    """
    Build the canonical Log Analysis finding dict.

    Args:
        source_event:   The triggering OCSF base event (used for timestamp).
        agent_role:     Must equal config.AGENT_ROLE for this agent.
        summary:        Human-readable narrative of the finding.
        severity:       One of config.SEVERITY_LEVELS ("low", "medium", "high").
                        Anything else raises ValueError immediately — a 4th tier
                        must never reach Kafka.
        pattern:        Short machine-readable pattern name matching one of the
                        four named detection patterns in detection_rules.py.
        affected_count: Number of distinct affected entities.
        timeline_range: (iso_start, iso_end) tuple bounding the event window.
        dfkg_refs:      Non-empty list of DFKG node/finding UIDs that ground
                        this finding. Raises ValueError if empty (item #20).
        kafka_offset:   The Kafka offset of the triggering batch.
        confidence:     Float [0.0, 1.0]. Computed outside this function per
                        item #22's two defined cases; attached by agent.py
                        before publish alongside escalation flag.

    Returns:
        Dict with exactly the keys in _REQUIRED_FINDING_KEYS, plus
        "confidence" (attached here for downstream use by agent.py).

    Raises:
        ValueError: if dfkg_refs is empty (item #20).
        ValueError: if severity is not in config.SEVERITY_LEVELS (item #21).
        TypeError:  if timeline_range is not a 2-tuple of strings.
    """
    # ── Validate severity (item #21) ──────────────────────────────────────────
    if severity not in config.SEVERITY_LEVELS:
        raise ValueError(
            f"Invalid severity '{severity}'. "
            f"Must be one of {config.SEVERITY_LEVELS}. "
            "A fourth severity tier is not permitted — reject at construction "
            "time, do not let it reach Kafka."
        )

    # ── Validate dfkg_refs (item #20) ─────────────────────────────────────────
    if not dfkg_refs:
        raise ValueError(
            "dfkg_refs must be non-empty. A finding with no DFKG citations "
            "violates item #20 (belt-and-braces enforced here AND in agent.py). "
            "Do not catch this error and continue — surface it."
        )

    # ── Validate timeline_range ───────────────────────────────────────────────
    if (
        not isinstance(timeline_range, (tuple, list))
        or len(timeline_range) != 2
        or not all(isinstance(t, str) for t in timeline_range)
    ):
        raise TypeError(
            f"timeline_range must be a 2-tuple of ISO 8601 strings, "
            f"got {type(timeline_range).__name__}: {timeline_range!r}"
        )

    # ── Build timestamp from source event (item #19) ──────────────────────────
    # source_event.time is already a corrected UTC datetime (see ocsf_base.py).
    ts = source_event.time
    if ts.tzinfo is None:
        # Treat naive datetimes as UTC per OCSF contract.
        ts = ts.replace(tzinfo=timezone.utc)
    timestamp_iso = ts.isoformat()

    # ── Assemble canonical finding ─────────────────────────────────────────────
    finding: dict[str, Any] = {
        "agent_role": agent_role,
        "summary": summary,
        "severity": severity,
        "pattern": pattern,
        "affected_count": affected_count,
        "timeline_range": (str(timeline_range[0]), str(timeline_range[1])),
        "dfkg_refs": list(dfkg_refs),
        "timestamp": timestamp_iso,
        "kafka_offset": kafka_offset,
        # Confidence is part of the finding payload but not in _REQUIRED_FINDING_KEYS
        # because agent.py attaches it alongside the escalation flag AFTER build_finding
        # returns, then re-validates before publishing. Included here for convenience.
        "confidence": confidence,
    }

    return finding


def get_required_keys() -> frozenset[str]:
    """Return the canonical required key set for test assertions (item 9.1)."""
    return _REQUIRED_FINDING_KEYS
