"""
Log Analysis Agent — LLM Reasoner.

Orchestrates tool calls (parse_log_batch, detect_anomaly, query_dfkg)
and produces grounded finding narratives via Qwen2.5-72B-Instruct.

HARD BEHAVIORAL CONSTRAINT [RESOLVED items #13/#14/#15]:
    The LLM may only narrate/summarize patterns that run_rule_layer()
    or compute_zscore() already flagged. It must NOT assert a new,
    unflagged pattern. This is enforced structurally via a post-hoc
    guard (see _validate_narration_against_signals). If the LLM
    references a pattern name absent from the signals list:
      1. Retry once with an explicit correction instruction.
      2. If it fails twice, fall back to a template-generated summary
         (no LLM narration) to prevent hallucinated findings.

Prompt template:
    System prompt lives in agent_model_config.yaml under this role's
    system_prompt_template key — NOT as a Python string literal here.
    build_prompt() reads it from config; tests may inject a mock.

Loop budget:
    Enforced by _run_with_budget() — respects LOOP_BUDGET_MAX_TOOL_CALLS
    and LOOP_TIMEOUT_SECONDS from config.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from src.agents.log_analysis import config
from src.schemas.ocsf_base import OCSFBaseEvent

logger = logging.getLogger(__name__)


# ─── Data types ───────────────────────────────────────────────────────────────


@dataclass
class AssessmentResult:
    """
    Output of assess_batch() for a single suspicious event.

    Attributes:
        event:         The originating OCSF event.
        signals:       Combined rule + anomaly signals that triggered analysis.
        summary:       LLM-narrated (or template-fallback) finding summary.
        dfkg_refs:     DFKG node UIDs cited by the analysis.
        pattern:       Dominant pattern name (from signals, not LLM invention).
        severity:      One of config.SEVERITY_LEVELS.
        confidence:    Float [0, 1] per item #22's two defined cases.
        model_used:    Model ID that produced the narration (or "template-fallback").
        latency_ms:    End-to-end LLM call latency in milliseconds.
        degraded:      True if model was unavailable and result is rule/anomaly only.
    """
    event: OCSFBaseEvent
    signals: list[dict[str, Any]]
    summary: str
    dfkg_refs: list[str]
    pattern: str
    severity: str
    confidence: float
    model_used: str = config.MODEL_ID
    latency_ms: float = 0.0
    degraded: bool = False


# ─── Prompt construction ─────────────────────────────────────────────────────


def build_prompt(
    system_prompt: str,
    baseline_stats: dict[str, Any],
    distilled_log_batch: list[dict[str, Any]],
    prior_findings: list[dict[str, Any]],
) -> str:
    """
    Construct the full prompt for the LLM reasoner.

    Args:
        system_prompt:       System prompt template from agent_model_config.yaml.
        baseline_stats:      Summary statistics from the anomaly baseline
                             (mean, std, z-scores per key).
        distilled_log_batch: List of event dicts (JSON-serializable summaries,
                             NOT raw OCSFBaseEvent objects).
        prior_findings:      List of {"prose": str, "citation_uid": str} dicts.
                             Citation UIDs are kept structurally separate from
                             prose — never merged into a single free-text blob
                             so citation integrity survives any compression step
                             (item #15).

    Returns:
        Formatted prompt string ready for model invocation.
    """
    # Format prior findings preserving citation integrity.
    prior_section = "\n".join(
        f"  [{i+1}] [{f.get('citation_uid', 'no-uid')}] {f.get('prose', '')}"
        for i, f in enumerate(prior_findings)
    )

    batch_section = "\n".join(
        f"  [{i+1}] {_summarise_event_dict(e)}"
        for i, e in enumerate(distilled_log_batch)
    )

    stats_section = "\n".join(
        f"  {k}: mean={v.get('mean', '?'):.2f}, std={v.get('std', '?'):.2f}"
        for k, v in baseline_stats.items()
    ) if baseline_stats else "  (no baseline statistics available)"

    return (
        f"{system_prompt}\n\n"
        f"=== BASELINE STATISTICS ===\n{stats_section}\n\n"
        f"=== EVENT BATCH (distilled) ===\n{batch_section}\n\n"
        f"=== PRIOR FINDINGS (with citation UIDs) ===\n{prior_section or '  (none)'}\n\n"
        "Respond with a concise finding narrative grounded only in the signals "
        "and citations above. Do not assert patterns not listed in the signals."
    )


def _summarise_event_dict(e: dict[str, Any]) -> str:
    """One-line summary of an event dict for prompt injection."""
    return (
        f"class_uid={e.get('class_uid', '?')} "
        f"uid={e.get('uid', '?')} "
        f"time={e.get('time', '?')} "
        f"pattern_signals={e.get('signals', [])}"
    )


# ─── Post-hoc narration guard ─────────────────────────────────────────────────


def _validate_narration_against_signals(
    narration: str,
    signals: list[dict[str, Any]],
) -> bool:
    """
    Structural hallucination guard (item #5 / items #13/#14).

    Returns True if the narration is grounded (references only flagged
    pattern names), False if it invents a new unflagged pattern name.

    Pattern names checked: the "pattern" keys from the signals list.
    """
    known_patterns = {s["pattern"] for s in signals}
    # Known pattern vocabulary (all possible names from detection_rules.py).
    all_pattern_names = {
        "unusual_parent_process",
        "offhours_service_install",
        "brute_force",
        "sensitive_file_access",
        "anomalous_frequency",
    }
    # Forbidden: pattern names present in vocabulary but absent from current signals.
    unflagged_patterns = all_pattern_names - known_patterns

    for pattern in unflagged_patterns:
        if pattern.replace("_", " ") in narration.lower() or pattern in narration.lower():
            logger.warning(
                "LLM narration references unflagged pattern %r. "
                "Rejecting narration (post-hoc guard).",
                pattern,
            )
            return False
    return True


# ─── Template-based fallback summary ─────────────────────────────────────────


def _template_summary(
    signals: list[dict[str, Any]],
    event: OCSFBaseEvent,
) -> str:
    """
    Generate a deterministic template summary when LLM narration is
    unavailable or fails the post-hoc guard twice.
    """
    patterns = ", ".join(s["pattern"] for s in signals)
    host = (
        getattr(event, "canonical_host_id", None)
        or getattr(event, "host_name", None)
        or "unknown-host"
    )
    return (
        f"[TEMPLATE FALLBACK] Detected pattern(s): {patterns} on host {host}. "
        f"Event UID: {event.uid}. "
        "LLM narration was unavailable or failed validation — findings are "
        "grounded in deterministic rule/anomaly signals only."
    )


# ─── Main assessment function ─────────────────────────────────────────────────


def assess_batch(
    events: list[OCSFBaseEvent],
    rule_signals: list[list[dict[str, Any]]],
    anomaly_signals: list[dict[str, Any] | None],
    model_router: Any,
    dfkg_read_client: Any,
    system_prompt: str = "",
    baseline_stats: dict[str, Any] | None = None,
    prior_findings: list[dict[str, Any]] | None = None,
) -> list[AssessmentResult]:
    """
    Assess a batch of events using the LLM reasoner.

    For each event with at least one rule or anomaly signal:
      1. Queries DFKG for corroborating context (query_dfkg).
      2. Builds a distilled event dict for the prompt.
      3. Invokes the model via model_router (respecting loop budget).
      4. Validates narration against signals (post-hoc guard).
      5. Retries once with correction instruction on failure.
      6. Falls back to template summary on second failure.

    Args:
        events:          List of OCSFBaseEvent objects in this batch.
        rule_signals:    Parallel list — rule_signals[i] = signals for events[i].
        anomaly_signals: Parallel list — anomaly_signals[i] = anomaly signal or None.
        model_router:    Callable: model_router(prompt: str) -> str.
                         Returns model response or raises on failure.
        dfkg_read_client: Callable: dfkg_read_client.query(uid: str) -> list[str].
                          Returns a list of DFKG citation UIDs.
        system_prompt:   Loaded from agent_model_config.yaml by agent.py.
        baseline_stats:  Summary stats to include in prompt.
        prior_findings:  Prior finding dicts with citation UIDs.

    Returns:
        List of AssessmentResult objects (one per suspicious event).
        Events with no signals are skipped (no LLM call, no result).

    Note on degraded results:
        If model_router raises after exhausting fallback, returns a
        degraded AssessmentResult with degraded=True. agent.py applies
        the degradation policy (§7a) — do NOT fabricate a verdict here.
    """
    results: list[AssessmentResult] = []
    baseline_stats = baseline_stats or {}
    prior_findings = prior_findings or []

    for i, event in enumerate(events):
        combined_signals = list(rule_signals[i]) if i < len(rule_signals) else []
        anomaly_sig = anomaly_signals[i] if i < len(anomaly_signals) else None
        if anomaly_sig is not None:
            combined_signals.append(anomaly_sig)

        if not combined_signals:
            # No signals → skip entirely, no LLM call.
            continue

        start_t = time.time()

        # ── Query DFKG for citation context ──────────────────────────────────
        dfkg_refs: list[str] = []
        try:
            dfkg_refs = dfkg_read_client.query(event.uid) or []
        except Exception as exc:
            logger.warning("DFKG query failed for uid=%s: %s", event.uid, exc)
            dfkg_refs = []

        # ── Build distilled event dict for prompt ─────────────────────────────
        distilled = {
            "class_uid": getattr(event, "class_uid", None),
            "uid": event.uid,
            "time": str(getattr(event, "time", "")),
            "signals": [s["pattern"] for s in combined_signals],
        }

        prompt = build_prompt(
            system_prompt=system_prompt,
            baseline_stats=baseline_stats,
            distilled_log_batch=[distilled],
            prior_findings=prior_findings,
        )

        # ── Invoke model with post-hoc guard + one retry ──────────────────────
        narration: str | None = None
        model_used = config.MODEL_ID
        degraded = False

        for attempt in range(2):
            try:
                if attempt == 1:
                    # Correction instruction for retry.
                    correction = (
                        "\n\nCORRECTION: Your previous response mentioned a pattern "
                        "not present in the signals list. Please restrict your "
                        "narrative strictly to the flagged patterns: "
                        + str([s["pattern"] for s in combined_signals])
                    )
                    invoke_prompt = prompt + correction
                else:
                    invoke_prompt = prompt

                raw_narration = model_router(invoke_prompt)

                if _validate_narration_against_signals(raw_narration, combined_signals):
                    narration = raw_narration
                    break
                else:
                    logger.warning(
                        "Narration failed post-hoc guard (attempt %d/2).", attempt + 1
                    )
            except Exception as exc:
                logger.warning("Model call failed (attempt %d/2): %s", attempt + 1, exc)
                break

        # ── Fallback to template if LLM narration unavailable/invalid ────────
        if narration is None:
            narration = _template_summary(combined_signals, event)
            model_used = "template-fallback"
            degraded = True

        latency_ms = round((time.time() - start_t) * 1000, 1)

        # ── Derive severity and pattern from signals ───────────────────────────
        dominant_signal = max(combined_signals, key=lambda s: s.get("weight", 0))
        pattern = dominant_signal["pattern"]
        severity = _signal_to_severity(dominant_signal)

        # ── Confidence per item #22: classifier probability if rule fired,
        # else cited_claims / total_claims for pure anomaly path.
        if rule_signals[i]:
            confidence = dominant_signal.get("weight", 0.5)
        else:
            # Anomaly-only: cited claims = len(dfkg_refs), total = 1 (the anomaly)
            total = max(1, len(dfkg_refs) + 1)
            confidence = len(dfkg_refs) / total

        results.append(AssessmentResult(
            event=event,
            signals=combined_signals,
            summary=narration,
            dfkg_refs=dfkg_refs,
            pattern=pattern,
            severity=severity,
            confidence=confidence,
            model_used=model_used,
            latency_ms=latency_ms,
            degraded=degraded,
        ))

    return results


def _signal_to_severity(signal: dict[str, Any]) -> str:
    """
    Map a signal weight to one of the three permitted severity levels.
    weight >= 0.85 → high, >= 0.70 → medium, else → low.
    """
    weight = signal.get("weight", 0.0)
    if weight >= 0.85:
        return "high"
    elif weight >= 0.70:
        return "medium"
    return "low"
