"""
Log Analysis Agent — Module-level constants.

All tunable parameters live here. No magic numbers are permitted in
detection_rules.py, anomaly_detector.py, dedup.py, llm_reasoner.py,
or agent.py. Any deviation from these defaults requires an explicit
environment-variable override documented in this file's docstring.

Reference: Implementation Plan §2a (resolved-decisions items #3–#45).
"""

from __future__ import annotations

# ─── Identity ────────────────────────────────────────────────────────────────

AGENT_ROLE: str = "Log-Analysis-Agent"

# ─── Kafka topology ──────────────────────────────────────────────────────────

# Events consumed by this agent — matches frozen class_uid defaults on
# ProcessActivityEvent (1007) and FileActivityEvent (1001) in ocsf_phase2_events.py.
# Test in test_finding_builder.py asserts equality against those frozen values
# rather than trusting this constant independently (belt-and-braces).
CONSUMED_CLASS_UIDS: frozenset[int] = frozenset({1007, 1001})

CONSUMED_TOPIC: str = "logs.normalized.ocsf"

# [RESOLVED] item #27
FINDINGS_TOPIC: str = "findings.log_analysis"

CONSUMER_GROUP: str = "log-analysis-agent"

# ─── Model ────────────────────────────────────────────────────────────────────

MODEL_ID: str = "Qwen/Qwen2.5-72B-Instruct"

# ─── Batch / tumbling-window parameters ──────────────────────────────────────
# [RESOLVED] item #4 — tumbling window (events OR seconds, whichever first).

BATCH_MAX_EVENTS: int = 1000
BATCH_MAX_SECONDS: int = 5

# ─── Detection thresholds ─────────────────────────────────────────────────────

# [RESOLVED] item #9 — brute-force window, config-overridable per deployment.
BRUTE_FORCE_WINDOW_SECONDS: int = 900  # 15 min

# [RESOLVED] items #11/#12 — z-score anomaly detection.
ANOMALY_Z_SCORE_THRESHOLD: float = 3.0
# Baseline is not considered warm until this many events observed for a
# given host/event-type key. compute_zscore returns None (not 0.0) below
# this count. Callers MUST treat None as "no anomaly signal yet."
ANOMALY_BASELINE_MIN_EVENTS: int = 100_000

# ─── ReAct loop budget ────────────────────────────────────────────────────────
# [RESOLVED] items #16/#18 — system defaults, no agent-specific override yet.

LOOP_BUDGET_MAX_ITERATIONS: int = 10
LOOP_BUDGET_MAX_TOOL_CALLS: int = 15
LOOP_TIMEOUT_SECONDS: int = 60

# [RESOLVED] item #29 — dead-end detection: seconds of no new findings/tool
# progress before the agent exposes a dead-end signal to the Supervisor.
# This agent does NOT implement dead-end detection itself; it only exposes
# the progress signal that the Supervisor polls.
DEAD_END_NO_PROGRESS_SECONDS: int = 90

# ─── Severity ────────────────────────────────────────────────────────────────
# [RESOLVED] item #21 — exactly three tiers, no fourth "critical" level.
# build_finding() validates against this tuple and raises on anything else.

SEVERITY_LEVELS: tuple[str, ...] = ("low", "medium", "high")

# ─── Confidence / escalation ──────────────────────────────────────────────────
# [RESOLVED] item #41 — findings with confidence below this are escalated.

LOW_CONFIDENCE_ESCALATION_THRESHOLD: float = 0.7

# ─── Entropy / distillation ───────────────────────────────────────────────────
# [RESOLVED] item #33 — MUST be set via environment-specific silhouette-score
# sweep before the distillation stage is invoked. agent.py raises at startup
# if this is still None when distillation is requested.

ENTROPY_THRESHOLD: float | None = None  # MUST be tuned before production use

# ─── Deduplication ────────────────────────────────────────────────────────────
# [RESOLVED] item #23 — TTL is set to match the case's active window at runtime.
# Not a constant — this placeholder documents intent, not a hardcoded value.

DEDUP_FINGERPRINT_TTL_SECONDS: int | None = None  # set per-case at runtime

# ─── Performance targets (recommendations, not hard SLA gates) ────────────────
# [RESOLVED] items #39/#40 — targets tracked via metrics, not enforced by code.
# Do NOT treat these as SLA-hard until measured against production-shaped load.

THROUGHPUT_TARGET_EVENTS_PER_SEC: int = 1000
LATENCY_TARGET_SECONDS_PER_BATCH: int = 30

# ─── Allowed DFKG node/edge types ─────────────────────────────────────────────
# [RESOLVED] item #24/#25 — whitelist enforced in agent.py wherever Cypher
# parameters are constructed. Do not silently add types without sign-off.

ALLOWED_NODE_TYPES: frozenset[str] = frozenset({
    "User", "Process", "File", "Host", "SuspiciousActivity"
})

ALLOWED_EDGE_TYPES: frozenset[str] = frozenset({
    "EXECUTED", "ACCESSED", "AUTHENTICATED_AS", "FLAGGED_ANOMALOUS"
})

# Explicitly forbidden — checked by a whitelist assertion in agent.py.
FORBIDDEN_EDGE_TYPES: frozenset[str] = frozenset({
    "Malware", "ATT&CK_Technique", "NetworkEndpoint"
})

# ─── Permission manifest (RBAC — [RESOLVED] item #44) ─────────────────────────
# Consumed by the harness's least-privilege check.

ALLOWED_TOOLS: frozenset[str] = frozenset({
    "mcp-dfkg-cypher",       # read + Kafka-mediated publish only; NO direct write
    "detect_anomaly",
    "parse_log_batch",
    "query_dfkg",
    "publish_finding",       # Kafka-only
    "retrieve_similar_events",  # event-level vector search only
})

FORBIDDEN_TOOLS: frozenset[str] = frozenset({
    "mcp-vmi-sandbox",
    "mcp-threat-intel",
    "retrieve_similar_cases",  # cross-case search forbidden for this agent
})
