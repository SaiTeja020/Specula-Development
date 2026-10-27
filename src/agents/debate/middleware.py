"""Debate middleware — Plan v2 §1 (gate), §2 (model routing), §5 (context, blinding, citations)."""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from pydantic import ValidationError

from .schemas import AgentPayload
from .store import DebatePayloadStore

MAX_VALIDATION_ATTEMPTS = 3
MAX_ROUNDS = 3
AGENT_MAX_ITERATIONS = 5
AGENT_TIMEOUT_SECONDS = 40.0
# M6: total wall-clock budget for one debate run, derived from 60s allocation within 300s pipeline SLO.
TOTAL_DEBATE_BUDGET_SECONDS = 60.0
MAX_CITATIONS_PER_SIDE = 10


# ---------------------------------------------------------------- §1 gate
class DebateGateError(RuntimeError):
    pass


def check_debate_gate(
    case_state: str,
    dispatched_agents: Sequence[str],
    completed_agents: Sequence[str],
    lagging_consumer_writes: bool = False,
) -> None:
    """Debate is only invoked if case_state == FROZEN, every dispatched agent
    completed, and there are no lagging consumer writes."""
    if case_state != "FROZEN":
        raise DebateGateError(f"case_state must be FROZEN, got {case_state!r}")
    missing = set(dispatched_agents) - set(completed_agents)
    if missing:
        raise DebateGateError(f"dispatched agents not completed: {sorted(missing)}")
    if lagging_consumer_writes:
        raise DebateGateError("consumer writes are still lagging")


# ---------------------------------------------------------------- §2 routing
PRIMARY_DEBATE_MODELS: Dict[str, str] = {
    "PROPONENT": "nemotron-3-super-120b",
    "CRITIC": "llama-3.3-70b-instruct",     # different family: avoids correlated blind spots
    "JUDGE": "nemotron-3-ultra-550b",
}
DEBATE_MODELS = PRIMARY_DEBATE_MODELS
LOCAL_FALLBACK_MODEL = "local-quantized-7b"


def resolve_model(
    role: str,
    api_available: bool = True,
    air_gapped: bool = False,
    model_override: Optional[str] = None,
) -> Tuple[str, bool]:
    """Returns (model_id, degraded_capability_mode).

    Catches both local quantization fallbacks and cloud-to-cloud model switches
    (e.g., Nemotron Ultra falling back to another cloud LLM on the Judge).
    """
    if air_gapped or not api_available:
        return LOCAL_FALLBACK_MODEL, True
    if model_override:
        is_fallback = model_override != PRIMARY_DEBATE_MODELS[role]
        return model_override, is_fallback
    return PRIMARY_DEBATE_MODELS[role], False


def resolve_all_models(
    api_available: Optional[Dict[str, bool]] = None,
    air_gapped: bool = False,
    model_overrides: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, str], bool]:
    """M5: resolve every role. Returns ({role: model_id}, degraded).
    ANY fallback (local or cloud-to-cloud) => degraded, and a degraded run is always
    routed to HITL regardless of the verdict.
    """
    api_available = api_available or {}
    model_overrides = model_overrides or {}
    models: Dict[str, str] = {}
    degraded = False
    for role in PRIMARY_DEBATE_MODELS:
        model, flag = resolve_model(
            role,
            api_available=api_available.get(role, True),
            air_gapped=air_gapped,
            model_override=model_overrides.get(role),
        )
        models[role] = model
        degraded = degraded or flag
    return models, degraded


# ---------------------------------------------------------------- run id / blind seed (M7)
def make_debate_run_id(case_id: str, trace_id: str, attempt: int = 0) -> str:
    """Deterministic: the same (case, trace, attempt) always yields the same run id."""
    return hashlib.sha256(f"{case_id}|{trace_id}|{attempt}".encode("utf-8")).hexdigest()[:16]


def blind_seed(debate_run_id: str, round_index: int) -> int:
    return int(hashlib.sha256(f"{debate_run_id}|{round_index}".encode("utf-8")).hexdigest()[:16], 16)


# ---------------------------------------------------------------- §5.1 context
def _summarize(text: str, limit: int = 160) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def hydrate_context(
    store: DebatePayloadStore,
    case_id: str,
    run_id: str,
    round_index: int,
    summarizer: Callable[[str], str] = _summarize,
) -> Dict[str, Any]:
    """Active round is NEVER compacted (it is simply absent from `closed_rounds`; the live
    payloads are loaded in full by the nodes). Closed rounds: exact citation UIDs pinned
    and unaltered, rhetorical rationale summarised. Raises PayloadMissingError (fail closed)."""
    closed: List[Dict[str, Any]] = []
    for rec in store.load_rounds(case_id, run_id):
        if rec["round_index"] >= round_index:
            continue
        for role, uid in (("PROPONENT", rec["proponent_uid"]), ("CRITIC", rec["critic_uid"])):
            p = store.load_payload(case_id, uid)
            closed.append({
                "round_index": rec["round_index"],
                "role": role,
                "summary": summarizer(p.hypothesis),
                "pinned_uids": sorted({u for c in p.claims for u in c.cited_uids}),
            })
    return {"closed_rounds": closed}


def pinned_uids(context: Dict[str, Any]) -> List[str]:
    return sorted({u for r in context["closed_rounds"] for u in r["pinned_uids"]})


# ---------------------------------------------------------------- §5.1 blinding
def make_blind_map(rng: Optional[random.Random] = None) -> Dict[str, str]:
    """Randomly map H1/H2 onto Hypothesis A/B. Returns label -> hypothesis."""
    rng = rng or random.Random()
    return {"A": "H1", "B": "H2"} if rng.random() < 0.5 else {"A": "H2", "B": "H1"}


# ---------------------------------------------------------------- §5.3 citations
@dataclass
class CitationResult:
    ok: bool
    payload: Optional[AgentPayload] = None
    invalid_uids: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    def feedback(self) -> str:
        parts = list(self.reasons)
        if self.invalid_uids:
            parts.append("Missing/invalid UIDs: " + ", ".join(self.invalid_uids))
        return "PARAMETRIC_KNOWLEDGE_REJECTED: " + "; ".join(parts)


def enforce_citations(
    raw: Dict[str, Any],
    case_id: str,
    round_index: int,
    verify_uids: Callable[[str, List[str]], List[str]],
    retrieved_uids: Sequence[str],
    max_citations_per_side: int = MAX_CITATIONS_PER_SIDE,
) -> CitationResult:
    """Strict citation enforcement via mcp-dfkg-cypher:verify_uids.

    1. Empty check & justification check
    2. Volume cap check (M3: max citations per side to prevent volume bias)
    3. Provenance check (must be in turn's retrieved_uids)
    4. Existence check (must exist in DFKG)
    Note: M4 per-claim entailment is evaluated by the Judge from raw node content,
    not self-reported by the agent.
    """
    data = dict(raw)
    data["case_id"] = case_id
    data["round_index"] = round_index
    data["retrieved_uids"] = sorted(set(retrieved_uids))

    # 1. Empty Check & schema
    try:
        payload = AgentPayload.model_validate(data)
    except ValidationError as exc:
        return CitationResult(False, reasons=[f"schema/empty-citation violation: {exc.error_count()} error(s)"])
    if not payload.claims:
        return CitationResult(False, reasons=["no claims provided"])
    for c in payload.claims:
        if len(c.cited_uids) == 0:
            return CitationResult(False, reasons=["claim with empty cited_uids"])
        if not (c.justification or "").strip():
            return CitationResult(False, reasons=["claim missing non-empty justification"])

    # 2. Volume cap: reject payloads exceeding citation volume cap (M3)
    cited = sorted({u for c in payload.claims for u in c.cited_uids})
    if len(cited) > max_citations_per_side:
        return CitationResult(
            False,
            reasons=[
                f"citation volume cap exceeded: cited {len(cited)} distinct UIDs (max allowed: {max_citations_per_side}); cite at most {max_citations_per_side}, choose the strongest"
            ],
        )

    # 3. Provenance Check
    retrieved = set(payload.retrieved_uids)
    not_retrieved = [u for u in cited if u not in retrieved]
    if not_retrieved:
        return CitationResult(False, invalid_uids=not_retrieved, reasons=["cited UIDs not in retrieved_uids"])

    # 4. Existence Check (through MCP layer only)
    existing = set(verify_uids(case_id, cited))
    missing = [u for u in cited if u not in existing]
    if missing:
        return CitationResult(False, invalid_uids=missing, reasons=["cited UIDs do not exist in DFKG"])

    return CitationResult(True, payload=payload, reasons=[])
