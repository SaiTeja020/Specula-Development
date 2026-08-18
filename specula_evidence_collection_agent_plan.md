# Specula Evidence Collection Agent — Implementation Plan (v1)

**Status:** Approved for execution.
**Scope:** The first Phase 4 agent. Consumes Kafka-published / DFKG-persisted OCSF events produced by the (already complete) ingestion pipeline; performs case-scoped relevance triage; publishes a Kafka finding. Excludes the Supervisor's dispatch logic, the Log Analysis Agent, and any downstream debate/HITL/report stages — those are separate plans.
**Audience:** Implementer should be able to build this without asking a single clarifying question. If something here is ambiguous, that is a defect in this document, not a gap to fill in with judgment.
**Reconciled against:**
- Master doc §8/§9 — all agents publish findings to Kafka; there is **no direct-DFKG-write path** for any agent, including this one.
- Master doc §14.1 — dead-end detection is a Supervisor-side inactivity heuristic; this agent never implements dead-end detection itself, it only reports `dead_end: bool` observations upward.
- `Specula_LangGraph_Skeleton_Implementation_Plan` — lifecycle enum reuse (`agent_verdict` family), `agent_model_config.yaml` registration pattern (no new router), single-writer state fields (no append-reducer).
- `specula_ingestion_final_plan.md` §7 — this agent does **not** re-implement entropy distillation (Drain3/SimHash/MiniBatchKMeans); it consumes `is_summary`/`is_anomalous` flags already produced by Component 6.

---

## 0. How to read this document

Every component section has four parts:
1. **Purpose** — one sentence, what this exists to do.
2. **Exact specification** — file paths, function signatures, config values. Not descriptions — literal values to implement.
3. **Explicit mistakes to avoid** — things that look correct, compile, and pass a naive test, but are wrong, with the reason stated.
4. **Acceptance test** — how to know this component is done correctly.

Do not skip the "mistakes to avoid" sections.

---

## 1. Where this sits in the architecture

```
[Ingestion Pipeline — COMPLETE, Phases 1-3]
   Quickwit (sealed raw evidence, never touched again)
   Kafka topics: logs.normalized.ocsf.*
   DFKG (Neo4j): typed nodes/edges, deterministic UIDs
        │
        ▼
[Evidence Collection Agent — THIS PLAN, Phase 4]
   ReAct agent, Qwen2.5-7B-Instruct (per Master doc §2.5 Agent-Model
   Rationale Matrix — cheapest model reliable at function calling /
   tool-calling-heavy, low-reasoning-load role)
   Reads:  Kafka consumer group on logs.normalized.ocsf.* (scoped to
           one case_id per invocation) OR mcp-dfkg-cypher query
   Writes: findings.evidence_collection topic ONLY — no DFKG write path
        │
        ▼
[Supervisor Agent]
   Consumes findings.evidence_collection, decides next dispatch
   (Log Analysis / dead-end handling / etc.) — out of scope here.
```

**Global invariant — do not violate this anywhere in this component:** this agent never writes to Neo4j and never touches Quickwit. Its entire output surface is one Kafka message per invocation. If any implementation detail below appears to require a direct graph write, that is a scope violation — stop and re-read Master doc §14.1.

---

## 2. Component 1 — State Schema

**Purpose:** Define the single-writer LangGraph state object this agent's ReAct loop operates on, matching the reconciled `ChatbotTurnState` pattern (single-writer fields, no append-reducer semantics needed).

### 2.1 `src/agents/evidence_collection/state.py`

```python
from typing import TypedDict, Literal


class EvidenceCollectionState(TypedDict):
    """
    LangGraph subgraph state for one Evidence Collection Agent invocation.
    Every field is single-writer — no field is written by more than one
    node in this subgraph, so no append-reducer is required (same
    invariant established for ChatbotTurnState).
    """
    case_id: str                       # REQUIRED. Never UNASSIGNED_CONTINUOUS
                                        # for this agent — see §5 Mistakes.
    trace_id: str                      # W3C trace-context id, propagated
                                        # from Supervisor dispatch.
    batch_uids: list[str]              # DFKG node uids under review this pass.
    kept_uids: list[str]
    discarded_uids: list[str]
    escalated_uids: list[str]          # ambiguous cases — never silently
                                        # dropped, always routed onward.
    discard_reason_codes: dict[str, str]   # uid -> reason code (enum value,
                                            # not free text).
    iteration_count: int               # loop-budget enforcement, per
                                        # runtime harness §9.5.
    max_iterations: int                # supplied by Supervisor at dispatch;
                                        # this agent does not hardcode it.
    dead_end: bool                     # observation only — this agent
                                        # NEVER decides dead-end itself,
                                        # only reports "found nothing new
                                        # to keep this pass."
    status: Literal["running", "complete", "escalated_to_supervisor"]
```

### 2.2 Reused enum — `src/agents/shared/agent_verdict.py`

```python
"""
Shared tri-state verdict enum, reused across agents wherever a
KEEP/DISCARD/ESCALATE-shaped decision applies (Evidence Collection is
the first consumer; Log Analysis and others may reuse this later).
Per the project's reuse-over-invent principle: do NOT create a second,
parallel enum for this agent.
"""
from enum import Enum


class AgentVerdict(str, Enum):
    KEEP = "KEEP"
    DISCARD = "DISCARD"
    ESCALATE = "ESCALATE"
```

If `agent_verdict.py` already exists from prior work (chatbot / skeleton plan) with an equivalent tri-state shape, **extend that file** rather than creating this one. Check before implementing.

### Mistakes to avoid — Component 1
- **Do not** default `case_id` to `"UNASSIGNED_CONTINUOUS"` for this agent's dispatch. Unlike ingestion-time events (which may legitimately be unassigned pending case-open), the Supervisor only ever dispatches this agent *for* an open case. A missing/unassigned `case_id` at dispatch time is a Supervisor bug, and this agent should raise, not silently default.
- **Do not** add an append-reducer to any field "just in case." Every field here is written exactly once per invocation by exactly one node. If a future change needs multi-write semantics, that's a new field, not a retrofit of these.
- **Do not** invent a second `KEEP/DISCARD/ESCALATE`-shaped enum if one already exists in the codebase from the chatbot/skeleton reconciliation work.

### Acceptance test
- Instantiating `EvidenceCollectionState` with `case_id="UNASSIGNED_CONTINUOUS"` raises at the dispatch boundary (test at the Supervisor-dispatch call site, not inside the TypedDict itself, since TypedDict has no runtime validation).
- `AgentVerdict` has exactly three members; no additional states added without an explicit plan revision.

---

## 3. Component 2 — Relevance Classifier

**Purpose:** Decide, per DFKG-tagged event, whether it stays in the investigator-facing working set for this case, is dropped from it, or is too ambiguous to decide automatically.

### 3.1 `src/agents/evidence_collection/relevance_filter.py`

```python
from dataclasses import dataclass
from typing import Optional

from src.agents.shared.agent_verdict import AgentVerdict
from src.schemas.ocsf_base import OCSFBaseEvent


@dataclass
class CaseContext:
    """
    Minimal case-scoped context needed for relevance decisions.
    Populated by a bounded mcp-dfkg-cypher query at the start of each
    invocation — NOT the full subgraph (that would violate the same
    APOC-bounded-BFS discipline used elsewhere: max 3 hops, max 100
    nodes, max 300 relationships, per Master doc §2.4 Feature 2).
    """
    case_id: str
    known_host_uids: set[str]          # canonical_host_id values already
                                        # present in this case's DFKG subgraph


@dataclass
class RelevanceResult:
    uid: str
    verdict: AgentVerdict
    reason_code: str                   # always populated, even for KEEP
                                        # (e.g. "KEEP_DEFAULT",
                                        # "DISCARD_LOW_SEVERITY_KNOWN_HOST")


# Low-signal allowlist: source-type + class_uid combinations that are
# candidates for DISCARD when all other criteria also hold. This is a
# STATIC, checked-in table for v1 — see §7 Open Items re: rule-engine
# migration.
LOW_SIGNAL_CLASS_UIDS: set[int] = {
    3002,   # Authentication — only when activity/status indicate routine success
}


def classify_event(event: OCSFBaseEvent, ctx: CaseContext) -> RelevanceResult:
    """
    Conjunctive DISCARD rule — ALL FOUR criteria must hold, this is not
    a single weighted score with a cutoff:

      1. event.severity_id <= 1 (informational only)
      2. event.canonical_host_id is CONFIRMED absent from ctx.known_host_uids
         (i.e. resolver returned a definite value, and that value is not
         in the known set — NOT "resolver returned None")
      3. event.class_uid is in LOW_SIGNAL_CLASS_UIDS, AND the event's
         specific fields indicate the routine case (e.g. Authentication
         with status == "Success" and no off-hours/impossible-travel flag
         — that flag is a DetectionFindingEvent emitted separately by
         upstream/UEBA logic, not recomputed here)
      4. event was already flagged is_summary=True by the ingestion
         pipeline's entropy clusterer (Component 6) — this agent trusts
         that flag, it does not re-cluster.

    ESCALATE (never silently discarded):
      - event.canonical_host_id is None / unresolved (resolver gap, not
        evidence of irrelevance — mirrors entity_resolver.py's own
        contract: raise/flag rather than guess).
      - Any event where criteria 1-4 are partially satisfied in a way
        that makes the DISCARD conjunction indeterminate (e.g. severity
        present but class_uid not in the allowlist AND host is unknown —
        two independent signals pointing different directions).

    KEEP: everything else, including the default when in doubt. This
    function is intentionally asymmetric: staying in the working set is
    the safe failure mode, being silently dropped is not.
    """
    reason: str

    host_id = event.canonical_host_id if hasattr(event, "canonical_host_id") else None

    if host_id is None:
        return RelevanceResult(uid=event.uid, verdict=AgentVerdict.ESCALATE,
                                reason_code="ESCALATE_UNRESOLVED_HOST")

    host_known = host_id in ctx.known_host_uids
    is_low_severity = event.severity_id <= 1
    is_low_signal_class = event.class_uid in LOW_SIGNAL_CLASS_UIDS
    is_pre_collapsed = bool(getattr(event, "is_summary", False))

    if is_low_severity and (not host_known) and is_low_signal_class and is_pre_collapsed:
        return RelevanceResult(uid=event.uid, verdict=AgentVerdict.DISCARD,
                                reason_code="DISCARD_ALL_FOUR_CRITERIA_MET")

    return RelevanceResult(uid=event.uid, verdict=AgentVerdict.KEEP,
                            reason_code="KEEP_DEFAULT")
```

### Mistakes to avoid — Component 2
- **Do not** collapse the four DISCARD criteria into a single ML confidence score with a threshold, as the *first* implementation. This is the deterministic baseline; a learned scorer, if added later, augments ESCALATE routing — it does not replace criteria 1–4. (Matches the project's stated principle that deterministic skills ship with golden-fixture tests before probabilistic layers are added.)
- **Do not** treat `canonical_host_id is None` the same as `canonical_host_id not in known_host_uids`. The first is a resolver gap (ESCALATE); the second is a confirmed non-match (a candidate for DISCARD, pending the other three criteria). Conflating these repeats the exact defect class `entity_resolver.py`'s test suite already guards against (`test_unresolvable_ip_raises_or_flags_rather_than_guessing`).
- **Do not** re-derive `is_summary` by re-running SimHash/Drain3/MiniBatchKMeans logic in this module. If the flag is missing on an event that should have it, that's a wiring defect upstream — fix the Kafka consumer's field mapping, don't duplicate Component 6.
- **Do not** query the full DFKG subgraph to populate `CaseContext.known_host_uids`. Use the same APOC-bounded BFS discipline (max 3 hops / 100 nodes / 300 relationships) already established for GraphRAG retrieval — an unbounded query here reintroduces the exact traversal-explosion risk Component 7's supernode detection exists to prevent.
- **Do not** make `classify_event` mutate `event` in place. It returns a `RelevanceResult`; the source `OCSFBaseEvent` is never touched, matching the "discard never touches the record" invariant in §4.

### Acceptance test — exact assertions required in `tests/agents/test_relevance_filter.py`
```python
def test_discard_requires_all_four_criteria_conjunctively():
    # event failing ONLY criterion 3 (class_uid not in allowlist) but
    # satisfying 1, 2, 4 -> must be KEEP, not DISCARD
    ...

def test_unresolved_host_escalates_never_discards():
    # canonical_host_id is None -> ESCALATE, regardless of severity/class
    ...

def test_confirmed_unknown_host_is_discard_eligible():
    # canonical_host_id is a real string NOT in known_host_uids -> may
    # combine with other criteria to DISCARD
    ...

def test_every_verdict_carries_a_reason_code():
    # KEEP, DISCARD, and ESCALATE all populate reason_code — never None
    ...

def test_is_summary_flag_trusted_not_recomputed():
    # mock event with is_summary=True and no raw command_line/template
    # fields available -> classify_event does not attempt to recluster,
    # completes using the flag alone
    ...
```

---

## 4. Component 3 — Kafka Finding Publisher

**Purpose:** Emit exactly one `EvidenceCollectionFinding` per invocation, on the same host-keyed partitioning discipline as ingestion, with per-UID auditable reasons.

### 4.1 `src/schemas/agent_findings.py` (new; extend if a shared findings-schema file already exists)

```python
from typing import Literal
from pydantic import BaseModel, Field


class EvidenceCollectionFinding(BaseModel):
    case_id: str
    trace_id: str
    agent_role: Literal["EvidenceCollection"] = "EvidenceCollection"
    kept_uids: list[str]
    discarded_uids: list[str]
    escalated_uids: list[str]
    discard_reason_codes: dict[str, str] = Field(
        ...,
        description=(
            "Per-UID reason code for EVERY uid in kept_uids, "
            "discarded_uids, AND escalated_uids — not discarded_uids "
            "only. Daubert admissibility (Master doc §9.6) requires "
            "showing why an agent examined a piece of evidence, not "
            "just what it concluded about the ones it dropped."
        ),
    )
    batch_size: int
    dead_end: bool
```

### 4.2 `src/agents/evidence_collection/kafka_publisher.py`

```python
from src.agents.evidence_collection.state import EvidenceCollectionState
from src.schemas.agent_findings import EvidenceCollectionFinding

FINDING_TOPIC = "findings.evidence_collection"


def build_finding(state: EvidenceCollectionState) -> EvidenceCollectionFinding:
    return EvidenceCollectionFinding(
        case_id=state["case_id"],
        trace_id=state["trace_id"],
        kept_uids=state["kept_uids"],
        discarded_uids=state["discarded_uids"],
        escalated_uids=state["escalated_uids"],
        discard_reason_codes=state["discard_reason_codes"],
        batch_size=len(state["batch_uids"]),
        dead_end=state["dead_end"],
    )


def publish_finding(state: EvidenceCollectionState, producer) -> None:
    """
    Publishes to FINDING_TOPIC, partitioned by hash(canonical_host_id) of
    the FIRST uid in batch_uids's originating host — matching ingestion
    plan §6.4's rule (partition by host, never by case_id). If a batch
    spans multiple hosts (it should not, per §5 Mistakes below), this
    is a bug to surface, not paper over with a fallback partition key.
    """
```

### Mistakes to avoid — Component 3
- **Do not** populate `discard_reason_codes` only for `discarded_uids`. Every UID the agent examined — kept, discarded, or escalated — needs a reason code. An aggregate "discarded 40 of 200, see count" is insufficient for the same reason the ingestion plan requires per-artifact SHA-256 hashes rather than a batch checksum: an investigator or opposing counsel needs to interrogate individual decisions, not just totals.
- **Do not** publish more than one finding per invocation. One `run_evidence_collection` call → one Kafka message. If the agent's ReAct loop needs multiple internal passes to converge, that's internal to the loop (tracked via `iteration_count`), not multiple published findings — matches the "Judge Agent publishes one verdict, not per-round" precedent from the debate tier.
- **Do not** partition by `case_id` or a `(case_id, host_id)` composite. Strictly `hash(canonical_host_id)`, identical reasoning to ingestion §6.4: case reassignment must never move a host's event stream to a different partition mid-investigation.

### Acceptance test
- A finding with 3 kept, 2 discarded, 1 escalated UIDs has exactly 6 keys in `discard_reason_codes`, not 2.
- Two invocations against the same `case_id` and `batch_uids` but different internal loop paths still each produce exactly one Kafka message — verified by asserting producer call count, not just message content.
- Partition key computed from `canonical_host_id` matches the ingestion pipeline's `FakeKafkaTopic.partition_for_key()` fixture behavior for the same host — i.e. reuse the existing test fixture rather than reimplementing the hash check.

---

## 5. Component 4 — Agent Entrypoint / ReAct Loop

**Purpose:** Wire Components 1–3 together as one LangGraph subgraph node, respecting loop-budget enforcement and single-case-per-invocation scoping.

### 5.1 `src/agents/evidence_collection/agent.py`

```python
from src.agents.evidence_collection.state import EvidenceCollectionState
from src.agents.evidence_collection.relevance_filter import classify_event, CaseContext
from src.agents.evidence_collection.kafka_publisher import build_finding, publish_finding
from src.agents.shared.agent_verdict import AgentVerdict


def run_evidence_collection(state: EvidenceCollectionState, deps) -> EvidenceCollectionState:
    """
    Single entrypoint. `deps` bundles the mcp-dfkg-cypher client and the
    Kafka producer — injected, not constructed inside this function, so
    the node is testable against fakes (matches FakeNeo4j / FakeKafkaTopic
    fixtures already established in tests/conftest.py).

    Enforces:
      - exactly one case_id per invocation (raises otherwise)
      - loop budget: state["iteration_count"] must not exceed
        state["max_iterations"]; on exceeding, return partial results
        with dead_end=True rather than looping unboundedly (runtime
        harness §9.5's "graceful timeout returning a partial observation").
    """
    case_ids_in_batch = {deps.lookup_case_id(uid) for uid in state["batch_uids"]}
    if len(case_ids_in_batch) > 1:
        raise ValueError(
            f"EvidenceCollectionAgent invoked with a batch spanning "
            f"multiple case_ids: {case_ids_in_batch}. Supervisor dispatch "
            f"bug — one case per invocation, no exceptions."
        )

    ctx = deps.load_case_context(state["case_id"])  # bounded DFKG query, §3.1

    for uid in state["batch_uids"]:
        if state["iteration_count"] >= state["max_iterations"]:
            state["dead_end"] = True
            break
        event = deps.fetch_event(uid)
        result = classify_event(event, ctx)
        state["discard_reason_codes"][uid] = result.reason_code
        if result.verdict == AgentVerdict.KEEP:
            state["kept_uids"].append(uid)
        elif result.verdict == AgentVerdict.DISCARD:
            state["discarded_uids"].append(uid)
        else:
            state["escalated_uids"].append(uid)
        state["iteration_count"] += 1

    finding = build_finding(state)
    publish_finding(state, deps.kafka_producer)
    state["status"] = "complete"
    return state
```

### 5.2 `agent_model_config.yaml` registration

```yaml
evidence_collection_generation:
  model: Qwen2.5-7B-Instruct
  provider: Novita/Together via HF
  rationale: >
    Mostly tool-calling/fetching against DFKG + classification against a
    deterministic rule table, low reasoning load — cheapest model
    reliable at function calling. Matches Master doc §2.5 Agent-Model
    Rationale Matrix exactly; do not upgrade the model tier without
    updating that matrix too, or the two documents diverge silently.
```

Registered under the existing `agent_model_config.yaml`, reusing the `*_generation` key pattern already established for the chatbot (`chatbot_generation`) — no new router, no separate config file.

### Mistakes to avoid — Component 4
- **Do not** let `deps.lookup_case_id` / `deps.load_case_context` / `deps.fetch_event` be constructed inline inside `run_evidence_collection`. They must be injected via `deps` so unit tests can substitute `FakeNeo4j`/`FakeKafkaTopic` without a live docker-compose stack — matches the existing `tests/conftest.py` fixture pattern used across every other component's test suite.
- **Do not** silently truncate `batch_uids` to fit `max_iterations` without setting `dead_end = True`. A truncated pass that reports `status: "complete"` without flagging `dead_end` misleads the Supervisor into thinking the case was fully triaged this round when it wasn't.
- **Do not** hardcode `Qwen2.5-7B-Instruct` as a Python constant inside `agent.py`. The model is resolved via `agent_model_config.yaml` at the model-router layer (Master doc §9.6's central model router) — hardcoding it here bypasses the fallback/confidence-flagging mechanism that layer provides.
- **Do not** catch and swallow exceptions from `deps.fetch_event(uid)` to "keep the batch going." A fetch failure for one UID is exactly the kind of tool-timeout scenario the Operational Rule Engine's explicit degradation policy (Master doc §9.4) governs: escalate, don't hallucinate a plausible KEEP/DISCARD verdict for evidence you couldn't actually read.

### Acceptance test
- Invoking with `batch_uids` resolving to two different `case_id`s raises `ValueError` before any classification or Kafka publish occurs.
- Setting `max_iterations` below `len(batch_uids)` results in `dead_end=True`, a finding published with fewer than `batch_size` total classified UIDs, and `status="complete"` (partial completion is still "complete" for this invocation — dead-end handling is the Supervisor's job on the next dispatch, not this agent's job to retry internally).
- `deps` is fully substitutable with fakes; test suite never requires live Kafka/Neo4j (`pytest -m "not live_infra"` passes for this whole module).

---

## 6. Full acceptance checklist (run before declaring this agent "done")

- [ ] Zero direct Neo4j writes anywhere in `src/agents/evidence_collection/` — verified by code review/grep, not just test (mirrors the ingestion plan's "no string-concatenated Cypher" verification discipline).
- [ ] Zero Quickwit imports/references anywhere in this module.
- [ ] `AgentVerdict` enum is reused from (or promoted to) a shared location — not duplicated.
- [ ] Every published `EvidenceCollectionFinding.discard_reason_codes` has exactly `len(kept_uids) + len(discarded_uids) + len(escalated_uids)` entries.
- [ ] `classify_event` never returns DISCARD when `canonical_host_id is None`.
- [ ] `classify_event` never re-invokes Drain3/SimHash/MiniBatchKMeans logic.
- [ ] `CaseContext` population query is APOC-bounded (max 3 hops / 100 nodes / 300 relationships) — confirmed via `PROFILE`/`EXPLAIN` against a synthetic large-subgraph fixture, no full label scan.
- [ ] Kafka partition key is `hash(canonical_host_id)`, confirmed unaffected by `case_id`.
- [ ] One finding published per invocation — confirmed via producer call-count assertion, not just message content inspection.
- [ ] Loop budget (`max_iterations`) enforced with `dead_end=True` on truncation, never an unbounded loop.
- [ ] Batch spanning multiple `case_id`s raises before any side effect (no partial Kafka publish, no partial classification).
- [ ] `agent_model_config.yaml` entry present under `evidence_collection_generation`, matching Master doc §2.5's model/provider assignment.
- [ ] All tests in `tests/agents/test_relevance_filter.py` and the Component 4 suite pass under `pytest -m "not live_infra"`.

---

## 7. Open items to resolve before finalizing (carry into next revision)

| Open issue | Why it's still open | Proposed resolution |
|---|---|---|
| Low-signal allowlist (`LOW_SIGNAL_CLASS_UIDS`) source of truth | v1 hardcodes a Python set; Master doc §9.4 establishes a per-role, hot-reloadable Operational Rule Engine as the pattern for exactly this kind of scoped rule table | Migrate to rule-engine-backed lookup once that service exists; keep the static table as the v1 fallback, not a permanent fixture |
| ESCALATE routing target | This plan assumes escalated UIDs eventually reach the Log Analysis Agent, but that dispatch edge isn't confirmed in the Supervisor's routing table | Needs an explicit Supervisor dispatch-rule addendum before this agent is considered fully integrated |
| `max_iterations` default value | Not yet specified numerically anywhere in the project docs | Should follow whatever loop-budget convention gets set project-wide for primary-tier agents (runtime harness §9.5) — do not pick an arbitrary number in isolation here |
| `CaseContext` staleness across a long-running case | `known_host_uids` is queried fresh each invocation, but no caching/TTL policy is defined | Low priority for v1 given the bounded query is cheap; revisit if profiling shows repeated invocations are DFKG-query-bound |

---

*End of Evidence Collection Agent implementation plan (v1). Any deviation from this document during implementation must be raised as an explicit change, not silently substituted.*
