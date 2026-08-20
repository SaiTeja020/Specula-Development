# Specula Stage 2 — Consolidated Implementation Plan

A unified plan synthesizing both validation review documents. Where the two sources diverge, this plan picks one approach (noted with rationale) so the IDE has a single source of truth.

---

## Source Reconciliation

| Issue | Doc 1 (`Defects_And_...`) | Doc 2 (`IMPLEMENTATION_CORRECTIONS_...`) | This Plan |
|---|---|---|---|
| C1 DISCARD | Inline comment-out | `_conjunctive_discard_path()` helper (Option A) | **Doc 2's helper** (more future-friendly; uncomment-once when Stage 4b ships) |
| M1 ReAct label | Comment-out YAML entry; keep function name | Delete YAML entry; rename to `run_evidence_collection_triage` | **Doc 2's approach** (delete + rename is cleaner and matches the actual utility role) |
| M2 Partition key | Integer `partition=N` (calc'd hash) | String `key="host:..."` | **Doc 2's string key** (avoids coupling to `num_partitions`; Kafka's default partitioner handles hashing) |
| N1 Auth check | `_is_routine_authentication()` helper (status, activity, off-hours, impossible-travel) | Inline `is_routine_authentication` (status, activity) | **Doc 1's helper** (more comprehensive, future-proof for Stage 4b) |
| N2 BFS misapply | Both align | Both align | Use indexed `MATCH (h:Host) WHERE h.case_id = $case_id` |
| N3 Trigger | §4 rewrite + new §4b rationale | §4 rewrite only | **Doc 1's expanded approach** (rationale section prevents regression) |
| N4 Canary | Both align | Both align | Replace "canary-token logic" → "heuristic pattern-matching" everywhere |
| N5 / Minor | Minor 1/2/3 split out | N5a/5b/5c grouped | Apply all three minor fixes |

---

## Executive Summary

| Severity | Count | Issues |
|---|---|---|
| **Critical** | 1 | C1 — DISCARD verdict silently unreachable |
| **Major** | 2 | M1 — Agent mislabeled ReAct, no LLM; M2 — Kafka partition key has no single-host enforcement |
| **Moderate** | 4 | N1 — Criterion 3 missing auth-status check; N2 — BFS applied to flat lookup; N3 — case-opened trigger undefined; N4 — canary-token misnaming |
| **Minor** | 3 | N5a — Defensive typing; N5b — Unused Kafka read path; N5c — `is_anomalous` mentioned but unused |

**Estimated effort:** ~10–15 hours, 1–2 engineers.

**Order:** C1 → M1 → M2 → N1 → N2 → N3 → N4 → N5 (strict dependency chain; N1 depends on C1's helper being in place).

---

## 1. Critical — C1: DISCARD Verdict Unreachable

**File:** `src/agents/evidence_collection/relevance_filter.py`

**Action:** Replace `classify_event()` with the disabled-v1 version. Move the full four-criterion logic to a separate `_conjunctive_discard_path()` helper (commented in usage, but syntactically live so Stage 4b can uncomment it without surprises).

```python
def classify_event(event: OCSFBaseEvent, ctx: CaseContext) -> RelevanceResult:
    """
    Evidence relevance classifier. Returns KEEP or ESCALATE in v1.

    DISCARD is INTENTIONALLY DISABLED until Stage 4b (entropy distillation /
    Drain3 clustering) ships. Criterion 4 (is_summary flag) is never true in
    Stage 2's ingestion output, making the full DISCARD conjunction unreachable.
    See Stage 2 plan §3, §6.

    Once Stage 4b adds is_summary=True to summaries, re-enable DISCARD by
    wiring classify_event() to call _conjunctive_discard_path() and asserting
    on the DISCARD result.

    TICKET: <link to Stage 4b tracking ticket>
    """
    host_id = event.canonical_host_id if hasattr(event, "canonical_host_id") else None

    if host_id is None:
        return RelevanceResult(
            uid=event.uid,
            verdict=AgentVerdict.ESCALATE,
            reason_code="ESCALATE_UNRESOLVED_HOST",
        )

    return RelevanceResult(
        uid=event.uid,
        verdict=AgentVerdict.KEEP,
        reason_code="KEEP_DEFAULT_V1_DISCARD_DISABLED_PENDING_STAGE_4B",
    )


def _conjunctive_discard_path(event: OCSFBaseEvent, ctx: CaseContext) -> RelevanceResult:
    """
    STAGE 4B: Wire into classify_event() once entropy distillation ships.
    All four criteria must hold for DISCARD.

    1. event.severity_id <= 1 (informational only)
    2. event.canonical_host_id is CONFIRMED absent from ctx.known_host_uids
    3. event.class_uid in LOW_SIGNAL_CLASS_UIDS AND event fields indicate
       routine case (e.g., Authentication with status == "Success" or
       activity_id == 1, no off-hours/impossible-travel flags)
    4. event.is_summary == True (set by Stage 4b entropy clustering)
    """
    host_id = event.canonical_host_id
    host_known = host_id in ctx.known_host_uids
    is_low_severity = event.severity_id <= 1
    is_low_signal_class = event.class_uid in LOW_SIGNAL_CLASS_UIDS
    is_pre_collapsed = bool(getattr(event, "is_summary", False))

    is_routine_case = _is_routine_authentication(event) if event.class_uid == 3002 else True

    if is_low_severity and (not host_known) and is_low_signal_class and is_routine_case and is_pre_collapsed:
        return RelevanceResult(
            uid=event.uid,
            verdict=AgentVerdict.DISCARD,
            reason_code="DISCARD_ALL_FOUR_CRITERIA_MET",
        )

    return RelevanceResult(
        uid=event.uid,
        verdict=AgentVerdict.KEEP,
        reason_code="KEEP_DEFAULT",
    )
```

**Tests** — `tests/agents/test_relevance_filter.py`:

```python
def test_discard_path_disabled_until_stage_4b_regression():
    """
    REGRESSION: DISCARD must be unreachable in v1. When Stage 4b lands, this
    test should fail with DISCARD returned — at that point, re-wire
    classify_event() to use _conjunctive_discard_path().
    """
    event = OCSFBaseEvent(
        uid="test-uid-for-stage-4b",
        severity_id=1,
        class_uid=3002,
        canonical_host_id="unknown-host-12345",
        is_summary=True,  # would qualify if Stage 4b were live
    )
    ctx = CaseContext(case_id="test-case", known_host_uids={"known-host-1"})

    result = classify_event(event, ctx)

    assert result.verdict == AgentVerdict.KEEP
    assert "V1_DISCARD_DISABLED_PENDING_STAGE_4B" in result.reason_code


def test_discard_conjunction_v1_disabled_but_documented_for_stage_4b():
    """Sanity: _conjunctive_discard_path exists and is callable for Stage 4b."""
    from src.agents.evidence_collection.relevance_filter import _conjunctive_discard_path
    assert callable(_conjunctive_discard_path)
```

**Doc update** — `Specula_Stage2_Ingestion_Implementation_Plan.md` §9: add a "DISCARD path disabled in Evidence Collection v1" subsection stating that v1 only returns KEEP or ESCALATE, and that 0% of traffic will be DISCARD until Stage 4b.

---

## 2. Major — M1: Agent Mislabeled as ReAct; No LLM Calls

**Files:** `src/agents/evidence_collection/agent.py`, `agent_model_config.yaml`, plan doc §1 & §5.2, test file.

**Action:**

1. **`agent.py`** — rename `run_evidence_collection` → `run_evidence_collection_triage`. Update docstring to explicitly state: *"Deterministic evidence-relevance triage filter, not a ReAct agent. Does not invoke any LLM; this is a utility component, not an agent role."*

2. **`agent_model_config.yaml`** — **delete** the `evidence_collection_generation` block entirely (not comment out — the component doesn't route through the model layer).

3. **Plan doc §1** — replace "ReAct agent, Qwen2.5-7B-Instruct" with "Deterministic rules classifier (NO LLM)."

4. **Plan doc §5.2** — add a subsection titled "No model registration required" stating this component does not use the model layer.

5. **Test** — `tests/agents/test_evidence_collection_agent.py` (or `test_evidence_collection.py`):

```python
def test_no_llm_calls_made(mock_model_provider, fake_deps):
    """Regression: Evidence collection triage is deterministic. No LLM calls."""
    from src.agents.evidence_collection.agent import run_evidence_collection_triage

    state = EvidenceCollectionState(
        case_id="test-case",
        trace_id="trace-123",
        batch_uids=["uid-1", "uid-2"],
        kept_uids=[],
        discarded_uids=[],
        escalated_uids=[],
        discard_reason_codes={},
        iteration_count=0,
        max_iterations=10,
        dead_end=False,
        status="running",
    )

    run_evidence_collection_triage(state, fake_deps)
    mock_model_provider.assert_not_called()
```

---

## 3. Major — M2: Kafka Partition Key Has No Single-Host Enforcement

**Files:** `src/agents/evidence_collection/agent.py`, `kafka_publisher.py`, plan doc §4.2 & §5, test file.

**Action:**

1. **`agent.py`** — add a single-host raise **next to** the existing single-`case_id` raise:

```python
host_ids_in_batch = {deps.lookup_host_id(uid) for uid in state["batch_uids"]}
if len(host_ids_in_batch) > 1:
    raise ValueError(
        f"EvidenceCollectionTriage invoked with a batch spanning multiple hosts: "
        f"{host_ids_in_batch}. Supervisor dispatch bug — one host per batch. "
        f"Partition key is host_id; cross-host batches break per-host ordering. "
        f"Split at the dispatch boundary."
    )
```

2. **`kafka_publisher.py`** — update `publish_finding()` to use a string partition key:

```python
def publish_finding(state: EvidenceCollectionState, producer) -> None:
    """
    Publishes to FINDING_TOPIC, partitioned by hash(canonical_host_id).

    Batches are guaranteed single-host by run_evidence_collection_triage's
    enforcement. The partition key is computed from the (only) host in the batch.
    This preserves per-host chronological ordering, matching ingestion's
    partitioning discipline (Stage 2 plan §6.4).
    """
    if not state["batch_uids"]:
        raise ValueError("Cannot publish empty batch")

    first_uid = state["batch_uids"][0]
    host_id = producer.deps.lookup_host_id(first_uid)
    partition_key = f"host:{host_id}"

    finding = build_finding(state)
    producer.send(FINDING_TOPIC, value=finding.dict(), key=partition_key)
```

3. **Plan doc §4.2** — update the "Partition Key" caption to state batches are single-host by Supervisor enforcement.

4. **Plan doc §5 "Mistakes to avoid"** — add: *"Do not allow multi-host batches; the partition key is host_id and arbitrary host selection loses ordering guarantees. Enforce at the dispatch boundary with an explicit raise."*

5. **Test** — `test_multi_host_batch_raises`:

```python
def test_multi_host_batch_raises():
    state = EvidenceCollectionState(
        case_id="test-case",
        batch_uids=["uid-host-1", "uid-host-2"],
        # ... other fields
    )
    fake_deps = FakeDeps()
    fake_deps.lookup_host_id.side_effect = lambda uid: (
        "host-1" if "host-1" in uid else "host-2"
    )
    with pytest.raises(ValueError, match="spanning multiple hosts"):
        run_evidence_collection_triage(state, fake_deps)
```

---

## 4. Moderate — N1: Criterion 3 Code Doesn't Implement Its Docstring

**File:** `src/agents/evidence_collection/relevance_filter.py`

**Action:** Add `_is_routine_authentication()` helper and call it from `_conjunctive_discard_path()`:

```python
ROUTINE_AUTH_ACTIVITY_CODES: set[int] = {1, 2}  # Logon, Logoff
ROUTINE_AUTH_STATUS_CODES: set[str] = {"Success"}


def _is_routine_authentication(event: OCSFBaseEvent) -> bool:
    """
    Returns True iff Authentication (class_uid 3002) is routine (eligible for
    DISCARD). Returns False for failed logons, off-hours access, or
    impossible-travel flags — those are high-signal and MUST NOT be discarded.
    """
    if event.class_uid != 3002:
        return False

    status = getattr(event, "status", None)
    if status not in ROUTINE_AUTH_STATUS_CODES:
        return False

    activity_id = getattr(event, "activity_id", None)
    if activity_id not in ROUTINE_AUTH_ACTIVITY_CODES:
        return False

    if getattr(event, "is_off_hours", False) or getattr(event, "is_impossible_travel", False):
        return False

    return True
```

Wire it into `_conjunctive_discard_path()` (already shown in C1 above).

**Tests** — `tests/agents/test_relevance_filter.py`:

```python
def test_authentication_failure_never_discarded():
    """Failed authentication is high-signal; criterion 3 fails -> KEEP."""
    event = OCSFBaseEvent(
        uid="failed-auth-uid",
        severity_id=1,
        class_uid=3002,
        canonical_host_id="new-host",
        status="Failure",
        activity_id=1,
        is_summary=True,
    )
    ctx = CaseContext(case_id="test-case", known_host_uids={"known-host"})
    result = _conjunctive_discard_path(event, ctx)
    assert result.verdict == AgentVerdict.KEEP


def test_authentication_success_off_hours_not_routine():
    event = OCSFBaseEvent(
        uid="off-hours-uid",
        severity_id=1,
        class_uid=3002,
        canonical_host_id="new-host",
        status="Success",
        activity_id=1,
        is_off_hours=True,
        is_summary=True,
    )
    assert _is_routine_authentication(event) is False
```

---

## 5. Moderate — N2: CaseContext Misapplies BFS to Flat Lookup

**Files:** `src/agents/evidence_collection/relevance_filter.py` (docstring), `src/dfkg/cypher_queries.py` (or wherever `load_case_context` lives), plan doc §3.1.

**Action:**

1. **`relevance_filter.py`** — update `CaseContext` docstring to state: *"Populated by indexed case_id-scoped MATCH query (NOT a bounded BFS — that's reserved for GraphRAG multi-hop context retrieval)."*

2. **DFKG query layer** — replace the APOC-bounded BFS with:

```python
def query_known_hosts_for_case(case_id: str) -> set[str]:
    """
    Retrieve all host UIDs tagged with a given case_id.

    Indexed MATCH — flat property lookup, not a multi-hop traversal.
    BFS-bounding is for GraphRAG-style multi-hop context, not flat lookups.

    Cypher: MATCH (h:Host) WHERE h.case_id = $case_id RETURN h.uid
    """
    cypher = "MATCH (h:Host) WHERE h.case_id = $case_id RETURN h.uid"
    results = neo4j_session.run(cypher, {"case_id": case_id})
    return {record["uid"] for record in results}
```

3. **Plan doc §3.1** — update the `CaseContext` docstring and remove references to BFS-bounding in this context.

---

## 6. Moderate — N3: `case.opened` Trigger Undefined

**File:** `Specula_Stage2_Ingestion_Implementation_Plan.md` §4 (and add new §4b).

**Action:** Replace the "after enough evidence has landed" framing with the **alert-triggered model**:

1. **Case-id assignment is ingestion-time:** `ActiveCasesCache` (Redis, populated externally) maps `trace_id` → `case_id`. Ingestion tags evidence as it flows; it doesn't decide when a case starts.

2. **Case-open is external:** SIEM alert, investigator query, or equivalent external system publishes `case.opened` to Kafka topic `specula.cases.opened`. This is the Supervisor's entry point.

3. **Supervisor consumes and starts:** It subscribes to `specula.cases.opened`; on a message, it initializes graph state with just `case_id`/`trace_id` and begins investigation. Evidence for that case is already tagged in DFKG.

**Add new §4b — Alert-Triggered Model Rationale:**

> The case-open trigger is external to ingestion, not ingestion-driven. Ingestion is a background, always-on process; investigation is event-driven. Ingestion should not guess "enough has landed" — that's fragile and impossible to get right (10 events? 100? per host? per hour?). The external system is the authoritative source for "is investigation happening?" This aligns with Master_doc §4.3 and the Stage 0 architecture.

Also add a Stage 1 TODO comment in the Supervisor skeleton noting the future entry-point change from `graph.invoke(raw_input=...)` to a Kafka consumer on `specula.cases.opened`.

---

## 7. Moderate — N4: "Canary-Token Logic" Misnamed for Static Ingestion Detection

**Files:** `Specula_Stage2_Ingestion_Implementation_Plan.md` §1, §3 (Step 2), §7 (Fixture 3); `src/ingestion/security_gate.py` (or `injection_detector.py`) docstring.

**Action:** Search/replace **every** instance of "canary-token logic" → "heuristic pattern-matching" with a clarification that canary tokens belong at the agent-output/guardrail layer (Stage 3+), where completions exist to inspect.

Specifically:
- §1 Decisions Locked table: rewrite the Injection detection row.
- §3 Step 2 description: add a note that this is NOT canary-token detection.
- §7 Fixture 3: rename to "Prompt-injection payload (heuristic detection, not canary)".
- `security_gate.py` / `injection_detector.py` docstring: state this is purely static pattern-matching on raw evidence text, and explain where canary-token logic actually applies.

---

## 8. Minor — N5a/b/c Cleanup

### N5a. Defensive `getattr`/`hasattr` on Typed Schema

**File:** `src/schemas/ocsf_base.py`

Declare the fields explicitly:

```python
class OCSFBaseEvent(BaseModel):
    uid: str
    severity_id: int
    class_uid: int
    canonical_host_id: Optional[str] = None
    is_summary: bool = False
    status: Optional[str] = None
    activity_id: Optional[int] = None
    is_off_hours: bool = False
    is_impossible_travel: bool = False
    # ... other fields
```

Then in `relevance_filter.py`, drop the `hasattr`/`getattr` defensive calls — access fields directly. If the schema is external/immutable, wrap with a single `_safe_field(event, name, default)` helper and use it consistently.

### N5b. Unused Kafka Read Path in Architecture Diagram

**File:** Evidence Collection Agent plan §1.

Replace the ambiguous "Reads: Kafka consumer group OR mcp-dfkg-cypher" with:

```
Reads: DFKG via mcp-dfkg-cypher (UID-based lookup for triage).
[Kafka-consumer path deferred to Stage 3+ if direct log streaming is needed.]
```

### N5c. `is_anomalous` Mentioned But Not Used

**File:** Evidence Collection Agent plan header.

Replace the "consumes `is_summary`/`is_anomalous` flags" line with:

```
consumes `is_summary` flag already produced by Component 6 (entropy clustering).
Note: `is_anomalous` is deferred for future expansion; not currently used in v1.
```

---

## 9. Implementation Sequencing & Timeline

| Order | Issue | Effort | Dependencies |
|---|---|---|---|
| 1 | **C1** — DISCARD gate | 2–4 h | none |
| 2 | **M1** — ReAct label | 1 h | C1 (so `_conjunctive_discard_path` exists for naming) |
| 3 | **M2** — Single-host batch | 1–2 h | none |
| 4 | **N1** — Auth-status check | 1–2 h | C1 (helper structure) |
| 5 | **N2** — DFKG indexed lookup | 1 h | none |
| 6 | **N3** — case.opened trigger | 1 h | none (doc only) |
| 7 | **N4** — Terminology fix | 0.5 h | none (doc only) |
| 8 | **N5a/b/c** — Minor cleanups | 1 h | N1 (so auth fields are in schema) |
| | **Total** | **~10–14 h** | |

---

## 10. Files-to-Modify Summary

| File | C1 | M1 | M2 | N1 | N2 | N3 | N4 | N5 |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `src/agents/evidence_collection/relevance_filter.py` | ✓ | | | ✓ | ✓ | | | ✓ |
| `src/agents/evidence_collection/agent.py` | | ✓ | ✓ | | | | | |
| `src/agents/evidence_collection/kafka_publisher.py` | | | ✓ | | | | | |
| `src/schemas/ocsf_base.py` | | | | | | | | ✓ |
| `src/dfkg/cypher_queries.py` (or DFKG client) | | | | | ✓ | | | |
| `src/ingestion/security_gate.py` | | | | | | | ✓ | |
| `agent_model_config.yaml` | | ✓ | | | | | | |
| `Specula_Stage2_Ingestion_Implementation_Plan.md` | ✓ | | | | | ✓ | ✓ | |
| `specula_evidence_collection_agent_plan.md` | | ✓ | ✓ | | ✓ | | | ✓ |
| `tests/agents/test_relevance_filter.py` | ✓ | | | ✓ | ✓ | | | |
| `tests/agents/test_evidence_collection_agent.py` | | ✓ | ✓ | | | | | |

---

## 11. Acceptance Checklist (Run In Order)

### Critical
- [ ] C1: DISCARD path disabled, `_conjunctive_discard_path()` exists and is syntactically valid
- [ ] C1: `test_discard_path_disabled_until_stage_4b_regression` passes
- [ ] C1: `test_discard_conjunction_v1_disabled_but_documented_for_stage_4b` passes
- [ ] M1: `agent_model_config.yaml` has no `evidence_collection_generation` entry
- [ ] M1: Function renamed to `run_evidence_collection_triage` with deterministic docstring
- [ ] M1: `test_no_llm_calls_made` passes

### Major
- [ ] M2: `run_evidence_collection_triage` raises on multi-host batch
- [ ] M2: `kafka_publisher.py` uses `key="host:<host_id>"` string partition
- [ ] M2: `test_multi_host_batch_raises` passes

### Moderate
- [ ] N1: `_is_routine_authentication` checks status, activity, off-hours, impossible-travel
- [ ] N1: `test_authentication_failure_never_discarded` passes
- [ ] N1: `test_authentication_success_off_hours_not_routine` passes
- [ ] N2: `load_case_context` uses indexed `MATCH (h:Host) WHERE h.case_id = $case_id` (no APOC BFS)
- [ ] N2: CaseContext docstring states "indexed lookup, not BFS"
- [ ] N3: Stage 2 plan §4 states alert-triggered model; §4b rationale added
- [ ] N4: All "canary-token logic" replaced with "heuristic pattern-matching"

### Minor
- [ ] N5a: `OCSFBaseEvent` declares `canonical_host_id`, `is_summary`, `status`, `activity_id`, `is_off_hours`, `is_impossible_travel`; defensive `getattr` removed or wrapped consistently
- [ ] N5b: Plan §1 removes/clarifies the unused Kafka-consumer read path
- [ ] N5c: Plan header clarifies `is_anomalous` is not used in v1

### Code Quality
- [ ] Zero direct Neo4j writes in `src/agents/evidence_collection/`
- [ ] Zero Quickwit imports in evidence_collection module
- [ ] All existing unit tests pass (`pytest -m "not live_infra"`)
- [ ] Schema validation tests pass on malformed/tampered events

---

## 12. Pre-Handoff Validation

Before handing to the IDE, confirm:

- [ ] All file paths in this plan match the actual codebase layout
- [ ] `FakeDeps`, `FakeNeo4j`, `FakeKafkaTopic` test fixtures exist (or create them)
- [ ] `OCSFBaseEvent` schema location confirmed
- [ ] Kafka producer/consumer interface matches the `producer.send(topic, value=, key=)` signature used
- [ ] Master_doc §10 is available for case-tagging index reference
- [ ] Stage 1 skeleton is available for Supervisor entry-point cross-reference

---

**End of Consolidated Implementation Plan**

The plan above is the single source of truth for the IDE. Where Doc 1 and Doc 2 disagreed, one approach was chosen (rationale in the reconciliation table) so the agent doesn't have to re-derive a choice mid-implementation. C1 must be fixed first; everything else is a clean dependency chain.
