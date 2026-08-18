# Specula Skeleton — Review Against Stage 1 Exit Criteria

## Verdict

The **build** (nodes.py, graph.py, hitl_api.py, kafka_utils.py, guardrails.py) is structurally correct against the implementation plan — topology, `Send` fan-out, `Command` routing, and the dual-entry HITL fix are all present and match spec.

The **test suite** does not yet prove this. It currently verifies roughly half of the Stage 1 plan's §11 exit criteria; the other half either has a stub test (`pass`, no assertions) or is structurally impossible to verify with the current test setup (no Kafka, no Neo4j, no persistent checkpointer). Treat "tests pass" and "skeleton is verified" as two different claims right now — they are not the same thing yet.

## Exit-Criteria Coverage Table

| Plan §11 criterion | Covered? | Gap |
|---|---|---|
| 1. Dead-end toggled both ways reaches final output | ✅ Yes | — |
| 2. `agent_traces` correct, in order, distinguishable | ⚠️ Partial | Order never checked, only membership |
| 3. Debate loop: reject→loop-back AND round-cap exhaustion both exercised | ❌ No | Reject→loop-back test is `pass`; stub can't currently express "reject once then accept" |
| 4. Guardrail fail→HITL at each tier, resume on approve/reject/clarify | ⚠️ Partial | Never confirms lower tiers didn't run (short-circuit); never tests genuine (non-forced) detection |
| 5. Kafka topics + Neo4j dedup'd writes | ❌ No | No integration test exists at all |
| 6. HITL resume survives process restart | ❌ No | `InMemorySaver` only proves same-process resume |

## Required Changes, in Priority Order

### 1. (Blocking) Add per-round control to the stub Judge
Current `FORCE_JUDGE_REJECT` rejects every round unconditionally, which makes it impossible to test "reject once, then converge" separately from full 3-round exhaustion. Add a second flag:

- `FORCE_JUDGE_REJECT_ROUNDS:N` — reject rounds `1..N`, accept from round `N+1` onward
- Keep `FORCE_JUDGE_REJECT` as-is for the exhaustion case

This is a source change in the stub agent logic (`nodes.py`'s judge node), not a test-only fix — the test cannot verify real behavior that the stub is incapable of producing.

### 2. Fix `TestDebateLoop.test_reject_cycles_back`
Once (1) is done, this needs real assertions: Proponent fires exactly twice, `debate_round` reaches 2, `judge_verdict` is `reject` after round 1 and `accept` after round 2, `debate_outcome == "converged"`.

### 3. Add short-circuit assertions to guardrail tests
For each tier-failure test, assert that **later tiers did not run**: e.g. on Tier 1 failure, assert `guardrail_tier2_result is None` and `guardrail_tier3_result is None`, not just that `guardrail_fail_tier == 1`.

### 4. Add genuine-detection tests for Tier 1 / Tier 2
Test the actual regex/embedding logic with real malicious-shaped content (e.g. a Cypher-injection string, a "ignore previous instructions" phrase) *without* the `FORCE_*` flag, and confirm it fails on its own. Also test that clean content passes without the flag. Right now the 12 regex rules and the cosine-similarity check are completely unexercised by anything except a hardcoded bypass flag.

### 5. Add order-checking to `agent_traces` verification
Assert a partial order, not full membership only — e.g. `supervisor` index < `evidence_collection` index < `primary_tier_join`-dependent nodes < `timeline_reconstruction` index < `threat_attribution` index < `proponent` index, etc.

### 6. Add a Kafka-unreachable regression test
Point the producer at an invalid broker address and confirm the graph still completes end-to-end with no unhandled exception — this is the only way to actually validate the "degrades silently" design claim rather than just asserting it in prose.

### 7. Add an integration test suite (separate file, requires docker-compose infra)
Unit tests with stub LLM + `InMemorySaver` **cannot** verify criteria 5 and 6 by construction — these need real Kafka, real Neo4j, and a real persistent checkpointer (Redis or Postgres-backed, not in-memory). This should be a separate, explicitly-marked test file (e.g. `pytest.mark.integration`) that is skipped by default in CI but run before declaring Stage 1 complete.

Specifically this suite must prove:
- A finding published by an agent node is actually consumable off its Kafka topic
- The DFKG consumer writes a node/edge into a real Neo4j instance
- Replaying the same finding twice does not create a duplicate node (the `Entity.uid` uniqueness constraint added to `schema_constraints.cypher` is never currently tested against anything)
- A HITL interrupt survives an actual process restart (kill and restart the Python process / worker, then issue the resume call from a fresh process) — this is the one criterion that structurally cannot be satisfied by any unit test, no matter how well-written

## Bottom Line

Do not treat the current green test run as "Stage 1 verified." Fix items 1–6 in the unit suite (all achievable without new infra), then add the integration suite in item 7 before marking Stage 1 exit criteria as met. Items 5 and 6 from the original plan are currently **unverified, not verified-and-passing** — there's a real difference between "we didn't write a test for this" and "we tested it and it works," and right now it's the former.
