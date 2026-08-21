# Supervisor Agent Test Suite

This test suite covers the Supervisor Agent's contracts, orchestration routing logic, and guardrail enforcement policies to ensure strict compliance with the architectural blueprints.

### File Breakdown

* **`test_supervisor_entry.py`**: Verifies the Kafka consumer contract. Ensures `specula.cases.opened` events produce minimal state containing `case_id` and `trace_id` rather than raw evidence payloads, and tests that test-control flags are correctly parsed.
* **`test_dispatch_tier.py`**: Validates the parallel dispatching of primary-tier agents and the conditional execution of the specialist tier based on dead-end heuristic triggers.
* **`test_dead_end_heuristic.py`**: A vital regression guard that ensures dead-end logic evaluates agent finding velocity exclusively, explicitly forbidding reliance on Neo4j APOC database triggers for dead-end identification.
* **`test_synthesis_wait.py`**: Validates the sequential gating between the Timeline Reconstruction (TR) and Threat Attribution (TA) nodes, enforcing that downstream synthesis strictly waits on specialist completion.
* **`test_debate_handoff.py`**: Enforces the ACH Debate state constraints, ensuring only minimal UIDs pass through the LangGraph state while full argument payloads are correctly stashed in the Redis cache to prevent state bloat.
* **`test_hitl_escalation.py`**: Tests the Human-In-The-Loop escalation thresholds (confidence < 0.7, containment actions, blast radius, debate non-convergence) and enforces the cycle bounds that transition cases to `MANUAL_OVERRIDE_REQUIRED` rather than bouncing indefinitely.
* **`test_skill_governance.py`**: Checks that the Supervisor introspects the dynamic versioned skill manifest rather than defaulting to hardcoded agent/tool arrays, successfully blocking out-of-scope access.
* **`test_regression_guards.py`**: Protects the explicitly resolved open-issues regarding TR/TA wait condition enforcement and strict HITL attempt cycle limits.
