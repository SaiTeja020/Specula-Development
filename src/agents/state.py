"""Specula LangGraph State Schema — §2 of implementation plan.

Every field written by more than one node in the same graph layer (parallel
fan-out) gets an append-reducer. Every field written by exactly one node gets
plain overwrite. Fields spanning sequential stages are never touched by two
different nodes without an explicit edge-order dependency.
"""
from __future__ import annotations

import operator
from typing import Annotated, Optional

from typing_extensions import TypedDict


class SpeculaState(TypedDict, total=False):
    """Full shared graph state for the Specula orchestration skeleton."""

    # §2.1 Core case metadata (single-writer, no merge needed)
    case_id: str
    trace_id: str
    input_type: str                          # siem_alert | investigator_query
    raw_input: str
    case_status: str                         # open | primary_tier | specialist_tier | synthesis | debate | guardrail | hitl_review | report | closed

    # §2.2 Findings (multi-writer, append-only reducer)
    findings: Annotated[list, operator.add]

    # §2.3 Dead-end / dispatch control
    dead_end_detected: bool
    dead_end_categories: list                # Supervisor sole writer; valid: "memory" | "identity" | "cloud_container" | "malware" | "insider"
    next_agents: list                        # Supervisor routing decision
    specialists_dispatched: list             # set once by Supervisor before fan-out
    specialists_completed: Annotated[list, operator.add]  # append for fan-in check

    # §2.4 Sequential synthesis
    timeline: Optional[dict]                 # Timeline Reconstruction only
    attribution: Optional[dict]              # Threat Attribution only (after timeline non-null)

    # §2.5 Debate subsystem
    debate_round: int
    proponent_argument: Optional[str]        # overwritten each round
    critic_argument: Optional[str]           # overwritten each round
    judge_verdict: Optional[str]             # accept | reject, overwritten each round
    confidence_delta: Optional[float]        # undefined on round 1
    debate_history: Annotated[list, operator.add]  # one entry per closed round
    debate_outcome: Optional[str]            # converged | round_cap_exhausted

    # §2.6 Guardrail subsystem
    guardrail_tier1_result: Optional[str]    # pass | fail
    guardrail_tier2_result: Optional[str]
    guardrail_tier3_result: Optional[str]
    guardrail_fail_tier: Optional[int]       # which tier failed, if any

    # §2.7 HITL
    hitl_required: bool
    hitl_case_snapshot: Optional[dict]
    hitl_decision: Optional[str]             # approve | reject | clarify

    # §2.8 Output
    report_output: Optional[str]             # Report Generation only
    timeline_artifact: Optional[str]         # Timeline Artifact Generation only
    final_output_ref: Optional[str]          # set once both converge

    # §2.9 Per-agent ReAct scratch (primary verification surface)
    agent_traces: Annotated[list, operator.add]

    # §2.10 Test injection control (production code never sets this field).
    # Used by dead_end_detector and other Stage 3+ components to short-circuit
    # real heuristics with deterministic values during unit testing.
    test_control: Optional[dict]
