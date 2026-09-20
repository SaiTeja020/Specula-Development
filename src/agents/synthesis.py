"""Plain-English synthesis step for the Specula investigation pipeline.

This module has ONE responsibility: take the completed SpeculaState (after
final_output_join) and produce a human-readable answer that a non-technical
user can understand.

It does NOT perform new forensic retrieval. It summarises what the agents
already found. The LLM call here is ONLY for formatting — not for reasoning
about new evidence.

Epistemic language is enforced:
  - "observed" / "the evidence shows" for directly supported facts
  - "possible" / "may indicate" for inferences
  - "the available evidence does not establish" for unsupported claims
"""
from __future__ import annotations

import logging
from typing import Any, Optional, TypedDict

from src.agents import investigation_trace

logger = logging.getLogger("Synthesis")


class InvestigationResult(TypedDict):
    """Clean structured output contract for a completed investigation."""
    case_id: str
    query: str
    status: str               # completed | partial | failed
    answer: str               # plain-English answer for the user
    evidence_uids: list       # UID provenance list
    agents_used: list         # agent roles that contributed findings
    human_intervention: bool  # True if HITL was triggered
    debate_outcome: Optional[str]  # converged | round_cap_exhausted | None
    validation_passed: Optional[bool]  # UID hallucination check result
    limitations: list         # known gaps in this result


_SYNTHESIS_SYSTEM_PROMPT = """\
You are a DFIR (Digital Forensics and Incident Response) analyst summarising an
investigation for a non-technical stakeholder.

You will receive:
- The original investigation question
- Verified forensic findings from specialised agents
- A final forensic report (already drafted)

Your task is to produce a SHORT, CLEAR plain-English summary (3–6 sentences).

MANDATORY RULES:
1. Use "observed" or "the evidence shows" only for claims directly supported by the findings.
2. Use "may indicate", "possible", "consistent with" for inferences.
3. Use "the available evidence does not establish" for things not proven.
4. Do NOT invent entities, IPs, process names, or timestamps.
5. Do NOT reproduce raw Cypher, JSON, UIDs, or internal traces.
6. Do NOT claim certainty when the agents expressed uncertainty.
7. If the investigation was incomplete (HITL paused, debate unresolved), say so.
8. Format:

Summary:
<1-2 sentences: what was investigated and the top-level finding>

Evidence:
<bullet points: key observed facts, with source agent role in brackets>

Conclusion:
<1-2 sentences: overall assessment, with explicit uncertainty>

Limitations:
<bullet points: what could not be determined, or what requires further investigation>
"""


def synthesize_plain_english(
    state: dict,
    query: str,
    llm_call_fn=None,
) -> InvestigationResult:
    """Convert completed SpeculaState into a plain-English InvestigationResult.

    Args:
        state:        Final SpeculaState dict after graph completion.
        query:        The original user investigation query.
        llm_call_fn:  Optional callable(prompt: str) -> str. If None, uses
                      get_llm() from config.py. Allows test injection.

    Returns:
        InvestigationResult TypedDict.
    """
    case_id = state.get("case_id", "unknown")
    case_status = state.get("case_status", "unknown")

    # --- Collect agent findings ---
    findings = state.get("findings", [])
    agents_used = list({f.get("agent_role", "unknown") for f in findings if f.get("agent_role")})
    evidence_uids = list({
        uid
        for f in findings
        for uid in (f.get("dfkg_refs") or [])
        if uid
    })

    # --- Detect HITL involvement ---
    human_intervention = bool(state.get("hitl_decision"))
    debate_outcome = state.get("debate_outcome")

    # --- Determine status ---
    if state.get("hitl_decision") == "reject":
        status = "rejected"
    elif case_status == "closed":
        status = "completed"
    elif case_status in ("hitl_review",):
        status = "partial"
    else:
        status = "completed" if state.get("final_output_ref") else "partial"

    # --- Build synthesis prompt ---
    report_output = state.get("report_output") or ""
    timeline_artifact = state.get("timeline_artifact") or ""

    findings_summary = _format_findings_for_synthesis(findings)

    synthesis_prompt = f"""{_SYNTHESIS_SYSTEM_PROMPT}

--- INVESTIGATION QUESTION ---
{query}

--- AGENT FINDINGS ---
{findings_summary}

--- FORENSIC REPORT ---
{report_output[:2000] if report_output else "(no report generated)"}

--- TIMELINE ARTIFACT ---
{timeline_artifact[:500] if timeline_artifact else "(no timeline generated)"}

--- HITL STATUS ---
Human intervention: {human_intervention}
HITL decision: {state.get("hitl_decision", "none")}

--- DEBATE STATUS ---
Debate outcome: {debate_outcome or "not triggered"}
Judge verdict: {state.get("judge_verdict", "none")}

Produce the plain-English investigation summary now.
"""

    # --- Generate plain-English answer ---
    if llm_call_fn is not None:
        answer = llm_call_fn(synthesis_prompt)
    else:
        answer = _call_llm_for_synthesis(synthesis_prompt, case_id)

    # --- Determine limitations ---
    limitations = _determine_limitations(state, agents_used, debate_outcome)

    logger.info(
        f"Synthesis complete: case={case_id}, status={status}, "
        f"agents={agents_used}, uids={len(evidence_uids)}"
    )

    return InvestigationResult(
        case_id=case_id,
        query=query,
        status=status,
        answer=answer,
        evidence_uids=evidence_uids,
        agents_used=agents_used,
        human_intervention=human_intervention,
        debate_outcome=debate_outcome,
        validation_passed=None,  # filled by caller if UID validation was run
        limitations=limitations,
    )
    
    investigation_trace.record_event("synthesis", "synthesis", {"result": result})
    return result


def _format_findings_for_synthesis(findings: list) -> str:
    """Format agent findings into a readable block for the synthesis prompt."""
    if not findings:
        return "(no findings available)"

    lines = []
    seen_roles = set()
    for f in findings[-20:]:  # cap at 20 most recent
        role = f.get("agent_role", "unknown")
        summary = (f.get("summary") or "").strip()
        if not summary or role in ("supervisor",):
            continue
        # One entry per role (latest wins — findings list is append-ordered)
        if role not in seen_roles:
            lines.append(f"[{role}] {summary[:600]}")
            seen_roles.add(role)

    return "\n\n".join(lines) if lines else "(no substantive findings)"


def _call_llm_for_synthesis(prompt: str, case_id: str) -> str:
    """Call the configured LLM to produce the plain-English synthesis."""
    try:
        from src.agents.config import get_llm
        llm = get_llm("report_generation", case_id=case_id)
        response = llm.invoke(prompt)
        if hasattr(response, "content"):
            content = response.content
            if isinstance(content, list):
                return "".join(
                    c.get("text", "") if isinstance(c, dict) else str(c)
                    for c in content
                )
            return str(content).strip()
        return str(response).strip()
    except Exception as exc:
        logger.error(f"Synthesis LLM call failed: {exc}")
        return _fallback_synthesis(prompt)


def _fallback_synthesis(prompt: str) -> str:
    """Return a minimal honest synthesis when the LLM call fails."""
    return (
        "Summary:\n"
        "The investigation completed, but the final synthesis step could not "
        "generate a formatted plain-English response (LLM unavailable).\n\n"
        "Evidence:\n"
        "- Agent findings were collected. See evidence_uids and agents_used fields.\n\n"
        "Conclusion:\n"
        "Review the raw report_output field for the full forensic report.\n\n"
        "Limitations:\n"
        "- Plain-English formatting unavailable in this environment."
    )


def _determine_limitations(
    state: dict,
    agents_used: list,
    debate_outcome: Optional[str],
) -> list:
    """Identify investigation limitations to surface to the user."""
    limitations = []

    all_primary = {"evidence_collection", "log_analysis", "network_forensics"}
    missing_primary = all_primary - set(agents_used)
    if missing_primary:
        limitations.append(
            f"Primary agents not dispatched: {', '.join(missing_primary)}. "
            "Their evidence domains were not analysed."
        )

    if debate_outcome == "round_cap_exhausted":
        limitations.append(
            "The evidentiary debate reached the maximum round limit without convergence. "
            "The conclusion required human review."
        )

    if state.get("hitl_decision") == "reject":
        limitations.append(
            "The investigation was rejected by a human analyst and was not completed."
        )

    if state.get("guardrail_fail_tier") is not None:
        tier = state["guardrail_fail_tier"]
        limitations.append(
            f"Guardrail Tier {tier} flagged a potential issue in the output. "
            "The result was reviewed by a human analyst before finalisation."
        )

    if not state.get("report_output"):
        limitations.append("No forensic report was generated (pipeline may have been incomplete).")

    if not state.get("findings"):
        limitations.append("No agent findings were recorded. The DFKG may not contain relevant evidence for this case.")

    return limitations
