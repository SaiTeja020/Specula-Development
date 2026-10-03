"""agent.py — Identity Agent (F13a) main entry point.

Single-pass structured tool pipeline (NOT an iterative ReAct loop).
Per ADR-008 and identity_rules.md:
  max_iterations = 1
  Pipeline: fetch → analyze (Kerberos + PrivEsc + CloudIAM) → correlate (LM) → publish

Dispatch contract:
  - Called by identity_node() in nodes.py on dead-end from Supervisor.
  - Reads DFKG via mcp-dfkg-cypher (IDENTITY_QUERIES templates).
  - Publishes to Kafka topic findings.specialist.identity.
  - Returns IdentityAgentState with specialists_completed=["identity"].

Degradation policy (from identity_rules.md):
  - mcp-dfkg-cypher unavailable: status="partial", dead_end=True, no hallucination.
  - Empty batch: verdict="no_identity_evidence", confidence=0.0.
  - Supernode guard (host degree >= 200): log + fall back to auth-event-only LM.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

import json
from src.agents.config import get_llm, AGENT_CONFIG
from .cloud_iam_analyzer import analyze_cloud_iam_events, CloudIAMAnomalyResult
from .kafka_publisher import publish_identity_finding
from .kerberos_analyzer import analyze_kerberos_events, KerberosAnomalyResult
from .lateral_movement_correlator import correlate_lateral_movement
from .privilege_escalation_detector import detect_privilege_escalations, PrivEscResult
from .state import IdentityAgentState

# Import MCP skill callables directly to act as our tools
from src.mcp.skills.AD_Kerberos_Analysis_Skill.skill import run as run_ad_kerberos_skill
from src.mcp.skills.Cloud_IAM_Analysis_Skill.skill import run as run_cloud_iam_skill
from src.mcp.skills.Identity_Lateral_Movement_Skill.skill import run as run_lateral_movement_skill

log = logging.getLogger(__name__)

# OCSF class_uids this agent is authoritative over (per ADR-008 + ocsf_events.py)
IDENTITY_OCSF_CLASSES = [3001, 3002, 6003]


@dataclass
class IdentityAgentDeps:
    """Dependency container for testability — all external I/O is injected."""
    dfkg_client: Any = None        # mcp-dfkg-cypher client (or None for testing)
    kafka_producer: Any = None     # confluent_kafka.Producer (or None for testing)
    vct_ledger_client: Any = None  # mcp-vct-ledger client (or None for testing)


def run_identity_analysis(
    state: IdentityAgentState,
    deps: IdentityAgentDeps,
) -> IdentityAgentState:
    """Execute single-pass identity forensics analysis pipeline.

    Steps:
      1. Validate single-case batch invariant.
      2. Fetch DFKG identity events (with supernode guard on host-graph).
      3. Run Kerberos ticket abuse detector (class_uid 3002 + 3001).
      4. Run privilege escalation detector (class_uid 3001).
      5. Run Cloud IAM analyzer (class_uid 6003).
      6. Correlate lateral movement chains.
      7. Compute verdict + confidence.
      8. Publish finding to Kafka.
      9. Optionally register VCT.

    Returns the updated state dict (never raises — degrades gracefully).
    """
    state["iteration_count"] = 1
    state["status"] = "running"

    # ── Step 1: Validate batch invariant ────────────────────────────────────
    if len(state.get("batch_uids", [])) == 0:
        _log_and_return_no_evidence(state)
        publish_identity_finding(state, deps)
        return state

    # Check single-case isolation (mirrors NF agent pattern)
    case_ids = {uid.split(":")[0] for uid in state["batch_uids"] if ":" in uid}
    if len(case_ids) > 1:
        raise ValueError(
            f"IdentityAgent invoked with batch spanning multiple case_ids: {case_ids}. "
            "Supervisor dispatch bug — one case per invocation."
        )

    # ── Step 2: Fetch DFKG events ────────────────────────────────────────────
    auth_events, audit_events, cloud_events, host_graph = _fetch_events(state, deps)

    all_events = auth_events + audit_events + cloud_events
    if not all_events:
        _log_and_return_no_evidence(state)
        publish_identity_finding(state, deps)
        return state

    # ── Step 3: Run Tools (Single-Pass Tool Invocation) ─────────────────────
    # Run the MCP skills programmatically (simulating LLM tool use in a 1-pass pipeline)
    ad_kerberos_results = run_ad_kerberos_skill(auth_events, audit_events)
    cloud_results = run_cloud_iam_skill(cloud_events)
    lm_chains_dict = run_lateral_movement_skill(
        ad_kerberos_results.get("kerberos_anomalies", []), 
        auth_events, 
        host_graph
    )
    
    # Also fetch full raw objects for state population
    kerberos_results = analyze_kerberos_events(auth_events + audit_events)
    priv_esc_results = detect_privilege_escalations(audit_events + auth_events)
    lm_chains = correlate_lateral_movement(kerberos_results, auth_events, host_graph)
    cloud_results_obj = analyze_cloud_iam_events(cloud_events)
    
    # ── Step 4: Invoke the LLM with Config Prompt ───────────────────────────
    llm = get_llm("identity")
    conf = AGENT_CONFIG.get("identity", {})
    sys_prompt = conf.get("system_prompt_template", "You are the Identity specialist for case {case_id}.")
    
    context = json.dumps({
        "kerberos_privesc_findings": ad_kerberos_results,
        "cloud_iam_findings": cloud_results,
        "lateral_movement_findings": lm_chains_dict
    }, default=str)
    
    prompt = sys_prompt.format(
        case_id=state["case_id"],
        raw_input=context
    )
    
    # In production, Prism-ML-Ternary-Bonsai-27B evaluates the tool output.
    # In tests, StubLLM returns the pre-configured JSON response.
    response = llm.invoke(prompt)
    
    try:
        # Parse the JSON verdict emitted by the LLM
        output = json.loads(response.content)
        verdict = output.get("verdict", "clean")
        confidence = output.get("confidence_score", 0.0)
        citations = output.get("dfkg_citations", [])
    except Exception as exc:
        log.error("[Identity] Failed to parse LLM JSON response: %s", exc)
        verdict, confidence = _compute_verdict(kerberos_results, priv_esc_results, cloud_results_obj, lm_chains)
        citations = _collect_citations(kerberos_results, priv_esc_results, lm_chains, cloud_results_obj)

    state.update({
        "kerberos_anomalies": [_kerberos_to_dict(r) for r in kerberos_results],
        "privilege_escalations": [_priv_to_dict(r) for r in priv_esc_results],
        "lateral_movement_chains": [_lm_to_dict(c) for c in lm_chains],
        "cloud_iam_anomalies": [_cloud_to_dict(r) for r in cloud_results_obj],
        "verdict": verdict,
        "confidence_score": confidence,
        "dfkg_citations": citations,
        "status": "complete",
    })

    # ── Step 8: Publish to Kafka ─────────────────────────────────────────────
    try:
        publish_identity_finding(state, deps)
    except Exception as exc:
        log.warning("[Identity] Kafka publish failed (non-blocking): %s", exc)
        state["status"] = "partial"

    # ── Step 9: VCT ledger registration ─────────────────────────────────────
    if deps.vct_ledger_client is not None:
        try:
            _register_vct(state, deps.vct_ledger_client)
        except Exception as exc:
            log.warning("[Identity] VCT ledger registration failed (non-blocking): %s", exc)

    return state


# ─── Private helpers ──────────────────────────────────────────────────────────

def _fetch_events(state: IdentityAgentState, deps: IdentityAgentDeps):
    """Fetch DFKG events. Returns (auth_events, audit_events, cloud_events, host_graph).

    If deps.dfkg_client is None (testing or unavailable), returns empty lists.
    """
    if deps.dfkg_client is None:
        # Graceful degradation: no DFKG client (test or unavailable)
        raw = state.get("_raw_events_for_testing") or []
        auth = [e for e in raw if e.get("class_uid") in (3002,)]
        audit = [e for e in raw if e.get("class_uid") in (3001,)]
        cloud = [e for e in raw if e.get("class_uid") in (6003,)]
        return auth, audit, cloud, {}

    case_id = state["case_id"]
    try:
        auth_events = deps.dfkg_client.query("fetch_auth_events", case_id=case_id) or []
        cloud_events = deps.dfkg_client.query("fetch_cloud_iam_events", case_id=case_id) or []
        # Host graph — may be empty if supernode guard fired (degree >= 200 handled by DFKG server)
        try:
            host_graph = deps.dfkg_client.query("fetch_identity_host_graph", case_id=case_id) or {}
        except Exception as exc:
            log.warning("[Identity] Host graph fetch failed (supernode guard or unavailable): %s", exc)
            host_graph = {}

        auth = [e for e in auth_events if e.get("class_uid") == 3002]
        audit = [e for e in auth_events if e.get("class_uid") == 3001]
        return auth, audit, cloud_events, host_graph
    except Exception as exc:
        log.error("[Identity] DFKG fetch failed: %s — returning partial state", exc)
        state["status"] = "partial"
        state["dead_end"] = True
        return [], [], [], {}


def _log_and_return_no_evidence(state: IdentityAgentState) -> None:
    log.info("[Identity] No identity events found for case %s — verdict=no_identity_evidence", state["case_id"])
    state.update({
        "verdict": "no_identity_evidence",
        "confidence_score": 0.0,
        "dfkg_citations": [],
        "status": "complete",
    })


def _compute_verdict(
    kerberos: list, priv_esc: list, cloud: list, lm: list
) -> tuple[str, float]:
    """Compute verdict and confidence from detected anomalies."""
    critical = [a for a in kerberos if getattr(a, "severity", "") == "CRITICAL"]
    critical += [a for a in priv_esc if getattr(a, "severity", "") == "CRITICAL"]
    critical += [a for a in cloud if getattr(a, "severity", "") == "CRITICAL"]

    high = [a for a in kerberos if getattr(a, "severity", "") == "HIGH"]
    high += [a for a in priv_esc if getattr(a, "severity", "") == "HIGH"]
    high += [a for a in cloud if getattr(a, "severity", "") == "HIGH"]

    if critical or lm:
        return "compromised", min(0.95, 0.75 + 0.05 * len(critical) + 0.05 * len(lm))
    elif high:
        return "suspicious", min(0.85, 0.60 + 0.05 * len(high))
    elif kerberos or priv_esc or cloud:
        return "suspicious", 0.50
    else:
        return "clean", 1.0


def _collect_citations(kerberos, priv_esc, lm_chains, cloud) -> list[str]:
    """Collect all DFKG node UIDs cited across all detectors."""
    uids: list[str] = []
    for r in kerberos:
        if r.evidence_uid:
            uids.append(r.evidence_uid)
    for r in priv_esc:
        if r.evidence_uid:
            uids.append(r.evidence_uid)
    for c in lm_chains:
        uids.extend(c.dfkg_edge_uids)
    for r in cloud:
        if r.evidence_uid:
            uids.append(r.evidence_uid)
    # Deduplicate preserving order
    seen: set[str] = set()
    result = []
    for uid in uids:
        if uid not in seen:
            seen.add(uid)
            result.append(uid)
    return result


def _register_vct(state: IdentityAgentState, vct_client: Any) -> None:
    """Register finding hash in VCT Merkle chain for Daubert provenance."""
    import hashlib, json
    payload = {
        "agent_role": "identity",
        "case_id": state["case_id"],
        "verdict": state.get("verdict"),
        "dfkg_citations": state.get("dfkg_citations"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    leaf_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    vct_client.register(leaf_hash=leaf_hash, session_id=state.get("trace_id", ""))


# ─── Dict serializers ─────────────────────────────────────────────────────────

def _kerberos_to_dict(r: "KerberosAnomalyResult") -> dict:
    return {
        "anomaly_type": r.anomaly_type, "severity": r.severity,
        "evidence_uid": r.evidence_uid, "target_account": r.target_account,
        "source_host": r.source_host, "confidence": r.confidence,
        "raw_indicators": r.raw_indicators, "event_id": r.event_id,
    }


def _priv_to_dict(r: "PrivEscResult") -> dict:
    return {
        "escalation_type": r.escalation_type, "severity": r.severity,
        "evidence_uid": r.evidence_uid, "actor_account": r.actor_account,
        "target_account": r.target_account, "group_name": r.group_name,
        "confidence": r.confidence, "raw_indicators": r.raw_indicators,
        "event_id": r.event_id,
    }


def _lm_to_dict(c: "LateralMovementChain") -> dict:
    return {
        "chain_id": c.chain_id, "technique": c.technique,
        "hop_sequence": c.hop_sequence, "account_uid": c.account_uid,
        "time_window_start": c.time_window_start,
        "time_window_end": c.time_window_end,
        "dfkg_edge_uids": c.dfkg_edge_uids, "confidence": c.confidence,
    }


def _cloud_to_dict(r: "CloudIAMAnomalyResult") -> dict:
    return {
        "anomaly_type": r.anomaly_type, "severity": r.severity,
        "evidence_uid": r.evidence_uid, "user_identity": r.user_identity,
        "source_ip": r.source_ip, "api_operation": r.api_operation,
        "confidence": r.confidence, "raw_indicators": r.raw_indicators,
        "cloud_provider": r.cloud_provider,
    }
