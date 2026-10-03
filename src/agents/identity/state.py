"""Identity Agent state schema (F13a) — IdentityAgentState TypedDict.

OCSF classes used by this agent:
  3001 = AuditActivity  (AD config changes, group membership, directory access)
  3002 = Authentication (Kerberos TGT/TGS, NTLM logon events)
  6003 = CloudAudit     (AWS CloudTrail IAM, Azure AD — identity plane only)

max_iterations = 1: single-pass structured pipeline, not an iterative ReAct loop
(per ADR-008; same M1 pattern as Evidence Collection Agent).
"""
from __future__ import annotations

from typing import Optional
from typing_extensions import TypedDict


class IdentityAgentState(TypedDict):
    case_id: str
    batch_uids: list[str]              # DFKG node UIDs for identity events to analyze
    ocsf_classes: list[int]            # [3001, 3002, 6003] — never use 3003 or 6001
    kerberos_anomalies: list[dict]     # Kerberoasting, AS-REP, PTT, DCSync, Golden Ticket
    privilege_escalations: list[dict]  # Group adds, token abuse, SID injection
    lateral_movement_chains: list[dict]  # PTH/PTT cross-host chains
    cloud_iam_anomalies: list[dict]    # IAM priv-esc, AssumeRole chain, MFA bypass
    verdict: Optional[str]             # "compromised"|"suspicious"|"clean"|"no_identity_evidence"
    confidence_score: float            # 0.0–1.0
    dfkg_citations: list[str]          # DFKG node UIDs cited; MUST be non-empty for non-clean verdict
    iteration_count: int
    max_iterations: int                # 1 — single-pass pipeline
    dead_end: bool
    status: str                        # "pending"|"running"|"complete"|"partial"
    trace_id: str
