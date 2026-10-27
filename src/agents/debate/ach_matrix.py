"""Deterministic ACH matrix computation — Implementation Plan v3 §6.

Invoked by code, never by the LLM. Contradiction-based elimination protocol (Richards Heuer).

v3 criteria:
  M2  Diagnostic-only items: only items where relation_to_A != relation_to_B are counted.
      Non-diagnostic items do not discriminate. Fewer than min_diagnostic items in round 1
      returns PENDING; at round cap returns INSUFFICIENT_EVIDENCE.
  K1  Contradiction-based winner criterion: the winning hypothesis must NOT exceed
      max_winner_contradictions (<= 1). Heavily contradicted hypotheses (e.g. 5 vs 7)
      cannot win as dominant, resolving the softmax (0,2) vs (5,7) ambiguity.
  M1  Contradiction margin: a decisive win requires min_contradiction_margin >= 2
      net diagnostic contradictions. Evidence is evaluated cumulatively across rounds.
  M3  Volume bias mitigation: citations are capped per side. Citing confirming nodes
      cannot overpower diagnostic contradictions.
  --  Thresholds are encapsulated in AchConfig and pinned by RULES_VERSION.
      Marked explicitly as calibrated=False (uncalibrated).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

RULES_VERSION = "ach-rules-v3-uncalibrated"


@dataclass(frozen=True)
class AchConfig:
    rules_version: str = RULES_VERSION
    calibrated: bool = False                # Provisional thresholds: see module docstring
    min_diagnostic: int = 3                 # Minimum diagnostic items required for any verdict
    dominance_threshold: float = 0.95       # Dominant blowout requires margin >= 3 (P >= 0.952)
    stable_delta: float = 0.02              # |P(H1) - prev P(H1)| below this => stable cross-round
    min_contradiction_margin: int = 2       # Net contradiction margin required to declare a winner (M1)
    max_winner_contradictions: int = 1      # Winner cannot have > 1 diagnostic contradiction (K1)
    min_winner_confirmations: int = 1       # Winner must have at least 1 CONFIRMS item (defect 3)
    max_citations_per_side: int = 10        # Maximum citations evaluated per side to mitigate volume bias (M3)
    max_rounds: int = 3


DEFAULT_CONFIG = AchConfig()


def unblind_scores(
    p_A: float, p_B: float, blind_map: Optional[Dict[str, str]] = None
) -> Tuple[float, float]:
    """Reverse the judge blind: map (A, B) back to (H1=Proponent, H2=Critic).

    blind_map maps label -> hypothesis, e.g. {"A": "H1", "B": "H2"}.
    Default (no blind recorded) is the identity mapping.
    """
    blind_map = blind_map or {"A": "H1", "B": "H2"}
    scores = {blind_map["A"]: p_A, blind_map["B"]: p_B}
    return scores["H1"], scores["H2"]


def compute_ach_verdict(
    evaluations: List[Dict],
    round_index: int,
    prev_p_h1: Optional[float],
    blind_map: Optional[Dict[str, str]] = None,
    config: AchConfig = DEFAULT_CONFIG,
) -> Dict:
    """Compute contradiction-based ACH verdict.

    Evaluates cumulative evidence across rounds.
    `prev_p_h1` is the previous judge round's P(H1) (None in round 1), read directly
    from LangGraph state.
    """
    cfg = config
    at_cap = round_index >= cfg.max_rounds

    # 1. Diagnostic items filter (M2): only items that discriminate between A and B
    diag = [e for e in evaluations if e.get("relation_to_A") != e.get("relation_to_B")]
    n_diag = len(diag)

    # Count total contradictions per hypothesis across all items and diagnostic items
    total_xA = sum(1 for e in evaluations if e.get("relation_to_A") == "CONTRADICTS")
    total_xB = sum(1 for e in evaluations if e.get("relation_to_B") == "CONTRADICTS")
    tot_x_h1, tot_x_h2 = unblind_scores(float(total_xA), float(total_xB), blind_map)

    # Count total confirmations per hypothesis (defect 3: affirmative supporting evidence)
    total_cA = sum(1 for e in evaluations if e.get("relation_to_A") == "CONFIRMS")
    total_cB = sum(1 for e in evaluations if e.get("relation_to_B") == "CONFIRMS")
    tot_c_h1, tot_c_h2 = unblind_scores(float(total_cA), float(total_cB), blind_map)
    c_h1, c_h2 = int(tot_c_h1), int(tot_c_h2)

    diag_xA = sum(1 for e in diag if e.get("relation_to_A") == "CONTRADICTS")
    diag_xB = sum(1 for e in diag if e.get("relation_to_B") == "CONTRADICTS")
    diag_x_h1, diag_x_h2 = unblind_scores(float(diag_xA), float(diag_xB), blind_map)
    dx_h1, dx_h2 = int(diag_x_h1), int(diag_x_h2)

    # Empty / Thin diagnostic evidence guard (M2)
    if n_diag < cfg.min_diagnostic:
        status = "INSUFFICIENT_EVIDENCE" if at_cap else "PENDING"
        return {
            "status": status,
            "p_h1": 0.5,
            "p_h2": 0.5,
            "rules_version": cfg.rules_version,
            "calibrated": cfg.calibrated,
            "n_diagnostic": n_diag,
            "contradictions": {"H1": dx_h1, "H2": dx_h2},
            "total_contradictions": {"H1": int(tot_x_h1), "H2": int(tot_x_h2)},
            "confirmations": {"H1": c_h1, "H2": c_h2},
            "margin": 0,
        }

    # 2. Probability inversion based on diagnostic contradictions:
    # Lower contradictions = higher probability.
    eA, eB = math.exp(-diag_xA), math.exp(-diag_xB)
    p_A = eA / (eA + eB)
    p_B = eB / (eA + eB)
    p_h1, p_h2 = unblind_scores(p_A, p_B, blind_map)

    # 3. Contradiction-based winner determination (K1, M1):
    # The hypothesis with FEWER diagnostic contradictions is the leader.
    if dx_h1 < dx_h2:
        leader_h = "H1"
        x_leader, x_trailer = dx_h1, dx_h2
        c_leader = c_h1
    elif dx_h2 < dx_h1:
        leader_h = "H2"
        x_leader, x_trailer = dx_h2, dx_h1
        c_leader = c_h2
    else:
        leader_h = "TIE"
        x_leader, x_trailer = dx_h1, dx_h2
        c_leader = min(c_h1, c_h2)

    margin = x_trailer - x_leader

    # Eligibility to win (K1 + M1 + Defect 3):
    # 1. Must satisfy net contradiction margin (>= 2 fewer diagnostic contradictions)
    # 2. Leader must not be heavily contradicted (x_leader <= max_winner_contradictions)
    # 3. Leader must have at least 1 confirming evidence item (cannot win on pure neutral)
    eligible = (
        leader_h != "TIE"
        and margin >= cfg.min_contradiction_margin
        and x_leader <= cfg.max_winner_contradictions
        and c_leader >= cfg.min_winner_confirmations
    )

    base_result = {
        "p_h1": p_h1,
        "p_h2": p_h2,
        "rules_version": cfg.rules_version,
        "calibrated": cfg.calibrated,
        "n_diagnostic": n_diag,
        "contradictions": {"H1": dx_h1, "H2": dx_h2},
        "total_contradictions": {"H1": int(tot_x_h1), "H2": int(tot_x_h2)},
        "confirmations": {"H1": c_h1, "H2": c_h2},
        "margin": margin,
    }

    # 4. Convergence logic:
    # Dominant convergence (margin >= 3, P >= 0.952)
    if eligible and max(p_h1, p_h2) >= cfg.dominance_threshold:
        return {**base_result, "status": "CONVERGED_DOMINANT"}

    # Stable cross-round convergence (margin >= 2 consistent across rounds)
    if (
        eligible
        and round_index > 1
        and prev_p_h1 is not None
        and abs(p_h1 - prev_p_h1) < cfg.stable_delta
    ):
        return {**base_result, "status": "CONVERGED_STABLE"}

    # Round cap reached (Round 3): consistent labeling (defect 5)
    if at_cap:
        if leader_h != "TIE":
            # Leader exists but is heavily contradicted -> INSUFFICIENT_EVIDENCE (e.g. 5 vs 6)
            if x_leader > cfg.max_winner_contradictions:
                return {**base_result, "status": "INSUFFICIENT_EVIDENCE"}
            # Leader lacks affirmative confirmations -> INSUFFICIENT_EVIDENCE
            if c_leader < cfg.min_winner_confirmations:
                return {**base_result, "status": "INSUFFICIENT_EVIDENCE"}
        # Equal contradictions (TIE) or insufficient margin without disqualification -> DEADLOCK_TIE
        return {**base_result, "status": "DEADLOCK_TIE"}

    return {**base_result, "status": "PENDING"}

