"""Case-grounded Threat Attribution with deterministic ATT&CK profile scoring."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import time
from typing import Any

from src.agents.threat_attribution.candidate_retriever import retrieve_group_profiles
from src.agents.threat_attribution.models import ThreatAttributionResult
from src.agents.threat_attribution.scoring import confidence_bounds, rank_candidates
from src.agents.threat_attribution.ttp_extractor import extract_observed_ttps
from src.schemas.uid_generator import generate_deterministic_uid

logger = logging.getLogger(__name__)


def _query_graph_evidence_uids(driver: Any, case_id: str) -> set[str]:
    """Read case-linked events and case-tagged findings through parameterized Cypher."""
    if driver is None:
        return set()
    queries = (
        "MATCH (c:Case {uid: $case_id})-[:HAS_EVENT]->(e:Event) RETURN e.uid AS uid",
        "MATCH (e:Entity {case_id: $case_id}) RETURN e.uid AS uid",
    )
    uids: set[str] = set()
    for query in queries:
        records, _, _ = driver.execute_query(query, case_id=case_id)
        for record in records:
            uid = record.get("uid") if hasattr(record, "get") else record["uid"]
            if uid:
                uids.add(uid)
    return uids


def _narrative(result: ThreatAttributionResult, case_id: str, llm_factory=None) -> tuple[str, str, bool]:
    if result.top_candidate is None:
        return "Attribution unavailable: no scored ATT&CK group profile is supported by this case's evidence.", "none", False
    default = (f"Top ATT&CK profile is {result.top_candidate.name} "
               f"({result.top_candidate.actor_id}; similarity {result.top_candidate.combined_score:.3f}). "
               f"Evidence-adjusted confidence is {result.overall_confidence:.3f} "
               f"(bounds {result.confidence_lower:.3f}-{result.confidence_upper:.3f}). "
               "This profile comparison does not establish actor identity.")
    explanations = {"profile_similarity": "The ranking compares the cited case TTPs with ATT&CK group profiles."}
    if "actor_sequence_inferred" in result.degraded_flags:
        explanations["inferred_sequence"] = "Profile sequence is inferred from ATT&CK tactic order, not a recorded actor chronology."
    if "actor_sequence_unavailable" in result.degraded_flags:
        explanations["missing_sequence"] = "No actor sequence is available for this comparison."
    if "insufficient_evidence" in result.degraded_flags:
        explanations["limited_evidence"] = "Fewer than two cited TTPs support this comparison."
    if "stale_corpus" in result.degraded_flags:
        explanations["stale_corpus"] = "The threat intelligence corpus is stale."
    try:
        from src.agents.config import get_llm
        llm = llm_factory(case_id) if llm_factory else get_llm("threat_attribution", case_id=case_id)
        if llm.__class__.__name__ == "StubLLM":
            return default, "stub", False
        model_id = (getattr(llm, "model_name", None) or getattr(llm, "model", None)
                    or getattr(llm, "model_id", None) or llm.__class__.__name__)
        prompt = json.dumps({
            "instruction": "Select relevant explanation codes from allowed_explanations. "
                           "Return JSON with only explanation_codes, a nonempty list of unique allowed codes. "
                           "Do not return prose, actor identities, scores or additional fields.",
            "allowed_explanations": explanations,
            "case_id": case_id,
            "observed_ttps": [item.model_dump(mode="json") for item in result.observed_ttps],
            "candidate_actors": [item.model_dump(mode="json") for item in result.candidate_actors],
            "confidence_bounds": [result.confidence_lower, result.confidence_upper],
            "degraded_flags": result.degraded_flags,
        }, sort_keys=True)
        response = llm.invoke(prompt)
        content = response.content if hasattr(response, "content") else str(response)
        parsed = json.loads(str(content).strip())
        codes = parsed.get("explanation_codes") if isinstance(parsed, dict) else None
        usable = (isinstance(parsed, dict) and set(parsed) == {"explanation_codes"}
                  and isinstance(codes, list) and bool(codes)
                  and all(isinstance(code, str) and code in explanations for code in codes)
                  and len(set(codes)) == len(codes))
        narrative = default + " " + " ".join(explanations[code] for code in codes) if usable else default
        return narrative, str(model_id), usable
    except Exception as exc:
        logger.warning("Threat attribution explanation unavailable: %s", exc)
        return default, "unavailable", False


def run_threat_attribution(state: dict, neo4j_driver=None, threat_intel=None, llm_factory=None) -> tuple[dict, dict, dict]:
    started = time.monotonic()
    case_id = state.get("case_id")
    if not case_id:
        raise ValueError("Threat Attribution requires case_id")
    trace_id = state.get("trace_id", "")
    flags: set[str] = set()
    health: dict = {}
    try:
        confirmed_uids = _query_graph_evidence_uids(neo4j_driver, case_id)
    except Exception as exc:
        logger.warning("Threat Attribution DFKG read failed for %s: %s", case_id, exc)
        confirmed_uids = set()
        flags.add("dfkg_unavailable")
    if neo4j_driver is None:
        flags.add("dfkg_unavailable")
    if not confirmed_uids:
        flags.add("no_confirmed_dfkg_evidence")
    try:
        if threat_intel is None:
            from src.mcp.threat_intel_mcp import ThreatIntelMCPServer
            threat_intel = ThreatIntelMCPServer()
        health = threat_intel.health_check()
        if health.get("status") != "ready":
            flags.add("corpus_unavailable")
        if health.get("artifacts_verified") is False:
            flags.update({"corpus_unavailable", "corpus_artifacts_unverified"})
        if health.get("is_stale"):
            flags.add("stale_corpus")
    except Exception as exc:
        logger.warning("Threat intel unavailable: %s", exc)
        flags.add("corpus_unavailable")
    timeline = dict(state.get("timeline") or {})
    timeline["events"] = [
        {**event, "dfkg_refs": sorted(set(event.get("dfkg_refs") or []) & confirmed_uids)}
        for event in timeline.get("events", [])
        if set(event.get("dfkg_refs") or []) & confirmed_uids
    ]
    observed = []
    if "corpus_unavailable" not in flags:
        try:
            observed, extraction_flags = extract_observed_ttps(timeline, threat_intel)
            flags.update(extraction_flags)
        except Exception as exc:
            logger.warning("TTP extraction failed: %s", exc)
            flags.add("ttp_mapping_unavailable")
    profiles = []
    if observed:
        try:
            query = " ".join(item.technique_id for item in observed) + " " + str(timeline.get("summary", ""))[:500]
            profiles, retrieval_flags = retrieve_group_profiles(threat_intel, query)
            flags.update(retrieval_flags)
        except Exception as exc:
            logger.warning("Group profile retrieval failed: %s", exc)
            flags.add("group_profiles_unavailable")
    if "corpus_unavailable" not in flags:
        try:
            final_health = threat_intel.health_check()
            if (final_health.get("status") != "ready"
                    or not health.get("corpus_hash")
                    or any(final_health.get(key) != health.get(key)
                           for key in ("corpus_hash", "corpus_generation"))):
                flags.add("corpus_changed_during_attribution")
                observed, profiles = [], []
                health = {}  # Mixed results must not carry either generation's provenance.
        except Exception:
            flags.add("corpus_provenance_unavailable")
            observed, profiles, health = [], [], {}
    candidates = rank_candidates([item.technique_id for item in observed], profiles)
    if candidates and candidates[0].combined_score == 0:
        flags.add("no_profile_match")
    if candidates and not any(item.sequence_available for item in candidates):
        flags.add("actor_sequence_unavailable")
    if candidates and candidates[0].sequence_basis == "attack_tactic_order":
        flags.add("actor_sequence_inferred")
    if len(observed) < 2:
        flags.add("insufficient_evidence")
    refs = sorted({uid for item in observed for uid in item.evidence_uids})
    intel_refs = sorted({ref for item in observed for ref in item.threat_intel_refs} |
                        {f"{item.actor_id}:{item.source_hash}" for item in candidates if item.source_hash})
    lower, confidence, upper = confidence_bounds(
        candidates, len(observed), "stale_corpus" in flags,
        bool(observed) and all(item.evidence_uids and item.threat_intel_refs for item in observed),
    )
    if "insufficient_evidence" in flags:
        confidence = min(confidence, 0.25)
        upper = min(upper, 0.35)
        lower = min(lower, confidence)
    if "no_profile_match" in flags:
        lower = confidence = upper = 0.0
    result = ThreatAttributionResult(
        observed_ttps=observed, candidate_actors=candidates,
        top_candidate=candidates[0] if candidates and "no_profile_match" not in flags else None,
        overall_confidence=confidence, confidence_lower=lower, confidence_upper=upper,
        confidence_basis="deterministic_similarity_with_evidence" if candidates and "no_profile_match" not in flags else "unavailable",
        dfkg_refs=refs, threat_intel_refs=intel_refs,
        corpus_version=(candidates[0].source_version if candidates else
                        (health.get("source_versions") or {}).get("mitre_attack_stix")),
        corpus_hash=health.get("corpus_hash") if isinstance(health.get("corpus_hash"), str) else None,
        degraded_flags=sorted(flags), narrative="", summary="",
    )
    narrative, model_id, explained = _narrative(result, case_id, llm_factory)
    if result.top_candidate is not None and not explained:
        flags.add("explanation_model_unavailable")
    result.degraded_flags = sorted(flags)
    result.narrative = narrative
    result.summary = narrative
    attribution = result.model_dump(mode="json")
    finding = {
        "uid": generate_deterministic_uid("threat_attribution", {
            "case_id": case_id, "corpus_hash": result.corpus_hash,
            "observed": [(item.technique_id, item.evidence_uids) for item in observed],
        }),
        "agent_role": "threat_attribution", "case_id": case_id, "trace_id": trace_id,
        "summary": narrative, "dfkg_refs": refs, "threat_intel_refs": intel_refs,
        "attribution_detail": attribution,
        "timestamp": datetime.now(timezone.utc).isoformat(), "kafka_offset": None,
    }
    trace = {
        "agent_role": "threat_attribution", "action": "deterministic_attack_profile_scoring",
        "thought": f"Scored {len(profiles)} ATT&CK profiles from {len(observed)} cited TTPs.",
        "observation": narrative[:300], "model_used": model_id,
        "algorithm_version": result.algorithm_version,
        "scoring_parameters": result.scoring_parameters,
        "corpus_hash": result.corpus_hash, "corpus_version": result.corpus_version,
        "dfkg_refs": refs, "threat_intel_refs": intel_refs,
        "candidate_scores": [{"actor_id": item.actor_id, "combined_score": item.combined_score}
                             for item in candidates],
        "trace_id": trace_id, "degraded_flags": result.degraded_flags,
        "latency_ms": round((time.monotonic() - started) * 1000, 1),
    }
    return attribution, finding, trace
