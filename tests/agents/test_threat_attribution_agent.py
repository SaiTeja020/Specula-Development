"""End-to-end attribution contract with local DFKG, corpus and model doubles."""

import json
import pytest
from unittest.mock import patch

from src.agents.threat_attribution_agent import run_threat_attribution
from src.agents.threat_attribution.ttp_extractor import extract_observed_ttps


TECHNIQUES = {
    "T1059.001": {"record_id": "T1059.001", "record_type": "attack_technique", "source_hash": "tech-a"},
    "T1021.002": {"record_id": "T1021.002", "record_type": "attack_technique", "source_hash": "tech-b"},
}
PROFILES = {
    "G0001": {"record_id": "G0001", "record_type": "attack_group", "title": "Actor A",
              "technique_ids": ["T1059.001", "T1021.002"],
              "technique_sequence": ["T1059.001", "T1021.002"],
              "source_hash": "group-a", "source_version": "ATT&CK-v15.1"},
    "G0002": {"record_id": "G0002", "record_type": "attack_group", "title": "Actor B",
              "technique_ids": ["T1059.001", "T1021.002"],
              "technique_sequence": ["T1021.002", "T1059.001"],
              "source_hash": "group-b", "source_version": "ATT&CK-v15.1"},
    "G0003": {"record_id": "G0003", "record_type": "attack_group", "title": "Actor C",
              "technique_ids": ["T1059.001"], "technique_sequence": [],
              "source_hash": "group-c", "source_version": "ATT&CK-v15.1"},
}
STATE = {
    "case_id": "case-one", "trace_id": "trace-one",
    "timeline": {"frozen": True, "summary": "PowerShell then SMB movement", "events": [
        {"time": "2026-10-03T00:02:00Z", "attacks": ["T1021.002"],
         "dfkg_refs": ["event-two"], "summary": "SMB lateral movement"},
        {"time": "2026-10-03T00:01:00Z", "attacks": ["T1059.001"],
         "dfkg_refs": ["event-one"], "summary": "PowerShell execution"},
    ]},
}


class FakeIntel:
    def __init__(self, ready=True, stale=False):
        self.ready, self.stale = ready, stale

    def health_check(self):
        return {"status": "ready" if self.ready else "not_ready", "is_stale": self.stale,
                "corpus_hash": "corpus-hash"}

    def get_attack_technique(self, technique_id):
        record = TECHNIQUES.get(technique_id)
        return {"status": "ok" if record else "not_found", "record": record}

    def query_attack_techniques(self, query_text, top_k):
        return {"status": "ok", "results": []}

    def query_attack_groups(self, query_text, top_k):
        assert top_k >= 10
        return {"status": "ok", "results": [{"record_id": key} for key in PROFILES]}

    def get_attack_group_profile(self, group_id):
        return {"status": "ok", "profile": PROFILES[group_id]}

    def list_attack_group_profiles(self):
        return {"status": "ok", "profiles": list(PROFILES.values())}


class FakeGraph:
    def __init__(self, refs=("event-one", "event-two")):
        self.refs = refs
        self.queries = []

    def execute_query(self, query, **params):
        self.queries.append((query, params))
        assert params == {"case_id": "case-one"}
        assert "RETURN" in query and "DELETE" not in query
        if "HAS_EVENT" in query:
            return [{"uid": uid} for uid in self.refs], None, None
        return [], None, None


class FakeModel:
    model_name = "kimi-k2.6"

    def invoke(self, prompt):
        class Response:
            content = json.dumps({"explanation_codes": ["profile_similarity"]})
        return Response()


def test_ordered_ttp_extraction_requires_evidence_and_trusted_ids():
    timeline = {"frozen": True, "events": [
        {"time": "2026-10-03T00:02:00Z", "dfkg_refs": ["e2"], "attacks": ["T9999"]},
        {"time": "2026-10-03T00:01:00Z", "dfkg_refs": ["e1"], "attacks": ["T1059.001"]},
        {"time": "2026-10-03T00:03:00Z", "dfkg_refs": [], "attacks": ["T1021.002"]},
    ]}
    observed, flags = extract_observed_ttps(timeline, FakeIntel())
    assert [item.technique_id for item in observed] == ["T1059.001"]
    assert observed[0].evidence_uids == ["e1"]
    assert "unsupported_technique_id" in flags


def test_semantic_match_requires_source_verification_before_ranking():
    class SemanticIntel(FakeIntel):
        def query_attack_techniques(self, query_text, top_k):
            return {"status": "ok", "results": [{
                "record_id": "T1059.001", "score": 0.9,
                "metadata": TECHNIQUES["T1059.001"],
            }]}
    timeline = {"frozen": True, "events": [{
        "time": "2026-10-03T00:01:00Z", "dfkg_refs": ["event-one"],
        "summary": "PowerShell execution", "attacks": [],
    }]}
    suggestions=[]
    observed, flags = extract_observed_ttps(timeline, SemanticIntel(),suggestions)
    assert observed == []
    assert suggestions[0]['technique_id']=='T1059.001' and suggestions[0]['status']=='unverified_candidate'
    assert 'semantic_candidate_requires_source_verification' in flags


def test_hash_vectors_cannot_infer_technique_from_summary():
    class HashIntel(FakeIntel):
        def health_check(self):
            return super().health_check() | {"embedding_model_version": "sha384-byte-repeat-v1"}
        def query_attack_techniques(self, query_text, top_k):
            raise AssertionError("hash-vector similarity is not semantic mapping")
    observed, flags = extract_observed_ttps({"frozen": True, "events": [{
        "time": "2026-10-03T00:01:00Z", "dfkg_refs": ["event-one"], "summary": "PowerShell",
    }]}, HashIntel())
    assert observed == []
    assert "semantic_mapping_unavailable" in flags


def test_known_order_ranks_actor_and_ignores_model_score_edits():
    graph = FakeGraph()
    attribution, finding, trace = run_threat_attribution(
        STATE, neo4j_driver=graph, threat_intel=FakeIntel(), llm_factory=lambda case_id: FakeModel())
    assert [item["technique_id"] for item in attribution["observed_ttps"]] == ["T1059.001", "T1021.002"]
    assert [item["actor_id"] for item in attribution["candidate_actors"]] == ["G0001", "G0002", "G0003"]
    assert attribution["top_candidate"]["combined_score"] == 1.0
    assert attribution["candidate_actors"][1]["combined_score"] == 0.7
    assert "does not establish actor identity" in attribution["narrative"]
    assert "ranking compares the cited case TTPs" in attribution["narrative"]
    assert "G9999" not in json.dumps(attribution)
    assert finding["attribution_detail"] == attribution
    assert finding["dfkg_refs"] == ["event-one", "event-two"]
    assert attribution["corpus_hash"] == "corpus-hash"
    assert attribution["threat_intel_refs"]
    assert trace["model_used"] == "kimi-k2.6"
    assert trace["algorithm_version"] == "jaccard-sw-v2"
    assert len(graph.queries) == 2


def test_missing_corpus_never_uses_llm_only_attribution():
    attribution, _, _ = run_threat_attribution(STATE, FakeGraph(), FakeIntel(ready=False))
    assert attribution["candidate_actors"] == []
    assert attribution["overall_confidence"] == 0
    assert "corpus_unavailable" in attribution["degraded_flags"]


def test_missing_graph_evidence_prevents_attribution():
    attribution, finding, _ = run_threat_attribution(STATE, FakeGraph(refs=()), FakeIntel())
    assert attribution["observed_ttps"] == []
    assert attribution["candidate_actors"] == []
    assert finding["dfkg_refs"] == []
    assert "no_confirmed_dfkg_evidence" in attribution["degraded_flags"]


def test_repeated_single_technique_remains_insufficient_evidence():
    repeated = STATE | {"timeline": {"frozen": True, "events": [
        {"time": "2026-10-03T00:01:00Z", "attacks": ["T1059.001"], "dfkg_refs": ["event-one"]},
        {"time": "2026-10-03T00:02:00Z", "attacks": ["T1059.001"], "dfkg_refs": ["event-two"]},
    ]}}
    result, _, _ = run_threat_attribution(repeated, FakeGraph(), FakeIntel())
    assert "insufficient_evidence" in result["degraded_flags"]
    assert result["overall_confidence"] <= 0.25


def test_exhaustive_profile_listing_does_not_use_hash_vector_shortlist():
    class ListedIntel(FakeIntel):
        def query_attack_groups(self, query_text, top_k):
            raise AssertionError("attribution must not use hash-vector group search")
    result, _, _ = run_threat_attribution(STATE, FakeGraph(), ListedIntel())
    assert result["top_candidate"] is not None


def test_legacy_search_only_adapter_cannot_shortlist_attribution_profiles():
    from src.agents.threat_attribution.candidate_retriever import retrieve_group_profiles
    class SearchOnly:
        def query_attack_groups(self, **kwargs):
            raise AssertionError("hash-vector shortlist must never be used")
    profiles, flags = retrieve_group_profiles(SearchOnly(), "T1059.001")
    assert profiles == [] and flags == ["group_profiles_unavailable"]


def test_stale_corpus_lowers_confidence():
    fresh, _, _ = run_threat_attribution(STATE, FakeGraph(), FakeIntel())
    stale, _, _ = run_threat_attribution(STATE, FakeGraph(), FakeIntel(stale=True))
    assert stale["overall_confidence"] < fresh["overall_confidence"]
    assert "stale_corpus" in stale["degraded_flags"]


def test_unmatched_profiles_keep_candidates_without_actor_claim():
    class UnmatchedIntel(FakeIntel):
        def list_attack_group_profiles(self):
            profiles = [profile | {"technique_ids": ["T1111"],
                                   "technique_sequence": ["T1111"]} for profile in PROFILES.values()]
            return {"status": "ok", "profiles": profiles}
    attribution, _, _ = run_threat_attribution(STATE, FakeGraph(), UnmatchedIntel())
    assert len(attribution["candidate_actors"]) == 3
    assert attribution["top_candidate"] is None
    assert attribution["overall_confidence"] == 0
    assert "no_profile_match" in attribution["degraded_flags"]


def test_malformed_model_output_leaves_ranking_unchanged():
    class BadModel:
        model_name = "bad-model"
        def invoke(self, prompt):
            return "invalid json"
    attribution, _, trace = run_threat_attribution(
        STATE, FakeGraph(), FakeIntel(), llm_factory=lambda case_id: BadModel())
    assert attribution["top_candidate"]["actor_id"] == "G0001"
    assert "explanation_model_unavailable" in attribution["degraded_flags"]
    assert trace["model_used"] == "unavailable"


def test_model_narrative_cannot_introduce_unsupported_actor_id():
    class HallucinatingModel:
        model_name = "kimi-k2.6"
        def invoke(self, prompt):
            return json.dumps({"narrative": "G9999 carried out the attack."})
    attribution, _, _ = run_threat_attribution(
        STATE, FakeGraph(), FakeIntel(), llm_factory=lambda case_id: HallucinatingModel())
    assert "G9999" not in attribution["narrative"]
    assert attribution["top_candidate"]["actor_id"] == "G0001"
    assert "explanation_model_unavailable" in attribution["degraded_flags"]


def test_configured_kimi_backend_receives_explicit_endpoint(monkeypatch):
    from src.agents.config import get_llm
    monkeypatch.setenv("SPECULA_THREAT_ATTRIBUTION_BACKEND", "openai_compatible")
    monkeypatch.setenv("SPECULA_THREAT_ATTRIBUTION_BASE_URL", "https://model.example/v1")
    monkeypatch.setenv("SPECULA_THREAT_ATTRIBUTION_API_KEY", "test-key")
    monkeypatch.setenv("SPECULA_THREAT_ATTRIBUTION_MODEL", "kimi-k2.6")
    with patch("langchain_openai.ChatOpenAI") as model:
        get_llm("threat_attribution", case_id="case-one")
    assert model.call_args.kwargs["model"] == "kimi-k2.6"
    assert model.call_args.kwargs["base_url"] == "https://model.example/v1"


@pytest.mark.parametrize("content", [
    {"narrative": "G0001 is confirmed as attacker with 100% confidence; score 1.0"},
    {"narrative": "An unrelated named organization carried out the attack."},
    {"explanation_codes": ["limited_evidence"]},
    {"explanation_codes": ["profile_similarity"], "narrative": "Confirmed attacker"},
    {"explanation_codes": ["profile_similarity", "profile_similarity"]},
    {"explanation_codes": [{}]},
])
def test_model_cannot_add_unsupported_claims_or_explanations(content):
    class Model:
        def invoke(self, prompt): return json.dumps(content)
    result, _, _ = run_threat_attribution(STATE, FakeGraph(), FakeIntel(), lambda case_id: Model())
    assert "explanation_model_unavailable" in result["degraded_flags"]
    assert "does not establish actor identity" in result["narrative"]
    assert "100%" not in result["narrative"]


@pytest.mark.parametrize("same_hash", [False, True])
def test_corpus_refresh_rejects_mixed_generation_results(same_hash):
    class ChangingIntel(FakeIntel):
        calls = 0
        def health_check(self):
            self.calls += 1
            return super().health_check() | {
                "corpus_hash": "corpus-hash" if same_hash or self.calls == 1 else "new-corpus",
                "corpus_generation": self.calls,
            }
    result, finding, trace = run_threat_attribution(STATE, FakeGraph(), ChangingIntel())
    assert "corpus_changed_during_attribution" in result["degraded_flags"]
    assert result["candidate_actors"] == []
    assert result["overall_confidence"] == 0
    assert result["corpus_hash"] is None
    assert finding["threat_intel_refs"] == []
    assert trace["candidate_scores"] == []


def test_attribution_stub_overrides_global_gemini(monkeypatch):
    from src.agents.config import get_llm, StubLLM
    monkeypatch.setenv("SPECULA_LLM_BACKEND", "gemini")
    monkeypatch.setenv("SPECULA_THREAT_ATTRIBUTION_BACKEND", "stub")
    assert isinstance(get_llm("threat_attribution"), StubLLM)


def test_attribution_gemini_overrides_global_stub(monkeypatch):
    from src.agents.config import get_llm
    monkeypatch.setenv("SPECULA_LLM_BACKEND", "stub")
    monkeypatch.setenv("SPECULA_THREAT_ATTRIBUTION_BACKEND", "gemini")
    with patch("src.agents.config._get_gemini_model", return_value="test-model"), \
         patch("langchain_google_genai.ChatGoogleGenerativeAI") as model:
        get_llm("threat_attribution")
    assert model.call_args.kwargs["model"] == "test-model"


def test_unknown_backend_is_explicit_configuration_error(monkeypatch):
    from src.agents.config import get_llm
    monkeypatch.setenv("SPECULA_THREAT_ATTRIBUTION_BACKEND", "unknown")
    with pytest.raises(ValueError, match="Unsupported model backend"):
        get_llm("threat_attribution")


def test_legacy_unverified_artifacts_cannot_support_attribution():
    class LegacyIntel(FakeIntel):
        def health_check(self): return super().health_check() | {"artifacts_verified": False}
    result, _, _ = run_threat_attribution(STATE, FakeGraph(), LegacyIntel())
    assert result["candidate_actors"] == []
    assert "corpus_artifacts_unverified" in result["degraded_flags"]
