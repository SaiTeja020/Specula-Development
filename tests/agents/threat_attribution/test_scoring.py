import pytest
from threading import RLock
from unittest.mock import MagicMock, patch
import numpy as np

from src.agents.threat_attribution.scoring import (
    jaccard_similarity, smith_waterman_similarity, rank_candidates, confidence_bounds,
)
from src.ingestion.indexing.threat_intel_sources import AttackStixFetcher
from src.schemas.threat_intel_metadata import ThreatIntelRecordMetadata
from src.ingestion.indexing.threat_intel_index import ThreatIntelIndex


def test_jaccard_and_smith_waterman_alignment():
    assert jaccard_similarity(["T1001", "T1002"], ["T1002", "T1003"]) == pytest.approx(1 / 3)
    assert smith_waterman_similarity(["T1001", "T1002"], ["T1001", "T1002"]) == 1
    assert smith_waterman_similarity(["T1002", "T1001"], ["T1001", "T1002"]) == 0.5
    assert smith_waterman_similarity([], ["T1001"]) == 0


def test_exact_weighted_top_three_and_tie_break():
    observed = ["T1001", "T1002"]
    profiles = [
        {"record_id": "G0003", "title": "C", "technique_ids": observed, "technique_sequence": []},
        {"record_id": "G0002", "title": "B", "technique_ids": observed, "technique_sequence": observed[::-1]},
        {"record_id": "G0001", "title": "A", "technique_ids": observed, "technique_sequence": observed},
        {"record_id": "G0004", "title": "D", "technique_ids": [], "technique_sequence": []},
    ]
    ranked = rank_candidates(observed, profiles)
    assert [item.actor_id for item in ranked] == ["G0001", "G0002", "G0003"]
    assert ranked[0].combined_score == pytest.approx(0.4 * 1 + 0.6 * 1)
    assert ranked[1].combined_score == pytest.approx(0.4 * 1 + 0.6 * 0.5)
    assert ranked[2].combined_score == pytest.approx(0.4)
    tied = rank_candidates(observed, profiles[:1] + [profiles[0] | {"record_id": "G0000"}])
    assert [item.actor_id for item in tied] == ["G0000", "G0003"]


def test_confidence_is_lower_for_stale_and_sparse_evidence():
    profile = {"record_id": "G1", "technique_ids": ["T1001", "T1002"],
               "technique_sequence": ["T1001", "T1002"]}
    ranked = rank_candidates(["T1001", "T1002"], [profile])
    fresh = confidence_bounds(ranked, 2, False, True)
    stale = confidence_bounds(ranked, 2, True, True)
    sparse = confidence_bounds(ranked, 1, False, False)
    assert fresh[1] > stale[1] and fresh[1] > sparse[1]
    assert fresh[0] <= fresh[1] <= fresh[2]


def test_stix_uses_relationship_populates_labeled_canonical_tactic_order():
    bundle = {"objects": [
        {"id": "attack-pattern--one", "type": "attack-pattern", "name": "PowerShell",
         "kill_chain_phases": [{"phase_name": "execution"}],
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}]},
        {"id": "attack-pattern--two", "type": "attack-pattern", "name": "SMB",
         "kill_chain_phases": [{"phase_name": "lateral-movement"}],
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1021.002"}]},
        {"id": "intrusion-set--one", "type": "intrusion-set", "name": "Actor",
         "external_references": [{"source_name": "mitre-attack", "external_id": "G0001"}]},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--one",
         "target_ref": "attack-pattern--one"},
        {"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--one",
         "target_ref": "attack-pattern--two"},
    ]}
    group = next(record for record in AttackStixFetcher().parse(bundle) if record.record_type == "attack_group")
    assert group.technique_ids == ["T1021.002", "T1059.001"]
    assert group.technique_sequence == ["T1059.001", "T1021.002"]
    assert group.sequence_basis == "attack_tactic_order"
    assert len(group.source_hash) == 64
    assert group.source_version == "ATT&CK-v15.1"


def test_profile_metadata_rejects_invalid_technique_id():
    with pytest.raises(ValueError):
        ThreatIntelRecordMetadata(record_id="G0001", record_type="attack_group", title="A",
                                  source="mitre_attack_stix", source_version="v1",
                                  technique_ids=["T9999", "made-up"])


def test_group_search_expands_past_cve_heavy_prefix():
    index = ThreatIntelIndex.__new__(ThreatIntelIndex)
    index._lock = RLock()
    index._id_map = {i: f"CVE-{i}" for i in range(12)} | {12: "G0001"}
    index._metadata = {f"CVE-{i}": {"record_type": "cve"} for i in range(12)} | {
        "G0001": {"record_type": "attack_group", "title": "Actor"}}
    index.default_nprobe = 1
    index._faiss_index = MagicMock(ntotal=13, nprobe=1)
    index._faiss_index.search.side_effect = lambda vec, k: (
        np.array([[1.0 - i / 100 for i in range(k)]]), np.array([list(range(k))]))
    with patch("src.ingestion.indexing.vector_store.EmbeddingGenerator") as embedder:
        embedder.return_value.embed.return_value = [0.0, 1.0]
        results = index.query("actor activity", record_type="attack_group", top_k=1)
    assert [item["record_id"] for item in results] == ["G0001"]
    assert index._faiss_index.search.call_count > 1
