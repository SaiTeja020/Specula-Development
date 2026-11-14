"""The local corpus must preserve source identity and group/technique links."""
import hashlib
from collections import Counter
from pathlib import Path

from src.ingestion.indexing.attack_xlsx_source import load_attack_workbook
from src.mcp.threat_intel_mcp import ThreatIntelMCPServer


def test_versioned_local_workbook_has_retrievable_group_profiles():
    source = Path("known_attacks/enterprise-attack-v19.2.xlsx")
    records, digest = load_attack_workbook(source)
    counts = Counter(record.record_type for record in records)
    assert counts == {"attack_technique": 697, "attack_group": 176}
    assert digest == hashlib.sha256(source.read_bytes()).hexdigest()
    by_id = {record.record_id: record for record in records}
    assert len(by_id) == len(records)
    assert by_id["G0016"].technique_ids
    assert set(by_id["G0016"].technique_ids) <= set(by_id)
    assert set(by_id["G0016"].technique_sequence) == set(by_id["G0016"].technique_ids)
    assert all(record.source_version == "ATT&CK-xlsx-v19.2" and record.source_hash == digest
               for record in records)


def test_versioned_local_corpus_does_not_expire_on_daily_feed_timer(tmp_path):
    from tests.ingestion.test_threat_intel import _build_minimal_index, GOLDEN_STIX_BUNDLE
    from src.ingestion.indexing.threat_intel_sources import AttackStixFetcher
    import json
    _build_minimal_index(str(tmp_path), list(AttackStixFetcher().parse(GOLDEN_STIX_BUNDLE)))
    path = tmp_path / "build_manifest.json"
    manifest = json.loads(path.read_text())
    manifest["source_versions"] = {"local_attack_xlsx": "ATT&CK-xlsx-v19.2"}
    manifest["build_timestamp"] = "2020-01-01T00:00:00Z"
    manifest["artifact_hashes"] = {name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
                                   for name in ("faiss_index.bin", "faiss_id_map.json", "metadata_store.json")}
    path.write_text(json.dumps(manifest))
    health = ThreatIntelMCPServer(index_dir=str(tmp_path)).health_check()
    assert health["status"] == "ready"
    assert health["is_stale"] is False
    assert health["freshness_basis"] == "versioned_local_source"
