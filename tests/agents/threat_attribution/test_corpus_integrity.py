import hashlib
import json

from src.ingestion.indexing.threat_intel_index import ThreatIntelIndex
from tests.ingestion.test_threat_intel import _build_minimal_index, GOLDEN_STIX_BUNDLE
from src.ingestion.indexing.threat_intel_sources import AttackStixFetcher


def test_manifest_bound_artifacts_reject_partial_rebuild(tmp_path):
    _build_minimal_index(str(tmp_path), list(AttackStixFetcher().parse(GOLDEN_STIX_BUNDLE)))
    manifest_path = tmp_path / "build_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    names = ["faiss_index.bin", "faiss_id_map.json", "metadata_store.json"]
    manifest["artifact_hashes"] = {name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() for name in names}
    manifest_path.write_text(json.dumps(manifest))
    index = ThreatIntelIndex(str(tmp_path))
    assert index.provenance["artifacts_verified"]
    prior = index.provenance
    (tmp_path / "metadata_store.json").write_text("{}")
    manifest["build_timestamp"] = "2026-10-07T01:00:00Z"
    manifest_path.write_text(json.dumps(manifest))
    index.reload_if_stale()
    assert index.provenance == prior
    assert index.get_record_metadata("T1059.001") is not None
    assert not ThreatIntelIndex(str(tmp_path)).is_ready()
