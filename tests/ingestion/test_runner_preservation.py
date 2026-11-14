import hashlib
import json
from unittest.mock import Mock
import pytest

from src.ingestion.run_pipeline import run_pipeline_on_event
from src.ingestion.preservation.quickwit_client import QuickwitClientError
from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.schemas.entity_resolver import CanonicalEntityResolver


def test_runner_preserves_exact_input_and_matching_digest():
    original = {"Id": 99999, "TimeCreated": "2026-10-07T00:00:00Z", "Message": "sample"}
    before = dict(original)
    quickwit = Mock()
    chain = VCTAtomicChain()
    run_pipeline_on_event(original, chain, CanonicalEntityResolver(), TimeNormalizer(), quickwit)
    committed = quickwit.commit_raw_evidence.call_args.kwargs
    assert committed["raw_bytes"] == json.dumps(before, sort_keys=True).encode()
    assert committed["sha256_digest"] == hashlib.sha256(committed["raw_bytes"]).hexdigest()
    assert original == before
    assert chain.verify_chain()


def test_runner_preservation_failure_stops_processing(monkeypatch):
    quickwit = Mock()
    quickwit.commit_raw_evidence.side_effect = QuickwitClientError("storage failed")
    gate = Mock(side_effect=AssertionError("must not process unpreserved evidence"))
    monkeypatch.setattr("src.ingestion.run_pipeline.run_security_gate", gate)
    chain = VCTAtomicChain()
    previous = chain.current_chain_hash
    with pytest.raises(QuickwitClientError):
        run_pipeline_on_event({"Id": 4688}, chain, CanonicalEntityResolver(), TimeNormalizer(), quickwit)
    assert chain.current_chain_hash == previous
    gate.assert_not_called()
