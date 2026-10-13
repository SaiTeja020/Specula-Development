"""
tests/ingestion/test_memory_ingestion.py

Verification oracle for TASK-4.9 (memory dump ingestion).

Covers:
  1. Mock extractor output shape & completeness.
  2. memory_dump_normalizer branching (pslist / netscan / malfind).
  3. OCSF class_uid / category_uid correctness.
  4. clock_skew_unverified=True (no DC anchor for memory captures).
  5. Pipeline integration: run_pipeline_on_event with source_type="memory".
  6. Error paths: empty payload, unknown plugin label.
  7. UID determinism across identical payloads.

Verification command:
  .\\venv\\Scripts\\pytest.exe tests/ingestion/test_memory_ingestion.py -v
"""

import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.abspath("."))

# Force mock mode for all tests so no real WinPmem / Volatility3 is required.
os.environ["SPECULA_MEMORY_MOCK"] = "true"
os.environ["SPECULA_MEMORY_ENABLED"] = "true"

from src.ingestion.extractors.memory_extractor import (
    _generate_mock_records,
    _map_row,
    _parse_vol3_json,
    extract_memory_events,
)
from src.ingestion.normalization.memory_dump_normalizer import normalize
from src.schemas.ocsf_phase2_events import (
    DetectionFindingEvent,
    NetworkActivityEvent,
    ProcessActivityEvent,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def mock_records():
    return _generate_mock_records()


@pytest.fixture()
def pslist_record(mock_records):
    return next(r for r in mock_records if r["plugin"] == "pslist")


@pytest.fixture()
def netscan_record(mock_records):
    return next(r for r in mock_records if r["plugin"] == "netscan")


@pytest.fixture()
def malfind_record(mock_records):
    return next(r for r in mock_records if r["plugin"] == "malfind")


# ── 1. Mock extractor output ──────────────────────────────────────────────────


class TestMockExtractor:
    def test_returns_nonempty_list(self, mock_records):
        assert len(mock_records) > 0

    def test_all_three_plugin_types_present(self, mock_records):
        labels = {r["plugin"] for r in mock_records}
        assert labels == {"pslist", "netscan", "malfind"}

    def test_extract_memory_events_mock(self):
        events = extract_memory_events()
        assert isinstance(events, list)
        assert len(events) == 6  # 3 pslist + 2 netscan + 1 malfind

    def test_all_records_have_capture_time(self, mock_records):
        for rec in mock_records:
            assert "capture_time" in rec
            assert rec["capture_time"]  # not empty

    def test_all_records_have_dc_anchor_false(self, mock_records):
        for rec in mock_records:
            assert rec["has_dc_anchor"] is False

    def test_pslist_record_fields(self, pslist_record):
        assert "ImageFileName" in pslist_record
        assert "PID" in pslist_record
        assert "PPID" in pslist_record

    def test_netscan_record_fields(self, netscan_record):
        assert "LocalAddr" in netscan_record
        assert "Proto" in netscan_record

    def test_malfind_record_fields(self, malfind_record):
        assert "process_name" in malfind_record
        assert malfind_record["severity_id"] == 5


# ── 2. Normaliser branching ───────────────────────────────────────────────────


class TestMemoryNormaliserBranching:
    def test_pslist_produces_process_activity_event(self, pslist_record):
        events = normalize(pslist_record, trace_id="t1", case_id="C1")
        assert len(events) == 1
        assert isinstance(events[0], ProcessActivityEvent)

    def test_netscan_produces_network_activity_event(self, netscan_record):
        events = normalize(netscan_record, trace_id="t1", case_id="C1")
        assert len(events) == 1
        assert isinstance(events[0], NetworkActivityEvent)

    def test_malfind_produces_detection_finding_event(self, malfind_record):
        events = normalize(malfind_record, trace_id="t1", case_id="C1")
        assert len(events) == 1
        assert isinstance(events[0], DetectionFindingEvent)


# ── 3. OCSF class_uid / category_uid ─────────────────────────────────────────


class TestOCSFClassIds:
    def test_pslist_class_uid(self, pslist_record):
        ev = normalize(pslist_record, trace_id="t1", case_id="C1")[0]
        assert ev.class_uid == 1007
        assert ev.category_uid == 1

    def test_netscan_class_uid(self, netscan_record):
        ev = normalize(netscan_record, trace_id="t1", case_id="C1")[0]
        assert ev.class_uid == 4001
        assert ev.category_uid == 4

    def test_malfind_class_uid(self, malfind_record):
        ev = normalize(malfind_record, trace_id="t1", case_id="C1")[0]
        assert ev.class_uid == 2004
        assert ev.category_uid == 2


# ── 4. Clock skew / timestamp behaviour ──────────────────────────────────────


class TestTimestampBehaviour:
    def test_pslist_clock_skew_unverified(self, pslist_record):
        ev = normalize(pslist_record, trace_id="t1", case_id="C1")[0]
        assert ev.clock_skew_unverified is True
        assert ev.clock_skew_offset_ms == 0

    def test_netscan_clock_skew_unverified(self, netscan_record):
        ev = normalize(netscan_record, trace_id="t1", case_id="C1")[0]
        assert ev.clock_skew_unverified is True

    def test_malfind_clock_skew_unverified(self, malfind_record):
        ev = normalize(malfind_record, trace_id="t1", case_id="C1")[0]
        assert ev.clock_skew_unverified is True


# ── 5. Pipeline integration ───────────────────────────────────────────────────


class TestPipelineIntegration:
    """
    Test that run_pipeline_on_event properly routes source_type="memory"
    through memory_dump_normalizer without hitting Neo4j or Quickwit.
    """

    def test_pipeline_on_pslist_event(self, pslist_record):
        from src.ingestion.normalization.time_normalizer import TimeNormalizer
        from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
        from src.ingestion.run_pipeline import run_pipeline_on_event
        from src.schemas.entity_resolver import CanonicalEntityResolver

        results = run_pipeline_on_event(
            raw_event=dict(pslist_record),
            vct_chain=VCTAtomicChain(),
            resolver=CanonicalEntityResolver(),
            time_normalizer=TimeNormalizer(dc_anchor_skew_ms=0),
            qw_client=None,
            source_type="memory",
            neo4j_client=None,
        )
        assert len(results) == 1
        validated_evt, cypher_q, neo4j_res = results[0]
        assert validated_evt is not None
        assert neo4j_res is None  # No Neo4j client provided

    def test_pipeline_on_netscan_event(self, netscan_record):
        from src.ingestion.normalization.time_normalizer import TimeNormalizer
        from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
        from src.ingestion.run_pipeline import run_pipeline_on_event
        from src.schemas.entity_resolver import CanonicalEntityResolver

        results = run_pipeline_on_event(
            raw_event=dict(netscan_record),
            vct_chain=VCTAtomicChain(),
            resolver=CanonicalEntityResolver(),
            time_normalizer=TimeNormalizer(dc_anchor_skew_ms=0),
            qw_client=None,
            source_type="memory",
            neo4j_client=None,
        )
        assert len(results) == 1

    def test_pipeline_on_malfind_event(self, malfind_record):
        from src.ingestion.normalization.time_normalizer import TimeNormalizer
        from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
        from src.ingestion.run_pipeline import run_pipeline_on_event
        from src.schemas.entity_resolver import CanonicalEntityResolver

        results = run_pipeline_on_event(
            raw_event=dict(malfind_record),
            vct_chain=VCTAtomicChain(),
            resolver=CanonicalEntityResolver(),
            time_normalizer=TimeNormalizer(dc_anchor_skew_ms=0),
            qw_client=None,
            source_type="memory",
            neo4j_client=None,
        )
        assert len(results) == 1

    def test_all_mock_records_through_pipeline(self, mock_records):
        from src.ingestion.normalization.time_normalizer import TimeNormalizer
        from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
        from src.ingestion.run_pipeline import run_pipeline_on_event
        from src.schemas.entity_resolver import CanonicalEntityResolver

        chain = VCTAtomicChain()
        resolver = CanonicalEntityResolver()
        tn = TimeNormalizer(dc_anchor_skew_ms=0)

        total_results = []
        for record in mock_records:
            results = run_pipeline_on_event(
                raw_event=dict(record),
                vct_chain=chain,
                resolver=resolver,
                time_normalizer=tn,
                qw_client=None,
                source_type="memory",
                neo4j_client=None,
            )
            total_results.extend(results)

        assert len(total_results) == len(mock_records)


# ── 6. Error paths ────────────────────────────────────────────────────────────


class TestErrorPaths:
    def test_empty_payload_returns_generic_fallback(self):
        """
        Unknown plugin label with no meaningful fields -> generic
        ProcessActivityEvent fallback with process_name='unknown'.
        """
        empty = {
            "plugin": "unknown_plugin",
            "capture_time": "2026-09-29T00:00:00+00:00",
            "has_dc_anchor": False,
        }
        events = normalize(empty, trace_id="t1", case_id="C1")
        assert len(events) == 1
        assert isinstance(events[0], ProcessActivityEvent)
        assert events[0].process_name == "unknown"

    def test_invalid_vol3_json_returns_empty(self):
        records = _parse_vol3_json("not valid json {{{{", label="pslist")
        assert records == []

    def test_empty_vol3_json_rows_returns_empty(self):
        import json
        payload = json.dumps({"columns": ["ImageFileName", "PID"], "rows": []})
        records = _parse_vol3_json(payload, label="pslist")
        assert records == []

    def test_pslist_row_with_no_filename_or_pid_filtered_out(self):
        record = _map_row(
            {"ImageFileName": None, "PID": None},
            label="pslist",
            capture_time="2026-09-29T00:00:00+00:00",
        )
        assert record is None


# ── 7. UID determinism ────────────────────────────────────────────────────────


class TestUIDDeterminism:
    def test_pslist_uid_is_deterministic(self, pslist_record):
        ev_a = normalize(dict(pslist_record), trace_id="t1", case_id="C1")[0]
        ev_b = normalize(dict(pslist_record), trace_id="t1", case_id="C1")[0]
        assert ev_a.uid == ev_b.uid

    def test_malfind_uid_is_deterministic(self, malfind_record):
        ev_a = normalize(dict(malfind_record), trace_id="t1", case_id="C1")[0]
        ev_b = normalize(dict(malfind_record), trace_id="t1", case_id="C1")[0]
        assert ev_a.uid == ev_b.uid

    def test_different_processes_have_different_uids(self, mock_records):
        pslist_records = [r for r in mock_records if r["plugin"] == "pslist"]
        assert len(pslist_records) >= 2
        ev_a = normalize(pslist_records[0], trace_id="t1", case_id="C1")[0]
        ev_b = normalize(pslist_records[1], trace_id="t1", case_id="C1")[0]
        assert ev_a.uid != ev_b.uid
