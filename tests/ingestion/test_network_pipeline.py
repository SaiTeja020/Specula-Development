import json
from datetime import datetime, timezone

from src.ingestion.network_pipeline import ingest_network_files, load_dhcp_leases, tail_network_files_once
from src.ingestion.preservation.quickwit_client import QuickwitClientError
from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain


def test_file_ingestion_preserves_and_normalizes_zeek_and_suricata(tmp_path):
    epoch = datetime(2026, 6, 1, tzinfo=timezone.utc).timestamp()
    zeek_record = {
        "ts": epoch, "uid": "C1", "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.8.8",
        "id.orig_p": 52000, "id.resp_p": 443, "proto": "tcp", "orig_bytes": 900,
        "resp_bytes": 80,
    }
    suricata_record = {
        "timestamp": "2026-06-01T00:00:02Z", "event_type": "flow", "flow_id": 12,
        "src_ip": "10.0.0.5", "dest_ip": "8.8.8.8", "src_port": 52000,
        "dest_port": 443, "proto": "TCP", "flow": {"bytes_toserver": 700, "bytes_toclient": 60},
    }
    zeek_path, eve_path, lease_path = tmp_path / "conn.jsonl", tmp_path / "eve.json", tmp_path / "leases.json"
    zeek_bytes = (json.dumps(zeek_record) + "\n").encode()
    suricata_bytes = (json.dumps(suricata_record) + "\n").encode()
    zeek_path.write_bytes(zeek_bytes)
    eve_path.write_bytes(suricata_bytes)
    lease_path.write_text(json.dumps([{
        "ip": "10.0.0.5", "canonical_host_uid": "host-5",
        "valid_from": "2026-01-01T00:00:00Z", "valid_to": None,
    }]))

    class Quickwit:
        def __init__(self):
            self.raw = []
        def commit_raw_evidence(self, **kwargs):
            self.raw.append(kwargs)
    class Producer:
        def __init__(self):
            self.events = []
        def produce_event(self, event):
            self.events.append(event)
    class Graph:
        def __init__(self):
            self.writes = []
        def execute(self, query, params):
            self.writes.append((query, params))

    quickwit, producer, graph, chain = Quickwit(), Producer(), Graph(), VCTAtomicChain()
    events, errors = ingest_network_files(
        zeek_jsonl=[str(zeek_path)], suricata_eve=[str(eve_path)],
        resolver=load_dhcp_leases(str(lease_path)), vct_chain=chain,
        quickwit_client=quickwit, event_producer=producer, neo4j_client=graph,
        case_id="case-1",
    )
    assert not errors
    assert len(events) == len(quickwit.raw) == len(producer.events) == len(graph.writes) == 2
    assert [record["raw_bytes"] for record in quickwit.raw] == [zeek_bytes, suricata_bytes]
    assert [event.canonical_host_id for event in events] == ["host-5", "host-5"]
    assert [event.case_id for event in events] == ["case-1", "case-1"]
    assert events[0].bytes_out == 900
    assert events[0].clock_skew_unverified
    assert chain.verify_chain()


def test_file_ingestion_reports_bad_records_but_preserves_them(tmp_path):
    source = tmp_path / "bad.jsonl"
    raw = b"not-json\n"
    source.write_bytes(raw)
    class Quickwit:
        def __init__(self):
            self.raw = []
        def commit_raw_evidence(self, **kwargs):
            self.raw.append(kwargs["raw_bytes"])
    class Producer:
        def produce_event(self, event):
            raise AssertionError("Malformed record must not reach Kafka")

    quickwit = Quickwit()
    events, errors = ingest_network_files(
        zeek_jsonl=[str(source)], resolver=load_dhcp_leases(None),
        vct_chain=VCTAtomicChain(), quickwit_client=quickwit,
        event_producer=Producer(),
    )
    assert events == []
    assert len(errors) == 1 and "bad.jsonl:1" in errors[0]
    assert quickwit.raw == [raw]


def test_file_ingestion_stops_on_preservation_failure(tmp_path):
    source = tmp_path / "conn.jsonl"
    source.write_text(json.dumps({"ts": 1, "uid": "x"}) + "\n")
    class Quickwit:
        def commit_raw_evidence(self, **kwargs):
            raise QuickwitClientError("offline")
    class Producer:
        def produce_event(self, event):
            raise AssertionError("Unpreserved data must not reach Kafka")

    try:
        ingest_network_files(
            zeek_jsonl=[str(source)], resolver=load_dhcp_leases(None),
            vct_chain=VCTAtomicChain(), quickwit_client=Quickwit(),
            event_producer=Producer(),
        )
    except QuickwitClientError:
        pass
    else:
        raise AssertionError("Preservation failure should stop network ingestion")


def test_follow_checkpoints_complete_lines_and_resumes_after_append(tmp_path):
    source, offsets = tmp_path / "conn.jsonl", tmp_path / "offsets.json"
    leases = tmp_path / "leases.json"
    leases.write_text(json.dumps([{"ip": "10.0.0.5", "canonical_host_uid": "host-5",
                                   "valid_from": "2020-01-01T00:00:00Z"}]))
    record = {"ts": 1780272000, "uid": "C1", "id.orig_h": "10.0.0.5",
              "id.resp_h": "8.8.8.8", "id.orig_p": 52000, "id.resp_p": 443,
              "proto": "tcp", "orig_bytes": 10, "resp_bytes": 20}

    class Quickwit:
        def __init__(self): self.raw = []
        def commit_raw_evidence(self, **kwargs): self.raw.append(kwargs["raw_bytes"])
    class Producer:
        def __init__(self): self.events = []
        def produce_event(self, event): self.events.append(event)

    quickwit, producer = Quickwit(), Producer()
    common = dict(zeek_jsonl=[str(source)], resolver=load_dhcp_leases(str(leases)),
                  vct_chain=VCTAtomicChain(), quickwit_client=quickwit,
                  event_producer=producer, offset_file=str(offsets))
    source.write_bytes(json.dumps(record).encode())  # trailing partial line is held
    events, errors = tail_network_files_once(**common)
    assert not events and not errors and not offsets.exists()

    with source.open("ab") as stream:
        stream.write(b"\n")
    events, errors = tail_network_files_once(**common)
    assert len(events) == 1 and not errors
    assert len(quickwit.raw) == len(producer.events) == 1
    events, errors = tail_network_files_once(**common)
    assert not events and not errors and len(quickwit.raw) == 1

    record["uid"] = "C2"
    with source.open("ab") as stream:
        stream.write((json.dumps(record) + "\n").encode())
    events, errors = tail_network_files_once(**common)
    assert len(events) == 1 and not errors and len(quickwit.raw) == 2

    record["uid"] = "C3"
    replacement = (json.dumps(record) + "\n").encode()
    source.write_bytes(replacement)  # smaller file simulates truncation/restart
    events, errors = tail_network_files_once(**common)
    assert len(events) == 1 and not errors and len(quickwit.raw) == 3


def test_follow_retries_record_when_preservation_fails(tmp_path):
    source, offsets = tmp_path / "conn.jsonl", tmp_path / "offsets.json"
    source.write_text(json.dumps({"ts": 1, "uid": "C1"}) + "\n")
    class Quickwit:
        def commit_raw_evidence(self, **kwargs): raise QuickwitClientError("offline")
    class Producer:
        def produce_event(self, event): raise AssertionError("must not publish")

    try:
        tail_network_files_once(
            zeek_jsonl=[str(source)], resolver=load_dhcp_leases(None),
            vct_chain=VCTAtomicChain(), quickwit_client=Quickwit(),
            event_producer=Producer(), offset_file=str(offsets),
        )
    except QuickwitClientError:
        pass
    else:
        raise AssertionError("preservation failure must stop and leave offset uncommitted")
    assert not offsets.exists()
