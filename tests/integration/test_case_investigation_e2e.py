"""Live local-Docker oracle. No infrastructure mocks or availability skips.

Synthetic sensor records and an explicitly labeled local ATT&CK profile fixture
exercise real stores and graph execution; hosted models are not claimed here.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import threading
import time
import uuid
from datetime import datetime, timezone

import pytest

pytestmark = pytest.mark.integration


def test_preserved_network_case_through_http_review_and_dashboard(tmp_path, monkeypatch, api_auth):
    import chromadb
    import faiss
    import numpy as np
    import redis
    import requests
    import uvicorn
    from confluent_kafka import Consumer, Producer, TopicPartition
    from confluent_kafka.admin import AdminClient, NewTopic
    from langgraph.checkpoint.memory import InMemorySaver
    from neo4j import GraphDatabase
    from websockets.sync.client import connect
    from scripts.build_threat_intel_index import _write_artifacts_atomic
    from src.agents.graph import build_graph
    import src.agents.visualizer_api as visualizer
    from src.graph.cypher_builder import CypherBuilder
    from src.ingestion.broker.active_cases_cache import ActiveCasesCache
    from src.ingestion.broker.kafka_consumer import deserialize_event
    from src.ingestion.broker.kafka_producer import EventProducer
    from src.ingestion.indexing.threat_intel_sources import ThreatIntelRecord
    from src.ingestion.indexing.vector_store import EmbeddingGenerator
    from src.ingestion.network_pipeline import ingest_network_json, load_dhcp_leases
    from src.ingestion.preservation.quickwit_client import QuickwitClient
    from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
    from src.ingestion.validation.schema_registry_client import OCSF_BASE_JSON_SCHEMA
    from src.mcp.threat_intel_mcp import ThreatIntelMCPServer

    backend = os.environ.get("SPECULA_VALIDATION_BACKEND", "stub")
    assert backend in {"stub", "ollama"}, "Only offline/local validation is authorized"
    monkeypatch.setenv("SPECULA_LLM_BACKEND", backend)
    monkeypatch.setenv("SPECULA_THREAT_ATTRIBUTION_BACKEND", backend)
    run_id = uuid.uuid4().hex
    case_id = "VALIDATION-" + run_id
    topic = "specula.validation." + run_id
    broker = "localhost:9092"
    admin = AdminClient({"bootstrap.servers": broker})
    for future in admin.create_topics([NewTopic(topic, num_partitions=1, replication_factor=1)]).values():
        future.result(timeout=15)
    cache = redis.Redis(socket_timeout=5)
    assert cache.ping()
    driver = GraphDatabase.driver("bolt://localhost:7687", auth=None)
    driver.verify_connectivity()
    driver.execute_query("CREATE CONSTRAINT validation_event_uid IF NOT EXISTS FOR (e:Event) REQUIRE e.uid IS UNIQUE")
    driver.execute_query("CREATE CONSTRAINT validation_case_uid IF NOT EXISTS FOR (c:Case) REQUIRE c.uid IS UNIQUE")
    quickwit = QuickwitClient()
    quickwit.ensure_index()
    producer = EventProducer(OCSF_BASE_JSON_SCHEMA, topic, ActiveCasesCache())
    assert producer._real_producer is not None, "In-memory Kafka fallback is not a live pass"
    consumer = Consumer({"bootstrap.servers": broker, "group.id": "validation-" + run_id,
                         "enable.auto.commit": False, "auto.offset.reset": "earliest"})
    consumer.assign([TopicPartition(topic, 0, 0)])
    chain = VCTAtomicChain()
    lease_file = tmp_path / "leases.json"
    lease_file.write_text(json.dumps([{"ip": "10.123.0.5", "canonical_host_uid": "validation-host-" + run_id,
                                      "valid_from": "2026-01-01T00:00:00Z", "valid_to": None}]))
    resolver = load_dhcp_leases(str(lease_file))
    originals, events = {}, []
    epoch = datetime(2026, 10, 7, tzinfo=timezone.utc).timestamp()
    for i in range(4):
        raw = json.dumps({"ts": epoch + i * 60, "uid": run_id + str(i),
            "id.orig_h": "10.123.0.5", "id.resp_h": "8.8.8.8", "id.orig_p": 52000 + i,
            "id.resp_p": 443, "proto": "tcp", "orig_bytes": 1_500_001, "resp_bytes": 100}).encode()
        digest = hashlib.sha256(raw).hexdigest()
        originals[digest] = raw
        events.append(ingest_network_json(raw, source_type="zeek", trace_id="validation-" + run_id,
            case_id=case_id, resolver=resolver, vct_chain=chain, quickwit_client=quickwit,
            event_producer=producer))
    assert chain.verify_chain()
    assert producer.flush(15) == 0 and not producer._buffer
    offsets = []
    try:
        deadline = time.monotonic() + 30
        while len(offsets) < 4 and time.monotonic() < deadline:
            message = consumer.poll(1)
            if message is None: continue
            assert not message.error(), str(message.error())
            event = deserialize_event(message.value(), topic)
            assert event["case_id"] == case_id
            query, params = CypherBuilder.dispatch_event(event)
            driver.execute_query(query, parameters_=params)
            offsets.append(message.offset())
            cache.set("specula:validation:" + run_id, message.offset(), ex=3600)
        assert len(offsets) == 4, "All preserved events must be consumed from Kafka"
        assert int(cache.get("specula:validation:" + run_id)) == offsets[-1]
    finally:
        consumer.close()
    records, _, _ = driver.execute_query(
        "MATCH (:Case {uid: $case_id})-[:HAS_EVENT]->(e:Event) RETURN e.uid AS uid", case_id=case_id)
    event_uids = sorted(record["uid"] for record in records)
    assert event_uids == sorted(event.uid for event in events)
    # Real persistent Chroma collection, explicit embeddings avoid model downloads.
    collection = chromadb.HttpClient(host="localhost", port=8000).get_or_create_collection("specula_validation")
    embedder = EmbeddingGenerator()
    collection.upsert(ids=event_uids, embeddings=[embedder.embed(uid) for uid in event_uids],
                      metadatas=[{"case_id": case_id} for _ in event_uids])
    assert set(collection.get(where={"case_id": case_id})["ids"]) == set(event_uids)

    # A real FAISS index with fixture-only provenance, not a claimed live MITRE feed.
    corpus_dir = tmp_path / "corpus"
    records = [ThreatIntelRecord(key, kind, title, title, "mitre_attack_stix", "local-validation-fixture")
               for key, kind, title in [("T1071", "attack_technique", "Application Layer Protocol"),
                   ("T1048", "attack_technique", "Exfiltration Over Alternative Protocol"),
                   ("G0001", "attack_group", "Local validation profile; no actor identity claim")]]
    metadata = [{"record_id": item.record_id, "record_type": item.record_type, "title": item.title,
                 "source": item.source, "source_version": item.source_version,
                 "source_hash": hashlib.sha256(item.embed_text.encode()).hexdigest(),
                 "technique_ids": ["T1071", "T1048"] if item.record_type == "attack_group" else [],
                 "technique_sequence": []} for item in records]
    matrix = np.array([embedder.embed(item.embed_text) for item in records], dtype="float32")
    index = faiss.IndexFlatIP(matrix.shape[1])
    index.add(matrix)
    _write_artifacts_atomic(str(corpus_dir), index, {}, metadata, records, {
        "build_timestamp": datetime.now(timezone.utc).isoformat(), "total_records": 3,
        "source_versions": {"mitre_attack_stix": "local-validation-fixture"}})
    intel = ThreatIntelMCPServer(index_dir=str(corpus_dir))
    assert intel.health_check()["artifacts_verified"]
    finding_producer = Producer({"bootstrap.servers": broker})
    graph = build_graph(checkpointer=InMemorySaver(), redis_client=cache,
                        neo4j_driver=driver, kafka_producer=finding_producer, threat_intel=intel)
    monkeypatch.setattr(visualizer, "_specula_graph", graph)
    monkeypatch.setattr(visualizer, "_neo4j_driver", driver)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(visualizer.app, log_level="error"))
    thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline: time.sleep(0.05)
        assert server.started
        base = f"http://127.0.0.1:{port}"
        # Long local inference can emit more than the client's default 16 frames
        # while this thread waits for HTTP. Keep receiving protocol pongs.
        with connect(f"ws://127.0.0.1:{port}/api/graph/stream", open_timeout=5, max_queue=None,
                     additional_headers=api_auth) as websocket:
            assert json.loads(websocket.recv(timeout=5))["type"] == "authenticated"
            websocket.send("ping")
            assert websocket.recv(timeout=5) == "pong"
            response = requests.post(base + "/api/investigations", json={"case_id": case_id,
                "raw_input": "Investigate periodic network egress. FORCE_GUARDRAIL3_FAIL"}, timeout=600, headers=api_auth)
            assert response.status_code == 200, response.text
            paused = response.json()
            destination = Path("data/verification")
            destination.mkdir(parents=True, exist_ok=True)
            (destination / "full_run_paused_latest.json").write_text(json.dumps({
                "backend": backend, "snapshot": paused}, indent=2), encoding="utf-8")
            assert "hitl" in paused["paused_at"]
            assert paused["attribution"]["top_candidate"] is not None
            assert set(paused["attribution"]["dfkg_refs"]) == set(event_uids)
            streamed = []
            while True:
                event = json.loads(websocket.recv(timeout=10))
                streamed.append(event)
                if event["type"] == "hitl_required": break
            assert any(event["payload"].get("node") == "threat_attribution" for event in streamed)
            reviewed = requests.post(base + f"/api/investigations/{case_id}/review",
                                     json={"decision": "approve"}, timeout=600, headers=api_auth)
            assert reviewed.status_code == 200, reviewed.text
            completed = reviewed.json()
            approvals = 1
            # Real debate may exhaust before guardrails. Approval can then
            # reach a second, distinct guardrail review; do not assume one gate.
            while "hitl" in completed["paused_at"] and approvals < 3:
                reviewed = requests.post(base + f"/api/investigations/{case_id}/review",
                                         json={"decision": "approve"}, timeout=600, headers=api_auth)
                assert reviewed.status_code == 200, reviewed.text
                completed = reviewed.json()
                approvals += 1
            (destination / "full_run_reviewed_latest.json").write_text(json.dumps({
                "backend": backend, "approvals": approvals, "snapshot": completed}, indent=2), encoding="utf-8")
            assert completed["case_status"] == "closed" and not completed["paused_at"]
            assert any(f["agent_role"] == "report_generation" and set(f["dfkg_refs"]) == set(event_uids)
                       for f in completed["findings"])
            while True:
                event = json.loads(websocket.recv(timeout=10))
                if event["type"] == "run_complete":
                    assert event["payload"]["case_id"] == case_id
                    break
        assert requests.get(base + f"/api/investigations/{case_id}", timeout=5, headers=api_auth).json()["case_status"] == "closed"
        assert completed["evidence_collection"]["status"] == "complete"
        assert set(completed["report_metadata"]["dfkg_refs"]) == set(event_uids)
        assert completed["report_output"].endswith("END OF SPECULA REPORT")
        assert completed["timeline_artifact"].endswith("END OF SPECULA TIMELINE")
        assert finding_producer.flush(10) == 0
        deadline = time.monotonic() + 40
        preserved = {}
        while len(preserved) < len(originals) and time.monotonic() < deadline:
            for digest in originals:
                record = quickwit.get_evidence(digest)
                if record:
                    assert record["raw_bytes"] == originals[digest]
                    assert record["sha256"] == hashlib.sha256(record["raw_bytes"]).hexdigest()
                    preserved[digest] = record["sha256"]
            if len(preserved) < len(originals): time.sleep(0.5)
        assert len(preserved) == 4, "Preservation must be searchable and hash-verifiable"
        if backend == "ollama":
            assert any(trace.get("model_used") == os.environ.get("SPECULA_OLLAMA_MODEL", "qwen3:8b")
                       for trace in completed["agent_traces"]), "No actual Ollama model trace"
        result = {"case_id": case_id, "backend": backend, "corpus": "local-validation-fixture",
                  "agent_traces": completed["agent_traces"],
                  "findings": completed["findings"],
                  "analyst_approvals": approvals,
                  "kafka_topic": topic, "kafka_offsets": offsets, "preserved_hashes": preserved,
                  "event_uids": event_uids, "case_status": completed["case_status"],
                  "http_review": "approved", "websocket_result": "run_complete",
                  "chroma_records": len(event_uids), "vct_chain_verified": chain.verify_chain()}
        destination = Path("data/verification")
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "local_case_latest.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        issues = [trace for trace in completed["agent_traces"] if trace.get("terminal") is False]
        assert not issues, "One or more workers returned incomplete execution; see saved agent traces"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listener.close()
        driver.close()
