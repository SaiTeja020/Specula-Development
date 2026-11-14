"""Execute concrete gates without equating development smoke tests to production readiness."""
import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
import time
import uuid

import pytest
import requests

pytestmark = pytest.mark.production_readiness


def latest_case():
    path = Path("data/verification/local_case_latest.json")
    assert path.is_file(), "Run the complete local investigation oracle first"
    assert time.time() - path.stat().st_mtime < 86400, "Investigation evidence is older than 24 hours"
    return json.loads(path.read_text())


def test_complete_integration_evidence_is_present():
    evidence = latest_case()
    assert evidence["case_status"] == "closed" and evidence["http_review"] == "approved"
    assert evidence["websocket_result"] == "run_complete"
    assert evidence["vct_chain_verified"] and len(evidence["kafka_offsets"]) == 4
    assert evidence["chroma_records"] == len(evidence["event_uids"]) == 4
    assert len(evidence["preserved_hashes"]) == 4
    assert all(uid == digest for uid, digest in evidence["preserved_hashes"].items())


def test_measured_redis_throughput_meets_approved_threshold():
    import redis
    client = redis.Redis(socket_timeout=5)
    prefix = "specula:performance:" + uuid.uuid4().hex
    started = time.perf_counter()
    pipeline = client.pipeline(transaction=False)
    for i in range(1000):
        pipeline.set(prefix + str(i), str(i), ex=60)
        pipeline.get(prefix + str(i))
    results = pipeline.execute()
    duration = time.perf_counter() - started
    assert all(results[i * 2 + 1] == str(i).encode() for i in range(1000))
    rate = 2000 / duration
    target = Path("data/verification/redis_performance_latest.json")
    target.write_text(json.dumps({"operations": 2000, "seconds": duration, "operations_per_second": rate}, indent=2))
    minimum = os.getenv("SPECULA_APPROVED_REDIS_OPS_PER_SECOND")
    assert minimum, f"Measured {rate:.0f} Redis ops/sec; approved throughput threshold is not configured"
    assert rate >= float(minimum)


def test_sensitive_graph_data_requires_authorization():
    response = requests.get("http://localhost:8300/api/data/neo4j", timeout=10)
    assert response.status_code in (401, 403), "Development API exposes graph data without authorization; production security gate fails"


def test_raw_evidence_backup_restores_to_isolated_index(tmp_path):
    from src.ingestion.preservation.quickwit_client import QuickwitClient
    evidence = latest_case()
    assert len(evidence["preserved_hashes"]) == 4, "Restore requires exactly four preserved records"
    source = QuickwitClient()
    backup = []
    for uid in evidence["preserved_hashes"]:
        record = source.get_evidence(uid)
        assert record is not None
        assert hashlib.sha256(record["raw_bytes"]).hexdigest() == record["sha256"] == evidence["preserved_hashes"][uid]
        backup.append({"uid": uid, "sha256": record["sha256"], "source_type": record["source_type"],
                       "raw_data_b64": base64.b64encode(record["raw_bytes"]).decode()})
    backup_path = tmp_path / "raw_evidence_backup.json"
    backup_path.write_text(json.dumps(backup))
    restored = QuickwitClient(index_name="specula_restore_validation_" + uuid.uuid4().hex)
    restored.ensure_index()
    started = time.monotonic()
    for record in json.loads(backup_path.read_text()):
        restored.commit_raw_evidence(uid=record["uid"], trace_id="restore-validation",
            sha256_digest=record["sha256"], raw_bytes=base64.b64decode(record["raw_data_b64"]),
            source_type=record["source_type"])
    remaining = {record["uid"]: record for record in backup}
    deadline = time.monotonic() + 40
    while remaining and time.monotonic() < deadline:
        for uid in list(remaining):
            record = restored.get_evidence(uid)
            if record:
                assert record["sha256"] == hashlib.sha256(record["raw_bytes"]).hexdigest() == remaining[uid]["sha256"]
                del remaining[uid]
        if remaining: time.sleep(0.5)
    assert not remaining, "Restored raw evidence failed hash verification"
    assert len(backup) == 4
    Path("data/verification/raw_restore_latest.json").write_text(json.dumps({
        "scope": "four raw evidence records only", "index": restored.index_name,
        "verified_records": len(backup), "restore_seconds": time.monotonic() - started,
        "full_multistore_restore_verified": False}, indent=2))


def test_checkpoint_durability_is_configured():
    # Two fresh processes use the actual visualizer initialization path. Redis
    # cache persistence cannot substitute for surviving graph checkpoint state.
    environment = os.environ.copy()
    environment.update({"SPECULA_LLM_BACKEND": "stub", "SPECULA_THREAT_ATTRIBUTION_BACKEND": "stub",
                        "VALIDATION_CASE_ID": latest_case()["case_id"],
                        "VALIDATION_THREAD_ID": "restart-validation-" + uuid.uuid4().hex})
    common = '''
import json, os
from src.agents.visualizer_api import _get_specula_graph
graph = _get_specula_graph()
assert graph is not None
config = {"configurable": {"thread_id": os.environ["VALIDATION_THREAD_ID"]}}
'''
    pause = common + '''
graph.invoke({"case_id": os.environ["VALIDATION_CASE_ID"], "trace_id": "restart-validation",
    "input_type": "siem_alert", "raw_input": "Network egress. FORCE_GUARDRAIL3_FAIL",
    "case_status": "open", "findings": [], "agent_traces": [], "debate_round": 1,
    "debate_history": [], "specialists_completed": [], "dead_end_detected": False,
    "dead_end_categories": [], "loop_count": 0}, config)
assert "hitl" in graph.get_state(config).next
print(json.dumps({"paused": True}))
'''
    first = subprocess.run([sys.executable, "-"], input=pause, text=True, env=environment,
                           capture_output=True, timeout=45)
    assert first.returncode == 0, "Could not establish a paused case for restart test"
    resume = common + '''
from langgraph.types import Command
snapshot = graph.get_state(config)
assert snapshot.values.get("case_id") == os.environ["VALIDATION_CASE_ID"], "Checkpoint was lost on process restart"
assert "hitl" in snapshot.next
result = graph.invoke(Command(resume="approve"), config)
assert result["case_status"] == "closed"
print(json.dumps({"resumed_after_restart": True}))
'''
    second = subprocess.run([sys.executable, "-"], input=resume, text=True, env=environment,
                            capture_output=True, timeout=45)
    assert second.returncode == 0, "Paused investigation failed real process restart/resume verification"


def test_operational_owner_and_recovery_objectives_are_approved():
    assert Path("docs/operations_runbook.md").is_file()
    for name in ("SPECULA_OPERATIONS_OWNER", "SPECULA_APPROVED_RPO_SECONDS", "SPECULA_APPROVED_RTO_SECONDS"):
        assert os.getenv(name), f"Production approval/ownership missing: {name}"
    assert float(os.environ["SPECULA_APPROVED_RPO_SECONDS"]) >= 0
    assert float(os.environ["SPECULA_APPROVED_RTO_SECONDS"]) > 0
