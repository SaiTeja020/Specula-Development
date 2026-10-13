from types import SimpleNamespace

from src.agents import case_analysis as analysis
from src.agents.graph import _dead_end_route
from src.agents.log_analysis_factory import CaseDFKGClient


def state():
    return {"case_id": "C1", "evidence_collection": {"records": [
        {"uid": "ps", "class_uid": 1007, "time": "2026-10-13T03:08:00Z", "canonical_host_id": "host-A", "command_line": "powershell.exe -EncodedCommand test"},
        {"uid": "clear", "class_uid": 1007, "time": "2026-10-13T03:15:00Z", "canonical_host_id": "host-A", "command_line": "cmd /c wevtutil cl Security"},
        {"uid": "mft", "class_uid": 1001, "time": "2025-01-01T00:00:00Z", "si_created": "2025-01-01T00:00:00Z", "fn_created": "2026-10-13T03:10:00Z"},
        {"uid": "memory", "class_uid": 2004, "time": "2026-10-13T03:13:00Z", "source_type": "memory", "details": '{"plugin":"windows.malfind","finding":"RWX memory"}'},
        {"uid": "cloud", "class_uid": 6003, "time": "2026-10-13T03:20:00Z", "api_operation": "CreateServiceAccountKey"},
        {"uid": "normal", "class_uid": 2004, "time": "2026-10-13T03:00:00Z", "source_type": "ueba", "source_baseline_status": "normal"},
        {"uid": "failed", "class_uid": 3002, "time": "2026-10-13T03:05:00Z", "source_event_id": 4625, "user": {"name": "admin"}, "src_endpoint": {"ip_address": "192.0.2.1"}},
        {"uid": "success", "class_uid": 3002, "time": "2026-10-13T03:07:00Z", "source_event_id": 4624, "user": {"name": "admin"}, "src_endpoint": {"ip_address": "192.0.2.1"}},
    ]}}


def test_expected_observations_and_normal_control():
    findings = analysis.detections(state(), "log_analysis")
    assert {f["finding_type"] for f in findings} >= {"encoded_powershell", "security_log_clear_attempt", "timestamp_inconsistency"}
    assert analysis.detections(state(), "insider_threat") == []
    assert analysis.detections(state(), "identity")[0]["dfkg_refs"] == ["failed", "success"]
    targets = {send.node for send in _dead_end_route(state())}
    assert targets >= {"memory_forensics", "identity", "cloud_container", "insider_threat"}


def test_hallucinated_graph_output_is_rejected_and_timelines_have_citations(monkeypatch):
    llm = SimpleNamespace(model_name="qwen3:8b", invoke=lambda prompt: SimpleNamespace(content='{"selected_ids":[999],"probability":0.998}'))
    monkeypatch.setattr(analysis, "get_llm", lambda *args, **kwargs: llm)
    s = state()
    s["findings"] = analysis.detections(s, "log_analysis") + [{"source": "validated_case_rule", "dfkg_refs": ["foreign"], "finding_type": "invented"}]
    timeline = analysis.timeline(s)
    assert len(timeline["timeline"]["events"]) == 8
    assert all(e["dfkg_refs"] for e in timeline["timeline"]["events"])
    graph = analysis.activity_graph(s)
    assert len(graph["attack_graph"]["nodes"]) == 3
    assert graph["attack_graph"]["exploit_path_status"] == "unavailable"
    assert not graph["agent_traces"][0]["model_output_validated"]
    assert "probability" not in graph["attack_graph"]


def test_real_citation_query_is_scoped_to_case():
    calls = []
    def execute(query, **params):
        calls.append(params)
        return ([{"uid": "owned"}] if params == {"case_id": "C1", "uid": "owned"} else [], None, None)
    client = CaseDFKGClient(SimpleNamespace(execute_query=execute), "C1")
    assert client.query("owned") == ["owned"] and client.query("foreign") == []
    assert calls[-1]["case_id"] == "C1"
