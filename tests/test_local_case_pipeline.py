"""Date-bounded local ingestion must preserve existing graph data and link a case."""

from types import SimpleNamespace
from unittest.mock import patch

from scripts import local_case_pipeline


def test_ingest_case_uses_selected_window_ports_and_case():
    queries = []
    calls = []

    class Graph:
        def execute(self, query, params):
            queries.append((query, params))
            return []

        def close(self):
            pass

    class Quickwit:
        def ensure_index(self):
            pass

    event = SimpleNamespace(uid="event-1", model_dump=lambda mode: {
        "uid": "event-1", "case_id": "LOCAL-1", "time": "2026-10-11T10:00:00+00:00",
        "src_endpoint": {"port": 4444}})

    def extract(channel, start, end, limit):
        calls.append((channel, start, end, limit))
        return [{"Id": 4688}] if channel == "System" else []

    def normalize(*args, **kwargs):
        assert kwargs["case_id"] == "LOCAL-1"
        assert kwargs["exclude_ports"] == {80, 443}
        return [(SimpleNamespace(valid=True, event=event), "MERGE", [])]

    with patch("src.ingestion.broker.case_stream.publish_normalized_case", return_value={"status":"verified"}), patch(
            "src.agents.case_analytics.write_case_analytics", return_value={"status": "verified"}), patch(
            "src.graph.process_lineage.persist_lineage", return_value={"resolved": 0}), patch(
            "src.ingestion.indexing.case_evidence.CaseEvidenceIndex") as index, patch(
            "src.ingestion.run_pipeline.extract_windows_events", side_effect=extract), patch(
            "src.ingestion.run_pipeline.run_pipeline_on_event", side_effect=normalize), patch(
            "src.ingestion.preservation.quickwit_client.QuickwitClient", return_value=Quickwit()), patch(
            "src.graph.neo4j_client.Neo4jClient", return_value=Graph()):
        index.return_value.index.return_value = {"status": "verified", "stored": 1}
        result = local_case_pipeline.ingest_case("LOCAL-1", "2026-10-11T09:00:00",
                                                 "2026-10-11T11:00:00", 25, [80, 443])

    assert result == {"case_id": "LOCAL-1", "extracted": 1, "accepted": 1}
    assert len(calls) == len(local_case_pipeline.CHANNELS)
    assert all(item[1:] == ("2026-10-11T09:00:00", "2026-10-11T11:00:00", 25) for item in calls)
    assert len(queries) == 4
    assert "DETACH DELETE" not in str(queries)
    assert "HAS_EVENT" in queries[1][0]
    assert queries[1][1]["event_uid"] == "event-1"


def test_background_investigation_has_no_false_read_deadline(monkeypatch):
    from pathlib import Path
    monkeypatch.setattr(Path,'read_text',lambda *a,**k:'test-token')
    with patch('scripts.local_case_pipeline.requests.Session') as session:
        client=session.return_value.__enter__.return_value
        client.post.return_value.ok=True
        client.post.return_value.json.return_value={'case_status':'hitl_review'}
        assert local_case_pipeline.investigate_case('LOCAL-test')['case_status']=='hitl_review'
        assert client.post.call_args.kwargs['timeout']==(10,None)
