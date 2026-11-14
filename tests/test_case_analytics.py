from src.agents.case_analytics import write_case_analytics, case_analytics_view, case_path


def test_durable_case_tables_chronology_shared_uid_and_context(monkeypatch,tmp_path):
    monkeypatch.setenv("SPECULA_ANALYTICS_DIR",str(tmp_path))
    events = [{"uid":"shared","time":"2026-10-13T00:01:00Z","class_uid":1007,"source_type":"evtx",
               "canonical_host_id":"host-A","unmapped":{"source_context":{"result":"denied"}}},
              {"uid":"earlier","time":"2026-10-12T23:59:00Z","class_uid":4001,"source_type":"edr"}]
    assert write_case_analytics("A",events)["events"] == 2
    assert write_case_analytics("B",events[:1])["events"] == 1
    a = case_analytics_view("A")
    b = case_analytics_view("B")
    assert a["timeline"][0]["uid"] == "earlier"
    assert dict((r['name'],r['rows']) for r in a['tables'])['events'] == 2
    assert len(b['timeline']) == 1
    assert case_analytics_view("unknown")["status"] == "unavailable"
    import duckdb
    with duckdb.connect(str(case_path("A")),read_only=True) as db:
        assert 'denied' in db.execute("SELECT original_context FROM events WHERE uid=?",['shared']).fetchone()[0]
    write_case_analytics("A",events,findings=[{"agent_role":"identity","summary":"Denied operation","classification":"failed","dfkg_refs":["shared"]}],
                         traces=[{"agent_role":"identity","model_used":"qwen3:8b","model_output_validated":True}])
    assert case_analytics_view("A")["metrics"]["classifications"] == {"failed":1}
