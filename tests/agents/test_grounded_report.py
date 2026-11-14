from src.agents.grounded_report import render_report, render_timeline_artifact


def state(records=None):
    return {"case_id": "case-1", "report_generated_at": "2026-10-07T10:00:00Z",
            "evidence_collection": {"status": "complete", "records": records if records is not None else [
                {"uid": "event-1", "case_id": "case-1", "time": "2026-10-07T09:00:00Z",
                 "src_endpoint": {"ip": "192.0.2.1", "port": 443}, "bytes": 2048}]}}


def test_report_excludes_model_hallucination_and_preserves_original_citations():
    data = state()
    data.update({"raw_input": "invented C2", "proponent_argument": "2099-01-01 C2 verified",
                 "timeline": {"summary": "invented date", "events": [{"time": "2099-01-01"}]},
                 "findings": [{"summary": "invented actor identity", "dfkg_refs": ["fake"]}]})
    text, metadata = render_report(data)
    assert "invented" not in text and "2099" not in text and "C2" not in text
    assert "2048" in text and "192.0.2.1" in text
    assert "event:" in text and metadata["dfkg_refs"] == ["event-1"]
    assert metadata["generated_at"] == "2026-10-07T10:00:00+00:00"
    assert metadata["status"] == "complete"
    assert text.endswith("END OF SPECULA REPORT")


def test_unverified_attribution_refs_cannot_support_actor_scores():
    data = state()
    data["attribution"] = {"dfkg_refs": ["event-1", "made-up"], "threat_intel_refs": ["profile:hash"],
                           "candidate_actors": [{"actor_id": "G9999", "combined_score": 0.9}]}
    text, metadata = render_report(data)
    assert "G9999" not in text and "made-up" not in text
    assert metadata["dfkg_refs"] == ["event-1"] and metadata["threat_intel_refs"] == []
    assert metadata["status"] == "incomplete"


def test_bound_attribution_reports_only_score_not_model_narrative():
    data = state()
    data["attribution"] = {"dfkg_refs": ["event-1"], "threat_intel_refs": ["profile:hash"],
                           "summary": "definitely evil", "candidate_actors": [{"actor_id": "G0001", "combined_score": .6}]}
    text, metadata = render_report(data)
    assert "G0001" in text and "0.6" in text and "definitely evil" not in text
    assert "does not establish actor identity" in text
    assert metadata["threat_intel_refs"] == ["profile:hash"]


def test_no_data_and_incomplete_collection_are_explicit():
    text, metadata = render_report({"case_id": "empty"})
    assert metadata["status"] == "incomplete" and "No verified case evidence" in text
    data = state()
    data["evidence_collection"]["status"] = "incomplete"
    assert render_report(data)[1]["status"] == "incomplete"


def test_foreign_case_and_missing_uids_are_excluded():
    text, metadata = render_report(state([
        {"uid": "foreign", "case_id": "case-2", "bytes": 999999}, {"bytes": 123456}]))
    assert "999999" not in text and "123456" not in text
    assert metadata["dfkg_refs"] == []


def test_event_values_cannot_inject_markdown_or_html():
    data = state()
    data["evidence_collection"]["records"][0]["src_endpoint"] = {"ip": "```\n# forged\n<script>alert(1)</script>", "note": "invented"}
    text, _ = render_report(data)
    assert "```" not in text and "\n# forged" not in text and "<script>" not in text
    assert "invented" not in text


def test_output_is_not_truncated_at_model_token_limit():
    records = [{"uid": f"event-{i}", "time": "2026-10-07T09:00:00Z", "bytes": i} for i in range(500)]
    text, metadata = render_report(state(records))
    assert len(text.split()) > 1024 and len(metadata["dfkg_refs"]) == 500
    assert "499" in text and text.endswith("END OF SPECULA REPORT")


def test_timeline_orders_timezone_normalized_raw_events():
    data = state([{"uid": "later", "time": "2026-10-07T11:00:00+01:00"},
                  {"uid": "earlier", "time": "2026-10-07T14:30:00+05:30"},
                  {"uid": "unknown", "time": "2026-10-07T08:00:00"}])
    data["timeline"] = {"summary": "made-up", "events": [{"time": "2099-01-01"}]}
    text, metadata = render_timeline_artifact(data)
    assert text.index("earlier") < text.index("later") < text.index("unknown")
    assert "09:00:00+00:00" in text and "10:00:00+00:00" in text
    assert "2099" not in text and "made-up" not in text
    assert metadata["status"] == "incomplete" and text.endswith("END OF SPECULA TIMELINE")


def test_graph_serialized_endpoints_are_decoded():
    data = state([{"uid": "event-json", "time": 1791363600000,
                   "src_endpoint_json": '{"ip":"192.0.2.55","port":22}'}])
    text, _ = render_report(data)
    assert "192.0.2.55" in text and "22" in text


def test_triage_is_bounded_to_verified_uids_and_enum_verdicts():
    data = state()
    data["evidence_collection"]["triage"] = [
        {"uid": "event-1", "verdict": "KEEP", "reason": "unsupported C2"},
        {"uid": "fake", "verdict": "ESCALATE"}]
    text, _ = render_report(data)
    assert "Recorded triage: KEEP" in text and "fake" not in text and "unsupported C2" not in text


def test_conflicting_same_uid_records_are_excluded():
    data = state([{"uid": "conflict", "bytes": 1}, {"uid": "conflict", "bytes": 2}])
    _, metadata = render_report(data)
    assert metadata["dfkg_refs"] == [] and "conflicting_evidence_uid" in metadata["degraded_flags"]


def test_shared_graph_event_uses_confirmed_collection_case_membership():
    data = state([{"uid": "shared", "case_id": "first-case", "time": "2026-10-07T09:00:00Z"}])
    data["evidence_collection"]["case_id"] = "case-1"
    text, metadata = render_report(data)
    assert "shared" in text and metadata["dfkg_refs"] == ["shared"]
    assert "foreign_case_evidence_excluded" not in metadata["degraded_flags"]
    data["evidence_collection"]["case_id"] = "wrong-case"
    assert render_report(data)[1]["dfkg_refs"] == []


def test_unverified_corpus_artifacts_cannot_support_profile_scores():
    data = state()
    data["attribution"] = {"dfkg_refs": ["event-1"], "threat_intel_refs": ["profile:hash"],
                           "degraded_flags": ["corpus_artifacts_unverified"],
                           "candidate_actors": [{"actor_id": "G0001", "combined_score": .6}]}
    text, metadata = render_report(data)
    assert "G0001" not in text and metadata["threat_intel_refs"] == []
    assert metadata["status"] == "incomplete"
