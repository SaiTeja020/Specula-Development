import pytest

from src.graph.cypher_builder import CypherBuilder


@pytest.mark.parametrize("cls", [1007, 1001, 2004, 3001, 2005, 2002, 4002, 3002])
def test_unknown_hosts_are_optional_not_placeholder_entities(cls):
    event = {"uid": "fixture", "class_uid": cls, "canonical_host_id": None,
             "user": {"name": "examiner"}, "time": "2026-10-13T10:00:00Z"}
    query, params = CypherBuilder.dispatch_event(event)
    assert params["canonical_host_id"] is None
    assert "CASE WHEN $canonical_host_id IS NULL THEN [] ELSE [1] END" in query
    assert "UNKNOWN_HOST" not in str(params)
    event["canonical_host_id"] = "source-host"
    assert CypherBuilder.dispatch_event(event)[1]["canonical_host_id"] == "source-host"


def test_source_titles_and_cves_survive_typed_writes():
    assert CypherBuilder.build_detection_finding({"finding_title": "Source finding"})[1]["finding_info"] == "Source finding"
    assert CypherBuilder.build_vulnerability_finding({"vulnerability_id": "CVE-TEST"})[1]["cve"] == "CVE-TEST"
