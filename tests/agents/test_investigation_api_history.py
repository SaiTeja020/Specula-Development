from src.agents.investigation_api import _has_attack_analysis


def test_attack_graph_projection_counts_as_attack_analysis_without_dag_finding():
    assert _has_attack_analysis({"attack_graph": {"kind": "observed_activity_graph"}, "findings": []})


def test_dag_finding_remains_a_legacy_attack_analysis_signal():
    assert _has_attack_analysis({"findings": [{"agent_role": "dag"}]})


def test_empty_graph_and_findings_have_no_attack_analysis():
    assert not _has_attack_analysis({"attack_graph": {}, "findings": []})
