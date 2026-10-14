import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from src.agents import case_analysis as analysis
from src.agents import evidence_review as review
from src.agents.nodes import judge_node


class Selections:
    model_name = "qwen3:8b"
    def __init__(self):
        self.calls = []
    def invoke_structured(self, prompt, schema):
        self.calls.append((prompt, schema))
        items = json.loads(prompt.split("Return JSON only.\n", 1)[1].split("\nRequired JSON schema:")[0])
        return SimpleNamespace(content=json.dumps({"selected_ids": [row["id"] for row in items]}))


def test_all_batches_reviewed_without_silent_cutoff():
    llm = Selections()
    facts = [{"summary": f"Observation {i}", "dfkg_refs": [f"e{i}"]} for i in range(97)]
    trace = review.review("timeline_reconstruction", {}, facts, llm)
    assert len(llm.calls) == 4
    assert trace["selected_observation_ids"] == list(range(97))
    assert trace["review_coverage"] == {"submitted": 97, "validated": 97, "total": 97, "complete": True}
    assert all(schema["additionalProperties"] is False for _,schema in llm.calls)


def test_one_retry_and_invalid_ids_fail_closed():
    responses = iter(['prose', '{"selected_ids":[0]}'])
    llm = SimpleNamespace(invoke=lambda prompt: SimpleNamespace(content=next(responses)))
    trace = review.review("identity", {}, [{"summary": "test", "dfkg_refs": ["e"]}], llm)
    assert trace["model_output_validated"]
    assert len(trace["review_batches"][0]["attempts"]) == 2
    llm = SimpleNamespace(invoke=lambda prompt: SimpleNamespace(content='{"selected_ids":[99]}'))
    trace = review.review("identity", {}, [{"summary": "test", "dfkg_refs": ["e"]}], llm)
    assert not trace["model_output_validated"] and trace["review_coverage"]["validated"] == 0


def test_critic_decoder_limits_citations_per_hypothesis():
    facts=[{'summary':'First source observation','dfkg_refs':['a'],'canonical_host_id':'H'},
           {'summary':'Unrelated second source','dfkg_refs':['b'],'canonical_host_id':'H'}]
    state={'proponent_review':{'hypotheses':[{'kind':'unresolved','hypothesis':'First source needs investigation','observation_ids':[0],'limitations':'Source remains unverified'},
        {'kind':'unresolved','hypothesis':'Second source needs investigation','observation_ids':[1],'limitations':'Source remains unverified'}],
        'observation_batches':[{'observation_ids':[0,1],'hypothesis_ids':[0,1]}]}}
    def invoke(prompt,schema):
        variants=schema['properties']['challenges']['items']['oneOf']
        assert variants[0]['properties']['hypothesis_id']['enum']==[0]
        assert variants[0]['properties']['supporting_ids']['items']['enum']==[0]
        assert variants[1]['properties']['counter_ids']['items']['enum']==[1]
        return SimpleNamespace(content=json.dumps({'challenges':[{'hypothesis_id':i,'assessment':'unresolved','supporting_ids':[i],'counter_ids':[],
            'rationale':'Specific source context remains unverified.'} for i in [0,1]]}))
    assessment,trace=review.debate('critic',state,facts,SimpleNamespace(invoke_structured=invoke))
    assert assessment and trace['model_output_validated']


def test_distinct_roles_and_real_judgment(monkeypatch):
    facts = [{"summary": "Suspicious staging", "dfkg_refs": ["a"], "classification": "suspicious"},
             {"summary": "Operation access denied", "dfkg_refs": ["b"], "classification": "failed"}]
    responses = {
        "proponent": {"hypotheses": [{"kind": "incident", "hypothesis": "Possible staging on host A", "observation_ids": [0,1], "limitations": "Credential extraction unproven"}]},
        "critic": {"challenges": [{"hypothesis_id": 0, "assessment": "unresolved", "supporting_ids": [0], "counter_ids": [1], "rationale": "Access was denied; extraction is unproven"}]},
        "judge": {"verdict": "incomplete", "resolutions": [{"hypothesis_id": 0, "disposition": "unresolved", "observation_ids": [0,1], "rationale": "Denied access limits the incident hypothesis"}], "rationale": "Additional corroboration required"}}
    state = {}
    prompts = []
    for role in responses:
        def invoke(prompt, schema, role=role):
            prompts.append(prompt)
            return SimpleNamespace(content=json.dumps(responses[role]))
        assessment, trace = review.debate(role, state, facts, SimpleNamespace(invoke_structured=invoke))
        assert trace["model_output_validated"]
        state[role+"_review"] = assessment
    assert "proponent" in prompts[1] and "critic" in prompts[2]
    assert len(set(prompts)) == 3
    state["evidence_collection"] = {"records": [{"uid": "a"}]}
    monkeypatch.setattr("src.agents.nodes._run_agent", lambda *args: ({"summary": "structured judgment", "assessment": state["judge_review"], "review_valid": True}, {}))
    command = judge_node(state)
    assert command.goto == "hitl" and command.update["judge_verdict"] == "incomplete"
    assert command.update["acceptance_status"] == "incomplete"


def test_invalid_review_cannot_become_acceptance(monkeypatch):
    monkeypatch.setattr("src.agents.nodes._run_agent", lambda *args: ({"summary": "VERDICT: ACCEPT", "review_valid": False}, {}))
    command = judge_node({"evidence_collection": {"records": [{"uid": "a"}]}})
    assert command.goto == "hitl" and command.update["review_status"] == "incomplete"


def test_benign_alternative_is_valid_but_compromise_claim_is_not():
    facts = [{"summary": "Source-reported approved deployment", "classification": "benign", "dfkg_refs": ["b"]}]
    response = {"hypotheses": [{"kind": "alternative", "hypothesis": "Legitimate approved deployment explains the activity", "observation_ids": [0], "limitations": "Source approval needs examiner verification"}]}
    llm = SimpleNamespace(invoke_structured=lambda *args: SimpleNamespace(content=json.dumps(response)))
    assessment, trace = review.debate("proponent", {}, facts, llm)
    assert assessment and trace["model_output_validated"]
    response["hypotheses"][0]["kind"] = "incident"
    assessment, trace = review.debate("proponent", {}, facts, llm)
    assert assessment is None and not trace["model_output_validated"]


def test_unrelated_host_control_is_not_mandatory_counter_evidence():
    facts=[{'summary':'Suspicious event','classification':'suspicious','canonical_host_id':'A','dfkg_refs':['a']},
           {'summary':'Unrelated benign event','classification':'benign','canonical_host_id':'A','dfkg_refs':['b']}]
    state={'proponent_review':{'hypotheses':[{'kind':'incident','hypothesis':'Possible suspicious activity',
              'observation_ids':[0],'limitations':'Needs corroboration'}],
              'observation_batches':[{'observation_ids':[0],'hypothesis_ids':[0]}]}}
    payload={'challenges':[{'hypothesis_id':0,'assessment':'unresolved','supporting_ids':[0],
              'counter_ids':[],'rationale':'Insufficient source evidence to conclude intent'}]}
    llm=SimpleNamespace(invoke_structured=lambda prompt,schema:SimpleNamespace(content=json.dumps(payload)))
    assessment,trace=review.debate('critic',state,facts,llm)
    assert assessment and trace['model_output_validated']


def test_global_hypothesis_ids_are_constrained_across_batches():
    facts = [{"summary": f"Observed suspicious event {i}", "classification": "suspicious", "dfkg_refs": [f"e{i}"]} for i in range(33)]
    seen = []
    def invoke(prompt, schema):
        if "Hypothesis" in schema.get("$defs", {}):
            ids = schema["$defs"]["Hypothesis"]["properties"]["observation_ids"]["items"]["enum"]
            payload = {"hypotheses": [{"kind": "incident", "hypothesis": "Possible suspicious source activity", "observation_ids": ids, "limitations": "Source corroboration remains necessary"}]}
        else:
            properties = schema["$defs"]["Challenge"]["properties"]
            hypothesis = properties["hypothesis_id"]["enum"][0]
            ids = properties["supporting_ids"]["items"]["enum"]
            seen.append(hypothesis)
            payload = {"challenges": [{"hypothesis_id": hypothesis, "assessment": "unresolved", "supporting_ids": [ids[0]], "counter_ids": [], "rationale": "Independent source corroboration missing"}]}
        return SimpleNamespace(content=json.dumps(payload))
    llm = SimpleNamespace(invoke_structured=invoke)
    proponent, _ = review.debate("proponent", {}, facts, llm)
    critic, trace = review.debate("critic", {"proponent_review": proponent}, facts, llm)
    assert critic and seen == list(range(6)) and trace["review_coverage"]["complete"]


def test_unrelated_counter_evidence_and_omitted_observations_rejected():
    facts = [{"summary":"Suspicious executable", "classification":"suspicious", "canonical_host_id":"A","dfkg_refs":["a"]},
             {"summary":"Other benign activity", "classification":"benign", "canonical_host_id":"A","dfkg_refs":["b"]}]
    prop = {"hypotheses":[{"kind":"incident","hypothesis":"Potential suspicious execution", "observation_ids":[0],"limitations":"No malicious verdict"}]}
    llm = SimpleNamespace(invoke_structured=lambda *a:SimpleNamespace(content=json.dumps(prop)))
    assessment,trace=review.debate('proponent',{},facts,llm)
    assert assessment is None and 'Every required' in trace['review_attempts'][-1]['error']
    state={'proponent_review':{'hypotheses':prop['hypotheses'],
        'observation_batches':[{'observation_ids':[0,1],'hypothesis_ids':[0]}]}}
    payload={'challenges':[{'hypothesis_id':0,'assessment':'unsupported','supporting_ids':[0],'counter_ids':[1],
                           'rationale':'An unrelated benign operation refutes the hypothesis'}]}
    llm=SimpleNamespace(invoke_structured=lambda *a:SimpleNamespace(content=json.dumps(payload)))
    assessment,trace=review.debate('critic',state,facts,llm)
    assert assessment is None and 'share its evidence' in trace['review_attempts'][-1]['error']
    facts[1]['canonical_host_id']='B'
    assessment,trace=review.debate('critic',state,facts,llm)
    assert assessment is None


def test_guardrails_distinguish_cited_commands_from_model_advice():
    from src.agents.nodes import guardrail_tier1_node,guardrail_tier2_node
    cited={'summary':'Source ran os.system(x) and recommended disabling logging and deleting evidence',
           'source':'validated_case_rule','dfkg_refs':['a']}
    state={'findings':[cited]}
    assert guardrail_tier1_node(state).goto=='guardrail_tier2'
    assert guardrail_tier2_node(state).goto=='guardrail_tier3'
    assert guardrail_tier1_node({'findings':[{**cited,'source':'model_assessment'}]}).goto=='hitl'


def test_missing_live_collection_is_not_legacy_acceptance(monkeypatch):
    llm = SimpleNamespace(invoke=lambda prompt: SimpleNamespace(content='prose'))
    result, trace = review.debate("proponent", {}, [], llm)
    assert result is None and not trace["model_output_validated"]
    monkeypatch.setattr("src.agents.nodes.get_llm", lambda *args, **kwargs: llm)
    command = judge_node({"evidence_review_required": True, "evidence_collection": {"records": []}})
    assert command.goto == "hitl" and command.update["judge_verdict"] == "incomplete"


@pytest.fixture(scope="module")
def complex_case(tmp_path_factory):
    from scripts import generate_complex_evidence as generator
    from src.ingestion import run_pipeline
    from src.ingestion.upload_archive import validate_archive, archive_batches
    from src.ingestion.normalization.time_normalizer import TimeNormalizer
    from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
    from src.schemas.entity_resolver import CanonicalEntityResolver
    out = tmp_path_factory.mktemp("complex-fixture")
    with patch.object(generator, "OUT", out):
        generator.main()
    archive = out / "complex-evidence.zip"
    inventory = validate_archive(archive.read_bytes())
    events, outputs = {}, 0
    resolver, clock, chain = CanonicalEntityResolver(), TimeNormalizer(None), VCTAtomicChain()
    with patch.object(run_pipeline, "run_security_gate", return_value=SimpleNamespace(injection_blocked=False)), \
         patch("src.ingestion.normalization.evtx_normalizer.detect_prompt_injection", return_value=(False, True)), \
         patch("src.ingestion.normalization.mft_usn_normalizer.detect_prompt_injection", return_value=(False, True)), \
         patch("src.ingestion.normalization.cloud_normalizer.detect_prompt_injection", return_value=(False, True)):
        for item, (source, rows) in zip(inventory["files"], archive_batches(archive, inventory)):
            for raw in rows:
                batch = run_pipeline.run_pipeline_on_event(raw, chain, resolver, clock, source_type=source,
                           exported_log_path=item["path"], case_id="FIXTURE")
                assert batch, raw["record_id"]
                for validated, query, _ in batch:
                    assert validated.valid and query
                    event = validated.event.model_dump(mode="json")
                    event.update({"source_type": source, "source_event_id": raw.get("event_id"), "source_finding": raw.get("finding") or raw.get("detection"),
                                  "source_event_type": raw.get("event_type") or raw.get("event"), "source_baseline_status": raw.get("baseline_status")})
                    events[event["uid"]] = event
                    outputs += 1
    assert outputs == 1229 and len(events) == 1227
    return {"case_id": "FIXTURE", "evidence_collection": {"records": list(events.values())}}


def test_source_hosts_outcomes_and_context_survive(complex_case):
    for event in analysis.records(complex_case):
        raw = analysis.context(event)
        if raw.get("host"):
            assert event["canonical_host_id"] == "host-"+raw["host"]
        elif event.get("source_type") == "memory":
            assert event["canonical_host_id"] is None
    cloud = analysis.detections(complex_case, "cloud_container")
    assert len([f for f in cloud if f["finding_type"] == "service_account_key_failed"]) == 1
    assert len([f for f in cloud if f["finding_type"] == "service_account_key_creation" and f["operation_outcome"] == "confirmed"]) == 1


def test_complex_negative_controls_and_failed_branches(complex_case):
    logs = analysis.detections(complex_case, "log_analysis")
    assert any(f["finding_type"] == "security_log_clear_failed" and f["canonical_host_id"] == "host-WS-23" for f in logs)
    assert any(f["finding_type"] == "security_log_cleared" and f["canonical_host_id"] == "host-APP-03" for f in logs)
    assert any(f["finding_type"] == "encoded_powershell" and f["classification"] == "benign" and f["canonical_host_id"] == "host-MGMT-01" for f in logs)
    assert any(f["finding_type"] == "timestamp_inconsistency" and f["classification"] == "benign" and f["canonical_host_id"] == "host-BKP-01" for f in logs)
    assert any(f["finding_type"] == "network_connection_failed" for f in logs)
    memory = analysis.detections(complex_case, "memory_forensics")
    negative = next(f for f in memory if "No credential material recovered" in f["summary"])
    assert negative["classification"] == "negative" and negative["severity_id"] == 1 and negative["attacks"] == []
    identities = analysis.detections(complex_case, "identity")
    assert any(f["classification"] == "failed" and f["canonical_host_id"] == "host-WS-23" for f in identities)
    assert any(f["classification"] == "benign" and "b.chen" in f["summary"] for f in identities)


def test_graph_never_links_distinct_hosts_or_equal_instants(complex_case, monkeypatch):
    facts = []
    for role in ["log_analysis", "identity", "memory_forensics", "cloud_container", "malware_stylometry", "insider_threat"]:
        facts.extend(analysis.detections(complex_case, role))
    case = {**complex_case, "findings": facts}
    monkeypatch.setattr(analysis, "get_llm", lambda *args, **kwargs: Selections())
    graph = analysis.activity_graph(case)["attack_graph"]
    nodes = {n["id"]: n for n in graph["nodes"]}
    for edge in graph["edges"]:
        a,b = nodes[edge["source"]],nodes[edge["target"]]
        if edge['type']=='PRECEDES':
            assert a["canonical_host_id"] == b["canonical_host_id"]
            assert analysis.instant(a["time"]) < analysis.instant(b["time"])
        else:
            assert analysis.instant(a['time'])<=analysis.instant(b['time'])
            assert edge['basis'] and not edge['causal']
            assert set(edge['dfkg_refs'])==set(a['dfkg_refs']+b['dfkg_refs'])
    assert len([n for n in nodes.values() if n["label"] == "source_unsigned_executable"]) == 1


def test_log_adapter_decodes_context_and_loads_counter_evidence(complex_case, monkeypatch):
    from src.agents import log_analysis_factory as factory
    rows = []
    for event in complex_case["evidence_collection"]["records"]:
        item = dict(event)
        item["unmapped"] = json.dumps(item["unmapped"])
        rows.append({"e": item})
    driver = SimpleNamespace(execute_query=lambda *args, **kwargs: (rows, None, None))
    monkeypatch.setattr(factory, "get_llm", lambda *args, **kwargs: SimpleNamespace())
    monkeypatch.setattr(factory, "LogAnalysisAgent", lambda **kwargs: SimpleNamespace(run_on_batch=lambda *args, **kwargs: []))
    findings = factory.make_log_analysis_node(None, None, None, driver)({"case_id": "FIXTURE"})["findings"]
    assert any(f["finding_type"] == "security_log_clear_failed" for f in findings)
    assert any(f["finding_type"] == "security_log_cleared" for f in findings)
    assert any(f["finding_type"] == "encoded_powershell" and f["classification"] == "benign" for f in findings)
