"""Run with python -m unittest discover -s tests -p test_merge_integration.py.

Exercises merge boundaries without installing dependencies or contacting services.
"""
import argparse
import ast
from contextlib import redirect_stdout
from contextlib import contextmanager
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import Mock, patch
import uuid

import src.agents as agents_package
from src.agents.memory_forensics.agent import run_memory_forensics_analysis
from src.agents.memory_forensics_factory import make_memory_forensics_node

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def temporary_module(name, module):
    """Restore only our injected module, retaining unrelated imports/C extensions."""
    missing = object()
    previous = sys.modules.get(name, missing)
    sys.modules[name] = module
    try:
        yield
    finally:
        if previous is missing:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous


class MergeIntegrationTests(unittest.TestCase):
    def test_preserved_records_use_native_review_not_legacy_artifact_provider(self):
        state = {"case_id": "case-a", "evidence_collection": {"records": [{"uid": "e1"}]}}
        review = ModuleType("src.agents.case_analysis")
        expected = {"agent_traces": [{"review_status": "incomplete"}], "findings": []}
        review.specialist = Mock(return_value=expected)
        provider = Mock(side_effect=AssertionError("Legacy path bypassed native review"))
        with temporary_module("src.agents.case_analysis", review), patch.object(
                agents_package, "case_analysis", review, create=True):
            result = make_memory_forensics_node(artifact_provider=provider)(state)
        self.assertIs(result, expected)
        review.specialist.assert_called_once_with("memory_forensics", "memory", state)
        provider.assert_not_called()

    def test_shared_memory_is_read_by_case_membership_and_published(self):
        artifact = {"case_id": "original-case", "uid": "e1", "source_image_uid": "image-a",
                    "plugin": "psscan", "visible_in_pslist": False, "PID": 12}
        driver, producer = Mock(), Mock()
        driver.execute_query.return_value = ([{"e": artifact}], None, None)
        result = make_memory_forensics_node(driver, producer)({"case_id": "case-a"})
        query = driver.execute_query.call_args.args[0]
        self.assertIn("(:Case {uid: $case_id})-[:HAS_EVENT]->(e:Event)", query)
        self.assertNotIn("e.case_id", query)
        self.assertEqual(driver.execute_query.call_args.kwargs, {"case_id": "case-a"})
        self.assertEqual(result["findings"][0]["dfkg_refs"], ["e1"])
        self.assertEqual(result["findings"][0]["case_id"], "case-a")
        self.assertEqual(artifact["case_id"], "original-case")
        self.assertEqual(producer.produce.call_args.kwargs["topic"], "findings.specialist.memory")

    def test_negative_memory_result_cannot_become_injection_finding(self):
        artifact = {"uid": "negative", "plugin": "malfind", "result_status": "negative"}
        self.assertEqual(run_memory_forensics_analysis([artifact], case_id="case-a"), [])
        positive = {**artifact, "uid": "positive", "result_status": "positive"}
        self.assertEqual(run_memory_forensics_analysis([positive], case_id="case-a")[0]["rule_id"],
                         "MEM-INJECTED-CODE")

    def test_memory_provider_cannot_publish_another_cases_artifacts(self):
        producer = Mock()
        node = make_memory_forensics_node(kafka_producer=producer,
            artifact_provider=lambda state: [{"case_id": "foreign", "plugin": "malfind"}])
        with self.assertRaisesRegex(ValueError, "another case"):
            node({"case_id": "case-a"})
        producer.produce.assert_not_called()

    def test_memory_finding_uids_survive_publication_without_case_or_image_collisions(self):
        artifact = {"uid": "e1", "source_image_uid": "image-a", "plugin": "malfind", "PID": 12}
        first = run_memory_forensics_analysis([artifact], case_id="case-a")[0]
        again = run_memory_forensics_analysis([artifact], case_id="case-a")[0]
        other_case = run_memory_forensics_analysis([artifact], case_id="case-b")[0]
        other_image = run_memory_forensics_analysis([{**artifact, "source_image_uid": "image-b"}],
                                                    case_id="case-a")[0]
        self.assertEqual(first["uid"], again["uid"])
        self.assertEqual(len({first["uid"], other_case["uid"], other_image["uid"]}), 3)
        self.assertEqual(first["case_id"], "case-a")
        self.assertNotIn("case_id", artifact)
        producer = Mock()
        node = make_memory_forensics_node(kafka_producer=producer, artifact_provider=lambda state: [artifact])
        node({"case_id": "case-a"})
        self.assertEqual(json.loads(producer.produce.call_args.kwargs["value"])["uid"], first["uid"])

    def test_gcp_runner_reaches_publication_and_preserves_existing_graph(self):
        # Execute the actual main function with infrastructure boundaries replaced.
        # Loading just this function avoids unavailable third-party imports.
        source = ast.parse((ROOT / "src/ingestion/run_pipeline.py").read_text(encoding="utf-8"))
        main = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        driver, producer, logger = Mock(), Mock(), Mock()
        neo4j_module = ModuleType("src.graph.neo4j_client")
        neo4j_module.Neo4jClient = Mock(return_value=driver)
        neo4j_module.Neo4jClientError = RuntimeError
        fetcher = Mock()
        fetcher.fetch_audit_logs.return_value = [{"protoPayload": {"methodName": "test"}}]
        normalizer = Mock(return_value=Mock())
        namespace = dict(argparse=argparse, os=os, json=json, datetime=datetime, timezone=timezone,
            uuid=uuid, logger=logger, subprocess=Mock(), extract_windows_events=Mock(return_value=[]),
            MEMORY_ENABLED=False, QUICKWIT_ENABLED=False, NEO4J_ENABLED=True,
            VCTAtomicChain=Mock(), CanonicalEntityResolver=Mock(), TimeNormalizer=Mock(),
            GCP_PROJECT_ID="local-test", GOOGLE_APPLICATION_CREDENTIALS=None,
            ActiveCasesCache=Mock(), EventProducer=Mock(return_value=producer),
            OCSF_BASE_JSON_SCHEMA="{}", GCPAuditFetcher=Mock(return_value=fetcher),
            compute_sha256_bytes=Mock(return_value="digest"),
            run_security_gate=Mock(return_value=Mock(injection_blocked=False)),
            normalize_gcp_audit=normalizer)
        exec(compile(ast.Module(body=[main], type_ignores=[]), "run_pipeline.py", "exec"), namespace)
        previous = Path.cwd()
        with tempfile.TemporaryDirectory(dir=ROOT / "data") as directory:
            try:
                os.chdir(directory)
                with patch.object(sys, "argv", ["run_pipeline.py"]), temporary_module(
                        "src.graph.neo4j_client", neo4j_module), redirect_stdout(io.StringIO()):
                    namespace["main"]()
            finally:
                os.chdir(previous)
        producer.produce_event.assert_called_once_with(normalizer.return_value)
        driver.execute.assert_not_called()
        driver.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
