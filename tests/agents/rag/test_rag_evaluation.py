import json
import os
import pytest
from unittest.mock import MagicMock

from src.agents.rag.dfkg_retriever import DFKGRetriever
from src.agents.rag.response_validator import validate_response_uids

def load_cases():
    json_path = os.path.join(os.path.dirname(__file__), "rag_evaluation_cases.json")
    with open(json_path, "r") as f:
        return json.load(f)

EVAL_CASES = load_cases()

def test_evaluation_case_schema():
    """Verify the evaluation dataset has the required fields."""
    for case in EVAL_CASES:
        assert "id" in case
        assert "question" in case
        assert "expected_uids" in case
        assert "expected_entities" in case
        assert "expected_relationships" in case
        assert "sufficient_evidence" in case
        assert "expect_insufficient" in case

def test_unsupported_evidence_handling():
    """Verify that unsupported scenarios trigger the correct logic."""
    unsupported_cases = [c for c in EVAL_CASES if c["expect_insufficient"]]
    assert len(unsupported_cases) > 0, "Must have at least one unsupported case"
    case = unsupported_cases[0]
    
    # In a real system, the prompt would instruct the LLM to output "Insufficient evidence".
    # Here we just verify the dataset intends this.
    assert not case["sufficient_evidence"]

def test_citation_validation():
    """Verify output-side validation catches hallucinated citations."""
    mock_contexts = [
        {"nodes": {"abcdef123456": {"labels": ["NetworkEndpoint"], "properties": {"uid": "abcdef123456"}}}, "relationships": {}}
    ]
    
    # 1. Valid citation
    response_valid = "Based on the evidence uid=abcdef123456 it occurred."
    report_valid = validate_response_uids(response_valid, mock_contexts)
    assert not report_valid["has_unverified_uids"]
    
    # 2. Invalid citation
    response_invalid = "This is a hallucination uid=deadbeef1234."
    report_invalid = validate_response_uids(response_invalid, mock_contexts)
    assert report_invalid["has_unverified_uids"]
    assert "deadbeef1234" in report_invalid["unverified_uids"]

@pytest.fixture
def mock_retriever():
    mock_neo4j = MagicMock()
    mock_store = MagicMock()
    mock_embedder = MagicMock()
    return DFKGRetriever(
        neo4j_client=mock_neo4j,
        vector_store=mock_store,
        embedder=mock_embedder
    )

def test_node_anchor_retrieval(mock_retriever):
    """Verify the retriever can handle node anchors."""
    mock_retriever.neo4j.execute_read.side_effect = [
        # Check anchor type (Node)
        [{"type": "NODE"}],
        # Expansion result
        [{"nodes": [], "rels": []}]
    ]
    
    context = mock_retriever.expand_from_uid("node-uid-123")
    assert context is not None
    # Verify the NODE query was executed
    calls = mock_retriever.neo4j.execute_read.call_args_list
    assert "MATCH (path = (seed {uid: $uid})" in calls[1][0][0] or "MATCH path = (seed {uid: $uid})" in calls[1][0][0]

def test_relationship_anchor_retrieval(mock_retriever):
    """Verify the retriever can handle relationship anchors."""
    mock_retriever.neo4j.execute_read.side_effect = [
        # Check anchor type (None for NODE, then fallback to rel check)
        [],
        # Check anchor type (Relationship)
        [{"type": "RELATIONSHIP"}],
        # Expansion result
        [{"nodes": [], "rels": []}]
    ]
    
    context = mock_retriever.expand_from_uid("rel-uid-123")
    assert context is not None
    
    calls = mock_retriever.neo4j.execute_read.call_args_list
    assert "MATCH (source)-[seed {uid: $uid}]->(target)" in calls[2][0][0]

