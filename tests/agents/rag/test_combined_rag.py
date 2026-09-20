import pytest
from unittest.mock import MagicMock
from src.agents.rag.dfkg_retriever import DFKGRetriever

@pytest.mark.asyncio
async def test_combined_rag_retrieval():
    mock_neo4j = MagicMock()
    mock_vector_store = MagicMock()
    mock_embedder = MagicMock()
    
    # Setup mock to return a dummy vector result
    mock_embedder.embed.return_value = [0.1, 0.2, 0.3]
    mock_vector_store.query.return_value = [
        {"id": "dummy_uid", "score": 0.9, "text": "dummy text"}
    ]
    
    # Setup mock Neo4j to simulate a NODE anchor and empty graph
    mock_neo4j.execute_read.side_effect = [
        [{"c": 1}], # Is Node? Yes
        []          # Graph expansion returns empty
    ]
    
    retriever = DFKGRetriever(
        neo4j_client=mock_neo4j,
        vector_store=mock_vector_store,
        embedder=mock_embedder,
        max_hops=1, 
        max_nodes=10
    )
    query = "What file activity and network activity are associated with the suspicious process?"
    
    # The new API is `retrieve(query)` which returns a dict
    result = retriever.retrieve(query, top_k=1)
    
    assert isinstance(result, dict)
    assert result["query"] == query
    assert len(result["retrieved_uids"]) == 1
    assert result["retrieved_uids"][0]["uid"] == "dummy_uid"

    
    # Check if we retrieved anything
    print("Retrieved UIDs:", result["retrieved_uids"])
    print("Contexts length:", len(result["graph_contexts"]))
